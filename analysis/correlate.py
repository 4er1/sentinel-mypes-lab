"""correlate.py — Evalúa Sentinel-MYPES como un único prototipo integrado.

VI sugerida: tipo de incidente controlado (E0-E5).
VD: efectividad de la reconstrucción forense, con tres indicadores:
  - campos de metadatos confirmados correctamente / campos esperados
  - cobertura de preguntas (existe evidencia candidata)
  - exactitud de respuestas (coinciden con la verdad de referencia independiente)

Git, Kubernetes Audit y Argo CD son fuentes complementarias que el prototipo correlaciona; este informe no compara las
fuentes entre sí. La verdad de referencia se registra separadamente por lab.py. Solo usa la biblioteca estándar de Python.
"""
import argparse
import csv
import html
import json
import re
import statistics
import subprocess
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

WRITE_VERBS = {"create", "update", "patch", "delete", "deletecollection"}
NOISE_PREFIXES = ("system:serviceaccount:kube-system:", "system:kube-", "system:node", "system:apiserver")
SOURCES = ["git", "audit", "argocd"]


# ----------------------------------------------------------------------------- utilidades
def parse_ts(s):
    """Convierte timestamps ISO-8601 (Z, offsets, 3-9 decimales) a datetime UTC."""
    if not s:
        return None
    m = re.match(r"(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(\.\d+)?(Z|[+-]\d{2}:?\d{2})?$", s.strip())
    if not m:
        raise ValueError(f"timestamp no reconocido: {s}")
    d, t, frac, tz = m.groups()
    frac = (frac or ".0")[1:7].ljust(6, "0")
    tz = tz or "Z"
    if tz == "Z":
        tz = "+00:00"
    elif ":" not in tz:
        tz = tz[:3] + ":" + tz[3:]
    return datetime.fromisoformat(f"{d}T{t}.{frac}{tz}").astimezone(timezone.utc)


def fmt(ts):
    return ts.strftime("%Y-%m-%d %H:%M:%S")


def load_jsonl(path):
    out = []
    p = Path(path)
    if not p.exists():
        return out
    for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return out


def find_images(obj):
    """Busca recursivamente valores de la clave 'image' dentro de un objeto JSON."""
    found = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == "image" and isinstance(v, str):
                found.append(v)
            else:
                found.extend(find_images(v))
    elif isinstance(obj, list):
        for v in obj:
            found.extend(find_images(v))
    return found


def event(ts, source, actor, action, resource, detail, origin="", **extra):
    return {"ts": ts, "source": source, "actor": actor or "", "action": action or "",
            "resource": resource or "", "detail": detail or "", "origin": origin or "", "extra": extra}


# ----------------------------------------------------------------------------- cargadores
def load_git(repo):
    """Commits: autor, fecha, hash, mensaje y archivos cambiados."""
    fmt_str = "@@%H%x1f%an%x1f%ae%x1f%aI%x1f%s"
    r = subprocess.run(["git", "-C", str(repo), "log", "--name-only", f"--pretty=format:{fmt_str}"],
                       capture_output=True, text=True)
    if r.returncode != 0:
        return []
    evs, cur = [], None
    for line in r.stdout.splitlines():
        if line.startswith("@@"):
            h, an, ae, ai, subj = line[2:].split("\x1f")
            cur = event(parse_ts(ai), "git", f"{an} <{ae}>", "commit", "", subj, commit=h, files=[])
            evs.append(cur)
        elif line.strip() and cur is not None:
            cur["extra"]["files"].append(line.strip())
    for e in evs:
        e["resource"] = ", ".join(e["extra"]["files"])
    return sorted(evs, key=lambda e: e["ts"])


def image_at(repo, rev, manifest):
    r = subprocess.run(["git", "-C", str(repo), "show", f"{rev}:{manifest}"], capture_output=True, text=True)
    m = re.search(r"image:\s*(\S+)", r.stdout)
    return m.group(1) if m else None


def load_audit(path, ns):
    """Eventos relevantes del audit log de Kubernetes."""
    evs = []
    for a in load_jsonl(path):
        if a.get("stage") != "ResponseComplete":
            continue
        user = (a.get("user") or {}).get("username", "")
        imp = (a.get("impersonatedUser") or {}).get("username")
        eff = imp or user
        actor = f"{imp} (vía {user})" if imp else user
        if eff.startswith(NOISE_PREFIXES):
            continue
        ref = a.get("objectRef") or {}
        res, sub, name, rns = ref.get("resource", ""), ref.get("subresource", ""), ref.get("name", ""), ref.get("namespace", "")
        verb = a.get("verb", "")
        is_write = verb in WRITE_VERBS
        is_exec = res == "pods" and sub in ("exec", "attach")
        is_secret = res == "secrets"
        keep = (rns == ns and (is_write or is_exec or is_secret)) or \
               (is_secret and (eff.startswith(f"system:serviceaccount:{ns}:") or not eff.startswith("system:")))
        if not keep:
            continue
        resource = res + (f"/{sub}" if sub else "") + (f"/{name}" if name else "") + f" (ns={rns})"
        images = find_images(a.get("requestObject")) if (res == "deployments" and verb in ("patch", "update", "create")) else []
        config_data = {}
        if res == "configmaps" and verb in ("patch", "update", "create"):
            request_obj = a.get("requestObject") or {}
            config_data = request_obj.get("data") or {}
        ips = ", ".join(a.get("sourceIPs") or [])
        origin = f"{ips} | {a.get('userAgent', '')}".strip(" |")
        code = (a.get("responseStatus") or {}).get("code", "")
        detail = f"{verb} {a.get('requestURI', '')} -> HTTP {code}"
        if images:
            detail += f" | imagen={images[0]}"
        if config_data:
            # Solo se capturan valores sintéticos de ConfigMaps del laboratorio, nunca Secret bodies.
            detail += " | configmap_data=" + json.dumps(config_data, ensure_ascii=False, sort_keys=True)
        evs.append(event(parse_ts(a.get("requestReceivedTimestamp") or a.get("stageTimestamp")),
                         "audit", actor, verb, resource, detail, origin, images=images, config_data=config_data,
                         ips=a.get("sourceIPs") or [], code=code))
    return sorted(evs, key=lambda e: e["ts"])


def load_argo(path):
    p = Path(path)
    if not p.exists():
        return [], {}
    app = json.loads(p.read_text(encoding="utf-8"))
    name = app.get("metadata", {}).get("name", "app")
    st = app.get("status", {})
    evs, prev = [], None
    for h in st.get("history", []):
        init = h.get("initiatedBy") or {}
        who = init.get("username") or ("automated" if init.get("automated") else "")
        evs.append(event(parse_ts(h.get("deployedAt")), "argocd", who, "sync", f"application/{name}",
                         f"rev={str(h.get('revision', ''))[:7]} id={h.get('id')}", "",
                         revision=h.get("revision"), id=h.get("id"),
                         drift=(prev is not None and h.get("revision") == prev)))   # misma revisión otra vez = corrección de deriva
        prev = h.get("revision")
    summary = {"sync": st.get("sync", {}).get("status"), "health": st.get("health", {}).get("status")}
    return sorted(evs, key=lambda e: e["ts"]), summary


def load_snapshot(path):
    """Estado de la aplicación en Argo CD capturado al terminar un ensayo (Argo CD no conserva el historial de salud)."""
    p = Path(path)
    if not p.exists():
        return None
    st = json.loads(p.read_text(encoding="utf-8")).get("status", {})
    return f"{st.get('sync', {}).get('status')}/{st.get('health', {}).get('status')}"


# ----------------------------------------------------------------------------- las 5 preguntas
def near(e, t0, tol):
    """¿Ocurrió cerca de la acción real? (2 s de holgura antes por redondeo de segundos)."""
    return -2 <= (e["ts"] - t0).total_seconds() <= tol


def answer(covered, correct, text):
    return {"covered": bool(covered), "correct": bool(correct), "text": text or "sin evidencia"}


def executor_rx(sc):
    return re.compile(sc.get("truth_executor") or sc["truth_actor"], re.I)


def q1(sc, ev, t0, tol):
    rx = re.compile(sc["truth_actor"], re.I)
    cands = [e for e in ev if e["source"] in ("git", "audit") or (e["source"] == "argocd" and e["actor"] not in ("", "automated"))]
    ok = [e for e in cands if rx.search(e["actor"]) and near(e, t0, tol)]
    shown = ok or cands[:3]
    return answer(cands, ok, "; ".join(sorted({f"{e['actor']} ({fmt(e['ts'])} UTC)" for e in shown})))


def q2(sc, ev, t0, tol):
    rx = re.compile(sc["truth_resource"], re.I)
    cands = [e for e in ev if e["resource"]]
    ok = [e for e in cands if rx.search(e["resource"]) and near(e, t0, tol)]
    shown = ok or cands[:3]
    return answer(cands, ok, "; ".join(sorted({e["resource"] for e in shown})))


def q3(sc, ev, allowed, ctx):
    """Imagen ANTES del incidente, imagen DESPUÉS del cambio y (si hubo autocorrección) imagen RESTAURADA."""
    start = ctx["start"]
    before = after = restored = None
    notes = []
    if "argocd" in allowed:
        past = [h for h in ctx["argo_hist"] if h["ts"] < start]
        if past and "git" in allowed:
            before = image_at(ctx["repo"], past[-1]["extra"]["revision"], ctx["manifest"])
        elif past:
            notes.append(f"Argo CD: revisión previa {str(past[-1]['extra']['revision'])[:7]} (imagen desconocida)")
    if before is None and "git" in allowed:
        prev = [c for c in ctx["git"] if c["ts"] < start]
        if prev:
            before = image_at(ctx["repo"], prev[-1]["extra"]["commit"], ctx["manifest"])
    imgs = [(e, i) for e in ev if e["source"] == "audit" for i in e["extra"].get("images", [])]
    if imgs:
        after = imgs[0][1]
    elif "git" in allowed:
        inwin = [c for c in ev if c["source"] == "git"]
        if inwin:
            after = image_at(ctx["repo"], inwin[-1]["extra"]["commit"], ctx["manifest"])
    if sc.get("truth_restaurada"):
        argo_fix = [(e, i) for e, i in imgs if "argocd-application-controller" in e["actor"] and after and e["ts"] > imgs[0][0]["ts"]]
        if argo_fix:
            restored = argo_fix[-1][1]
        elif "argocd" in allowed and "git" in allowed:
            drift = [e for e in ev if e["source"] == "argocd" and e["extra"].get("drift")]
            if drift:
                restored = image_at(ctx["repo"], drift[-1]["extra"]["revision"], ctx["manifest"])
    txt = f"antes={before or '?'} | después del cambio={after or '?'}"
    if sc.get("truth_restaurada"):
        txt += f" | restaurada={restored or '?'}"
    if notes:
        txt += " | " + "; ".join(notes)
    correct = before == sc["truth_before"] and after == sc["truth_after"] and \
        (not sc.get("truth_restaurada") or restored == sc["truth_restaurada"])
    return answer(before or after or restored or notes, correct, txt)


def q4(sc, ev, t0, tol):
    rx = executor_rx(sc)
    aud = [e for e in ev if e["source"] == "audit" and e["extra"].get("ips")]
    ok = []
    for e in aud:
        if not (rx.search(e["actor"]) and near(e, t0, tol)):
            continue
        ip_ok = (sc["truth_origin_ip"] in e["extra"]["ips"]) if sc.get("truth_origin_ip") else True
        ua_ok = bool(re.search(sc["truth_ua"], e["origin"], re.I)) if sc.get("truth_ua") else True
        if ip_ok and ua_ok:
            ok.append(e)
    shown = ok or aud[:3]
    return answer(aud, ok, "; ".join(sorted({f"{e['actor']} desde {e['origin']}" for e in shown})))


def detectar(ev):
    """Detecciones simples (reglas explícitas) sobre el audit log y el historial de Argo CD.
    No son aprendizaje automático: son reglas que puedes explicar y citar en la metodología."""
    out = []

    def add(e, tipo):
        out.append({"ts": e["ts"], "tipo": tipo, "actor": e["actor"], "resource": e["resource"], "fuente": e["source"]})

    for e in ev:
        if e["source"] == "audit":
            actor, res = e["actor"], e["resource"]
            eff = actor.split(" (vía")[0]
            if e["action"] in WRITE_VERBS and res.startswith("deployments/") and "argocd-application-controller" not in actor:
                add(e, "cambio_manual")                     # cambio en un Deployment fuera del flujo GitOps
            if e["action"] in WRITE_VERBS and res.startswith("configmaps/") and "argocd-application-controller" not in actor:
                add(e, "cambio_configmap")                  # cambio de configuración fuera del flujo GitOps
            if res.startswith(("pods/exec", "pods/attach")):
                add(e, "exec_en_pod")
            if res.startswith("secrets") and e["action"] in ("get", "list"):
                if str(e["extra"].get("code", "")) == "403":
                    add(e, "lectura_secreto_denegada")
                else:
                    add(e, "lectura_secreto")
            m, n = re.match(r"system:serviceaccount:([^:]+):", eff), re.search(r"\(ns=([^)]*)\)", res)
            if m and n and res.startswith("secrets") and m.group(1) != n.group(1):
                add(e, "acceso_cruzado_ns")                 # una ServiceAccount lee secretos de OTRO namespace
        elif e["source"] == "argocd" and e["extra"].get("drift"):
            add(e, "autocorreccion_drift")                  # Argo CD volvió a aplicar la misma revisión: había deriva
    return out


def q5(sc, dets, t0, tol):
    rx = re.compile(sc["truth_rule"], re.I)
    ok = [d for d in dets if rx.search(d["tipo"]) and near(d, t0, max(tol, 30))]
    shown = (ok or dets)[:4]
    return answer(dets, ok, "; ".join(f"{d['tipo']} @ {fmt(d['ts'])} ({d['actor']} -> {d['resource']}) [{d['fuente']}]" for d in shown))


def q6(sc, ev, t0, tol):
    """Pregunta específica de E4: ¿se preservó el valor de configuración no autorizado y el estado restaurado?"""
    if not sc.get("truth_config_changed"):
        return None
    candidates = [e for e in ev if e["source"] == "audit" and
                  re.search(r"configmaps/tienda-config", e["resource"], re.I) and
                  near(e, t0, max(tol, 30)) and e["extra"].get("config_data")]
    changed = [e["extra"].get("config_data", {}).get("banner") for e in candidates]
    observed_change = sc.get("truth_config_changed") in changed
    restored = sc.get("truth_config_restored") == sc.get("truth_config_before")
    text = (f"antes={sc.get('truth_config_before', '?')} | cambio registrado="
            f"{sc.get('truth_config_changed') if observed_change else 'no recuperado del audit log'} | "
            f"restaurado={sc.get('truth_config_restored', '?')}")
    return answer(candidates, bool(candidates) and observed_change and restored, text)


# ----------------------------------------------------------------------------- campos principales recuperados CORRECTAMENTE
FIELDS = {"git": ["autor", "fecha", "commit", "cambios"],
          "audit": ["usuario", "hora", "accion", "recurso", "respuesta"],
          "argocd": ["version", "sincronizaciones", "estado"]}


def expected_sources(name):
    """Fuentes (y por tanto campos) que se esperan en cada escenario. selfHeal siempre activo."""
    if name.startswith("E0"):
        return ["git", "audit", "argocd"]
    if name.startswith("E1"):
        return ["audit", "argocd"]
    return ["audit"]


def campos_eval(sc, ev, allowed, ctx):
    """Para cada campo principal esperado: ¿se recuperó Y coincide con la verdad de referencia?"""
    t0, tol = parse_ts(sc["t_action"]), sc.get("tol_s", 15)
    out = {}
    for s_ in expected_sources(sc["scenario"]):
        field_names = list(FIELDS[s_])
        if s_ == "audit" and sc.get("scenario", "").startswith("E4"):
            field_names.append("valor_configuracion")
        d = {f: False for f in field_names}
        evs = [e for e in ev if e["source"] == s_] if s_ in allowed else []
        if s_ == "git":
            m = [c for c in evs if near(c, t0, tol)]
            d["autor"] = any(re.search(sc["truth_actor"], c["actor"], re.I) for c in m)
            d["fecha"] = bool(m)
            d["commit"] = any(c["extra"]["commit"] == sc.get("truth_commit") for c in m)
            d["cambios"] = any(re.search(sc.get("truth_files", "deployment"), f) for c in m for f in c["extra"]["files"])
        elif s_ == "audit":
            res_rx = re.compile(sc["truth_resource"], re.I)
            key = [e for e in evs if res_rx.search(e["resource"]) and near(e, t0, tol)]
            d["usuario"] = any(executor_rx(sc).search(e["actor"]) for e in key)
            d["hora"] = bool(key)
            d["accion"] = any(re.search(sc.get("truth_action", "."), e["action"]) for e in key)
            d["recurso"] = any(res_rx.search(e["resource"]) for e in evs)
            d["respuesta"] = any(re.search(sc.get("truth_response", "^(2..|101)$"), str(e["extra"].get("code", ""))) for e in key)
            if "valor_configuracion" in d:
                d["valor_configuracion"] = any(e["extra"].get("config_data", {}).get("banner") == sc.get("truth_config_changed") for e in key)
        else:
            m = [e for e in evs if e["ts"] >= t0 - timedelta(seconds=2)]
            d["sincronizaciones"] = bool(m)
            d["version"] = any(e["extra"].get("revision") == sc.get("truth_revision") for e in m)
            d["estado"] = "argocd" in allowed and ctx.get("estado") is not None and ctx["estado"] == sc.get("truth_argo_estado")
        out[s_] = d
    return out


# ----------------------------------------------------------------------------- evaluación
def evaluate(sc, events, allowed, ctx):
    ev = [e for e in events if e["source"] in allowed and ctx["a"] <= e["ts"] <= ctx["b"]]
    t0, tol = parse_ts(sc["t_action"]), sc.get("tol_s", 15)
    q = {"Q1": q1(sc, ev, t0, tol), "Q2": q2(sc, ev, t0, tol), "Q4": q4(sc, ev, t0, tol)}
    q["Q3"] = q3(sc, ev, allowed, ctx) if sc.get("truth_before") else None
    q["Q5"] = q5(sc, detectar(ev), t0, tol) if sc.get("truth_rule") else None
    q["Q6"] = q6(sc, ev, t0, tol) if sc.get("truth_config_changed") else None
    q = dict(sorted(q.items()))
    cd = campos_eval(sc, ev, allowed, ctx)
    total = sum(len(v) for v in cd.values())
    good = sum(sum(v.values()) for v in cd.values())
    qs = [v for v in q.values() if v is not None]
    return {"q": q, "campos": cd,
            "campos_pct": round(100 * good / total), "campos_n": f"{good}/{total}",
            "cobertura_pct": round(100 * sum(v["covered"] for v in qs) / len(qs)),
            "exactitud_pct": round(100 * sum(v["correct"] for v in qs) / len(qs))}


INDICADORES = [("campos_pct", "Campos correctos"), ("cobertura_pct", "Cobertura"), ("exactitud_pct", "Preguntas correctas")]


def code(v):
    if v is None:
        return "N/A"
    return "OK" if v["correct"] else ("CUB" if v["covered"] else "NO")   # OK exacta | CUB cubierta pero incorrecta | NO sin evidencia


def mean(xs):
    return round(statistics.mean(xs), 1) if xs else None


def narrativa_e1(win, res):
    """Reconstrucción antes / durante / después de la autocorrección de Argo CD (fuentes combinadas)."""
    lines = []
    q3r = res["q"].get("Q3")
    if q3r:
        lines.append(f"- **Antes:** {q3r['text'].split(' | ')[0]}")
    man = [e for e in win if e["source"] == "audit" and e["action"] in WRITE_VERBS and e["resource"].startswith("deployments/")
           and "argocd-application-controller" not in e["actor"]]
    if man:
        e = man[0]
        lines.append(f"- **Durante:** {fmt(e['ts'])} UTC, `{e['actor']}` ejecutó `{e['action']}` sobre `{e['resource']}` desde {e['origin']} ({e['detail'].split('|')[-1].strip()})")
    fix = [e for e in win if e["source"] == "argocd" and e["extra"].get("drift")]
    afix = [e for e in win if e["source"] == "audit" and "argocd-application-controller" in e["actor"] and man and e["ts"] > man[0]["ts"]]
    if fix or afix:
        t = (afix[0] if afix else fix[0])["ts"]
        sec = f" ({round((t - man[0]['ts']).total_seconds(), 1)} s después del cambio)" if man else ""
        lines.append(f"- **Después:** {fmt(t)} UTC, Argo CD corrigió la deriva{sec}; revisión {str((fix or afix)[0]['extra'].get('revision', ''))[:7] or 'n/d'}")
    return lines


# ----------------------------------------------------------------------------- principal
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--evidence", default="evidence")
    ap.add_argument("--repo", default=".")
    ap.add_argument("--out", default="resultados")
    ap.add_argument("--ns", default="mypes")
    ap.add_argument("--app", default="tienda-web")
    ap.add_argument("--manifest", default="gitops/app/deployment.yaml")
    ap.add_argument("--antes", type=int, default=5, help="segundos de margen antes de cada ensayo")
    ap.add_argument("--despues", type=int, default=20, help="segundos de margen después de cada ensayo")
    args = ap.parse_args()

    ev_dir, out = Path(args.evidence), Path(args.out)
    (out / "lineas_tiempo").mkdir(parents=True, exist_ok=True)

    git = load_git(args.repo)
    audit = load_audit(ev_dir / "audit.jsonl", args.ns)
    argo, argo_sum = load_argo(ev_dir / "argocd-app.json")
    events = sorted(git + audit + argo, key=lambda e: e["ts"])
    runs = sorted(load_jsonl(ev_dir / "scenarios.jsonl"), key=lambda s: parse_ts(s["start"]))
    print(f"Eventos cargados -> git:{len(git)} audit:{len(audit)} argocd:{len(argo)} | ensayos: {len(runs)}")
    if not runs:
        print("No hay ensayos en evidence/scenarios.jsonl (ejecuta: python lab.py e0 ... e3, o python lab.py experimento).")
        return

    METHODS = ["SENTINEL-MYPES"]
    valid, excluded, rows, per_run, fp, last = [], [], [], {}, [], {}
    for i, sc in enumerate(runs):
        name = sc["scenario"]
        if sc.get("analizar", True) is False:
            excluded.append(sc)
            continue
        start, end = parse_ts(sc["start"]), parse_ts(sc["end"])
        a, b = start - timedelta(seconds=args.antes), end + timedelta(seconds=args.despues)
        if sc.get("cleanup_ts"):
            b = min(b, parse_ts(sc["cleanup_ts"]))
        if i + 1 < len(runs):
            b = min(b, parse_ts(runs[i + 1]["start"]) - timedelta(seconds=args.antes))
        b = max(b, end)
        ctx = {"start": start, "a": a, "b": b, "git": git, "argo_hist": argo, "repo": args.repo, "manifest": args.manifest,
               "estado": load_snapshot(ev_dir / "argocd" / f"{sc.get('run_id')}.json")}
        # La tesis evalúa el prototipo integrado como un único sistema; no compara sus fuentes por separado.
        res = {"SENTINEL-MYPES": evaluate(sc, events, set(SOURCES), ctx)}
        win = [e for e in events if a <= e["ts"] <= b]
        if not sc.get("truth_rule"):
            fp.append(len(detectar([e for e in win if e["source"] != "git"])))
        valid.append(sc); per_run[sc["run_id"]] = res; last[name] = (sc, res, win, a, b)
        for m in METHODS:
            r = res[m]
            rows.append([sc["run_id"], name, m] + [code(r["q"].get(q)) for q in ["Q1", "Q2", "Q3", "Q4", "Q5", "Q6"]] +
                        [r["campos_n"], r["campos_pct"], r["cobertura_pct"], r["exactitud_pct"]])
        with open(out / "lineas_tiempo" / f"{sc['run_id']}_{name}.csv", "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["hora_utc", "fuente", "actor", "accion", "recurso", "detalle", "origen"])
            for e in win:
                w.writerow([fmt(e["ts"]), e["source"], e["actor"], e["action"], e["resource"], e["detail"], e["origin"]])

    with open(out / "ensayos.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["run_id", "escenario", "metodo", "Q1", "Q2", "Q3", "Q4", "Q5", "Q6", "campos_correctos", "campos_correctos_pct",
                    "cobertura_pct", "preguntas_correctas_pct"])
        w.writerows(rows)

    # -------- Informe integrado: qué reconstruyó el prototipo y qué quedó sin confirmar
    valid_names = sorted({sc["scenario"] for sc in valid})
    integrated = "SENTINEL-MYPES"
    all_q = [q for sc in valid for q in per_run[sc["run_id"]][integrated]["q"].values() if q is not None]
    fields_total = sum(sum(len(v) for v in per_run[sc["run_id"]][integrated]["campos"].values()) for sc in valid)
    fields_ok = sum(sum(sum(1 for good in v.values() if good) for v in per_run[sc["run_id"]][integrated]["campos"].values()) for sc in valid)
    question_coverage = round(100 * sum(q["covered"] for q in all_q) / len(all_q)) if all_q else 0
    question_accuracy = round(100 * sum(q["correct"] for q in all_q) / len(all_q)) if all_q else 0
    field_accuracy = round(100 * fields_ok / fields_total) if fields_total else 0

    # Reescribir ensayos.csv como una fila por ensayo, sin comparaciones por fuente.
    with open(out / "ensayos.csv", "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["run_id", "escenario", "resultado_entorno", "campos_correctos", "campos_correctos_pct",
                    "cobertura_pct", "preguntas_correctas_pct"])
        for sc in valid:
            r = per_run[sc["run_id"]][integrated]
            w.writerow([sc["run_id"], sc["scenario"], sc.get("resultado"), r["campos_n"], r["campos_pct"],
                        r["cobertura_pct"], r["exactitud_pct"]])

    metadata_rows = []
    for sc in valid:
        r = per_run[sc["run_id"]][integrated]
        for source_name, vals in r["campos"].items():
            for field_name, correct in vals.items():
                metadata_rows.append([sc["run_id"], sc["scenario"], source_name, field_name,
                                      "RECUPERADO_CORRECTO" if correct else "NO_CONFIRMADO_CORRECTO"])
    with open(out / "metadatos_por_ensayo.csv", "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["run_id", "escenario", "tipo_de_metadato", "campo", "estado"])
        w.writerows(metadata_rows)

    R = ["# Sentinel-MYPES — informe integrado de reconstrucción forense\n",
         "Este informe evalúa Sentinel-MYPES como un único prototipo. Git, Kubernetes Audit y Argo CD son fuentes de evidencia del sistema; no se comparan como herramientas independientes.\n",
         f"- Ensayos registrados: {len(runs)}.\n- Ensayos analizables: {len(valid)}.\n- Ensayos excluidos por criterio explícito `analizar=false`: {len(excluded)}.\n",
         f"- Eventos cargados: Git={len(git)}, Kubernetes Audit={len(audit)}, Argo CD={len(argo)}.\n",
         "## 1. Resultado global del prototipo\n",
         "| Indicador | Resultado |", "|---|---:|",
         f"| Campos confirmados correctos | {fields_ok}/{fields_total} ({field_accuracy}%) |",
         f"| Campos no confirmados (ausentes o discrepantes) | {fields_total-fields_ok}/{fields_total} ({round(100*(fields_total-fields_ok)/fields_total) if fields_total else 0}%) |",
         f"| Cobertura de preguntas | {question_coverage}% |",
         f"| Preguntas respondidas correctamente | {question_accuracy}% |",
         "\n**Interpretación:** ‘cubierta’ significa que existe evidencia candidata; ‘correcta’ significa que coincide con la verdad de referencia independiente. Un campo `NO_CONFIRMADO_CORRECTO` puede estar ausente o estar presente pero no coincidir con el valor esperado; revisa la línea de tiempo para distinguirlo.\n",
         "## 2. Resultados por escenario\n",
         "| Escenario | Ensayos analizables | Campos correctos | Cobertura | Preguntas correctas |", "|---|---:|---:|---:|---:|"]
    for name in valid_names:
        sts = [sc for sc in valid if sc["scenario"] == name]
        runs_r = [per_run[sc["run_id"]][integrated] for sc in sts]
        total_e = sum(sum(len(v) for v in r["campos"].values()) for r in runs_r)
        total_ok = sum(sum(sum(1 for good in vals.values() if good) for vals in r["campos"].values()) for r in runs_r)
        qlist = [q for r in runs_r for q in r["q"].values() if q is not None]
        cov = round(100 * sum(q["covered"] for q in qlist) / len(qlist)) if qlist else 0
        acc = round(100 * sum(q["correct"] for q in qlist) / len(qlist)) if qlist else 0
        R.append(f"| {name} | {len(sts)} | {total_ok}/{total_e} ({round(100*total_ok/total_e) if total_e else 0}%) | {cov}% | {acc}% |")

    R.append("\n## 3. Detalle de cada ensayo: metadatos recuperados y pendientes\n")
    qn = {"Q1": "¿Quién y cuándo?", "Q2": "¿Qué recurso?", "Q3": "¿Qué versión antes/después/restaurada?",
          "Q4": "¿Desde qué origen?", "Q5": "¿Qué actividad sospechosa se observó?",
          "Q6": "¿Qué valor de configuración cambió y se restauró?"}
    for sc in valid:
        r = per_run[sc["run_id"]][integrated]
        fields = [(src, field, good) for src, vals in r["campos"].items() for field, good in vals.items()]
        good_fields = [(src, field) for src, field, good in fields if good]
        pending_fields = [(src, field) for src, field, good in fields if not good]
        R.append(f"\n### {sc['scenario']} — {sc['run_id']}\n")
        R.append(f"- Resultado del escenario: **{sc.get('resultado','n/d')}**.\n- Ventana UTC: {sc.get('start')} → {sc.get('end')}.\n")
        R.append(f"- Metadatos confirmados correctos: **{len(good_fields)}/{len(fields)}** ({r['campos_pct']}%).\n")
        R.append(f"- Metadatos no confirmados: **{len(pending_fields)}/{len(fields)}** ({round(100*len(pending_fields)/len(fields)) if fields else 0}%).\n")
        R.append("**Campos confirmados correctos:** " + (", ".join(f"`{src}.{field}`" for src, field in good_fields) if good_fields else "ninguno") + ".\n")
        R.append("**Campos ausentes o no confirmados:** " + (", ".join(f"`{src}.{field}`" for src, field in pending_fields) if pending_fields else "ninguno") + ".\n")
        R.append("| Pregunta | Respuesta reconstruida | Hay evidencia | Correcta |\n|---|---|---|---|")
        for qname, val in r["q"].items():
            if val is not None:
                R.append(f"| {qname} {qn.get(qname,qname)} | {val['text'].replace('|','/')} | {'Sí' if val['covered'] else 'No'} | {'Sí' if val['correct'] else 'No'} |")
        folder = ev_dir / "runs" / sc["run_id"]
        R.append(f"\n**Evidencia preservada:** `{folder.as_posix()}` (si existe el paquete individual). Revisa `audit.jsonl`, `argocd-monitor.jsonl`, snapshots antes/después y `truth-reference.json`.\n")
        if sc.get("scenario", "").startswith("E1") or sc.get("scenario", "").startswith("E4"):
            if sc.get("mttr_s") is not None:
                R.append(f"Tiempo descriptivo hasta restauración observada: {sc['mttr_s']} segundos. Este dato no es el indicador principal del estudio.\n")

    R.append("\n## 4. Ensayos excluidos\n")
    if excluded:
        R.append("| Escenario | Resultado | Motivo |\n|---|---|---|")
        for sc in excluded:
            R.append(f"| {sc.get('scenario')} | {sc.get('resultado')} | {sc.get('motivo','verificar logs del ensayo')} |")
    else:
        R.append("No hubo ensayos excluidos por resultado del escenario. Esto no prueba ausencia de errores no detectados; solo indica que el criterio de aceptación del laboratorio se cumplió.\n")

    R += ["\n## 5. Limitaciones de interpretación\n",
          "- Los escenarios son simulaciones controladas en un clúster Minikube de un solo nodo; no representan todos los ataques reales ni una MYPE en producción.\n",
          "- Kubernetes Audit permite saber qué solicitudes llegaron al API Server, su identidad y respuesta; por sí solo no observa toda la actividad interna de los contenedores.\n",
          "- El registro de auditoría a nivel `Metadata` no almacena el contenido de los Secrets. El escenario E4 solo registra el cuerpo de un ConfigMap con datos sintéticos, nunca de un Secret real.\n",
          "- Un incidente se analiza aunque Argo CD no logre recuperarse: el fallo de recuperación no borra su valor forense. Solo se excluyen ensayos marcados explícitamente `analizar=false` por un problema que impidió ejecutar el incidente o invalidó la evidencia.\n",
          "- Los campos no confirmados correctos deben revisarse contra los eventos originales para decidir si faltó evidencia o si había evidencia contradictoria.\n",
          "- El muestreo de Argo CD se realiza aproximadamente cada 0,75 s; un cambio más breve podría no aparecer en una muestra, aunque quede en los eventos de auditoría.\n"]
    (out / "reporte.md").write_text("\n".join(R) + "\n", encoding="utf-8")
    metrics = {
        "ensayos_registrados": len(runs), "ensayos_analizables": len(valid), "ensayos_excluidos": len(excluded),
        "prototipo_integrado": {"campos_correctos": fields_ok, "campos_no_confirmados": fields_total - fields_ok,
                                "campos_esperados": fields_total, "campos_correctos_pct": field_accuracy,
                                "campos_no_confirmados_pct": round(100*(fields_total-fields_ok)/fields_total) if fields_total else 0,
                                "cobertura_pct": question_coverage,
                                "preguntas_correctas_pct": question_accuracy,
                                "preguntas_evaluadas": len(all_q)},
        "por_escenario": {}
    }
    for name in valid_names:
        sts = [sc for sc in valid if sc["scenario"] == name]
        rs = [per_run[sc["run_id"]][integrated] for sc in sts]
        qlist = [q for r in rs for q in r["q"].values() if q is not None]
        ft = sum(sum(len(v) for v in r["campos"].values()) for r in rs)
        fok = sum(sum(sum(1 for x in v.values() if x) for v in r["campos"].values()) for r in rs)
        metrics["por_escenario"][name] = {
            "ensayos_analizables": len(sts), "campos_correctos": fok, "campos_esperados": ft,
            "campos_correctos_pct": round(100*fok/ft) if ft else 0,
            "cobertura_pct": round(100*sum(q["covered"] for q in qlist)/len(qlist)) if qlist else 0,
            "preguntas_correctas_pct": round(100*sum(q["correct"] for q in qlist)/len(qlist)) if qlist else 0
        }
    (out / "metricas.json").write_text(json.dumps(metrics, indent=2, ensure_ascii=False), encoding="utf-8")

    # Informe HTML autónomo: resumen visual, metadatos confirmados/pendientes y enlace al paquete de evidencia.
    esc = html.escape
    h = ["<!doctype html><html lang='es'><head><meta charset='utf-8'>",
         "<meta name='viewport' content='width=device-width,initial-scale=1'>",
         "<title>Sentinel-MYPES — informe visual</title><style>",
         "body{font-family:Segoe UI,Arial,sans-serif;max-width:1180px;margin:28px auto;padding:0 18px;color:#1f2937;background:#f8fafc}",
         "h1{margin-bottom:6px}p.sub{color:#64748b;margin-top:0}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin:20px 0}",
         ".card{background:white;border:1px solid #e2e8f0;border-radius:12px;padding:16px}.big{font-size:28px;font-weight:700;margin:6px 0}.muted{color:#64748b;font-size:13px}",
         "section{background:white;border:1px solid #e2e8f0;border-radius:12px;padding:18px;margin:16px 0;overflow-x:auto}",
         "table{border-collapse:collapse;width:100%;font-size:14px}th,td{text-align:left;padding:9px;border-bottom:1px solid #e2e8f0;vertical-align:top}th{background:#f1f5f9}",
         ".ok{color:#047857;font-weight:600}.pending{color:#b45309;font-weight:600}.pill{display:inline-block;background:#e2e8f0;border-radius:999px;padding:3px 8px;font-size:12px}",
         ".bar{height:8px;background:#e2e8f0;border-radius:10px;overflow:hidden}.fill{height:100%;background:#0f766e}.links a{margin-right:10px}code{word-break:break-word}",
         "@media(max-width:620px){body{margin:12px auto;padding:0 8px}.card{padding:12px}section{padding:12px}}",
         "</style></head><body>",
         "<h1>Sentinel-MYPES</h1><p class='sub'>Informe visual de reconstrucción forense · prototipo integrado · fuentes: Git + Kubernetes Audit + Argo CD</p>",
         "<div class='cards'>",
         f"<div class='card'><div class='muted'>Campos confirmados correctos</div><div class='big'>{field_accuracy}%</div><div class='muted'>{fields_ok} de {fields_total}</div><div class='bar'><div class='fill' style='width:{field_accuracy}%'></div></div></div>",
         f"<div class='card'><div class='muted'>Campos no confirmados</div><div class='big'>{fields_total-fields_ok}</div><div class='muted'>de {fields_total} esperados</div></div>",
         f"<div class='card'><div class='muted'>Cobertura de preguntas</div><div class='big'>{question_coverage}%</div><div class='bar'><div class='fill' style='width:{question_coverage}%'></div></div></div>",
         f"<div class='card'><div class='muted'>Preguntas correctas</div><div class='big'>{question_accuracy}%</div><div class='bar'><div class='fill' style='width:{question_accuracy}%'></div></div></div>",
         f"<div class='card'><div class='muted'>Ensayos</div><div class='big'>{len(valid)}</div><div class='muted'>{len(excluded)} excluidos explícitamente</div></div>",
         "</div><section><h2>Resumen por escenario</h2><table><thead><tr><th>Escenario</th><th>Ensayos</th><th>Campos correctos</th><th>Cobertura</th><th>Preguntas correctas</th></tr></thead><tbody>"]
    for name in valid_names:
        sts = [sc for sc in valid if sc["scenario"] == name]
        rs = [per_run[sc["run_id"]][integrated] for sc in sts]
        total_e = sum(sum(len(v) for v in r["campos"].values()) for r in rs)
        total_ok = sum(sum(sum(1 for good in vals.values() if good) for vals in r["campos"].values()) for r in rs)
        qlist = [q for r in rs for q in r["q"].values() if q is not None]
        cov = round(100 * sum(q["covered"] for q in qlist) / len(qlist)) if qlist else 0
        acc = round(100 * sum(q["correct"] for q in qlist) / len(qlist)) if qlist else 0
        pc = round(100*total_ok/total_e) if total_e else 0
        h.append(f"<tr><td><strong>{esc(name)}</strong></td><td>{len(sts)}</td><td>{total_ok}/{total_e} ({pc}%)</td><td>{cov}%</td><td>{acc}%</td></tr>")
    h.append("</tbody></table></section><h2>Detalle por ensayo</h2>")
    q_names_html = {"Q1":"¿Quién y cuándo?", "Q2":"¿Qué recurso?", "Q3":"Imagen/versión antes y después", "Q4":"Origen", "Q5":"Actividad sospechosa", "Q6":"Valor de configuración y restauración"}
    for sc in valid:
        r = per_run[sc["run_id"]][integrated]
        fields = [(src, fld, ok) for src, vals in r["campos"].items() for fld, ok in vals.items()]
        n_ok = sum(1 for _, _, ok in fields if ok)
        h.append(f"<section><h3>{esc(sc['scenario'])} <span class='pill'>{esc(sc['run_id'])}</span></h3>")
        h.append(f"<p>Resultado del escenario: <strong>{esc(str(sc.get('resultado','n/d')))}</strong> · Metadatos correctos: <strong>{n_ok}/{len(fields)} ({r['campos_pct']}%)</strong></p>")
        h.append("<table><thead><tr><th>Fuente/campo</th><th>Estado</th></tr></thead><tbody>")
        for src, fld, ok in fields:
            status = "RECUPERADO CORRECTAMENTE" if ok else "NO CONFIRMADO / AUSENTE O DISCREPANTE"
            cl = "ok" if ok else "pending"
            h.append(f"<tr><td><code>{esc(src)}.{esc(fld)}</code></td><td class='{cl}'>{status}</td></tr>")
        h.append("</tbody></table><h4>Reconstrucción de preguntas</h4><table><thead><tr><th>Pregunta</th><th>Respuesta</th><th>Con evidencia</th><th>Exacta</th></tr></thead><tbody>")
        for qname, val in r["q"].items():
            if val is None:
                continue
            cl = "ok" if val["correct"] else "pending"
            h.append(f"<tr><td>{qname} · {esc(q_names_html.get(qname,qname))}</td><td>{esc(val['text'])}</td><td>{'Sí' if val['covered'] else 'No'}</td><td class='{cl}'>{'Sí' if val['correct'] else 'No'}</td></tr>")
        run_rel = f"../evidence/runs/{sc['run_id']}/README.md"
        h.append(f"</tbody></table><p class='links'><a href='{esc(run_rel)}'>Abrir paquete de evidencia</a></p></section>")
    h.append("<section><h2>Cómo interpretar</h2><p>‘No confirmado’ no significa automáticamente que el dato nunca existió: puede faltar en los registros o estar presente con un valor que no coincide con la verdad de referencia. Revisa el audit log, la línea de tiempo y los snapshots antes/después.</p><p>Argo CD visualiza principalmente el estado GitOps y la deriva de recursos. Lecturas de Secrets o intentos denegados pueden no cambiar el estado de la aplicación; quedan en Kubernetes Audit.</p></section></body></html>")
    (out / "informe_visual.html").write_text("\n".join(h), encoding="utf-8")
    print(f"\n== Sentinel-MYPES integrado: {len(valid)} ensayos analizables, {len(excluded)} excluidos ==")
    print(f"  Campos confirmados correctos: {fields_ok}/{fields_total} ({field_accuracy}%)")
    print(f"  Campos no confirmados: {fields_total-fields_ok}/{fields_total} ({round(100*(fields_total-fields_ok)/fields_total) if fields_total else 0}%)")
    print(f"  Cobertura de preguntas: {question_coverage}%")
    print(f"  Preguntas correctas: {question_accuracy}%")
    print(f"Listo. Resultados: {out}/reporte.md, informe_visual.html, ensayos.csv, metadatos_por_ensayo.csv, metricas.json, lineas_tiempo/")

if __name__ == "__main__":
    main()
