#!/usr/bin/env python3
"""
correlate.py - Análisis forense de metadatos de Git, Kubernetes (audit log) y Argo CD.

HIPÓTESIS PRINCIPAL (H1): la correlación de metadatos de Git, Kubernetes Audit y Argo CD mejora la efectividad de la
reconstrucción forense de incidentes frente al análisis de cada fuente por separado.

  VI  Método de análisis de metadatos : git | audit | argocd (por separado)  vs  COMBINADO (correlación de las tres)
  VD  Efectividad de la reconstrucción forense, con tres indicadores:
        - campos recuperados CORRECTAMENTE (de los campos principales esperados en el escenario)
        - cobertura de evidencias (hay evidencia candidata para la pregunta)
        - preguntas forenses respondidas correctamente (Q1-Q5, comparadas con la verdad de referencia)

Todos los métodos se evalúan sobre EXACTAMENTE los mismos incidentes y registros (comparación pareada).
La verdad de referencia (campos truth_*, t_action) la captura lab.py a partir de lo que realmente hizo y observó,
NO de los logs analizados. El auto-recuperado de Argo CD (selfHeal) forma parte del entorno, no es una variable.

Preguntas: Q1 ¿quién y cuándo? | Q2 ¿qué recurso? | Q3 ¿versión antes/después (y restaurada)? | Q4 ¿desde qué origen? |
Q5 ¿actividad sospechosa? (reglas simples sobre el audit log + autocorrección de Argo CD)
Solo usa la biblioteca estándar de Python (3.8+).
"""
import argparse
import csv
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
        ips = ", ".join(a.get("sourceIPs") or [])
        origin = f"{ips} | {a.get('userAgent', '')}".strip(" |")
        code = (a.get("responseStatus") or {}).get("code", "")
        detail = f"{verb} {a.get('requestURI', '')} -> HTTP {code}"
        if images:
            detail += f" | imagen={images[0]}"
        evs.append(event(parse_ts(a.get("requestReceivedTimestamp") or a.get("stageTimestamp")),
                         "audit", actor, verb, resource, detail, origin, images=images, ips=a.get("sourceIPs") or [], code=code))
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
            if res.startswith(("pods/exec", "pods/attach")):
                add(e, "exec_en_pod")
            if res.startswith("secrets") and e["action"] in ("get", "list"):
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
        d = {f: False for f in FIELDS[s_]}
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

    METHODS = SOURCES + ["COMBINADO"]
    valid, excluded, rows, per_run, fp, last = [], [], [], {}, [], {}
    for i, sc in enumerate(runs):
        name = sc["scenario"]
        if sc.get("resultado") != "exitoso":                      # entorno no válido: el incidente no se produjo/corrigió como se esperaba
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
        res = {m: evaluate(sc, events, set(SOURCES) if m == "COMBINADO" else {m}, ctx) for m in METHODS}
        win = [e for e in events if a <= e["ts"] <= b]
        if not sc.get("truth_rule"):
            fp.append(len(detectar([e for e in win if e["source"] != "git"])))
        valid.append(sc); per_run[sc["run_id"]] = res; last[name] = (sc, res, win, a, b)
        for m in METHODS:
            r = res[m]
            rows.append([sc["run_id"], name, m] + [code(r["q"].get(q)) for q in ["Q1", "Q2", "Q3", "Q4", "Q5"]] +
                        [r["campos_n"], r["campos_pct"], r["cobertura_pct"], r["exactitud_pct"]])
        with open(out / "lineas_tiempo" / f"{sc['run_id']}_{name}.csv", "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["hora_utc", "fuente", "actor", "accion", "recurso", "detalle", "origen"])
            for e in win:
                w.writerow([fmt(e["ts"]), e["source"], e["actor"], e["action"], e["resource"], e["detail"], e["origin"]])

    with open(out / "ensayos.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["run_id", "escenario", "metodo", "Q1", "Q2", "Q3", "Q4", "Q5", "campos_correctos", "campos_correctos_pct",
                    "cobertura_pct", "preguntas_correctas_pct"])
        w.writerows(rows)

    # -------- agregados por escenario y método; y comparación pareada (mismos incidentes) COMBINADO vs MEJOR fuente individual
    names = sorted({sc["scenario"] for sc in valid})
    agg = {(n, m): {k: mean([per_run[sc["run_id"]][m][k] for sc in valid if sc["scenario"] == n]) for k, _ in INDICADORES}
           for n in names for m in METHODS}
    pair = {}
    pair_rows = []
    for k, label in INDICADORES:
        mejor = peor = igual = 0
        for sc in valid:
            r = per_run[sc["run_id"]]
            best_ind = max(r[m][k] for m in SOURCES)
            d = r["COMBINADO"][k] - best_ind
            mejor += d > 0; peor += d < 0; igual += d == 0
            pair_rows.append([sc["run_id"], sc["scenario"], k, best_ind, r["COMBINADO"][k], d])
        pair[k] = (mejor, igual, peor)
    with open(out / "comparacion_pareada.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["run_id", "escenario", "indicador", "mejor_fuente_individual", "combinado", "diferencia"])
        w.writerows(pair_rows)
    glob = {m: {k: mean([per_run[sc["run_id"]][m][k] for sc in valid]) for k, _ in INDICADORES} for m in METHODS}
    qacc = {}
    for q in ["Q1", "Q2", "Q3", "Q4", "Q5"]:
        for m in METHODS:
            vals = [per_run[sc["run_id"]][m]["q"][q]["correct"] for sc in valid if per_run[sc["run_id"]][m]["q"].get(q)]
            qacc[(q, m)] = round(100 * sum(vals) / len(vals)) if vals else None

    # -------- Informe
    R = ["# Reporte de resultados\n",
         f"Eventos: Git={len(git)}, Kubernetes audit={len(audit)}, Argo CD={len(argo)}. Ensayos válidos analizados: {len(valid)}; "
         f"excluidos por entorno no válido: {len(excluded)}.\n",
         "**H1:** la correlación de metadatos de Git, Kubernetes Audit y Argo CD mejora la efectividad de la reconstrucción forense "
         "frente al análisis de cada fuente por separado. **VI** = método de análisis; **VD** = efectividad (3 indicadores). "
         "Todos los métodos se evalúan sobre los mismos incidentes y registros.\n",
         "## 1. Resultado principal (todos los ensayos válidos)\n",
         "| Método | " + " | ".join(l + " (%)" for _, l in INDICADORES) + " |", "|---|---|---|---|"]
    for m in METHODS:
        R.append(f"| {m} | " + " | ".join(str(glob[m][k]) for k, _ in INDICADORES) + " |")
    R += ["\n### Comparación pareada: COMBINADO frente a la MEJOR fuente individual de cada incidente\n",
          "| Indicador | COMBINADO mejor | Igual | COMBINADO peor |", "|---|---|---|---|"]
    for k, l in INDICADORES:
        R.append(f"| {l} | {pair[k][0]} | {pair[k][1]} | {pair[k][2]} |")
    R += ["\n## 2. Por escenario\n", "| Escenario | Método | " + " | ".join(l + " (%)" for _, l in INDICADORES) + " |", "|---|---|---|---|---|"]
    for n in names:
        for m in METHODS:
            R.append(f"| {n} ({sum(1 for sc in valid if sc['scenario'] == n)} ens.) | {m} | " + " | ".join(str(agg[(n, m)][k]) for k, _ in INDICADORES) + " |")
    R += ["\n## 3. Exactitud por pregunta (dónde aporta la correlación)\n", "| Pregunta | " + " | ".join(METHODS) + " |", "|---|" + "---|" * len(METHODS)]
    qn = {"Q1": "¿Quién y cuándo?", "Q2": "¿Qué recurso?", "Q3": "¿Versión antes/después/restaurada?", "Q4": "¿Origen?", "Q5": "¿Actividad sospechosa?"}
    for q in ["Q1", "Q2", "Q3", "Q4", "Q5"]:
        R.append(f"| {q} {qn[q]} | " + " | ".join(("—" if qacc[(q, m)] is None else f"{qacc[(q, m)]}%") for m in METHODS) + " |")
    # entorno
    e1 = [sc for sc in runs if sc["scenario"].startswith("E1")]
    mt = [float(sc["mttr_s"]) for sc in e1 if sc.get("resultado") == "exitoso" and sc.get("mttr_s") is not None]
    R += ["\n## 4. Verificación del entorno (no es una hipótesis)\n",
          "Se comprueba que Argo CD con `selfHeal` corrigió cada cambio manual, para que existan metadatos de antes, durante y después. "
          "Los ensayos en que no ocurrió se excluyen del análisis principal.\n",
          f"- Ensayos E1: {len(e1)}; corregidos y verificados: {len(mt)}; excluidos: {len(e1) - len(mt)}."
          + (f" Tiempo de corrección (descriptivo): media {mean(mt)} s, mediana {round(statistics.median(mt), 1)} s, rango {min(mt)}–{max(mt)} s." if mt else ""),
          f"- Ensayos excluidos en total: {len(excluded)}" + (": " + ", ".join(f"{sc['scenario']} ({sc.get('motivo') or sc.get('resultado')})" for sc in excluded) if excluded else "."),
          f"- Detecciones en el control E0 (no debería haber): {sum(fp)} en {len(fp)} ensayo(s)."]
    R.append("\n## 5. Detalle del último ensayo válido de cada escenario\n")
    for name, (sc, res, win, a, b) in sorted(last.items()):
        comb = res["COMBINADO"]
        R.append(f"\n### {name} (ensayo {sc['run_id']})\n")
        R.append(f"Ventana: {fmt(a)} a {fmt(b)} UTC. Verdad de referencia: responsable≈`{sc['truth_actor']}`, recurso≈`{sc['truth_resource']}`"
                 + (f", imagen {sc['truth_before']} → {sc['truth_after']}" if sc.get("truth_before") else "") + ".\n")
        if name.startswith("E1"):
            R.append("**Reconstrucción antes / durante / después (fuentes combinadas):**\n")
            R += narrativa_e1(win, comb)
            R.append("")
        R.append("| Pregunta | Respuesta (COMBINADO) | Cubierta | Exacta |\n|---|---|---|---|")
        for q, v in comb["q"].items():
            if v:
                R.append(f"| {q} {qn[q]} | {v['text'].replace('|', '/')} | {'Sí' if v['covered'] else 'No'} | {'Sí' if v['correct'] else 'No'} |")
        R.append("\n| Método | " + " | ".join(q for q, v in comb["q"].items() if v) + " | Campos correctos | Cobertura | Preguntas correctas |\n|---|" +
                 "---|" * (sum(1 for v in comb["q"].values() if v) + 3))
        for m in METHODS:
            r = res[m]
            R.append(f"| {m} | " + " | ".join(code(v) for v in r["q"].values() if v) + f" | {r['campos_n']} ({r['campos_pct']}%) | {r['cobertura_pct']}% | {r['exactitud_pct']}% |")
        det = comb["campos"]
        R.append("\nCampos principales (COMBINADO): " + "; ".join(f"{s_}: " + ", ".join(f"{f}{'✔' if ok else '✘'}" for f, ok in d.items()) for s_, d in det.items()))
    (out / "reporte.md").write_text("\n".join(R) + "\n", encoding="utf-8")
    (out / "metricas.json").write_text(json.dumps({
        "ensayos_validos": len(valid), "ensayos_excluidos": len(excluded),
        "global": glob, "por_escenario": {f"{n}|{m}": agg[(n, m)] for n in names for m in METHODS},
        "pareada": {k: {"combinado_mejor": v[0], "igual": v[1], "combinado_peor": v[2]} for k, v in pair.items()},
        "exactitud_por_pregunta": {f"{q}|{m}": v for (q, m), v in qacc.items()}}, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"\n== Resultado principal ({len(valid)} ensayos válidos, {len(excluded)} excluidos) ==")
    print(f"  {'método':10s} " + " ".join(f"{l[:18]:>19s}" for _, l in INDICADORES))
    for m in METHODS:
        print(f"  {m:10s} " + " ".join(f"{glob[m][k]:>18}%" for k, _ in INDICADORES))
    for k, l in INDICADORES:
        print(f"  Pareada ({l}): COMBINADO mejor en {pair[k][0]}, igual en {pair[k][1]}, peor en {pair[k][2]}")
    print(f"\nListo. Resultados en {out}/ (reporte.md, ensayos.csv, comparacion_pareada.csv, metricas.json, lineas_tiempo/)")


if __name__ == "__main__":
    main()
