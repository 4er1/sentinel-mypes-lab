#!/usr/bin/env python3
"""
lab.py - Orquestador del laboratorio (funciona en Windows, Linux y macOS; solo necesita Python 3.8+).

Uso:  python lab.py <comando> [argumentos]

  prereqs                 comprueba que tienes las herramientas
  minikube                crea el clúster con audit log activado
  argocd                  instala Argo CD
  app                     despliega la app "tienda-web" gestionada por Argo CD (selfHeal SIEMPRE activado)
  e0 | e1 | e2 | e3 | e4 | e5 ejecuta UN ensayo y guarda su paquete de evidencia
  experimento [N] [P]     N vueltas de los 6 escenarios; pausa P segundos entre ensayos
  nueva-serie             archiva el piloto anterior y prepara una serie limpia (no borra el clúster)
  verificar-integridad    comprueba los SHA-256 de los paquetes de evidencia guardados
  recolectar              actualiza la captura global de audit log y Argo CD
  analizar                genera un informe integrado con metadatos recuperados y ausentes
  limpiar                 borra el clúster de Minikube

Idea del estudio: evaluar Sentinel-MYPES como UN solo sistema integrado de reconstrucción. Cada ensayo guarda automáticamente su verdad de referencia, snapshots, audit log filtrado y monitor de Argo CD.
"""
import csv
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
EVID = ROOT / "evidence"
RUNS = EVID / "runs"
RUN_MONITORS = {}
CFG = json.loads((ROOT / "config.json").read_text(encoding="utf-8"))
APP, NS, PROFILE = CFG["app_name"], CFG["app_ns"], CFG["minikube_profile"]
TIMEOUT = int(CFG.get("timeout_recuperacion_s", 90))
PASANTE = f"system:serviceaccount:{NS}:pasante"
MANIFEST = ROOT / "gitops" / "app" / "deployment.yaml"
ARGOCD_URL = "https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml"


# ----------------------------------------------------------------------------- utilidades
def now_ms():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def secs_between(t1, t2):
    f = "%Y-%m-%dT%H:%M:%S.%fZ"
    return round((datetime.strptime(t2, f) - datetime.strptime(t1, f)).total_seconds(), 2)


def sh(args, check=True, capture=True, cwd=None, input_text=None):
    r = subprocess.run(args, cwd=cwd, text=True, encoding="utf-8", errors="replace",
                       capture_output=capture, input=input_text)
    if check and r.returncode != 0:
        raise SystemExit(f"\nERROR ejecutando: {' '.join(map(str, args))}\n{(r.stderr or r.stdout or '').strip()}")
    return r


def k(*args, **kw):
    return sh(["kubectl", *args], **kw)


def record(d):
    """Registra la verdad de referencia y guarda automáticamente un paquete de evidencia por ensayo."""
    EVID.mkdir(exist_ok=True)
    with open(EVID / "scenarios.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps(d, ensure_ascii=False) + "\n")
    try:
        save_run_bundle(d)
        print(f"   evidencia guardada: evidence/runs/{d['run_id']}/")
    except Exception as exc:
        # No se pierde el registro principal si una captura secundaria falla.
        print(f"   AVISO: ensayo registrado, pero alguna evidencia secundaria falló: {exc}")


def new_run_id(prefix):
    return prefix + "_" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")


def write_json(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")


def audit_time(event):
    text = event.get("requestReceivedTimestamp") or event.get("stageTimestamp")
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


def monitor_argocd(run_id, stop_event, folder):
    """Muestrea el estado de Argo CD para conservar cambios rápidos OutOfSync -> Synced."""
    path = folder / "argocd-monitor.jsonl"
    while not stop_event.is_set():
        sample = {"timestamp": now_ms()}
        try:
            app_raw = k("-n", "argocd", "get", "application", APP, "-o", "json").stdout
            app = json.loads(app_raw)
            status = app.get("status", {})
            sample.update({
                "sync": status.get("sync", {}).get("status"),
                "health": status.get("health", {}).get("status"),
                "revision": status.get("sync", {}).get("revision"),
                "operation_phase": status.get("operationState", {}).get("phase"),
                "operation_message": status.get("operationState", {}).get("message", ""),
            })
            try:
                d = deploy()
                sample["deployment_image"] = d["spec"]["template"]["spec"]["containers"][0]["image"]
                sample["available_replicas"] = d.get("status", {}).get("availableReplicas", 0)
            except Exception:
                pass
            try:
                cm = k("-n", NS, "get", "configmap", "tienda-config", "-o", "json", check=False)
                if cm.returncode == 0:
                    sample["configmap_banner"] = json.loads(cm.stdout).get("data", {}).get("banner")
            except Exception:
                pass
        except Exception as exc:
            sample["error"] = str(exc)
        try:
            with path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(sample, ensure_ascii=False) + "\n")
        except OSError:
            pass
        stop_event.wait(0.75)


def begin_run(run_id, scenario):
    """Guarda estado previo e inicia muestreo de Argo CD antes de provocar el incidente."""
    folder = RUNS / run_id
    folder.mkdir(parents=True, exist_ok=True)
    pre = {"run_id": run_id, "scenario": scenario, "captured_at": now_ms()}
    try:
        write_json(folder / "deployment-before.json", deploy())
    except Exception as exc:
        pre["deployment_snapshot_error"] = str(exc)
    try:
        app_raw = k("-n", "argocd", "get", "application", APP, "-o", "json").stdout
        (folder / "argocd-before.json").write_text(app_raw, encoding="utf-8")
    except Exception as exc:
        pre["argocd_snapshot_error"] = str(exc)
    try:
        cm = k("-n", NS, "get", "configmap", "tienda-config", "-o", "json", check=False)
        if cm.returncode == 0:
            (folder / "configmap-before.json").write_text(cm.stdout, encoding="utf-8")
    except Exception:
        pass
    try:
        pre["git_head_before"] = git_head()
        pre["git_status_before"] = sh(["git", "status", "--short"], cwd=ROOT, check=False).stdout.strip()
    except Exception:
        pass
    write_json(folder / "run-start.json", pre)
    stop_event = threading.Event()
    thread = threading.Thread(target=monitor_argocd, args=(run_id, stop_event, folder), daemon=True)
    RUN_MONITORS[run_id] = (stop_event, thread, folder)
    thread.start()
    print(f"   monitor Argo CD activo: evidence/runs/{run_id}/argocd-monitor.jsonl")


def collect_audit_lines():
    r = k("-n", "kube-system", "logs", f"kube-apiserver-{PROFILE}", check=False)
    if r.returncode != 0:
        return []
    out = []
    for line in r.stdout.splitlines():
        try:
            if json.loads(line).get("kind") == "Event":
                out.append(line)
        except (json.JSONDecodeError, AttributeError):
            continue
    return out


def save_run_bundle(d):
    """Persiste artefactos por ensayo y actualiza copias globales para el analizador."""
    run_id = d["run_id"]
    folder = RUNS / run_id
    folder.mkdir(parents=True, exist_ok=True)
    monitor = RUN_MONITORS.pop(run_id, None)
    if monitor:
        stop_event, thread, _ = monitor
        stop_event.set()
        thread.join(timeout=2)
    write_json(folder / "truth-reference.json", d)
    try:
        after_dep = deploy()
        write_json(folder / "deployment-after.json", after_dep)
    except Exception as exc:
        write_json(folder / "deployment-after-error.json", {"error": str(exc)})
    try:
        app_raw = k("-n", "argocd", "get", "application", APP, "-o", "json").stdout
        (folder / "argocd-after.json").write_text(app_raw, encoding="utf-8")
        (EVID / "argocd-app.json").write_text(app_raw, encoding="utf-8")
        (EVID / "argocd").mkdir(exist_ok=True)
        (EVID / "argocd" / f"{run_id}.json").write_text(app_raw, encoding="utf-8")
    except Exception as exc:
        write_json(folder / "argocd-after-error.json", {"error": str(exc)})
    try:
        head = git_head()
        details = sh(["git", "show", "-s", "--format=%H%n%an%n%aI%n%s", head], cwd=ROOT, check=False).stdout
        write_json(folder / "git-state.json", {"head": head, "show": details,
                   "status": sh(["git", "status", "--short"], cwd=ROOT, check=False).stdout.strip()})
    except Exception as exc:
        write_json(folder / "git-state.json", {"error": str(exc)})

    lines = collect_audit_lines()
    # Guardar la captura completa en evidence para que el análisis use las mismas evidencias.
    (EVID / "audit.jsonl").write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    start = audit_time({"requestReceivedTimestamp": d.get("start")})
    end = audit_time({"requestReceivedTimestamp": d.get("end")})
    picked = []
    if start and end:
        margin_start = start.timestamp() - 5
        margin_end = end.timestamp() + 5
        for line in lines:
            try:
                obj = json.loads(line)
                ts = audit_time(obj)
                if ts and margin_start <= ts.timestamp() <= margin_end:
                    picked.append(line)
            except json.JSONDecodeError:
                continue
    (folder / "audit.jsonl").write_text("\n".join(picked) + ("\n" if picked else ""), encoding="utf-8")
    write_json(folder / "bundle-summary.json", {
        "run_id": run_id, "scenario": d.get("scenario"), "resultado": d.get("resultado"),
        "start": d.get("start"), "end": d.get("end"),
        "audit_events_in_window": len(picked), "audit_events_total_at_capture": len(lines),
        "files": ["run-start.json", "truth-reference.json", "deployment-before.json", "deployment-after.json",
                  "configmap-before.json", "argocd-before.json", "argocd-after.json", "argocd-monitor.jsonl",
                  "audit.jsonl", "git-state.json", "README.md", "integrity-sha256.json"]
    })
    # Paquete legible incluso antes del análisis agregado.
    (folder / "README.md").write_text(
        f"# Evidencia del ensayo {run_id}\n\n"
        f"- Escenario: {d.get('scenario')}\n- Resultado del escenario: {d.get('resultado')}\n"
        f"- Inicio UTC: {d.get('start')}\n- Fin UTC: {d.get('end')}\n"
        f"- Eventos de auditoría en la ventana: {len(picked)}\n\n"
        "Archivos: `truth-reference.json` (verdad de referencia), `audit.jsonl` (eventos cercanos al ensayo), "
        "`argocd-monitor.jsonl` (muestreo del estado de Argo CD), `deployment-before.json`/`deployment-after.json` "
        "y snapshots de Argo CD antes/después. `integrity-sha256.json` contiene hashes para verificar que los archivos "
        "no han cambiado desde su captura. El informe global se genera con `python lab.py analizar`.\n",
        encoding="utf-8")
    hashes = {}
    for item in sorted(folder.iterdir()):
        if item.is_file() and item.name != "integrity-sha256.json":
            hashes[item.name] = hashlib.sha256(item.read_bytes()).hexdigest()
    write_json(folder / "integrity-sha256.json", {"algorithm": "SHA-256", "created_at": now_ms(), "files": hashes})


# ----------------------------------------------------------------------------- estado del Deployment
def deploy():
    return json.loads(k("-n", NS, "get", "deploy", APP, "-o", "json").stdout)


def current_image():
    return deploy()["spec"]["template"]["spec"]["containers"][0]["image"]


def spec_hash():
    """Huella de la configuración que importa (réplicas y contenedores): sirve para comprobar que el estado
    restaurado es IDÉNTICO al que había antes del incidente."""
    import hashlib
    d = deploy()["spec"]
    core = {"replicas": d.get("replicas"), "containers": d["template"]["spec"]["containers"]}
    return hashlib.sha256(json.dumps(core, sort_keys=True).encode()).hexdigest()[:16]


def deployment_ok(image):
    """Recuperado y funcionando = imagen esperada + el controlador ya vio la última generación +
    réplicas totales, actualizadas y disponibles = deseadas (sin réplicas viejas)."""
    try:
        d = deploy()
    except SystemExit:
        return False
    want = d["spec"].get("replicas", 1)
    st = d.get("status", {})
    return (d["spec"]["template"]["spec"]["containers"][0]["image"] == image
            and st.get("observedGeneration") == d["metadata"].get("generation")
            and st.get("replicas", 0) == want and st.get("updatedReplicas", 0) == want
            and st.get("availableReplicas", 0) == want)


def wait_ok(image, timeout):
    """Devuelve la hora (ms) del primer instante sano, o None si vence el plazo."""
    end = time.time() + timeout
    while time.time() < end:
        if deployment_ok(image):
            return now_ms()
        time.sleep(1)
    return None


def require_precondition(image):
    if not deployment_ok(image):
        raise SystemExit(f"PRECONDICIÓN NO CUMPLIDA: {APP} no está sano con {image}. Ensayo NO registrado. Espera o repáralo.")


def host_gateway():
    r = sh(["docker", "network", "inspect", PROFILE, "-f", "{{(index .IPAM.Config 0).Gateway}}"], check=False)
    return r.stdout.strip() if r.returncode == 0 else ""


# ----------------------------------------------------------------------------- infraestructura
def cmd_prereqs():
    ok = True
    for c in ["docker", "minikube", "kubectl", "git"]:
        p = shutil.which(c)
        print(("OK    " if p else "FALTA ") + c + (f"  ({p})" if p else ""))
        ok &= bool(p)
    if shutil.which("docker"):
        r = sh(["docker", "info"], check=False)
        print("OK    Docker Desktop está en ejecución" if r.returncode == 0 else "FALTA Docker Desktop no está en ejecución (ábrelo)")
        ok &= r.returncode == 0
    print(f"Python {sys.version.split()[0]}")
    print("config.json: " + ("falta poner tu repo_url" if "TU_USUARIO" in CFG["repo_url"] else "repo_url configurado"))
    sys.exit(0 if ok else 1)


def cmd_minikube():
    base = Path(os.environ.get("MINIKUBE_HOME") or Path.home())
    dest = base / ".minikube" / "files" / "etc" / "ssl" / "certs"
    dest.mkdir(parents=True, exist_ok=True)
    shutil.copy(ROOT / "k8s" / "audit-policy.yaml", dest / "audit-policy.yaml")
    print("Política de auditoría copiada a", dest)
    sh(["minikube", "start", "-p", PROFILE, "--driver=docker", f"--cpus={CFG['minikube_cpus']}",
        f"--memory={CFG['minikube_memory_mb']}",
        "--extra-config=apiserver.audit-policy-file=/etc/ssl/certs/audit-policy.yaml",
        "--extra-config=apiserver.audit-log-path=-"], capture=False)
    time.sleep(10)
    k("get", "ns")
    log = k("-n", "kube-system", "logs", f"kube-apiserver-{PROFILE}", check=False).stdout
    n = 0
    for line in log.splitlines():
        try:
            if json.loads(line).get("kind") == "Event":
                n += 1
        except (json.JSONDecodeError, AttributeError):
            continue
    print(f"Eventos de auditoría detectados: {n}  ->  " + ("OK, audit log activo" if n else
          "AVISO: aún no hay eventos; si sigue en 0, borra el clúster (python lab.py limpiar) y repite este paso"))


def cmd_argocd():
    k("create", "namespace", "argocd", check=False)
    print("Instalando Argo CD (puede tardar unos minutos) ...")
    k("apply", "-n", "argocd", "--server-side", "--force-conflicts", "-f", ARGOCD_URL)
    k("-n", "argocd", "rollout", "status", "deploy/argocd-server", "--timeout=300s", capture=False)
    k("-n", "argocd", "rollout", "status", "statefulset/argocd-application-controller", "--timeout=300s", capture=False)
    print("Argo CD instalado.")


def cmd_app():
    if "TU_USUARIO" in CFG["repo_url"]:
        raise SystemExit("Edita config.json: pon la URL de TU repo de GitHub (y haz git push antes).")
    k("apply", "-f", str(ROOT / "k8s" / "lab-extras.yaml"))
    app = (ROOT / "argocd" / "application.yaml").read_text(encoding="utf-8")
    app = app.replace("__REPO_URL__", CFG["repo_url"]).replace("__BRANCH__", CFG["git_branch"])
    k("apply", "-f", "-", input_text=app)
    print("Esperando a que Argo CD sincronice (hasta ~5 min) ...")
    estado = ""
    for _ in range(100):
        r = k("-n", "argocd", "get", "application", APP, "-o", "jsonpath={.status.sync.status}/{.status.health.status}", check=False)
        estado = r.stdout.strip()
        if estado == "Synced/Healthy":
            break
        time.sleep(3)
    print("Estado:", estado)
    if estado != "Synced/Healthy":
        raise SystemExit("Argo CD no llegó a Synced/Healthy: revisa repo_url (público) y 'kubectl -n argocd get application tienda-web -o yaml'")


# ----------------------------------------------------------------------------- escenarios
def argo_estado():
    return k("-n", "argocd", "get", "application", APP, "-o",
             "jsonpath={.status.sync.status}/{.status.health.status}", check=False).stdout.strip()


def snapshot_argo(run_id):
    """Guarda el estado de la aplicación en Argo CD al terminar el ensayo (Argo CD no conserva el historial de salud)."""
    d = EVID / "argocd"
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{run_id}.json").write_text(k("-n", "argocd", "get", "application", APP, "-o", "json").stdout, encoding="utf-8")


def git_head():
    return sh(["git", "rev-parse", "HEAD"], cwd=ROOT).stdout.strip()


def common(scen, run_id, start, end, t_action, resultado, tol, **extra):
    # Si hay un registro, el incidente/acción llegó a ejecutarse y debe poder analizarse incluso si la recuperación falló.
    d = {"run_id": run_id, "scenario": scen, "start": start, "end": end,
         "t_action": t_action, "resultado": resultado, "tol_s": tol, "analizar": True}
    d.update(extra)
    return d


def e0():
    """CONTROL: cambio legítimo vía GitOps (commit -> push -> Argo CD sincroniza)."""
    run_id = new_run_id("E0")
    before = current_image()
    require_precondition(before)
    begin_run(run_id, "E0_cambio_legitimo")
    after = "nginx:1.26" if before == "nginx:1.25" else "nginx:1.25"
    author = sh(["git", "config", "user.name"], cwd=ROOT).stdout.strip()
    argo_ip = k("-n", "argocd", "get", "pod", "-l", "app.kubernetes.io/name=argocd-application-controller",
                "-o", "jsonpath={.items[0].status.podIP}").stdout.strip()
    start = now_ms(); print(f">> E0 inicio {start}")
    t_action = now_ms()
    txt = MANIFEST.read_text(encoding="utf-8")
    MANIFEST.write_text(re.sub(r"image:\s*\S+", f"image: {after}", txt, count=1), encoding="utf-8")
    sh(["git", "add", "gitops/app/deployment.yaml"], cwd=ROOT)
    sh(["git", "commit", "-q", "-m", f"Actualiza nginx {before} -> {after}"], cwd=ROOT)
    commit = git_head()
    sh(["git", "push", "-q", "origin", CFG["git_branch"]], cwd=ROOT)
    k("annotate", "application", APP, "-n", "argocd", "argocd.argoproj.io/refresh=hard", "--overwrite")
    t_rec = wait_ok(after, 180)
    time.sleep(8)
    end = now_ms()
    estado = argo_estado(); snapshot_argo(run_id)
    res = "exitoso" if t_rec else "fallido"
    record(common("E0_cambio_legitimo", run_id, start, end, t_action, res, 60,
                  mttr_s=secs_between(t_action, t_rec) if t_rec else None,
                  truth_actor=re.escape(author), truth_executor="argocd-application-controller",
                  truth_resource="deployment", truth_action="patch|update|create", truth_response="^(2..)$",
                  truth_before=before, truth_after=current_image(), truth_origin_ip=argo_ip, truth_ua="argocd",
                  truth_rule="", truth_commit=commit, truth_files="deployment[.]yaml", truth_revision=commit,
                  truth_argo_estado=estado))
    print(f">> E0 resultado: {res}")


def e1():
    """Cambio manual no autorizado. Argo CD (selfHeal) debe corregirlo. Si el entorno no corrige y deja la aplicación
    idéntica y sana, el ensayo se marca 'fallido' y se EXCLUYE del análisis (el incidente no tendría 'después')."""
    run_id = new_run_id("E1")
    good = current_image()
    require_precondition(good)
    begin_run(run_id, "E1_cambio_manual_drift")
    hash_before = spec_hash()
    bad = "nginx:1.19"
    start = now_ms(); print(f">> E1 inicio {start}")
    t_action = now_ms()
    k("--as", PASANTE, "-n", NS, "set", "image", f"deploy/{APP}", f"web={bad}")
    obs_after = current_image()                              # estado realmente observado tras el cambio
    print(f"   cambio manual aplicado ({obs_after}); esperando la corrección de Argo CD hasta {TIMEOUT}s ...")
    t_rec = wait_ok(good, TIMEOUT)
    restaurado = bool(t_rec) and spec_hash() == hash_before
    time.sleep(8)
    end = now_ms()
    estado = argo_estado(); snapshot_argo(run_id)
    res = "exitoso" if restaurado else "fallido"
    extra = {}
    if not t_rec:
        extra["motivo"] = f"Argo CD no corrigió en {TIMEOUT}s"
    elif not restaurado:
        extra["motivo"] = "quedó sano pero la configuración no es idéntica a la previa"
    if res == "fallido":                                     # limpieza (no cuenta para la medición)
        extra["cleanup_ts"] = now_ms()
        k("-n", NS, "set", "image", f"deploy/{APP}", f"web={good}")
        if not wait_ok(good, 120):
            print("AVISO: la limpieza tampoco dejó el Deployment sano; revisa el clúster antes del siguiente ensayo")
    record(common("E1_cambio_manual_drift", run_id, start, end, t_action, res, 15,
                  mttr_s=secs_between(t_action, t_rec) if restaurado else None, estado_restaurado=restaurado,
                  truth_actor="pasante", truth_executor="pasante", truth_resource="deployment", truth_action="patch",
                  truth_response="^(2..)$", truth_before=good, truth_after=obs_after,
                  truth_restaurada=current_image() if restaurado else "",
                  truth_origin_ip="", truth_ua="kubectl", truth_rule="cambio_manual|autocorreccion_drift",
                  truth_revision=git_head(), truth_argo_estado=estado, **extra))
    print(f">> E1 resultado: {res}" + (f" ({extra['motivo']})" if "motivo" in extra else ""))


def e2():
    """Amenaza interna: un usuario con permisos entra a un pod y lee un secreto."""
    run_id = new_run_id("E2")
    require_precondition(current_image())
    begin_run(run_id, "E2_amenaza_interna")
    start = now_ms(); print(f">> E2 inicio {start}")
    t_action = now_ms()
    k("--as", PASANTE, "-n", NS, "exec", f"deploy/{APP}", "--", "sh", "-c", "id; hostname; ls /etc/nginx")
    k("--as", PASANTE, "-n", NS, "get", "secret", "db-credentials", "-o", "name")
    time.sleep(5)
    end = now_ms()
    record(common("E2_amenaza_interna", run_id, start, end, t_action, "exitoso", 15,
                  truth_actor="pasante", truth_executor="pasante", truth_resource="db-credentials", truth_action="get",
                  truth_response="^(2..)$", truth_before="", truth_after="", truth_origin_ip="", truth_ua="kubectl",
                  truth_rule="exec_en_pod|lectura_secreto"))
    print(">> E2 resultado: exitoso")


def e3():
    """Movimiento lateral: un pod comprometido usa su token de ServiceAccount para leer secretos de kube-system.
    El 'exec' inicial simula la explotación de la app (RCE)."""
    run_id = new_run_id("E3")
    require_precondition(current_image())
    k("-n", NS, "wait", "--for=condition=Ready", "pod/web-comprometido", "--timeout=120s")
    pod_ip = k("-n", NS, "get", "pod", "web-comprometido", "-o", "jsonpath={.status.podIP}").stdout.strip()
    begin_run(run_id, "E3_movimiento_lateral")
    script = ('TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token); '
              'curl -sk -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $TOKEN" '
              'https://kubernetes.default.svc/api/v1/namespaces/kube-system/secrets')
    start = now_ms(); print(f">> E3 inicio {start}")
    t_action = now_ms()
    code = k("-n", NS, "exec", "web-comprometido", "--", "sh", "-c", script).stdout.strip()
    time.sleep(5)
    end = now_ms()
    res = "exitoso" if code == "200" else "fallido"
    record(common("E3_movimiento_lateral", run_id, start, end, t_action, res, 15, http_code=code,
                  truth_actor="app-comprometida", truth_executor="app-comprometida",
                  truth_resource=r"secrets [(]ns=kube-system[)]", truth_action="list", truth_response=f"^{re.escape(code)}$",
                  truth_before="", truth_after="", truth_origin_ip=pod_ip, truth_ua="curl", truth_rule="acceso_cruzado_ns"))
    print(f">> E3 resultado: {res} (HTTP {code})")


def e5():
    """Intento de lectura de Secrets del namespace kube-system por una cuenta sin permiso; se espera HTTP 403."""
    run_id = new_run_id("E5")
    require_precondition(current_image())
    begin_run(run_id, "E5_lectura_secreto_denegada")
    start = now_ms(); print(f">> E5 inicio {start}")
    t_action = now_ms()
    result = k("--as", PASANTE, "-n", "kube-system", "get", "secrets", "--limit=1", "-o", "name", check=False)
    time.sleep(2)
    end = now_ms()
    denied = result.returncode != 0 and ("forbidden" in (result.stderr or "").lower())
    res = "exitoso" if denied else "fallido"
    record(common("E5_lectura_secreto_denegada", run_id, start, end, t_action, res, 15,
                  truth_actor="pasante", truth_executor="pasante", truth_resource=r"secrets",
                  truth_action="list", truth_response="^403$", truth_before="", truth_after="",
                  truth_origin_ip="", truth_ua="kubectl", truth_rule="lectura_secreto_denegada",
                  truth_revision=git_head(), truth_argo_estado=argo_estado()))
    print(f">> E5 resultado: {res} (se esperaba una denegación; comando denegado={denied})")


def manifest_image():
    m = re.search(r"image:\s*(\S+)", MANIFEST.read_text(encoding="utf-8"))
    return m.group(1) if m else None


def prepare_next_scenario(timeout=90):
    """Comprueba que el escenario anterior no deja el laboratorio en un estado sucio."""
    expected = manifest_image()
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            healthy = bool(expected) and deployment_ok(expected) and argo_estado() == "Synced/Healthy"
            cm = k("-n", NS, "get", "configmap", "tienda-config", "-o", "json", check=False)
            cm_ok = cm.returncode == 0
            if cm_ok:
                live = json.loads(cm.stdout).get("data", {}).get("banner")
                manifest = (ROOT / "gitops" / "app" / "configmap.yaml").read_text(encoding="utf-8")
                expected_cm = re.search(r"banner:\s*['\"]?(.*?)['\"]?\s*$", manifest, re.M)
                cm_ok = bool(expected_cm and live == expected_cm.group(1).strip().strip("'\""))
            if healthy and cm_ok:
                print("   preparación siguiente ensayo: app Synced/Healthy y recursos de prueba restaurados")
                return True
        except Exception:
            pass
        time.sleep(1)
    print("AVISO: el entorno no volvió a su estado base. Se detiene la serie para no contaminar el siguiente ensayo.")
    return False


def configmap_banner():
    raw = k("-n", NS, "get", "configmap", "tienda-config", "-o", "json").stdout
    return json.loads(raw).get("data", {}).get("banner", "")


def wait_configmap_banner(value, timeout):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if configmap_banner() == value:
                return now_ms()
        except Exception:
            pass
        time.sleep(0.5)
    return None


def e4():
    """Cambio no autorizado de ConfigMap gestionado por GitOps; Argo CD debe restaurar su dato."""
    run_id = new_run_id("E4")
    require_precondition(current_image())
    good = configmap_banner()
    if not good:
        raise SystemExit("PRECONDICIÓN NO CUMPLIDA: no existe mypes/tienda-config o no tiene data.banner. Ejecuta git push y python lab.py app.")
    begin_run(run_id, "E4_cambio_configmap")
    bad = "CAMBIO_NO_AUTORIZADO_SENTINEL"
    start = now_ms(); print(f">> E4 inicio {start}")
    t_action = now_ms()
    patch = json.dumps({"data": {"banner": bad}})
    k("--as", PASANTE, "-n", NS, "patch", "configmap/tienda-config", "--type=merge", "-p", patch)
    changed = configmap_banner()
    print(f"   ConfigMap alterado ({changed}); esperando que Argo CD lo restaure hasta {TIMEOUT}s ...")
    t_rec = wait_configmap_banner(good, TIMEOUT)
    time.sleep(2)
    end = now_ms()
    after = configmap_banner()
    estado = argo_estado()
    res = "exitoso" if t_rec and after == good else "fallido"
    record(common("E4_cambio_configmap", run_id, start, end, t_action, res, 15,
                  mttr_s=secs_between(t_action, t_rec) if t_rec else None,
                  truth_actor="pasante", truth_executor="pasante", truth_resource=r"configmaps/tienda-config",
                  truth_action="patch", truth_response="^(2..)$", truth_before="", truth_after="",
                  truth_config_before=good, truth_config_changed=changed,
                  truth_config_restored=after, truth_origin_ip="", truth_ua="kubectl",
                  truth_rule="cambio_configmap", truth_revision=git_head(), truth_argo_estado=estado))
    print(f">> E4 resultado: {res}; restaurado={after == good}")


def cmd_experimento(n=5, pausa=30):
    oscenarios = (e0, e1, e2, e3, e4, e5)
    abort = False
    for i in range(1, n + 1):
        print(f"\n=== Vuelta {i}/{n} ===")
        for fn in oscenarios:
            before = sum(1 for _ in open(EVID / "scenarios.jsonl", encoding="utf-8")) if (EVID / "scenarios.jsonl").exists() else 0
            try:
                fn()
            except SystemExit as ex:
                print(f"AVISO: {fn.__name__} terminó con error (ensayo NO registrado): {ex}")
                for stop_event, thread, _folder in list(RUN_MONITORS.values()):
                    stop_event.set()
                    thread.join(timeout=1)
                RUN_MONITORS.clear()
            after = sum(1 for _ in open(EVID / "scenarios.jsonl", encoding="utf-8")) if (EVID / "scenarios.jsonl").exists() else 0
            if after > before and not prepare_next_scenario():
                abort = True
                break
            time.sleep(pausa)
        if abort:
            break
    print("\nExperimento terminado. Guardando evidencias y generando informe integrado...")
    try:
        cmd_recolectar()
        cmd_analizar()
        print("Informe guardado en resultados/reporte.md; detalle por ensayo en evidence/runs/")
    except (SystemExit, Exception) as ex:
        print(f"AVISO: la evidencia por ensayo ya está guardada; el informe agregado no pudo completarse: {ex}")
        print("Ejecuta después: python lab.py recolectar; python lab.py analizar")


# ----------------------------------------------------------------------------- evidencia y análisis
def cmd_recolectar():
    EVID.mkdir(exist_ok=True)
    lines = collect_audit_lines()
    (EVID / "audit.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    app = k("-n", "argocd", "get", "application", APP, "-o", "json").stdout
    (EVID / "argocd-app.json").write_text(app, encoding="utf-8")
    n = sum(1 for _ in open(EVID / "scenarios.jsonl", encoding="utf-8")) if (EVID / "scenarios.jsonl").exists() else 0
    print(f"audit.jsonl: {len(lines)} eventos | argocd-app.json: {len(app)} bytes | ensayos registrados: {n}")
    print("(Git se lee directamente del repositorio al analizar)")


def cmd_analizar():
    sh([sys.executable, str(ROOT / "analysis" / "correlate.py"), "--evidence", str(EVID), "--repo", str(ROOT),
        "--out", str(ROOT / "resultados"), "--ns", NS, "--app", APP], capture=False)


def cmd_nueva_serie():
    """Archiva evidencia y resultados anteriores para iniciar una serie limpia sin borrar el clúster."""
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    archive = ROOT / "archivo_datos" / stamp
    archive.mkdir(parents=True, exist_ok=True)
    moved = []
    if EVID.exists():
        shutil.move(str(EVID), str(archive / "evidence"))
        moved.append("evidence")
    out = ROOT / "resultados"
    if out.exists():
        shutil.move(str(out), str(archive / "resultados"))
        moved.append("resultados")
    EVID.mkdir(parents=True, exist_ok=True)
    (EVID / ".gitkeep").write_text("", encoding="utf-8")
    print("Serie anterior archivada en:", archive.relative_to(ROOT))
    print("Archivos archivados:", ", ".join(moved) if moved else "ninguno")
    print("La infraestructura de Minikube y Argo CD NO se borró.")
    print("Ahora puedes ejecutar: python lab.py experimento 1 5")


def cmd_verificar_integridad():
    """Verifica que cada fichero del paquete individual conserve su SHA-256 registrado al guardarse."""
    rows = []
    for manifest in sorted(RUNS.glob("*/integrity-sha256.json")):
        try:
            data = json.loads(manifest.read_text(encoding="utf-8"))
        except Exception as exc:
            rows.append([manifest.parent.name, manifest.name, "MANIFIESTO_INVALIDO", str(exc)])
            continue
        for name, expected in data.get("files", {}).items():
            target = manifest.parent / name
            if not target.exists():
                status, actual = "FALTANTE", ""
            else:
                actual = hashlib.sha256(target.read_bytes()).hexdigest()
                status = "OK" if actual == expected else "ALTERADO"
            rows.append([manifest.parent.name, name, status, actual])
    out = ROOT / "resultados"
    out.mkdir(exist_ok=True)
    with (out / "integridad.csv").open("w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["run_id", "archivo", "estado", "sha256_actual"])
        w.writerows(rows)
    bad = [r for r in rows if r[2] != "OK"]
    print(f"Archivos verificados: {len(rows)} | íntegros: {len(rows)-len(bad)} | anomalías: {len(bad)}")
    print(f"Detalle: {out / 'integridad.csv'}")
    for r in bad[:20]:
        print(f"  {r[0]} / {r[1]}: {r[2]}")


def cmd_limpiar():
    sh(["minikube", "delete", "-p", PROFILE], capture=False)


def main():
    a = sys.argv[1:]
    if not a or a[0] in ("-h", "--help"):
        print(__doc__); return
    c = a[0]
    table = {"prereqs": cmd_prereqs, "minikube": cmd_minikube, "argocd": cmd_argocd, "app": cmd_app,
             "e0": e0, "e1": e1, "e2": e2, "e3": e3, "e4": e4, "e5": e5,
             "recolectar": cmd_recolectar, "analizar": cmd_analizar, "nueva-serie": cmd_nueva_serie,
             "verificar-integridad": cmd_verificar_integridad, "limpiar": cmd_limpiar}
    if c == "experimento":
        cmd_experimento(int(a[1]) if len(a) > 1 else 5, int(a[2]) if len(a) > 2 else 30)
    elif c in table:
        table[c]()
    else:
        print(f"Comando desconocido: {c}\n{__doc__}"); sys.exit(1)


if __name__ == "__main__":
    main()
