#!/usr/bin/env python3
"""
lab.py - Orquestador del laboratorio (funciona en Windows, Linux y macOS; solo necesita Python 3.8+).

Uso:  python lab.py <comando> [argumentos]

  prereqs                 comprueba que tienes las herramientas
  minikube                crea el clúster con audit log activado
  argocd                  instala Argo CD
  app                     despliega la app "tienda-web" gestionada por Argo CD (selfHeal SIEMPRE activado)
  e0 | e1 | e2 | e3       ejecuta UN ensayo del escenario indicado (queda registrado en evidence/scenarios.jsonl)
  experimento [N] [P]     N vueltas (def. 5) de los 4 escenarios; P = pausa en segundos entre ensayos (def. 30)
  recolectar              exporta audit log y estado de Argo CD a evidence/
  analizar                genera resultados/ (reporte.md, ensayos.csv, comparacion_pareada.csv, ...)
  limpiar                 borra el clúster de Minikube

Idea del estudio: los incidentes se ejecutan UNA vez y las mismas evidencias se analizan con distintos métodos
(cada fuente por separado vs. las tres correlacionadas). Argo CD con selfHeal es parte del entorno.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
EVID = ROOT / "evidence"
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
    EVID.mkdir(exist_ok=True)
    with open(EVID / "scenarios.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps(d, ensure_ascii=False) + "\n")


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
    n = sum(1 for line in log.splitlines() if line.startswith('{"kind":"Event"'))
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
    d = {"run_id": run_id, "scenario": scen, "start": start, "end": end,
         "t_action": t_action, "resultado": resultado, "tol_s": tol}
    d.update(extra)
    return d


def e0():
    """CONTROL: cambio legítimo vía GitOps (commit -> push -> Argo CD sincroniza)."""
    run_id = str(int(time.time()))
    before = current_image()
    require_precondition(before)
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
    run_id = str(int(time.time()))
    good = current_image()
    require_precondition(good)
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
    run_id = str(int(time.time()))
    require_precondition(current_image())
    start = now_ms(); print(f">> E2 inicio {start}")
    t_action = now_ms()
    k("--as", PASANTE, "-n", NS, "exec", f"deploy/{APP}", "--", "sh", "-c", "id; hostname; ls /etc/nginx")
    k("--as", PASANTE, "-n", NS, "get", "secret", "db-credentials", "-o", "yaml")
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
    run_id = str(int(time.time()))
    require_precondition(current_image())
    k("-n", NS, "wait", "--for=condition=Ready", "pod/web-comprometido", "--timeout=120s")
    pod_ip = k("-n", NS, "get", "pod", "web-comprometido", "-o", "jsonpath={.status.podIP}").stdout.strip()
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


def cmd_experimento(n=5, pausa=30):
    for i in range(1, n + 1):
        print(f"\n=== Vuelta {i}/{n} ===")
        for fn in (e0, e1, e2, e3):
            try:
                fn()
            except SystemExit as ex:
                print(f"AVISO: {fn.__name__} terminó con error (ensayo NO registrado): {ex}")
            time.sleep(pausa)
    print("\nExperimento terminado. Siguiente: python lab.py recolectar  y  python lab.py analizar")


# ----------------------------------------------------------------------------- evidencia y análisis
def cmd_recolectar():
    EVID.mkdir(exist_ok=True)
    log = k("-n", "kube-system", "logs", f"kube-apiserver-{PROFILE}").stdout
    lines = [l for l in log.splitlines() if l.startswith('{"kind":"Event"')]
    (EVID / "audit.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    app = k("-n", "argocd", "get", "application", APP, "-o", "json").stdout
    (EVID / "argocd-app.json").write_text(app, encoding="utf-8")
    n = sum(1 for _ in open(EVID / "scenarios.jsonl", encoding="utf-8")) if (EVID / "scenarios.jsonl").exists() else 0
    print(f"audit.jsonl: {len(lines)} eventos | argocd-app.json: {len(app)} bytes | ensayos registrados: {n}")
    print("(Git se lee directamente del repositorio al analizar)")


def cmd_analizar():
    sh([sys.executable, str(ROOT / "analysis" / "correlate.py"), "--evidence", str(EVID), "--repo", str(ROOT),
        "--out", str(ROOT / "resultados"), "--ns", NS, "--app", APP], capture=False)


def cmd_limpiar():
    sh(["minikube", "delete", "-p", PROFILE], capture=False)


def main():
    a = sys.argv[1:]
    if not a or a[0] in ("-h", "--help"):
        print(__doc__); return
    c = a[0]
    table = {"prereqs": cmd_prereqs, "minikube": cmd_minikube, "argocd": cmd_argocd, "app": cmd_app,
             "e0": e0, "e1": e1, "e2": e2, "e3": e3, "recolectar": cmd_recolectar, "analizar": cmd_analizar, "limpiar": cmd_limpiar}
    if c == "experimento":
        cmd_experimento(int(a[1]) if len(a) > 1 else 5, int(a[2]) if len(a) > 2 else 30)
    elif c in table:
        table[c]()
    else:
        print(f"Comando desconocido: {c}\n{__doc__}"); sys.exit(1)


if __name__ == "__main__":
    main()
