#!/usr/bin/env python3
"""Sentinel-MYPES v2: laboratorio aislado de metadatos forenses.

Solo funciona sobre Minikube. No usa datos reales ni ejecuta código dañino.
Escenarios: RoleBinding elevado dentro del namespace, CronJob inocuo y deriva GitOps.
"""
from __future__ import annotations

import csv
import hashlib
import json
import shutil
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CFG = json.loads((ROOT / "config.json").read_text(encoding="utf-8"))
NS = CFG.get("v2_lab_namespace", "mypes-lab")
APP = CFG.get("v2_app_name", "mype-demo")
PROFILE = CFG.get("v2_minikube_profile", "sentinel-mypes")
RUNS, RESULTS = ROOT / "evidence-v2" / "runs", ROOT / "resultados-v2"


def utc():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def shell(args, *, input_text=None, check=True):
    result = subprocess.run(args, cwd=ROOT, input=input_text, text=True, encoding="utf-8",
                            errors="replace", capture_output=True)
    if check and result.returncode:
        raise RuntimeError((result.stderr or result.stdout).strip())
    return result


def k(*args, input_text=None, check=True):
    return shell(["kubectl", *args], input_text=input_text, check=check)


def json_file(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")


def get(kind, name):
    response = k("-n", NS, "get", kind, name, "-o", "json", check=False)
    return json.loads(response.stdout) if response.returncode == 0 else {"absent": True}


def app():
    response = k("-n", "argocd", "get", "application", APP, "-o", "json", check=False)
    return json.loads(response.stdout) if response.returncode == 0 else {"unavailable": True}


def argo_ready():
    crd = k("get", "crd", "applications.argoproj.io", check=False)
    if crd.returncode != 0:
        return False
    server = k("-n", "argocd", "get", "deploy", "argocd-server", check=False)
    controller = k("-n", "argocd", "get", "statefulset", "argocd-application-controller", check=False)
    return server.returncode == 0 and controller.returncode == 0


def application_ready():
    current = app()
    return current.get("status", {}).get("sync", {}).get("status") == "Synced" and current.get("status", {}).get("health", {}).get("status") == "Healthy"


def require_application_ready():
    if not argo_ready():
        raise RuntimeError("Argo CD no está instalado todavía. Ejecuta primero: python lab_v2.py deploy")
    if not application_ready():
        raise RuntimeError(f"{APP} aún no está Synced/Healthy. Ejecuta 'python lab_v2.py deploy' y espera a que Argo CD termine la sincronización.")


def ensure_minikube():
    context = k("config", "current-context").stdout.strip()
    if "minikube" not in context and PROFILE not in context:
        raise RuntimeError("Seguridad: este programa solo se ejecuta en Minikube, nunca en producción.")


def audit_events():
    logs = k("-n", "kube-system", "logs", f"kube-apiserver-{PROFILE}", check=False).stdout
    events = []
    for line in logs.splitlines():
        try:
            item = json.loads(line)
            if item.get("kind") == "Event":
                events.append(item)
        except json.JSONDecodeError:
            continue
    return events


def new_run(scenario, resource):
    ensure_minikube()
    ident = f"{scenario}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    folder = RUNS / ident
    folder.mkdir(parents=True)
    truth = {"run_id": ident, "scenario": scenario, "resource_name": resource,
             "namespace": NS, "start": utc(), "experiment_only": True}
    json_file(folder / "argocd-before.json", app())
    return folder, truth


def save_manifest(folder, name, body):
    path = folder / name
    path.write_text(body, encoding="utf-8")
    return path


def finish(folder, truth):
    truth["end"] = utc()
    json_file(folder / "truth.json", truth)
    json_file(folder / "argocd-after.json", app())
    # Da al apiserver un instante para escribir los eventos finales (incluido delete).
    time.sleep(2)
    events = [e for e in audit_events() if e.get("objectRef", {}).get("namespace") == NS
              and e.get("objectRef", {}).get("name") == truth["resource_name"]]
    (folder / "audit.jsonl").write_text("\n".join(json.dumps(e, ensure_ascii=False) for e in events) +
                                         ("\n" if events else ""), encoding="utf-8")
    hashes = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
              for p in folder.iterdir() if p.is_file() and p.name != "integrity.json"}
    json_file(folder / "integrity.json", {"algorithm": "SHA-256", "files": hashes})
    print(f"Evidencia guardada: {folder}")


def rolebinding():
    """Simula escalada únicamente en mypes-lab; no crea ClusterRoleBinding."""
    require_application_ready()
    name = "binding-elevado-lab"
    folder, truth = new_run("E1_escalada_privilegios", name)
    manifest = f'''apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: {name}
  namespace: {NS}
  labels: {{sentinel-mypes/scenario: privilege-escalation}}
subjects:
- kind: ServiceAccount
  name: actor-laboratorio
  namespace: {NS}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
'''
    path = save_manifest(folder, "rolebinding-lab.yaml", manifest)
    truth["expected"] = {"verb": "create", "resource": "rolebindings", "role_ref": "cluster-admin"}
    k("apply", "-f", str(path)); truth["action_time"] = utc()
    json_file(folder / "created.json", get("rolebinding", name))
    k("-n", NS, "delete", "rolebinding", name, "--ignore-not-found=true")
    truth["deleted_time"] = utc(); json_file(folder / "after-delete.json", get("rolebinding", name))
    finish(folder, truth)


def cronjob():
    """Crea y borra un CronJob suspendido; nunca ejecuta red ni maneja datos reales."""
    require_application_ready()
    name = "tarea-temporal-lab"
    folder, truth = new_run("E2_persistencia_cronjob", name)
    manifest = f'''apiVersion: batch/v1
kind: CronJob
metadata:
  name: {name}
  namespace: {NS}
  labels: {{sentinel-mypes/scenario: persistence}}
spec:
  schedule: "0 0 1 1 *"
  suspend: true
  jobTemplate:
    spec:
      template:
        spec:
          restartPolicy: Never
          containers:
          - name: marcador
            image: busybox:1.36
            command: ["sh", "-c", "echo laboratorio-sentinel-mypes"]
'''
    path = save_manifest(folder, "cronjob-lab.yaml", manifest)
    truth["expected"] = {"verb": "create", "resource": "cronjobs", "schedule": "0 0 1 1 *"}
    k("apply", "-f", str(path)); truth["action_time"] = utc()
    json_file(folder / "created.json", get("cronjob", name))
    k("-n", NS, "delete", "cronjob", name, "--ignore-not-found=true")
    truth["deleted_time"] = utc(); json_file(folder / "after-delete.json", get("cronjob", name))
    finish(folder, truth)


def drift():
    """Crea deriva en ConfigMap GitOps y comprueba la reconciliación de Argo CD."""
    require_application_ready()
    name, altered = "mype-config", "CAMBIO-NO-AUTORIZADO-DE-LAB"
    folder, truth = new_run("E3_deriva_configuracion", name)
    before = get("configmap", name).get("data", {}).get("banner")
    if not before:
        raise RuntimeError("No existe mype-config. Ejecuta primero el despliegue GitOps indicado en README-v2.md.")
    k("-n", NS, "patch", "configmap", name, "--type=merge", "-p", json.dumps({"data": {"banner": altered}}))
    truth.update({"action_time": utc(), "expected": {"verb": "patch", "resource": "configmaps",
                  "before": before, "altered": altered, "restored": before}})
    json_file(folder / "altered.json", get("configmap", name))
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline and get("configmap", name).get("data", {}).get("banner") != before:
        time.sleep(2)
    truth["reconciled"] = get("configmap", name).get("data", {}).get("banner") == before
    truth["reconciled_time"] = utc() if truth["reconciled"] else None
    json_file(folder / "after-reconcile.json", get("configmap", name)); finish(folder, truth)


def events(path):
    if not path.exists(): return []
    output = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try: output.append(json.loads(line))
        except json.JSONDecodeError: pass
    return output


def analyze():
    RESULTS.mkdir(exist_ok=True)
    rows = []
    for folder in sorted(RUNS.glob("*")):
        if not (folder / "truth.json").exists(): continue
        truth, found = json.loads((folder / "truth.json").read_text(encoding="utf-8")), events(folder / "audit.jsonl")
        wanted = truth["expected"]
        created = next((e for e in found if e.get("verb") == wanted["verb"]), {})
        ref, request = created.get("objectRef", {}), created.get("requestObject", {})
        deleted = any(e.get("verb") == "delete" for e in found)
        fields = [bool(created.get("user", {}).get("username")), bool(created.get("stageTimestamp") or created.get("requestReceivedTimestamp")),
                  created.get("verb") == wanted["verb"], ref.get("resource") == wanted["resource"],
                  ref.get("namespace") == NS, bool(request),
                  truth.get("reconciled", deleted)]
        questions = [fields[0] and fields[1], fields[3] and fields[4], fields[2] and fields[5], fields[6]]
        rows.append({"run_id": truth["run_id"], "scenario": truth["scenario"], "audit_events": len(found),
                     "metadatos_pct": round(100 * sum(fields) / len(fields)),
                     "utilidad_forense_pct": round(100 * sum(questions) / len(questions)),
                     "reconciliado": truth.get("reconciled", "N/A")})
    with (RESULTS / "ensayos.csv").open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=list(rows[0]) if rows else ["run_id"]); writer.writeheader(); writer.writerows(rows)
    average = lambda key: round(sum(r[key] for r in rows) / len(rows)) if rows else 0
    summary = {"ensayos": len(rows), "disponibilidad_metadatos_pct": average("metadatos_pct"),
               "utilidad_forense_pct": average("utilidad_forense_pct"), "detalle": rows}
    json_file(RESULTS / "metricas.json", summary)
    lines = ["# Resultados Sentinel-MYPES v2", "", f"Ensayos analizados: {len(rows)}.", "",
             "| Escenario | Metadatos disponibles | Utilidad forense | Eventos auditados |", "|---|---:|---:|---:|"]
    lines += [f"| {r['scenario']} | {r['metadatos_pct']}% | {r['utilidad_forense_pct']}% | {r['audit_events']} |" for r in rows]
    lines += ["", f"Promedio de disponibilidad: **{summary['disponibilidad_metadatos_pct']}%**.",
              f"Promedio de utilidad forense: **{summary['utilidad_forense_pct']}%**.",
              "", "La utilidad forense resume cuatro preguntas: quién/cuándo, qué recurso, qué acción y si la evidencia sobrevivió."]
    (RESULTS / "reporte.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Informe generado: {RESULTS / 'reporte.md'}")


def check():
    missing = [x for x in ("docker", "minikube", "kubectl", "git") if not shutil.which(x)]
    print("Faltan: " + ", ".join(missing) if missing else "Herramientas locales: OK")
    print(f"Destino permitido: Minikube ({PROFILE}); namespace: {NS}")


def deploy():
    """Aplica los recursos no gestionados y registra la Application GitOps."""
    ensure_minikube()
    k("apply", "-f", str(ROOT / "k8s" / "lab-v2.yaml"))
    if not argo_ready():
        print("Argo CD no está instalado. Descargando e instalando sus manifiestos oficiales; puede tardar unos minutos...")
        k("create", "namespace", "argocd", check=False)
        manifest_url = "https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml"
        try:
            with urllib.request.urlopen(manifest_url, timeout=60) as response:
                manifest = response.read().decode("utf-8")
        except Exception as error:
            raise RuntimeError(f"No se pudo descargar Argo CD: {error}. Comprueba tu conexión e intenta otra vez.")
        # Argo CD incluye CRDs grandes. Server-side apply evita la anotación
        # kubectl.kubernetes.io/last-applied-configuration, que puede exceder
        # el límite de 256 KiB del API server.
        k("apply", "--server-side", "--force-conflicts", "-n", "argocd", "-f", "-", input_text=manifest)
        print("Esperando componentes principales de Argo CD...")
        k("-n", "argocd", "rollout", "status", "deploy/argocd-server", "--timeout=300s")
        k("-n", "argocd", "rollout", "status", "statefulset/argocd-application-controller", "--timeout=300s")
    if "TU_USUARIO" in CFG.get("repo_url", ""):
        raise RuntimeError("Configura repo_url en config.json antes de registrar la aplicación GitOps.")
    template = (ROOT / "argocd" / "application-v2.yaml").read_text(encoding="utf-8")
    rendered = template.replace("__REPO_URL__", CFG["repo_url"]).replace("__BRANCH__", CFG["git_branch"])
    k("apply", "-f", "-", input_text=rendered)
    print("Application registrada. Esperando Synced/Healthy (hasta 5 minutos)...")
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        if application_ready():
            print(f"{APP} está Synced/Healthy.")
            return
        time.sleep(3)
    raise RuntimeError(f"{APP} no llegó a Synced/Healthy. Revisa repo_url, rama y que gitops/app-v2 esté publicado.")


def experiment(repetitions):
    if repetitions < 1:
        raise RuntimeError("Las repeticiones deben ser al menos 1.")
    require_application_ready()
    for index in range(1, repetitions + 1):
        print(f"Ronda {index}/{repetitions}: escalada simulada")
        rolebinding()
        print(f"Ronda {index}/{repetitions}: persistencia simulada")
        cronjob()
        print(f"Ronda {index}/{repetitions}: deriva GitOps")
        drift()
    analyze()


def archive_incomplete_series():
    """Conserva, sin borrar, ensayos hechos antes de que el entorno estuviera listo."""
    if not RUNS.exists() or not any(RUNS.iterdir()):
        print("No hay evidencia v2 que archivar.")
        return
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    destination = ROOT / "archivo_datos" / f"serie-v2-incompleta-{stamp}"
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(RUNS), str(destination / "runs"))
    RUNS.mkdir(parents=True)
    print(f"Evidencia archivada, no eliminada: {destination}")


def bootstrap():
    """Prepara la política antes de iniciar el perfil Minikube por primera vez."""
    existing = shell(["minikube", "status", "-p", PROFILE], check=False)
    if existing.returncode == 0:
        raise RuntimeError(f"El perfil {PROFILE} ya existe. Para no cambiar su configuración sin control, elimínalo manualmente con 'minikube delete -p {PROFILE}' y vuelve a ejecutar bootstrap.")
    source = ROOT / "k8s" / "audit-policy-v2.yaml"
    mini_home = Path(__import__("os").environ.get("MINIKUBE_HOME", str(Path.home())))
    target = mini_home / ".minikube" / "files" / "etc" / "ssl" / "certs" / "audit-policy-v2.yaml"
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)
    shell(["minikube", "start", "-p", PROFILE, "--driver=docker",
           f"--cpus={CFG.get('minikube_cpus', 2)}", f"--memory={CFG.get('minikube_memory_mb', 4096)}",
           "--extra-config=apiserver.audit-policy-file=/etc/ssl/certs/audit-policy-v2.yaml",
           "--extra-config=apiserver.audit-log-path=-"])
    print("Minikube listo con política de auditoría v2. Ahora aplica k8s/lab-v2.yaml e instala/despliega Argo CD según README-v2.md.")


COMMANDS = {"check": check, "bootstrap": bootstrap, "deploy": deploy, "rolebinding": rolebinding, "cronjob": cronjob, "drift": drift, "analizar": analyze, "archivar": archive_incomplete_series}
if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "experimento" and sys.argv[2].isdigit():
        try: experiment(int(sys.argv[2]))
        except (RuntimeError, FileNotFoundError) as error: print(f"ERROR: {error}", file=sys.stderr); sys.exit(1)
    elif len(sys.argv) == 2 and sys.argv[1] in COMMANDS:
        try: COMMANDS[sys.argv[1]]()
        except (RuntimeError, FileNotFoundError) as error: print(f"ERROR: {error}", file=sys.stderr); sys.exit(1)
    else:
        print("Uso: python lab_v2.py check | bootstrap | deploy | rolebinding | cronjob | drift | analizar | archivar | experimento N"); sys.exit(1)
