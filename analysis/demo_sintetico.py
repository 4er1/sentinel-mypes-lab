#!/usr/bin/env python3
"""
demo_sintetico.py - PRUEBA DE HUMO (smoke test), NO es validación científica.

Genera evidencia SINTÉTICA con el formato de Kubernetes (audit log), Argo CD y Git, y ejecuta correlate.py.
Sirve para comprobar que el programa corre y para entender el formato de los datos.
Los eventos están diseñados a mano: que salgan bien aquí NO prueba nada sobre datos reales.
Incluye a propósito imperfecciones (un evento señuelo, un evento de auditoría perdido, una captura de estado de Argo CD
desfasada y un ensayo cuyo entorno falló y debe excluirse) para que veas la diferencia entre cobertura y exactitud.
No toca tu repo ni tu clúster: trabaja en una carpeta temporal.
"""
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
tmp = Path(tempfile.mkdtemp(prefix="demo-sentinel-"))
repo, ev, out = tmp / "repo", tmp / "evidence", tmp / "resultados"
(repo / "gitops/app").mkdir(parents=True)
(ev / "argocd").mkdir(parents=True)
BASE = datetime(2026, 10, 23, 15, 0, 0, tzinfo=timezone.utc)


def T(base, sec):
    return (base + timedelta(seconds=sec)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


# ---------------------------------------------------------------- git sintético
def git(*a, date=None):
    env = dict(os.environ, GIT_AUTHOR_NAME="Estudiante Demo", GIT_AUTHOR_EMAIL="demo@example.com",
               GIT_COMMITTER_NAME="Estudiante Demo", GIT_COMMITTER_EMAIL="demo@example.com")
    if date:
        env["GIT_AUTHOR_DATE"] = env["GIT_COMMITTER_DATE"] = date
    return subprocess.run(["git", "-C", str(repo), *a], env=env, check=True, capture_output=True, text=True).stdout.strip()


def set_image(image, msg, date):
    (repo / "gitops/app/deployment.yaml").write_text(f"kind: Deployment\nspec:\n  containers:\n    - name: web\n      image: {image}\n")
    git("add", "."); git("commit", "-q", "-m", msg, date=date)
    return git("rev-parse", "HEAD")


git("init", "-q")
c0 = set_image("nginx:1.25", "Despliegue inicial", "2026-10-23T14:00:00Z")

# ---------------------------------------------------------------- audit log
ARGO = "system:serviceaccount:argocd:argocd-application-controller"
PAS = "system:serviceaccount:mypes:pasante"
DEP = "/apis/apps/v1/namespaces/mypes/deployments/tienda-web"
K, A = "kubectl/v1.30.0", "argocd-application-controller/v2.13"
AU = []


def audit(ts, user, verb, res, name, ns, ips, ua, uri, code=200, imp=None, sub=None, image=None):
    a = {"kind": "Event", "apiVersion": "audit.k8s.io/v1", "level": "Metadata", "auditID": ts, "stage": "ResponseComplete",
         "requestURI": uri, "verb": verb, "user": {"username": user}, "sourceIPs": ips, "userAgent": ua,
         "objectRef": {"resource": res, "namespace": ns, "name": name, **({"subresource": sub} if sub else {})},
         "responseStatus": {"code": code}, "requestReceivedTimestamp": ts, "stageTimestamp": ts}
    if imp:
        a["impersonatedUser"] = {"username": imp}
    if image:
        a["requestObject"] = {"spec": {"template": {"spec": {"containers": [{"name": "web", "image": image}]}}}}
    AU.append(a)


history, runs = [{"id": 0, "revision": c0, "deployedAt": "2026-10-23T14:05:00Z", "initiatedBy": {"automated": True}}], []
image, head, hid = "nginx:1.25", c0, 0


def snap(run_id, estado):
    sync, health = estado.split("/")
    (ev / "argocd" / f"{run_id}.json").write_text(json.dumps({"status": {"sync": {"status": sync}, "health": {"status": health}}}))


def run(rid, scen, start, end, t_action, res, tol, **kw):
    runs.append({"run_id": rid, "scenario": scen, "start": start, "end": end, "t_action": t_action, "resultado": res, "tol_s": tol, **kw})


for r in range(3):                                   # 3 repeticiones de cada escenario
    b = BASE + timedelta(minutes=30 * r)
    # ---- E0: cambio legítimo por Git
    new = "nginx:1.26" if image == "nginx:1.25" else "nginx:1.25"
    commit = set_image(new, f"Actualiza nginx {image} -> {new}", T(b, 10).replace(".000Z", "Z"))
    hid += 1
    history.append({"id": hid, "revision": commit, "deployedAt": T(b, 25), "initiatedBy": {"automated": True}})
    audit(T(b, 24.1), ARGO, "patch", "deployments", "tienda-web", "mypes", ["10.244.0.15"], A, DEP, image=new)
    rid = f"e0-{r}"
    run(rid, "E0_cambio_legitimo", T(b, 0), T(b, 40), T(b, 9.5), "exitoso", 60, mttr_s=16.0,
        truth_actor="Estudiante Demo", truth_executor="argocd-application-controller", truth_resource="deployment",
        truth_action="patch|update|create", truth_response="^(2..)$", truth_before=image, truth_after=new,
        truth_origin_ip="10.244.0.15", truth_ua="argocd", truth_rule="", truth_commit=commit, truth_files="deployment[.]yaml",
        truth_revision=commit, truth_argo_estado="Synced/Healthy")
    snap(rid, "Synced/Progressing" if r == 1 else "Synced/Healthy")      # r=1: la captura se hizo antes de que Argo marcara Healthy
    image, head = new, commit

    # ---- E1: cambio manual y autocorrección de Argo CD
    b1 = b + timedelta(minutes=5)
    audit(T(b1, 5.3), "minikube-user", "patch", "deployments", "tienda-web", "mypes", ["192.168.49.1"], K, DEP, imp=PAS, image="nginx:1.19")
    rid = f"e1-{r}"
    if r == 2:                                       # el entorno FALLÓ: Argo CD no corrigió -> ensayo excluido
        run(rid, "E1_cambio_manual_drift", T(b1, 0), T(b1, 98), T(b1, 4.9), "fallido", 15, analizar=False, motivo="el entorno sintético marcó la evidencia como inválida",
            cleanup_ts=T(b1, 99), truth_actor="pasante", truth_executor="pasante", truth_resource="deployment", truth_action="patch",
            truth_response="^(2..)$", truth_before=image, truth_after="nginx:1.19", truth_restaurada="", truth_origin_ip="",
            truth_ua="kubectl", truth_rule="cambio_manual|autocorreccion_drift", truth_revision=head, truth_argo_estado="OutOfSync/Healthy")
    else:
        audit(T(b1, 19.8), ARGO, "patch", "deployments", "tienda-web", "mypes", ["10.244.0.15"], A, DEP, image=image)
        hid += 1
        history.append({"id": hid, "revision": head, "deployedAt": T(b1, 20), "initiatedBy": {"automated": True}})
        run(rid, "E1_cambio_manual_drift", T(b1, 0), T(b1, 32), T(b1, 4.9), "exitoso", 15, mttr_s=14.9, estado_restaurado=True,
            truth_actor="pasante", truth_executor="pasante", truth_resource="deployment", truth_action="patch",
            truth_response="^(2..)$", truth_before=image, truth_after="nginx:1.19", truth_restaurada=image, truth_origin_ip="",
            truth_ua="kubectl", truth_rule="cambio_manual|autocorreccion_drift", truth_revision=head, truth_argo_estado="Synced/Healthy")
        snap(rid, "Synced/Healthy")

    # ---- E2: amenaza interna
    b2 = b + timedelta(minutes=10)
    audit(T(b2, 5.1), "minikube-user", "create", "pods", "tienda-web-abc", "mypes", ["192.168.49.1"], K,
          "/api/v1/namespaces/mypes/pods/tienda-web-abc/exec?command=sh", imp=PAS, sub="exec", code=101)
    audit(T(b2, 8.4), "minikube-user", "get", "secrets", "db-credentials", "mypes", ["192.168.49.1"], K,
          "/api/v1/namespaces/mypes/secrets/db-credentials", imp=PAS)
    if r == 0:                                       # señuelo: otro usuario toca otro secreto casi a la vez
        audit(T(b2, 9.0), "otro-usuario", "get", "secrets", "otro-secreto", "mypes", ["192.168.49.1"], K, "/api/v1/namespaces/mypes/secrets/otro-secreto")
    run(f"e2-{r}", "E2_amenaza_interna", T(b2, 0), T(b2, 20), T(b2, 4.8), "exitoso", 15, truth_actor="pasante", truth_executor="pasante",
        truth_resource="db-credentials", truth_action="get", truth_response="^(2..)$", truth_before="", truth_after="",
        truth_origin_ip="", truth_ua="kubectl", truth_rule="exec_en_pod|lectura_secreto")

    # ---- E3: movimiento lateral
    b3 = b + timedelta(minutes=15)
    audit(T(b3, 3.0), "minikube-user", "create", "pods", "web-comprometido", "mypes", ["192.168.49.1"], K,
          "/api/v1/namespaces/mypes/pods/web-comprometido/exec", sub="exec", code=101)
    if r != 1:                                       # r=1: el evento de la ServiceAccount se PERDIÓ
        audit(T(b3, 5.2), "system:serviceaccount:mypes:app-comprometida", "list", "secrets", "", "kube-system", ["10.244.0.22"],
              "curl/8.5.0", "/api/v1/namespaces/kube-system/secrets")
    run(f"e3-{r}", "E3_movimiento_lateral", T(b3, 0), T(b3, 20), T(b3, 2.9), "exitoso", 15, http_code="200",
        truth_actor="app-comprometida", truth_executor="app-comprometida", truth_resource="secrets [(]ns=kube-system[)]",
        truth_action="list", truth_response="^200$", truth_before="", truth_after="", truth_origin_ip="10.244.0.22",
        truth_ua="curl", truth_rule="acceso_cruzado_ns")

# ruido que debe filtrarse
audit(T(BASE, 6), "system:serviceaccount:kube-system:replicaset-controller", "create", "pods", "x", "mypes", ["127.0.0.1"], "kube-controller-manager", "/api/v1/namespaces/mypes/pods")

(ev / "audit.jsonl").write_text("\n".join(json.dumps(a) for a in sorted(AU, key=lambda x: x["requestReceivedTimestamp"])) + "\n")
(ev / "argocd-app.json").write_text(json.dumps({"metadata": {"name": "tienda-web"}, "status": {
    "sync": {"status": "Synced"}, "health": {"status": "Healthy"}, "history": history}}))
(ev / "scenarios.jsonl").write_text("\n".join(json.dumps(x) for x in runs) + "\n")

print(f"Datos sintéticos en: {tmp}")
print("AVISO: esto es una prueba de humo con datos inventados; NO es evidencia para la tesis.\n")
subprocess.run([sys.executable, str(HERE / "correlate.py"), "--evidence", str(ev), "--repo", str(repo), "--out", str(out)], check=True)
print(f"\nAbre el reporte: {out / 'reporte.md'}")
