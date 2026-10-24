# Sentinel-MYPES Lab — reconstrucción forense integrada (Windows)

Laboratorio local para estudiar **qué metadatos pueden preservarse y reconstruirse después de incidentes simulados** en una arquitectura cloud-native representativa de una pequeña tienda/MYPE.

Stack: Windows + Docker Desktop + Minikube + Kubernetes Audit + Argo CD (`selfHeal: true`) + Git + Python. No requiere Falco, compilar eBPF, Bash ni Helm.

> **Importante:** el laboratorio genera datos sintéticos de la tienda y ejecuta acciones únicamente en tu clúster local. No uses Secrets, contraseñas ni datos reales de una empresa. El escenario E3 solo comprueba si un token de prueba obtiene autorización; no imprime los secretos del clúster.

## Qué hace ahora el prototipo

1. Ejecuta escenarios controlados de actividad legítima, cambios no autorizados, lecturas de secretos y cambios de configuración.
2. Guarda **automáticamente un paquete por ensayo** en `evidence/runs/<run_id>/` antes de pasar al escenario siguiente.
3. Captura el estado previo y posterior del Deployment y de la aplicación Argo CD; durante el ensayo muestrea aproximadamente cada 0,75 s el estado de sincronización/salud, revisión, imagen y configuración de prueba.
4. Filtra y preserva los eventos de Kubernetes Audit que caen en la ventana del ensayo.
5. Al finalizar `experimento`, actualiza la captura global y genera automáticamente el informe integrado.
6. El informe indica metadatos confirmados correctos, campos ausentes o no confirmados, preguntas cubiertas y respuestas exactas. No compara el rendimiento de Git, Audit y Argo CD por separado: evalúa Sentinel-MYPES como un único sistema.

## Hipótesis y variables sugeridas

**H1:** Sentinel-MYPES permite reconstruir correctamente una proporción previamente definida de las preguntas y campos de metadatos esperados después de los incidentes simulados.

- **VI:** tipo de incidente controlado (E0–E5).
- **VD:** efectividad de reconstrucción forense del prototipo.
- **Indicadores de la VD:** campos confirmados correctos / campos esperados; cobertura de preguntas; preguntas respondidas exactamente.

Decide el umbral de aceptación —por ejemplo, 80%— antes de ejecutar los ensayos formales. El umbral es un criterio metodológico, no un resultado que debamos presuponer.

## Escenarios incluidos

| ID | Escenario | Qué evidencia aporta |
|---|---|---|
| E0 | Cambio legítimo mediante GitOps | Commit, autor/fecha, revisión desplegada y actor de sincronización.
| E1 | Cambio manual de imagen de Deployment | Usuario/impersonación, acción, imagen antes/durante/después y restauración por Argo CD.
| E2 | Acceso interno al pod y lectura de un Secret de prueba | Eventos `pods/exec` y lectura del nombre del Secret; no imprime el contenido del Secret.
| E3 | Una ServiceAccount con permisos excesivos consulta el listado de Secrets de `kube-system` | Usuario de la ServiceAccount, solicitud, código HTTP y origen del pod.
| E4 | Cambio no autorizado de un ConfigMap gestionado por Argo CD | El audit log captura el valor de prueba cambiado, y los snapshots/monitor muestran si se restaura.
| E5 | Intento de leer Secrets de `kube-system` sin permiso | Evento denegado (HTTP 403); permite probar si se conserva evidencia de intentos bloqueados.

E4 usa únicamente el valor ficticio `Tienda-MYPES-configuracion-base`. Su contenido de solicitud se registra a nivel `Request` para ese ConfigMap de prueba; la política no captura el cuerpo de los Secrets.

## Ver Argo CD mientras ejecutas un ataque

Abre **una segunda ventana de PowerShell** y deja corriendo:

```powershell
kubectl port-forward svc/argocd-server -n argocd 8080:443
```

Abre `https://localhost:8080` en el navegador. Como el laboratorio usa un certificado local autofirmado, el navegador puede mostrar una advertencia de certificado.

Para obtener la contraseña inicial del usuario `admin` en PowerShell:

```powershell
$b64 = kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}"
[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($b64))
```

Inicia sesión y selecciona `tienda-web`. En la **primera ventana** ejecuta los escenarios; en la segunda observa `Synced/OutOfSync`, salud y recursos. El cambio puede revertirse rápidamente, así que el estado transitorio también se conserva en `argocd-monitor.jsonl` aunque no alcance a verse en cada refresco del navegador. El acceso por port-forward se mantiene local y no expone el servicio en una IP pública.

## Instalación inicial (Windows)

Requisitos: Docker Desktop con backend WSL2 funcionando, Minikube, kubectl, Git y Python 3.12.

```powershell
python lab.py prereqs
python lab.py minikube
python lab.py argocd
```

Antes de `python lab.py app`, configura `config.json` con la URL HTTPS pública de tu repositorio GitHub y sube los manifiestos del directorio `gitops/app/` a la rama configurada. Después ejecuta:

```powershell
python lab.py app
```

Debe terminar en `Synced/Healthy`.

## Actualizar desde la versión anterior

1. Haz una copia de tu carpeta actual. Copia los archivos actualizados (`lab.py`, `analysis/correlate.py`, `analysis/demo_sintetico.py`, `README.md`, `k8s/audit-policy.yaml`, `k8s/lab-extras.yaml`, `.gitignore`) sobre el proyecto existente y añade `gitops/app/configmap.yaml`. Conserva tu carpeta `.git` y `config.json`.
2. Publica las modificaciones para que Argo CD pueda leer el nuevo ConfigMap:

```powershell
git add lab.py analysis/correlate.py analysis/demo_sintetico.py README.md k8s/audit-policy.yaml k8s/lab-extras.yaml gitops/app/configmap.yaml .gitignore
git commit -m "Add per-run evidence preservation and new scenarios"
git push origin main
```

3. **La política de auditoría cambió** para guardar el cuerpo del ConfigMap sintético. Debes recrear Minikube para aplicar la política nueva; primero archiva el piloto anterior (siguiente apartado), luego:

```powershell
python lab.py limpiar
python lab.py minikube
python lab.py argocd
python lab.py app
```

Esto borra el clúster local, pero no los archivos del proyecto. Archiva la evidencia piloto antes de hacerlo.

## Prueba piloto y experimento

Primero guarda la evidencia previa y prepara una serie limpia; esto **no borra el clúster**:

```powershell
python lab.py nueva-serie
```

El comando mueve la carpeta `evidence/` y `resultados/` a `archivo_datos/<fecha>/` para no mezclar el piloto con la serie formal.

Ejecuta una ronda corta para validar los seis escenarios:

```powershell
python lab.py experimento 1 5
```

Cada ensayo se guarda automáticamente, el entorno se comprueba antes del siguiente y, al terminar, se genera el informe. Si cualquier escenario falla o el entorno no vuelve a su estado esperado, revisa la salida y no trates ese ensayo como éxito.

Cuando hayas validado todos los escenarios, empieza la serie formal. Ejemplo: 10 rondas de los seis escenarios, con pausa de 10 segundos:

```powershell
python lab.py nueva-serie
python lab.py experimento 10 10
```

No uses las salidas de `demo_sintetico.py` como evidencia de tesis: solo son una prueba de humo con datos inventados.

## Evidencia que se guarda en cada ensayo

Cada `evidence/runs/<run_id>/` contiene, cuando la fuente está disponible:

- `truth-reference.json`: verdad de referencia independiente (la acción que realmente lanzó el script).
- `audit.jsonl`: eventos de auditoría dentro de la ventana del ensayo.
- `argocd-before.json`, `argocd-after.json` y `argocd-monitor.jsonl`: estado antes/después y muestras temporales.
- `deployment-before.json`, `deployment-after.json` y, para E4, `configmap-before.json`.
- `git-state.json`: commit actual y estado del repositorio.
- `bundle-summary.json` y `README.md`: resumen del paquete de evidencia.

El informe global queda en `resultados/reporte.md`. Los archivos `ensayos.csv`, `metadatos_por_ensayo.csv` y `metricas.json` permiten consultar el resultado agregado y cada campo. En `metadatos_por_ensayo.csv`, `NO_CONFIRMADO_CORRECTO` significa que el campo no se pudo confirmar contra la verdad de referencia; puede estar ausente o ser discrepante, por lo que debe revisarse la línea de tiempo y la evidencia original.

## Recomendaciones metodológicas

- Registra por adelantado el umbral de suficiencia y define qué campos/preguntas aplican a cada escenario.
- Usa al menos 10 repeticiones por escenario como piloto ampliado; si la tesis exige inferencia estadística, acuerda el tamaño muestral con tu asesor.
- Mantén una verdad de referencia independiente: el script registra lo que envió y observó, pero la evaluación no debe depender únicamente del mismo log que se intenta evaluar.
- Reporta resultados por escenario; E2/E3 podrían ser fáciles de reconstruir con Audit mientras E0/E1/E4 prueban relaciones entre cambios declarados, estados y corrección.
- En una extensión futura puedes añadir eliminación de un Pod/Service gestionado y observar la diferencia entre la autorreparación del controlador de Kubernetes y la reconciliación de Argo CD. No lo mezcles con la primera serie hasta validar E0–E5.

## Limitaciones

- Minikube es un clúster de un nodo; los resultados no se generalizan automáticamente a producción o a todas las MYPES.
- Sin Falco no se registra toda la actividad interna de los contenedores; se observan llamadas a la API Kubernetes y los datos operativos de Argo CD/Git.
- La auditoría a nivel `Metadata` registra quién leyó un Secret y la respuesta, no el contenido del Secret.
- E3 es un escenario controlado con una ServiceAccount de laboratorio deliberadamente sobreprivilegiada; no prueba que cualquier atacante pueda reproducirlo.
- El muestreo de Argo CD cada ~0,75 s puede no capturar todos los estados transitorios. Por eso se conservan también los eventos auditados y las capturas previas/posteriores.
