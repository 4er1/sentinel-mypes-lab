# Sentinel-MYPES Lab — reconstrucción forense con metadatos (Windows, sin Falco)

Laboratorio del proyecto de bachiller:
**"Evaluación de la resiliencia en arquitecturas cloud nativas frente a incidentes en MYPES mediante el análisis de metadatos y auto-recuperación"**

Minikube + **Argo CD** (con auto-recuperación `selfHeal` siempre activada) + **audit log de Kubernetes** + **Git**.
Un solo programa, `lab.py`, controla todo (solo necesitas Python; sin bash, sin Helm, sin Linux).
Los incidentes se ejecutan una vez y **las mismas evidencias** se analizan con distintos métodos.

## 1. Hipótesis y variables

**H1 (principal).** La correlación de metadatos procedentes de Git, Kubernetes Audit y Argo CD mejora la efectividad de la reconstrucción forense de incidentes, en comparación con el análisis de cada fuente por separado, en un entorno cloud-native experimental representativo de una MYPE.

**H0.** La efectividad de la reconstrucción con las tres fuentes correlacionadas no es mayor que la de la mejor fuente individual.

| | Definición | Niveles / indicadores |
|---|---|---|
| **VI. Método de análisis de metadatos** | cómo se analiza la misma evidencia | `git`, `audit`, `argocd` (por separado) vs `COMBINADO` (correlación de las tres con `correlate.py`) |
| **VD. Efectividad de la reconstrucción forense** | qué tan bien se reconstruye el incidente | 3 indicadores (abajo) |

Indicadores de la VD (todos se calculan por ensayo y método, en %):
1. **Campos correctos** = campos principales esperados que se recuperaron **y coinciden con la verdad de referencia** ÷ campos esperados del escenario (E0: 12, E1: 8, E2 y E3: 5). El denominador es el mismo para todos los métodos.
2. **Cobertura** = preguntas forenses con alguna evidencia candidata ÷ preguntas aplicables.
3. **Preguntas correctas** = preguntas forenses cuya respuesta coincide con la verdad de referencia ÷ preguntas aplicables.

**Auto-recuperación = parte del entorno, no una variable.** `selfHeal` está siempre activado; sirve para que existan metadatos de *antes, durante y después* de que Argo CD corrija un cambio. Si en un ensayo Argo CD no corrige, ese ensayo se **excluye** del análisis principal y se reporta aparte (verificación del entorno). El tiempo de corrección se reporta solo como dato descriptivo.

Define el criterio de "mejora" antes de ver los resultados (por ejemplo, diferencia pareada estadísticamente significativa y COMBINADO ≥ la mejor fuente individual en la mayoría de incidentes).

## 2. Diseño pareado
Cada incidente genera una única evidencia y se evalúa con los 4 métodos. La comparación es **pareada**: por cada incidente se compara COMBINADO contra la **mejor** fuente individual (la más favorable para las fuentes por separado). `resultados/comparacion_pareada.csv` trae esos pares para tu prueba estadística (Wilcoxon de rangos con signo o prueba del signo).

## 3. Escenarios y preguntas

| Escenario | Qué simula |
|---|---|
| E0 Cambio legítimo (control) | commit + push; Argo CD sincroniza. En el audit log solo aparece la cuenta de Argo CD; el responsable humano está en Git |
| E1 Cambio manual no autorizado | el "pasante" cambia la imagen con `kubectl`; Argo CD lo corrige (antes / durante / después) |
| E2 Amenaza interna | el "pasante" entra a un pod y lee un Secret |
| E3 Movimiento lateral | un pod comprometido usa su token y lee secretos de `kube-system` |

Q1 ¿quién y cuándo? · Q2 ¿qué recurso? · Q3 ¿imagen antes y después (y restaurada, en E1)? · Q4 ¿desde qué origen? · Q5 ¿actividad sospechosa y evidencia?

Q5 se responde con **reglas simples y explícitas** (no hay Falco): `cambio_manual`, `exec_en_pod`, `lectura_secreto`, `acceso_cruzado_ns` y `autocorreccion_drift` (Argo CD vuelve a aplicar la misma revisión).

## 4. Inventario de metadatos

**Principales (12):**

| Fuente | Campos | Cuándo se da por "correcto" |
|---|---|---|
| Git (4) — solo E0 | autor, fecha, commit, cambios | autor = el real; fecha cerca de la acción; hash = el commit real; archivo = `deployment.yaml` |
| Kubernetes audit (5) | usuario, hora, acción, recurso, respuesta | usuario = quien ejecutó; evento cerca de la acción real; verbo y código HTTP esperados; recurso = el tocado |
| Argo CD (3) — E0 y E1 | versión desplegada, sincronizaciones, estado | revisión = la esperada; hay sincronización en la ventana; estado capturado al final del ensayo = el observado |

**Complementarios:** `sourceIPs` y `userAgent` (Q4), imagen en `requestObject` (Q3), `impersonatedUser`.
**De contexto:** `requestURI`, namespace, `initiatedBy` de Argo CD.

Argo CD no conserva el historial de salud de la aplicación: por eso `lab.py` guarda una captura de su estado al terminar cada ensayo E0/E1 (`evidence/argocd/<run_id>.json`). Es una limitación real de la fuente y vale la pena mencionarla.

## 5. Instalación en Windows
1. **Docker Desktop** (backend WSL2) abierto y en ejecución.
2. En PowerShell: `winget install Kubernetes.minikube Kubernetes.kubectl Git.Git Python.Python.3.12` (reinicia la terminal).
3. `python lab.py prereqs`

Con 2 CPU y 4 GB para Minikube alcanza (ajustable en `config.json`).

## 6. Paso a paso

```powershell
# 0. Sube esta carpeta a TU repo público de GitHub
git config user.name "Tu Nombre"; git config user.email "tu@correo"
git init -b main; git add .; git commit -m "Laboratorio inicial"
git remote add origin https://github.com/TU_USUARIO/sentinel-mypes-lab.git
git push -u origin main
# 1. Edita config.json (repo_url) y ejecuta:
python lab.py prereqs
python lab.py minikube        # clúster con audit log
python lab.py argocd          # instala Argo CD
python lab.py app             # despliega tienda-web (espera Synced/Healthy)

# 2. Un ensayo suelto de prueba
python lab.py e1              # debe terminar en "resultado: exitoso"

# 3. Experimento: N vueltas de los 4 escenarios (usa N >= 10 para tener muestra; 10 vueltas ≈ 1 h)
python lab.py experimento 10 30

# 4. Evidencia y análisis
python lab.py recolectar
python lab.py analizar
```
Para empezar de cero: `python lab.py limpiar` y borra la carpeta `evidence`.

**Probar el análisis sin clúster:** `python analysis/demo_sintetico.py`. Es una **prueba de humo con datos inventados** (con un señuelo, un evento perdido, una captura de estado desfasada y un ensayo excluido a propósito). No es evidencia para la tesis.

## 7. Cómo se evita dar por bueno lo que no está probado
- **Verdad de referencia independiente:** cada ensayo anota lo que realmente hizo y observó (hora de la acción, identidad usada, recurso, imagen antes/después vista con `kubectl get`, hash del commit, revisión esperada, IP real del pod cuando aplica). No sale de los logs analizados.
- **Cobertura ≠ exactitud:** cubrir no es acertar. En `ensayos.csv`: `OK` exacta, `CUB` cubierta pero incorrecta, `NO` sin evidencia, `N/A` no aplica.
- **Entorno verificado:** en E1 se exige que el Deployment vuelva a una configuración **idéntica** a la previa (huella de réplicas y contenedores) y quede sano; si no, el ensayo se excluye. Si falla la infraestructura (p. ej. `git push`) el ensayo no se registra.
- **Mismos incidentes y registros para todos los métodos.**

## 8. Resultados (`resultados/`)
- `reporte.md`: resultado principal por método, comparación pareada, resultados por escenario, exactitud por pregunta (dónde aporta la correlación), verificación del entorno y el detalle del último ensayo de cada escenario (en E1, con la reconstrucción antes / durante / después).
- `ensayos.csv`, `comparacion_pareada.csv`, `metricas.json`, `lineas_tiempo/` (un CSV por ensayo con los eventos de las 3 fuentes ordenados).

## 9. Límites que debes declarar
- Los **campos correctos** son en buena parte aditivos (cada campo viene de una sola fuente), así que en ese indicador COMBINADO tiende a igualar la suma de las fuentes. El valor de la **correlación** se ve sobre todo en las preguntas que necesitan varias fuentes (Q1 y Q3 en E0, Q3 en E1). Analiza e interpreta los tres indicadores por separado.
- En E2 y E3 el audit log por sí solo responde casi todo; la correlación aporta sobre todo en E0 y E1. Es un resultado válido: repórtalo tal cual.
- Las reglas de detección de Q5 y los escenarios los diseñas tú: los escenarios están pensados para activarlas. No generalices a ataques reales.
- Un solo nodo de laboratorio; no se generaliza a producción.
- `--as` simula al usuario interno; en E3 el `exec` inicial simula la explotación de la app.
- En Q4, para acciones hechas con `kubectl` desde tu PC solo se verifica el cliente (`kubectl`) y que haya IP de origen (en Windows/Docker Desktop esa IP no se puede conocer de forma independiente); en E0 y E3 sí se verifica la IP exacta del pod.
- El audit log no guarda el contenido de los Secrets (nivel `Metadata`), solo quién los leyó.
- `lab.py` lo probé con un `kubectl` simulado y `correlate.py` con datos sintéticos, no contra un clúster real: puede que debas ajustar algún detalle la primera vez.

## 10. Problemas frecuentes
- **"Docker Desktop no está en ejecución":** ábrelo y espera a que diga "Running".
- **`audit.jsonl` con 0 eventos:** crea el clúster con `python lab.py minikube`; si existía, `python lab.py limpiar` y repite.
- **Argo CD no llega a Synced/Healthy:** repo público y `repo_url` correcto; `kubectl -n argocd get application tienda-web -o yaml`.
- **E0 falla en `git push`:** configura credenciales de GitHub (token o Git Credential Manager).
- **"PRECONDICIÓN NO CUMPLIDA":** el Deployment no estaba sano al empezar; espera o repáralo. Ese ensayo no se registra.
- **Muchos ensayos E1 excluidos:** sube `timeout_recuperacion_s` en `config.json` o revisa recursos de Docker Desktop.
