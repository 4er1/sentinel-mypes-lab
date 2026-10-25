# Sentinel-MYPES v2

Laboratorio experimental para el título: **Evaluación de la resiliencia ante incidentes en una arquitectura cloud nativa en una MYPE mediante análisis de metadatos**.

No es un prototipo comercial ni se prueba contra la página o archivos reales de una empresa. Solo utiliza Minikube, el namespace `mypes-lab`, una aplicación nginx de demostración y datos sintéticos.

## Qué evalúa

La variable independiente es la fase del incidente: antes, durante y después de la eliminación o reconciliación. La variable dependiente es la utilidad forense de los metadatos, medida por disponibilidad de campos críticos y capacidad de responder cuatro preguntas: quién/cuándo, qué recurso, qué acción y si la evidencia sobrevivió.

Escenarios:

1. `E1_escalada_privilegios`: crea un `RoleBinding` que referencia `cluster-admin` **solo dentro de `mypes-lab`** y lo elimina. No crea `ClusterRoleBinding`.
2. `E2_persistencia_cronjob`: crea y elimina un CronJob suspendido; jamás se ejecuta ni realiza conexiones.
3. `E3_deriva_configuracion`: altera el ConfigMap gestionado por Git y comprueba que Argo CD restaura el valor aprobado.

## Preparación

1. Verifica dependencias: `python lab_v2.py check`.
2. En una máquina sin información empresarial, inicia un perfil Minikube nuevo: `python lab_v2.py bootstrap`. Si el perfil `sentinel-mypes` ya existe, el programa no lo cambia: elimínalo primero de forma explícita con `minikube delete -p sentinel-mypes`.
3. Aplica el namespace y la cuenta ficticia: `kubectl apply -f k8s/lab-v2.yaml`.
4. Ejecuta `python lab_v2.py deploy`. Si Argo CD aún no existe, el comando instala sus manifiestos oficiales, espera a sus componentes principales y registra la aplicación GitOps. Debe terminar con `mype-demo está Synced/Healthy`.
5. Confirma que `gitops/app-v2/` está publicado en el repositorio configurado.

La política de auditoría solo registra cuerpos de solicitudes para RoleBindings, CronJobs y ConfigMaps de laboratorio. Para Secrets registra únicamente metadatos, nunca valores.

## Ejecución

Si ya hiciste ensayos antes de que Argo CD y `mype-demo` estuvieran listos, consérvalos fuera de la serie formal con `python lab_v2.py archivar`. No los elimina: los mueve a `archivo_datos/`.

Ejecuta un escenario por vez:

```powershell
python lab_v2.py rolebinding
python lab_v2.py cronjob
python lab_v2.py drift
python lab_v2.py analizar
```

Para una serie formal de diez rondas (30 ensayos), usa `python lab_v2.py experimento 10`. El comando se detiene antes de iniciar si Argo CD o la aplicación no están listos.

La evidencia queda en `evidence-v2/runs/`; cada paquete incluye verdad de referencia, eventos de auditoría, snapshots de Argo CD y hashes SHA-256. El informe queda en `resultados-v2/reporte.md`.

## Límites

- No añadas archivos, tokens, credenciales ni datos de la empresa de tu papá.
- No ejecutes el laboratorio en un clúster remoto, productivo o compartido.
- Argo CD reconcilia recursos declarados y administrados desde Git; no se debe asumir que corregirá automáticamente recursos extra creados fuera de Git.
