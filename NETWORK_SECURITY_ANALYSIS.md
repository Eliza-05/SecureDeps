# SecureDeps — Análisis de Seguridad de Red y Arquitectura

**Proyecto:** Software Composition Analysis (SCA) Pipeline  
**Institución:** Escuela Colombiana de Ingeniería Julio Garavito  
**Repositorio:** https://github.com/Eliza-05/SecureDeps  
**Dashboard:** https://eliza-05.github.io/SecureDeps/dashboard/

---

## Tabla de contenido

1. [Tipo de red](#1-tipo-de-red)
2. [Puertos abiertos](#2-puertos-abiertos)
3. [Análisis de vulnerabilidades y riesgos](#3-análisis-de-vulnerabilidades-y-riesgos)
4. [Controles de seguridad](#4-controles-de-seguridad)
5. [Dónde está desplegado](#5-dónde-está-desplegado)
6. [Cómo se conectan los componentes](#6-cómo-se-conectan-los-componentes)
7. [Componentes del sistema](#7-componentes-del-sistema)

---

## 1. Tipo de red

SecureDeps no opera sobre una red privada propia (no hay VPC, subredes, Docker Compose ni servidores propios). Su infraestructura de red es **completamente gestionada por GitHub** y se compone de tres capas:

### 1.1 Red de GitHub Actions (runners efímeros)

Cada workflow se ejecuta en un runner `ubuntu-latest` hosteado por GitHub. Estos runners:

- Se asignan de forma dinámica y efímera; no tienen IP fija ni identidad de red persistente.
- Tienen acceso saliente irrestricto a internet (HTTPS/443) pero **no exponen puertos entrantes** al exterior.
- Se destruyen al finalizar cada job, eliminando cualquier estado de red residual.
- Se comunican con GitHub API, PyPI, el repositorio de Trivy y las bases de datos de CVE exclusivamente por HTTPS.

### 1.2 Red de GitHub Pages (CDN estático)

El dashboard (`dashboard/index.html`) se sirve desde la infraestructura CDN de GitHub Pages:

- Protocolo: **HTTPS forzado** (HTTP redirige automáticamente a HTTPS).
- Sin servidor de aplicación detrás; es contenido estático puro.
- El dashboard consume datos desde `raw.githubusercontent.com` (fetch del lado del cliente en el navegador del usuario).

### 1.3 Red pública de internet (solo tráfico saliente desde el browser)

Cuando un usuario abre el dashboard, su navegador realiza:

- `GET https://raw.githubusercontent.com/Eliza-05/SecureDeps/develop/metrics/security-metrics.json` — para cargar métricas.
- `GET https://fonts.googleapis.com` — para cargar fuentes Montserrat y DM Sans.

No existe ningún backend propio expuesto a internet. La Flask app (`app/main.py`) **no está desplegada**; únicamente se instancia dentro de los runners de CI durante las pruebas con `pytest`.

---

## 2. Puertos abiertos

### En el entorno de producción / GitHub Pages

| Puerto | Protocolo | Servicio | Estado |
|--------|-----------|----------|--------|
| 443    | HTTPS/TLS | GitHub Pages (dashboard) | Abierto — gestionado por GitHub |
| 80     | HTTP      | GitHub Pages             | Abierto — redirige a 443 |

No hay puertos adicionales. La infraestructura no gestiona ningún servidor TCP/UDP propio.

### En los runners de GitHub Actions (durante ejecución del pipeline)

| Puerto | Protocolo | Uso | Dirección |
|--------|-----------|-----|-----------|
| 443    | HTTPS     | GitHub API, PyPI, Trivy repo, OSV/NVD (CVE DBs) | Solo saliente |

Los runners no abren puertos entrantes. No existe superficie de ataque de red en el pipeline.

### En desarrollo local (única instancia donde la Flask app corre)

| Puerto | Protocolo | Servicio | Alcance |
|--------|-----------|----------|---------|
| 5000   | HTTP      | Flask (`app.run(debug=True)`) | Localhost únicamente (no expuesto a internet) |

> **Nota importante:** `app/main.py` usa `debug=True` por defecto, lo que habilita el Werkzeug interactive debugger. Este modo **nunca debe exponerse** fuera de localhost.

---

## 3. Análisis de vulnerabilidades y riesgos

### 3.1 Vulnerabilidades en la aplicación de demostración (intencionadas)

La `app/` contiene dependencias deliberadamente vulnerables para demostrar la capacidad del pipeline SCA. Estas son las CVEs que Trivy detecta en cada escaneo:

| Paquete | Versión vulnerable | CVE | Severidad | Descripción técnica |
|---------|--------------------|-----|-----------|---------------------|
| `flask` | 2.0.0 | CVE-2023-30861 | HIGH | Exposición de cookies de sesión cuando hay un proxy inverso mal configurado que no limpia el header `X-Forwarded-For` |
| `werkzeug` | 2.0.3 | CVE-2023-25577 | HIGH | Denegación de servicio (DoS) por consumo excesivo de memoria al parsear datos multipart/form-data malformados |
| `requests` | 2.25.0 | CVE-2023-32681 | MEDIUM | Leak de headers de autenticación (`Authorization`, `Proxy-Authorization`) a dominios de terceros durante redirecciones HTTP cross-origin |
| `cryptography` | 3.4.8 | CVE-2023-0286 | HIGH | Crash de la biblioteca al procesar estructuras ASN.1 malformadas vía `X.509 GeneralName` (tipo `OtherName`) |

### 3.2 Vulnerabilidades de código en la aplicación de demostración

Además de las CVEs de dependencias, el código de `app/main.py` contiene vulnerabilidades de diseño que son intencionalmente parte del escenario de demostración:

**Riesgo 1 — SSRF (Server-Side Request Forgery) en `/fetch`**

```python
# app/main.py:16-19
@app.route('/fetch')
def fetch_url():
    url = request.args.get('url', 'https://httpbin.org/get')
    response = requests.get(url)   # sin validación de destino
    return jsonify(response.json())
```

Un atacante puede pasar como parámetro `url` cualquier dirección, incluyendo:
- `http://169.254.169.254/latest/meta-data/` (metadata de instancias cloud)
- `http://localhost:5000/` (servicios internos)
- URLs de servidores internos no expuestos públicamente

Impacto: acceso no autorizado a recursos internos, exfiltración de metadatos de infraestructura.

**Riesgo 2 — Deserialización insegura / RCE en `/parse-yaml`**

```python
# app/main.py:22-25
@app.route('/parse-yaml')
def parse_yaml():
    data = request.args.get('data', 'key: value')
    parsed = yaml.load(data)   # Loader no especificado → usa FullLoader o UnsafeLoader
    return jsonify(parsed)
```

`yaml.load()` sin `Loader=yaml.SafeLoader` puede ejecutar código Python arbitrario al deserializar payloads YAML que usen constructores como `!!python/object/apply`. Impacto: RCE (Remote Code Execution) completo en el servidor.

**Riesgo 3 — Flask debug mode activo**

```python
# app/main.py:28
app.run(debug=True)
```

Con `debug=True`, Werkzeug habilita un debugger interactivo que permite ejecutar código Python desde el navegador si se produce una excepción. En un entorno expuesto, esto equivale a una consola de administración sin autenticación. Impacto: RCE inmediato.

### 3.3 Riesgos en el pipeline CI/CD

**Riesgo 4 — Permisos amplios del GITHUB_TOKEN**

El workflow `auto-remediate.yml` declara:

```yaml
permissions:
  contents: write
  pull-requests: write
```

Y `validate-pr.yml` también tiene `contents: write`. Si un atacante inyectara código malicioso en el pipeline (p. ej., via dependencia comprometida o workflow modificado), podría usar el token para modificar el repositorio o crear PRs fraudulentos.

**Riesgo 5 — Token expuesto en la URL del remote de git**

En `scripts/open_pr.py:87`:

```python
remote = f"https://x-access-token:{github_token}@github.com/{repo}.git"
run(f"git remote set-url origin {remote}")
```

Si los logs del runner no ocultan correctamente el token (GitHub Actions enmascara secrets registrados, pero esta interpolación podría aparecer en trazas de error), el token quedaría expuesto. El riesgo es mitigado parcialmente por el scope automático de los tokens efímeros de Actions.

**Riesgo 6 — Security Gate solo cubre severidad CRITICAL**

```yaml
# validate-pr.yml:113-117
trivy fs ./app \
  --scanners vuln \
  --severity CRITICAL \
  --ignore-unfixed \
  --exit-code 1
```

Vulnerabilidades de severidad HIGH (como CVE-2023-30861 en Flask y CVE-2023-0286 en cryptography) pasan el gate sin bloquear el merge. Esto es una limitación documentada del sistema actual.

**Riesgo 7 — Ausencia de Content Security Policy en el dashboard**

`dashboard/index.html` no define headers CSP. El dashboard carga recursos externos (Google Fonts) y ejecuta JavaScript que realiza fetch a `raw.githubusercontent.com`. Sin CSP, un eventual XSS podría exfiltrar datos o inyectar scripts.

**Riesgo 8 — Datos de métricas públicos y sin integridad verificable**

`security-metrics.json` se almacena en la rama `develop` del repositorio público y se consume directamente desde `raw.githubusercontent.com` sin firma ni checksum. Si el archivo fuera modificado externamente, el dashboard lo mostraría sin advertencia.

---

## 4. Controles de seguridad

### 4.1 Controles ya implementados

| Control | Dónde está | Descripción |
|---------|------------|-------------|
| Principio de mínimo privilegio en workflows | `.github/workflows/*.yml` | Cada workflow declara explícitamente solo los permisos que necesita (`permissions` a nivel de job) |
| Verificación de firma GPG al instalar Trivy | `sca-scan.yml:29-35` | La clave pública de Aqua Security se importa con `gpg --dearmor` y se registra en el keyring de apt antes de instalar; previene ataques de sustitución del binario |
| Security Gate que bloquea merge | `validate-pr.yml:110-118` | El job `security-gate` falla con `exit-code 1` si Trivy detecta CVEs CRITICAL con fix disponible, bloqueando el merge del PR |
| SARIF upload a GitHub Security tab | `sca-scan.yml:61-64` | Las vulnerabilidades se reportan a la pestaña Security del repositorio para visibilidad del equipo |
| Secrets gestionados por GitHub Actions | `auto-remediate.yml:95` | `GITHUB_TOKEN` se inyecta como variable de entorno desde el contexto de secrets; nunca está hardcodeado en el código |
| Tests automatizados antes de validar | `validate-pr.yml:44-45` | `pytest` corre sobre las dependencias actualizadas antes de que el Security Gate apruebe el PR |
| Tokens de acceso efímeros | GitHub Actions runtime | `GITHUB_TOKEN` expira al finalizar el workflow; no es un PAT de larga duración |
| Rama `main` aislada | Estrategia de ramas | Las dependencias vulnerables solo existen en `main` (demo); `develop` recibe solo PRs ya validados por el pipeline |

### 4.2 Controles recomendados a implementar

**Control 1 — Validar y restringir URLs en el endpoint `/fetch` (mitigación de SSRF)**

```python
# Implementar una allowlist de dominios permitidos
ALLOWED_HOSTS = {"httpbin.org", "api.github.com"}

@app.route('/fetch')
def fetch_url():
    url = request.args.get('url', '')
    parsed = urlparse(url)
    if parsed.hostname not in ALLOWED_HOSTS:
        return jsonify({"error": "URL no permitida"}), 403
    response = requests.get(url, timeout=5)
    return jsonify(response.json())
```

**Control 2 — Usar `yaml.safe_load()` en lugar de `yaml.load()` (mitigación de RCE)**

```python
# app/main.py — cambio de una línea
parsed = yaml.safe_load(data)   # en lugar de yaml.load(data)
```

`yaml.safe_load()` solo deserializa tipos YAML estándar y rechaza constructores Python que permiten ejecución de código.

**Control 3 — Deshabilitar debug mode en Flask**

```python
# app/main.py
if __name__ == '__main__':
    app.run(debug=False, host='127.0.0.1')   # nunca 0.0.0.0 en producción
```

**Control 4 — Elevar el Security Gate a severidad HIGH**

```yaml
# validate-pr.yml — ampliar la cobertura del gate
trivy fs ./app \
  --scanners vuln \
  --severity CRITICAL,HIGH \
  --ignore-unfixed \
  --exit-code 1
```

**Control 5 — Agregar Content Security Policy al dashboard**

```html
<!-- dashboard/index.html — dentro de <head> -->
<meta http-equiv="Content-Security-Policy"
      content="default-src 'self';
               script-src 'self' 'unsafe-inline';
               style-src 'self' 'unsafe-inline' https://fonts.googleapis.com;
               font-src https://fonts.gstatic.com;
               connect-src https://raw.githubusercontent.com;
               img-src 'self' data:;">
```

**Control 6 — Usar `GITHUB_TOKEN` con el scope mínimo necesario por job**

```yaml
# En lugar de permissions a nivel de workflow, definir por job:
jobs:
  auto-remediate:
    permissions:
      contents: write      # solo para el job que hace push
      pull-requests: write # solo para el job que crea PR

  register-metrics:
    permissions:
      contents: read       # este job solo lee
```

**Control 7 — Verificar integridad del archivo de métricas con checksum**

Al generar `security-metrics.json`, calcular y publicar un `security-metrics.json.sha256` firmado. El dashboard puede verificar el hash antes de renderizar los datos.

**Control 8 — Agregar timeout y validación de respuesta en el script de remediación**

En `scripts/remediate.py`, las llamadas a `json.load()` sobre el reporte de Trivy no validan el esquema del JSON. Si el artefacto está corrupto o fue manipulado, el script puede fallar silenciosamente. Implementar validación del esquema con `jsonschema`.

---

## 5. Dónde está desplegado

| Componente | Plataforma | URL / Acceso |
|------------|------------|--------------|
| Dashboard de métricas | GitHub Pages | https://eliza-05.github.io/SecureDeps/dashboard/ |
| Pipeline CI/CD (3 workflows) | GitHub Actions (runners ubuntu-latest hosteados por GitHub) | https://github.com/Eliza-05/SecureDeps/actions |
| Código fuente | GitHub (repositorio público) | https://github.com/Eliza-05/SecureDeps |
| Métricas (security-metrics.json) | Rama `develop` del repositorio GitHub | Accesible públicamente vía raw.githubusercontent.com |
| Reportes de seguridad (SARIF) | GitHub Security tab | https://github.com/Eliza-05/SecureDeps/security |
| Flask demo app (`main.py`) | **No desplegada** — solo corre en runners de CI durante `pytest` | N/A |

La arquitectura es **serverless desde la perspectiva de infraestructura propia**: no existe ningún servidor, VM, contenedor ni instancia cloud gestionada por el equipo del proyecto. Todo el cómputo ocurre en runners efímeros de GitHub.

---

## 6. Cómo se conectan los componentes

```
[Push a main / workflow_dispatch]
         │
         ▼ HTTPS/443
┌─────────────────────────────────────────────────────────┐
│  WORKFLOW 1 — SCA Security Scan (runner ubuntu-latest)  │
│                                                         │
│  1. Descarga Trivy desde aquasecurity.github.io (443)   │
│  2. Trivy consulta OSV/NVD/GitHub Advisory DB (443)     │
│  3. Genera trivy-report.json y trivy-results.sarif      │
│  4. Sube SARIF a GitHub Security tab via API (443)      │
│  5. Sube artefacto (trivy-report.json) a Actions (443)  │
│  6. Corre pytest sobre las dependencias vulnerables     │
└──────────────────────────┬──────────────────────────────┘
                           │ workflow_run (on: completed)
                           ▼ HTTPS/443
┌─────────────────────────────────────────────────────────┐
│  WORKFLOW 2 — Auto Remediation (runner ubuntu-latest)   │
│                                                         │
│  1. Descarga artefacto trivy-report.json (443)          │
│  2. Ejecuta remediate.py → modifica requirements.txt    │
│  3. Ejecuta metrics.py → registra detected_at           │
│  4. Ejecuta open_pr.py:                                 │
│     a. git push rama fix/* a GitHub (443)               │
│     b. gh pr create via GitHub API (443)                │
└──────────────────────────┬──────────────────────────────┘
                           │ on: pull_request
                           ▼ HTTPS/443
┌─────────────────────────────────────────────────────────┐
│  WORKFLOW 3 — Validate Remediation PR (runner)          │
│                                                         │
│  1. Instala dependencias actualizadas (PyPI, 443)       │
│  2. Corre pytest con dependencias nuevas                │
│  3. Re-escanea con Trivy (443)                          │
│  4. metrics.py → registra pr_validated_at y MTTR        │
│  5. git push métricas a rama fix/* (443)                │
│  Security Gate → exit 1 si hay CRITICAL con fix         │
└──────────────────────────┬──────────────────────────────┘
                           │ Merge manual a develop
                           ▼
┌─────────────────────────────────────────────────────────┐
│  GitHub Pages — Dashboard estático                      │
│                                                         │
│  Browser → fetch(raw.githubusercontent.com/...          │
│            /develop/metrics/security-metrics.json)      │
│  → Renderiza KPIs y tabla de vulnerabilidades           │
└─────────────────────────────────────────────────────────┘
```

Todas las comunicaciones entre componentes usan **HTTPS (puerto 443)**. No existe tráfico HTTP en texto plano en el flujo de producción del pipeline.

---

## 7. Componentes del sistema

### 7.1 Mapa de componentes

```
SecureDeps
├── Scanner
│   └── Trivy 0.49+              (binario, descargado en runtime en cada runner)
│                                 Fuente de datos: OSV, NVD, GitHub Advisory Database
│
├── Orquestación CI/CD
│   ├── sca-scan.yml             (Workflow 1 — disparo: push a main)
│   ├── auto-remediate.yml       (Workflow 2 — disparo: WF1 completado)
│   └── validate-pr.yml          (Workflow 3 — disparo: PR abierto por WF2)
│
├── Scripts Python
│   ├── remediate.py             (Actualiza requirements.txt / package.json / pom.xml)
│   ├── open_pr.py               (Crea rama y PR vía GitHub API + gh CLI)
│   └── metrics.py               (Registra detected_at, pr_validated_at, calcula MTTR)
│
├── Aplicación de demostración
│   ├── app/main.py              (Flask app con vulnerabilidades intencionadas)
│   └── app/requirements.txt     (Dependencias con CVEs conocidos)
│
├── Tests
│   └── tests/test_main.py       (pytest — valida endpoints de la Flask app)
│
├── Datos / Persistencia
│   └── metrics/security-metrics.json   (JSON en rama develop — fuente de verdad del dashboard)
│
└── Frontend
    └── dashboard/index.html     (SPA estático — GitHub Pages — consume metrics JSON via fetch)
```

### 7.2 Interfaces externas

| Interfaz | Protocolo | Autenticación | Dirección |
|----------|-----------|---------------|-----------|
| GitHub API (crear PR, subir SARIF) | HTTPS REST | `GITHUB_TOKEN` (Bearer) | Saliente desde runners |
| PyPI (instalar dependencias) | HTTPS | Sin auth | Saliente desde runners |
| Aqua Security Trivy repo (apt) | HTTPS + GPG signature | GPG key verificada | Saliente desde runners |
| OSV / NVD / GitHub Advisory DB | HTTPS | Sin auth | Saliente desde Trivy |
| `raw.githubusercontent.com` (métricas) | HTTPS | Sin auth (repo público) | Saliente desde browser |
| Google Fonts API | HTTPS | Sin auth | Saliente desde browser |

### 7.3 Flujo de datos sensibles

```
GITHUB_TOKEN (secret de Actions)
    │
    ├──→ auto-remediate.yml → inyectado como $GITHUB_TOKEN en entorno del runner
    │         └──→ open_pr.py → usado para autenticar gh CLI y git remote
    │
    └──→ validate-pr.yml → usado para git push de métricas

trivy-report.json (reporte de CVEs)
    │
    ├──→ Artefacto de Actions (retención 30 días, acceso con GITHUB_TOKEN)
    └──→ remediate.py lo deserializa para extraer fix_version por paquete

security-metrics.json (MTTR, CVEs, timestamps)
    │
    └──→ Rama develop (público) → raw.githubusercontent.com → dashboard
```

---

## Resumen ejecutivo

SecureDeps opera completamente sobre infraestructura gestionada por GitHub, sin servidores propios. La única superficie expuesta a internet es el dashboard estático en GitHub Pages (HTTPS/443). El pipeline CI/CD corre en runners efímeros sin puertos entrantes. Los principales riesgos son tres: (1) vulnerabilidades de código intencionadas en la app de demostración (SSRF, RCE vía YAML inseguro, Flask debug), que ilustran los patrones que el pipeline detecta y remedia; (2) el Security Gate que en su versión actual solo bloquea severidad CRITICAL, dejando pasar algunas HIGH; y (3) la ausencia de CSP en el dashboard. Los controles ya implementados (firma GPG de Trivy, permisos declarativos en workflows, tokens efímeros, Security Gate, SARIF a GitHub Security) cubren adecuadamente los riesgos del pipeline automatizado.
