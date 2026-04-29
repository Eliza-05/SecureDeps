<div align="center">

<img src="https://img.shields.io/badge/SecureDeps-SCA%20Pipeline-6B4EFF?style=for-the-badge&logo=shield&logoColor=white" alt="SecureDeps"/>

# 🔒 SecureDeps

### Integración de SCA en Pipelines CI/CD para Gestión de Vulnerabilidades

*De la detección pasiva a la remediación activa — completamente automatizado.*

<br/>

[![SCA — Trivy](https://img.shields.io/badge/SCA-Trivy-00C8E0?style=flat-square&logo=aquasecurity&logoColor=white)](https://github.com/Eliza-05/SecureDeps/actions)
[![Secret Detection](https://img.shields.io/badge/Secrets-Gitleaks%20%2B%20TruffleHog-EF4444?style=flat-square&logo=git&logoColor=white)](https://github.com/Eliza-05/SecureDeps/actions)
[![SAST](https://img.shields.io/badge/SAST-Bandit%20%2B%20Semgrep-F59E0B?style=flat-square&logo=python&logoColor=white)](https://github.com/Eliza-05/SecureDeps/actions)
[![Auto Remediation](https://img.shields.io/badge/Auto-Remediation-6B4EFF?style=flat-square&logo=github-actions&logoColor=white)](https://github.com/Eliza-05/SecureDeps/actions)
[![Dashboard](https://img.shields.io/badge/Dashboard-GitHub%20Pages-9B4EFF?style=flat-square&logo=github&logoColor=white)](https://eliza-05.github.io/SecureDeps/dashboard/)
[![Tests](https://img.shields.io/badge/Tests-9%20passing-22C55E?style=flat-square&logo=pytest&logoColor=white)](https://github.com/Eliza-05/SecureDeps/actions)
[![Python](https://img.shields.io/badge/Python-3.11.9-3B6EFF?style=flat-square&logo=python&logoColor=white)](https://python.org)

<br/>

[🌐 Dashboard en vivo](https://eliza-05.github.io/SecureDeps/dashboard/) · [⚡ Ver Pipeline](https://github.com/Eliza-05/SecureDeps/actions) · [📋 PRs automáticos](https://github.com/Eliza-05/SecureDeps/pulls) · [🔐 Security tab](https://github.com/Eliza-05/SecureDeps/security)

</div>

---

## 📌 ¿Qué es SecureDeps?

**SecureDeps** es un sistema de análisis de composición de software (**SCA**) integrado directamente en el pipeline CI/CD. Detecta vulnerabilidades en dependencias de terceros, aplica controles OWASP Top 10 al código fuente, detecta secretos expuestos, ejecuta análisis estático (SAST) y genera correcciones automáticas validadas con tests — sin intervención humana inicial.

> 💡 **El problema que resuelve:** El 80–90% del software moderno está compuesto por dependencias de terceros. Las herramientas SCA tradicionales solo *alertan* sobre vulnerabilidades, dejando la corrección como un proceso manual, lento y propenso a errores. SecureDeps cierra ese ciclo automáticamente y mide la eficiencia del proceso mediante la métrica **MTTR** (Mean Time to Remediate).

---

## 📋 Tabla de Contenido

| Sección | Descripción |
|---------|-------------|
| [🎯 Objetivos](#-objetivos-del-proyecto) | Metas del proyecto y estado de cumplimiento |
| [🏗️ Arquitectura](#️-arquitectura-del-sistema) | Diagrama de flujo del pipeline completo |
| [⚙️ Stack Tecnológico](#️-stack-tecnológico) | Herramientas, versiones y acciones de GitHub usadas |
| [🔍 Análisis de Seguridad](#-análisis-de-seguridad) | SCA (Trivy) · Secret Detection · SAST (Bandit + Semgrep) |
| [🔒 Evolución OWASP](#-evolución-del-proyecto--antes-vs-después-owasp-top-10) | Código vulnerable → código corregido con tests de validación |
| [🛡️ Threat Model](#️-threat-model-del-pipeline) | Vectores de ataque del pipeline y controles implementados |
| [📊 Resultados y Métricas](#-resultados-y-métricas) | MTTR, CVEs remediados, dashboard en tiempo real |
| [🔄 Flujo Paso a Paso](#-flujo-paso-a-paso) | Descripción detallada de cada etapa del pipeline |
| [📁 Estructura del Repositorio](#-estructura-del-repositorio) | Árbol de archivos y propósito de cada componente |
| [🚀 ¿Cómo usar SecureDeps?](#-cómo-usar-securedeps-en-cualquier-repositorio) | Guía de integración en otros repositorios |
| [👥 Equipo](#-equipo) | Integrantes del proyecto |
| [📚 Referencias](#-referencias) | Fuentes y documentación de las herramientas |

---

## 🎯 Objetivos del Proyecto

| # | Objetivo | Estado |
|---|----------|:------:|
| 1 | Configurar una herramienta SCA para identificación temprana de dependencias vulnerables | ✅ |
| 2 | Evaluar la viabilidad de remediación automática mediante Pull Requests | ✅ |
| 3 | Desarrollar pipelines de CI que ejecuten pruebas automatizadas sobre las propuestas de remediación | ✅ |
| 4 | Extraer y analizar métricas de seguridad (**MTTR**) para medir la eficiencia del flujo | ✅ |

---

## 🏗️ Arquitectura del Sistema

### Diagrama de flujo

<!-- DIAGRAMA: exportar de draw.io y guardar como docs/pipeline-flow.png -->
> 📸 *Diagrama de arquitectura — exportar desde draw.io y reemplazar esta línea con la imagen*
>
> ![Arquitectura SecureDeps](docs/pipeline-flow.png)

```
┌─────────────────────────────────────────────────────────────────┐
│                        RAMA main                                │
│              (app con dependencias vulnerables)                 │
└──────────────────────────┬──────────────────────────────────────┘
                           │ push / trigger manual
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│         🔍 WF1: SCA Security Scan  [sca-scan.yml]              │
│                                                                 │
│  • Trivy escanea ./app — genera tabla, JSON, SARIF, SBOM       │
│  • SARIF → GitHub Security tab (Code Scanning)                 │
│  • SBOM CycloneDX → artefacto de Actions (30 días)             │
│  • pytest corre los 9 tests de la aplicación                   │
└──────────────────────────┬──────────────────────────────────────┘
                           │ on: workflow_run (completed)
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│       🤖 WF2: Auto Remediation  [auto-remediate.yml]           │
│                                                                 │
│  • remediate.py: detecta lenguaje, actualiza dependencias      │
│  • metrics.py: registra detected_at y CVE                      │
│  • open_pr.py: crea rama fix/securedeps-auto-remediation-{id}  │
│  • gh pr create → PR automático hacia rama develop             │
└──────────────────────────┬──────────────────────────────────────┘
                           │ on: pull_request (main | develop)
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│       ✅ WF3: Validate Remediation PR  [validate-pr.yml]       │
│                                                                 │
│  • Job 1: instala deps actualizadas → pytest → Trivy check     │
│  • metrics.py: registra pr_validated_at → calcula MTTR         │
│  • Job 2 (Security Gate): falla con exit-code 1 si hay         │
│    vulnerabilidades CRITICAL con fix disponible                │
└──────────────────────────┬──────────────────────────────────────┘
                           │ merge a develop
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│              📊 Dashboard  [GitHub Pages]                       │
│                                                                 │
│  • fetch(raw.githubusercontent.com/…/metrics.json)             │
│  • Muestra: CVEs detectados, MTTR promedio, estado de PRs      │
│  • URL: eliza-05.github.io/SecureDeps/dashboard/               │
└─────────────────────────────────────────────────────────────────┘
```

**En paralelo — en cada push a `main`:**

```
🔐 WF4: Secret Detection  [secret-detection.yml]
   ├── Gitleaks v2        → historial Git completo → SARIF a Security tab
   └── TruffleHog v3.88.1 → secretos activos (--only-verified)

🔬 WF5: SAST Security Scan  [sast-scan.yml]
   ├── Bandit             → análisis estático Python → SARIF a Security tab
   └── Semgrep            → p/python + p/security-audit + p/flask → SARIF
```

---

## ⚙️ Stack Tecnológico

| Componente | Tecnología | Versión | Propósito |
|------------|-----------|---------|-----------|
| **Scanner SCA** | [Trivy](https://trivy.dev/) | Latest (apt + GPG) | Detección de CVEs · JSON · SARIF · SBOM CycloneDX |
| **SAST** | [Bandit](https://bandit.readthedocs.io/) | Latest (pip) | Análisis estático de seguridad Python |
| **SAST** | [Semgrep](https://semgrep.dev/) | Latest (pip) | Análisis multi-regla (Python · Flask · Security Audit) |
| **Secret Detection** | [Gitleaks](https://gitleaks.io/) | `@v2` | Escaneo de secretos en historial Git completo |
| **Secret Detection** | [TruffleHog](https://trufflesecurity.com/) | `@v3.88.1` | Verificación de secretos activos en tiempo real |
| **CI/CD** | GitHub Actions | — | Orquestación del pipeline — 5 workflows |
| **Runtime Python** | Python | `3.11.9` | Ejecución de scripts y tests |
| **Framework demo** | Flask | `2.0.0` (intencional) | Aplicación con CVEs reales para demostración |
| **Remediación** | Python + GitHub CLI | — | Generación automática de PRs |
| **Métricas** | JSON + GitHub Pages | — | Registro y visualización de MTTR |
| **Dashboard** | HTML · CSS · JavaScript | — | SPA de monitoreo — consumo de métricas via fetch |
| **Tests** | pytest | `9.0.2` | 9 tests: funcionales + SSRF + YAML + headers |

### Versiones exactas de GitHub Actions usadas

| Action | Versión |
|--------|---------|
| `actions/checkout` | `@v4` |
| `actions/setup-python` | `@v5` |
| `actions/upload-artifact` | `@v4` |
| `actions/download-artifact` | `@v4` |
| `github/codeql-action/upload-sarif` | `@v4` |
| `gitleaks/gitleaks-action` | `@v2` |
| `trufflesecurity/trufflehog` | `@v3.88.1` |

---

## 🔍 Análisis de Seguridad

### 4.1 SCA — Software Composition Analysis

**Archivo:** [`.github/workflows/sca-scan.yml`](.github/workflows/sca-scan.yml)  
**Herramienta:** Trivy (instalado con verificación de firma GPG de Aqua Security)  
**Trigger:** push a `main` · PR a `main` · `workflow_dispatch`

**Reportes generados en cada run:**

| Formato | Archivo | Destino |
|---------|---------|---------|
| Tabla | stdout | Logs de Actions y Step Summary |
| JSON | `trivy-report.json` | Artefacto (30 días) — consumido por WF2 |
| SARIF | `trivy-results.sarif` | GitHub Security tab (Code Scanning) |
| **CycloneDX SBOM** | `sbom-cyclonedx.json` | Artefacto (30 días) |

**Dependencias vulnerables en el demo:**

| Paquete | Versión demo | CVE | Severidad | Descripción |
|---------|-------------|-----|-----------|-------------|
| `requests` | 2.25.0 | CVE-2023-32681 | MEDIUM | Leak de headers auth en redirecciones cross-origin |
| `flask` | 2.0.0 | CVE-2023-30861 | HIGH | Exposición de cookies de sesión con proxy mal configurado |
| `werkzeug` | 2.0.3 | CVE-2023-25577 | HIGH | DoS por multipart/form-data malformado |
| `cryptography` | 3.4.8 | CVE-2023-0286 | HIGH | Crash al procesar estructuras ASN.1 malformadas |

---

### 4.2 Secret Detection

**Archivo:** [`.github/workflows/secret-detection.yml`](.github/workflows/secret-detection.yml)  
**Trigger:** push a `main` · PR a `main` · `workflow_dispatch`

| Herramienta | Versión | Alcance | Output |
|-------------|---------|---------|--------|
| **Gitleaks** | `@v2` | Historial Git completo (`fetch-depth: 0`) — detecta secretos en commits históricos | SARIF → GitHub Security tab |
| **TruffleHog** | `@v3.88.1` | Solo secretos verificables como activos (`--only-verified`) · En push: HEAD~1..HEAD · En PR: base..head SHA | Reporte en logs · no SARIF |

---

### 4.3 SAST — Static Application Security Testing

**Archivo:** [`.github/workflows/sast-scan.yml`](.github/workflows/sast-scan.yml)  
**Trigger:** push a `main` · PR a `main` · `workflow_dispatch`

| Herramienta | Rulesets | Output |
|-------------|----------|--------|
| **Bandit** | Análisis estático Python — detecta: inyecciones, hash débil, subprocess inseguro, SSRF, unsafe deserialización | SARIF → GitHub Security tab · artefacto |
| **Semgrep** | `p/python` · `p/security-audit` · `p/flask` | SARIF → GitHub Security tab · artefacto |

> Ambas herramientas usan `--exit-zero` / `|| true` — reportan hallazgos sin bloquear el pipeline. Los resultados son visibles en la [pestaña Security](https://github.com/Eliza-05/SecureDeps/security) del repositorio.

---

## 🔒 Evolución del Proyecto — Antes vs Después (OWASP Top 10)

El código en [`app/main.py`](app/main.py) evolucionó de una versión intencionalmente vulnerable a una versión con controles aplicados. El código "antes" está documentado con fragmentos exactos en [`NETWORK_SECURITY_ANALYSIS.md`](NETWORK_SECURITY_ANALYSIS.md) sección 3.2.

| OWASP | Categoría | Antes (código vulnerable) | Después (código corregido) | Test de validación |
|-------|-----------|--------------------------|---------------------------|--------------------|
| **A10:2021** | SSRF — Server-Side Request Forgery | `requests.get(url)` sin validar destino — permite acceso a 169.254.x (metadata cloud), localhost, redes internas | `_is_safe_url()` bloquea 127.x · 10.x · 172.16-31.x · 192.168.x · 169.254.x · ::1 · esquemas no-HTTP/HTTPS | `test_fetch_blocks_ssrf_localhost` · `test_fetch_blocks_ssrf_metadata` · `test_fetch_blocks_private_range` · `test_fetch_blocks_non_http_scheme` |
| **A03:2021** | Injection — Deserialización insegura / RCE | `yaml.load(data)` — ejecuta código Python arbitrario vía `!!python/object/apply` | `yaml.safe_load(data)` + captura `YAMLError` → HTTP 400 con mensaje de error | `test_parse_yaml_safe_input` · `test_parse_yaml_rejects_dangerous_payload` |
| **A05:2021** | Security Misconfiguration — Debug mode | `app.run(debug=True)` — Werkzeug debugger interactivo expuesto (RCE inmediato si hay excepción) | `app.run(debug=False)` · excepciones retornan JSON de error sin stack trace | `test_index` (smoke test confirma que la app corre) |
| **A01:2021** | Security Headers / Broken Access Control | Sin headers de seguridad — permite clickjacking, MIME sniffing, XSS reflection | `@app.after_request`: `X-Content-Type-Options: nosniff` · `X-Frame-Options: DENY` · `X-XSS-Protection: 1; mode=block` · `Content-Security-Policy: default-src 'self'` | `test_security_headers_present` |

### Validación SSRF — redes bloqueadas

```python
# app/main.py — _BLOCKED_NETWORKS
ipaddress.ip_network('127.0.0.0/8'),    # loopback
ipaddress.ip_network('10.0.0.0/8'),     # privada clase A
ipaddress.ip_network('172.16.0.0/12'),  # privada clase B
ipaddress.ip_network('192.168.0.0/16'), # privada clase C
ipaddress.ip_network('169.254.0.0/16'), # link-local / AWS metadata
ipaddress.ip_network('::1/128'),        # IPv6 loopback
ipaddress.ip_network('fc00::/7'),       # IPv6 unique local
ipaddress.ip_network('fe80::/10'),      # IPv6 link-local
```

---

## 🛡️ Threat Model del Pipeline

Análisis completo de red y vectores de ataque en [`NETWORK_SECURITY_ANALYSIS.md`](NETWORK_SECURITY_ANALYSIS.md).

<!-- DIAGRAMA: threat model del pipeline — exportar de draw.io y guardar como docs/threat-model.png -->
> 📸 *Diagrama threat model — exportar desde draw.io*
>
> ![Threat Model](docs/threat-model.png)

| Vector de ataque | Control implementado | Estado |
|-----------------|---------------------|:------:|
| `GITHUB_TOKEN` con permisos amplios | Permisos declarados explícitamente por workflow (`permissions:` por job) | ✅ |
| Actions de terceros sin versión fija | Todas las actions usan tag fijo: `@v4`, `@v5`, `@v2`, `@v3.88.1` | ✅ |
| Instalación de Trivy sin verificación | GPG key de Aqua Security verificada con `gpg --dearmor` antes del install | ✅ |
| Inyección de comandos en scripts | [`open_pr.py`](scripts/open_pr.py) usa `subprocess.run(lista, shell=False)` | ✅ |
| Artefacto `trivy-report.json` manipulado | Si no descarga correctamente, WF2 genera un reporte fresco como fallback | ✅ |
| Merge sin validación de tests | Security Gate falla con `exit-code 1` ante CRITICAL + fix disponible | ✅ |
| Secretos hardcodeados en commits | Gitleaks (historial completo) + TruffleHog (activos) en cada push/PR | ✅ |
| Vulnerabilidades HIGH pasan el gate | Security Gate cubre solo CRITICAL — HIGH no bloquea el merge | ⚠️ Riesgo identificado |
| Métricas sin integridad verificable | `security-metrics.json` público sin checksum — modificación no detectable | ⚠️ Riesgo identificado |

---

## 📊 Resultados y Métricas

El dashboard en [eliza-05.github.io/SecureDeps/dashboard/](https://eliza-05.github.io/SecureDeps/dashboard/) lee [`metrics/security-metrics.json`](metrics/security-metrics.json) en tiempo real via `fetch()` con cache-busting (`?t=Date.now()`).

| Métrica | Valor |
|---------|-------|
| CVEs detectados por ciclo | **4** CVEs reales (requests · flask · werkzeug · cryptography) |
| Dependencias remediadas | **4** por ciclo (Python) |
| MTTR promedio medido | **~2–5 minutos** (detección → validación del PR) |
| Tests automatizados | ✅ **9 passing** |
| Security Gate | ✅ Sin CRITICAL con fix disponible |
| Lenguajes soportados | Python · Node.js · Java |
| Formatos de reporte | JSON · SARIF · CycloneDX SBOM |

### Estructura de un registro de métricas

```json
{
  "run_id": "12345678",
  "pr_branch": "fix/securedeps-auto-remediation-12345678",
  "package": "flask",
  "from_version": "flask==2.0.0",
  "to_version": "flask==2.3.2",
  "vuln_id": "CVE-2023-30861",
  "severity": "HIGH",
  "detected_at": "2026-03-31T01:26:23Z",
  "pr_created_at": "2026-03-31T01:27:01Z",
  "pr_validated_at": "2026-03-31T01:30:37Z",
  "mttr_minutes": 4.23,
  "status": "validated"
}
```

---

## 🔄 Flujo Paso a Paso

### Paso 1 — Detección SCA 🔍

Se activa en cada push a `main`. Trivy escanea `app/` con verificación GPG y genera cuatro artefactos:

```bash
trivy fs ./app --scanners vuln --format table                          # logs
trivy fs ./app --scanners vuln --format json    --output trivy-report.json
trivy fs ./app --scanners vuln --format sarif   --output trivy-results.sarif
trivy fs ./app --scanners vuln --format cyclonedx --output sbom-cyclonedx.json
```

### Paso 2 — Remediación Automática 🤖

`remediate.py` detecta el lenguaje del proyecto y actualiza el archivo de dependencias con las versiones seguras del reporte de Trivy:

```
requests==2.25.0    →  requests==2.31.0    (CVE-2023-32681 · MEDIUM)
flask==2.0.0        →  flask==2.3.2        (CVE-2023-30861 · HIGH)
werkzeug==2.0.3     →  werkzeug==2.3.3     (CVE-2023-25577 · HIGH + compatibilidad Flask)
cryptography==3.4.8 →  cryptography==39.0.1 (CVE-2023-0286 · HIGH)
```

`metrics.py` registra `detected_at`. `open_pr.py` crea la rama y abre el PR usando `subprocess.run(lista, shell=False)` — sin riesgo de inyección de comandos.

### Paso 3 — Validación del PR ✅

`validate-pr.yml` se dispara en PRs hacia `main` o `develop`:

- **Job 1 — Validate Dependencies:** instala deps actualizadas → `pytest tests/ -v` (9 tests) → Trivy re-escanea
- `metrics.py` registra `pr_validated_at` y calcula `MTTR = pr_validated_at - detected_at`
- **Job 2 — Security Gate:** `trivy --severity CRITICAL --ignore-unfixed --exit-code 1`

### Paso 4 — Secret Detection & SAST 🔐🔬

En paralelo con WF1, en cada push/PR:

- **Gitleaks:** historial completo (`fetch-depth: 0`) → SARIF a Security tab
- **TruffleHog:** solo secretos activos (`--only-verified`) · diferencia push/PR con SHAs
- **Bandit:** análisis estático Python en `app/` → SARIF a Security tab
- **Semgrep:** `p/python` + `p/security-audit` + `p/flask` → SARIF a Security tab

---

## 📁 Estructura del Repositorio

```
SecureDeps/
│
├── .github/
│   └── workflows/
│       ├── sca-scan.yml               # WF1: Trivy SCA + pytest + SBOM
│       ├── auto-remediate.yml         # WF2: Remediación automática de dependencias
│       ├── validate-pr.yml            # WF3: Validación + Security Gate
│       ├── secret-detection.yml       # WF4: Gitleaks + TruffleHog
│       └── sast-scan.yml              # WF5: Bandit + Semgrep
│
├── app/
│   ├── main.py                        # Flask app con controles OWASP aplicados
│   └── requirements.txt               # Dependencias con CVEs reales (demo)
│
├── scripts/
│   ├── remediate.py                   # Actualiza dependencias (Python/Node.js/Java)
│   ├── open_pr.py                     # Crea rama y PR automático (shell=False)
│   └── metrics.py                     # Registra CVEs y calcula MTTR
│
├── dashboard/
│   └── index.html                     # SPA — Dashboard en GitHub Pages
│
├── metrics/
│   └── security-metrics.json          # Base de datos de métricas MTTR
│
├── tests/
│   └── test_main.py                   # 9 tests: funcionales + SSRF + YAML + headers
│
├── docs/
│   ├── pipeline-flow.png              # [PENDIENTE — exportar de draw.io]
│   └── threat-model.png               # [PENDIENTE — exportar de draw.io]
│
├── NETWORK_SECURITY_ANALYSIS.md       # Análisis de red · threat model · riesgos
└── README.md
```

---

## 🚀 ¿Cómo usar SecureDeps en cualquier repositorio?

**1.** Copiar `.github/workflows/` y `scripts/` al repositorio objetivo

**2.** Hacer push a `main` — el pipeline se activa automáticamente

**3.** Verificar resultados en:
- [GitHub Actions](https://github.com/Eliza-05/SecureDeps/actions) → logs del pipeline
- [GitHub Security](https://github.com/Eliza-05/SecureDeps/security) → hallazgos de Trivy, Bandit, Semgrep, Gitleaks
- [Pull Requests](https://github.com/Eliza-05/SecureDeps/pulls) → PR automático con tabla CVE por CVE
- [Dashboard](https://eliza-05.github.io/SecureDeps/dashboard/) → métricas MTTR en tiempo real

### Lenguajes soportados

| Lenguaje | Archivo detectado | Remediación automática |
|----------|------------------|:--------------------:|
| Python | `requirements.txt` | ✅ |
| Node.js | `package.json` | ✅ |
| Java | `pom.xml` | ✅ |

---

## 👥 Equipo

| Integrante | Rol |
|------------|-----|
| Elizabeth Correa | Desarrollo del pipeline y scripts |
| María Paula Rodríguez | Desarrollo del pipeline y scripts |
| Juan Andrés Suárez | Desarrollo del pipeline y scripts |
| Sebastián Ortega | Desarrollo del pipeline y scripts |

*Escuela Colombiana de Ingeniería Julio Garavito — FDSI 2026*

---

## 📚 Referencias

- [Black Duck OSSRA Report 2024](https://www.nuaware.com/hubfs/Black%20Duck/rep-ossra-2024.pdf)
- [What is Software Composition Analysis? — Black Duck](https://www.blackduck.com/glossary/what-is-software-composition-analysis.html)
- [SCA in CI/CD — Sonatype](https://www.sonatype.com/resources/articles/what-is-software-composition-analysis)
- [Trivy Documentation](https://trivy.dev/latest/docs/)
- [GitHub Dependabot Security Updates](https://docs.github.com/en/code-security/how-tos/secure-your-supply-chain/managing-your-dependency-security)
- [OWASP Top 10 — 2021](https://owasp.org/Top10/)
- [Bandit — Python Security Linter](https://bandit.readthedocs.io/)
- [Semgrep Rules — Security Audit](https://semgrep.dev/p/security-audit)
- [Gitleaks — Secret Detection](https://gitleaks.io/)
- [TruffleHog — Verified Secret Scanner](https://trufflesecurity.com/trufflehog)
- [CycloneDX SBOM Standard](https://cyclonedx.org/)

---

<div align="center">

**SecureDeps** · Pipeline SCA automatizado · FDSI 2026

*Escuela Colombiana de Ingeniería Julio Garavito*

</div>
