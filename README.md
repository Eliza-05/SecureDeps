<div align="center">

<img src="https://img.shields.io/badge/SecureDeps-SCA%20Pipeline-6B4EFF?style=for-the-badge&logo=shield&logoColor=white" alt="SecureDeps"/>

# 🔒 SecureDeps

### Integración de SCA en Pipelines CI/CD para Gestión de Vulnerabilidades

*De la detección pasiva a la remediación activa — completamente automatizado.*

<br/>

[![SCA Security Scan](https://img.shields.io/badge/SCA-Trivy-00C8E0?style=flat-square&logo=aquasecurity&logoColor=white)](https://github.com/Eliza-05/SecureDeps/actions)
[![Auto Remediation](https://img.shields.io/badge/Auto-Remediation-6B4EFF?style=flat-square&logo=github-actions&logoColor=white)](https://github.com/Eliza-05/SecureDeps/actions)
[![Dashboard](https://img.shields.io/badge/Dashboard-GitHub%20Pages-9B4EFF?style=flat-square&logo=github&logoColor=white)](https://eliza-05.github.io/SecureDeps/dashboard/)
[![Python](https://img.shields.io/badge/Python-3.11-3B6EFF?style=flat-square&logo=python&logoColor=white)](https://python.org)

<br/>

[🌐 Ver Dashboard en vivo](https://eliza-05.github.io/SecureDeps/dashboard/) · [⚡ Ver Pipeline](https://github.com/Eliza-05/SecureDeps/actions) · [📋 Ver PRs automáticos](https://github.com/Eliza-05/SecureDeps/pulls)

</div>

---

## 📌 ¿Qué es SecureDeps?

**SecureDeps** es un sistema de análisis de composición de software (**SCA**) integrado directamente en el pipeline CI/CD. Detecta vulnerabilidades en dependencias de software, genera correcciones automáticas y las valida antes de llegar a producción — sin intervención humana inicial.

> 💡 **El problema que resuelve:** El 80–90% del software moderno está compuesto por dependencias de terceros. Las herramientas SCA tradicionales solo *alertan* sobre vulnerabilidades, dejando la corrección como un proceso manual, lento y propenso a errores. SecureDeps cierra ese ciclo automáticamente.

---

## 🎯 Objetivos del Proyecto

| # | Objetivo |
|---|----------|
| 1 | Configurar una herramienta SCA para identificación temprana de dependencias vulnerables |
| 2 | Evaluar la viabilidad de remediación automática mediante Pull Requests |
| 3 | Desarrollar pipelines de CI que ejecuten pruebas automatizadas sobre las propuestas de remediación |
| 4 | Extraer y analizar métricas de seguridad (**MTTR**) para medir la eficiencia del flujo |

---

## 🏗️ Arquitectura del Sistema

```
┌─────────────────────────────────────────────────────────────────┐
│                        RAMA main                                │
│                  (dependencias vulnerables)                      │
└──────────────────────────┬──────────────────────────────────────┘
                           │ push / trigger manual
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│               🔍 SCA Security Scan (Trivy)                      │
│                                                                 │
│  • Escanea ./app en busca de CVEs conocidos                     │
│  • Genera reporte JSON + SARIF                                  │
│  • Publica resultados en GitHub Security tab                    │
│  • Corre tests de la aplicación con pytest                      │
└──────────────────────────┬──────────────────────────────────────┘
                           │ al completar exitosamente
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│              🤖 Auto Remediation (PR Generator)                 │
│                                                                 │
│  • Lee el reporte de Trivy                                      │
│  • Detecta el lenguaje (Python / Node.js / Java)                │
│  • Actualiza el archivo de dependencias con versiones seguras   │
│  • Registra métricas de detección (timestamp, CVE, severidad)   │
│  • Crea rama fix/securedeps-auto-remediation-{run_id}           │
│  • Abre Pull Request automático hacia develop                   │
└──────────────────────────┬──────────────────────────────────────┘
                           │ PR abierto
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│            ✅ Validate Remediation PR                           │
│                                                                 │
│  • Instala las dependencias actualizadas                        │
│  • Ejecuta tests con pytest                                     │
│  • Verifica que no queden vulnerabilidades CRITICAL             │
│  • Calcula el MTTR (tiempo detección → validación)              │
│  • Actualiza métricas en security-metrics.json                  │
└──────────────────────────┬──────────────────────────────────────┘
                           │ merge a develop
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│              📊 Dashboard (GitHub Pages)                        │
│                                                                 │
│  • Muestra vulnerabilidades detectadas y remediadas             │
│  • MTTR promedio en tiempo real                                 │
│  • Estado de cada PR (Pendiente / Validado)                     │
│  • Accesible en: eliza-05.github.io/SecureDeps/dashboard/       │
└─────────────────────────────────────────────────────────────────┘
```

---

## ⚙️ Stack Tecnológico

| Componente | Tecnología | Propósito |
|------------|-----------|-----------|
| **Scanner SCA** | [Trivy](https://trivy.dev/) | Detección de CVEs en dependencias |
| **CI/CD** | GitHub Actions | Orquestación del pipeline completo |
| **Lenguajes soportados** | Python · Node.js · Java | Análisis multi-lenguaje |
| **Remediación** | Python + GitHub API | Generación automática de PRs |
| **Métricas** | JSON + GitHub Pages | Registro y visualización de MTTR |
| **Dashboard** | HTML · CSS · JavaScript | Interfaz de monitoreo en tiempo real |
| **Tests** | pytest | Validación de dependencias actualizadas |

---

## 🔄 Flujo Paso a Paso

### Paso 1 — Detección 🔍

El pipeline se activa en cada push a `main`. Trivy escanea la carpeta `app/` y genera tres tipos de reporte:

- **Tabla** — visible en los logs de Actions
- **JSON** — usado por los scripts de remediación
- **SARIF** — integrado en la pestaña Security de GitHub

```bash
trivy fs ./app --scanners vuln --format json --output trivy-report.json
```

---

### Paso 2 — Remediación Automática 🤖

El script `remediate.py` lee el reporte JSON, detecta el lenguaje del proyecto y actualiza el archivo de dependencias con las versiones seguras disponibles:

```
requests==2.25.0  →  requests==2.31.0  (CVE-2023-32681 · MEDIUM)
flask==2.0.0      →  flask==2.3.2      (CVE-2023-30861 · HIGH)
werkzeug==2.0.3   →  werkzeug==2.2.3   (CVE-2023-25577 · HIGH)
cryptography==3.4.8 → cryptography==39.0.1 (CVE-2023-0286 · HIGH)
```

Luego `open_pr.py` crea una rama y abre el PR automáticamente con una tabla detallada de todos los cambios.

---

### Paso 3 — Validación Automática ✅

Cuando se valida el PR, el workflow `validate-pr.yml` ejecuta dos jobs en secuencia:

**Job 1 — Validate Updated Dependencies**
- Instala las dependencias con las versiones corregidas
- Ejecuta la suite de tests con pytest
- Verifica con Trivy que no queden vulnerabilidades CRITICAL

**Job 2 — Security Gate**
- Bloquea el merge si quedan vulnerabilidades CRITICAL con fix disponible
- Aprueba si todas las CRITICAL fueron resueltas

---

### Paso 4 — Métricas y Dashboard 📊

Cada vulnerabilidad detectada y remediada queda registrada en `metrics/security-metrics.json` con:

```json
{
  "package": "flask",
  "vuln_id": "CVE-2023-30861",
  "severity": "HIGH",
  "detected_at": "2026-03-31T01:26:23Z",
  "pr_validated_at": "2026-03-31T01:30:37Z",
  "mttr_minutes": 4.23,
  "status": "validated"
}
```

El dashboard en GitHub Pages lee este archivo en tiempo real y muestra:

- Total de vulnerabilidades detectadas
- PRs pendientes y validados
- **MTTR promedio** — la métrica clave de eficiencia
- Historial completo con barras visuales de MTTR por paquete

---

## 📁 Estructura del Repositorio

```
SecureDeps/
│
├── .github/
│   └── workflows/
│       ├── sca-scan.yml           # Escaneo SCA con Trivy
│       ├── auto-remediate.yml     # Generación automática de PRs
│       └── validate-pr.yml        # Validación y Security Gate
│
├── app/
│   ├── main.py                    # Aplicación Flask de ejemplo
│   └── requirements.txt           # Dependencias vulnerables (demo)
│
├── scripts/
│   ├── remediate.py               # Detección y actualización de dependencias
│   ├── open_pr.py                 # Creación automática de Pull Requests
│   └── metrics.py                 # Registro y cálculo de MTTR
│
├── dashboard/
│   └── index.html                 # Dashboard de métricas (GitHub Pages)
│
├── metrics/
│   └── security-metrics.json      # Base de datos de métricas
│
└── tests/
    └── test_main.py               # Tests de la aplicación
```

---

## 🚀 ¿Cómo usar SecureDeps en cualquier repositorio?

SecureDeps funciona como una herramienta que se instala en cualquier repositorio. Solo se necesitan tres pasos:

**1.** Copiar los archivos de workflows y scripts al repositorio objetivo

**2.** Hacer push — el pipeline se activa automáticamente

**3.** Ver los resultados en la pestaña Security y en el dashboard

### Lenguajes soportados

| Lenguaje | Archivo detectado | Remediación automática |
|----------|------------------|----------------------|
| Python | `requirements.txt` | ✅ |
| Node.js | `package.json` | ✅ |
| Java | `pom.xml` | ✅ |

---

## 📈 Resultados del Demo

| Métrica | Valor |
|---------|-------|
| Vulnerabilidades detectadas | **25+** CVEs reales |
| Dependencias remediadas | **5** por ciclo |
| MTTR promedio | **~2.5 minutos** |
| Tests automatizados | ✅ Pasando |
| Security Gate | ✅ Sin CRITICAL pendientes |

---

## 👥 Equipo

| Integrante | Rol |
|------------|-----|
| Elizabeth Correa | Desarrollo del pipeline y scripts |
| María Paula Rodríguez | Desarrollo del pipeline y scripts |
| Juan Andrés Suárez | Desarrollo del pipeline y scripts |
| Sebastián Ortega | Desarrollo del pipeline y scripts |

---

## 📚 Referencias

- [Black Duck OSSRA Report 2024](https://www.nuaware.com/hubfs/Black%20Duck/rep-ossra-2024.pdf)
- [What is Software Composition Analysis? — Black Duck](https://www.blackduck.com/glossary/what-is-software-composition-analysis.html)
- [SCA in CI/CD — Sonatype](https://www.sonatype.com/resources/articles/what-is-software-composition-analysis)
- [Trivy Documentation](https://trivy.dev/latest/docs/)
- [GitHub Dependabot Security Updates](https://docs.github.com/en/code-security/how-tos/secure-your-supply-chain/managing-your-dependency-security)

---

<div align="center">

**SecureDeps** · Pipeline SCA automatizado · 2026

*Escuela Colombiana de Ingeniería Julio Garavito*

</div>