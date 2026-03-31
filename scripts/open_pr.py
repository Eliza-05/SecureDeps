#!/usr/bin/env python3
"""
open_pr.py - Lee remediation-changes.json y abre un PR en GitHub
"""

import json
import os
import sys
import subprocess
from datetime import datetime


def run(cmd, check=True):
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check and result.returncode != 0:
        print(f"[ERROR] {cmd}\n{result.stderr}")
        sys.exit(1)
    return result.stdout.strip()


def create_pr_body(changes, timestamp):
    rows = []
    for c in changes:
        old_ver = c["old"].split("==")[-1] if "==" in c["old"] else "N/A"
        new_ver = c["new"].split("==")[-1] if "==" in c["new"] else "N/A"
        emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(c.get("severity", ""), "⚪")
        rows.append(f"| {c['package']} | {old_ver} | {new_ver} | {emoji} {c.get('severity','')} | {c.get('vuln_id','')} |")

    table = "\n".join(rows)
    return f"""## 🔒 SecureDeps — Remediación Automática

**Generado:** {timestamp}

### 📦 Dependencias actualizadas

| Paquete | Versión anterior | Versión segura | Severidad | CVE |
|---------|-----------------|----------------|-----------|-----|
{table}

### Próximos pasos
1. Verificar que los tests pasen en este PR
2. Revisar que la app funcione con las nuevas versiones
3. Aprobar y fusionar para cerrar las vulnerabilidades

---
*PR generado automáticamente por SecureDeps SCA Pipeline*"""


def main():
    changes_path  = os.environ.get("CHANGES_OUTPUT", "remediation-changes.json")
    github_token  = os.environ.get("GITHUB_TOKEN", "")
    repo          = os.environ.get("GITHUB_REPOSITORY", "")
    base_branch   = os.environ.get("BASE_BRANCH", "main")
    metrics_path  = os.environ.get("METRICS_PATH", "metrics/security-metrics.json")

    print("\n=== SecureDeps — Apertura de Pull Request ===\n")

    with open(changes_path) as f:
        data = json.load(f)

    changes = data.get("changes", [])
    if not changes:
        print("[INFO] No hay cambios. No se crea PR.")
        sys.exit(0)

    print(f"[INFO] Creando PR para {len(changes)} paquete(s)")

    run('git config user.email "securedeps-bot@github.com"')
    run('git config user.name "SecureDeps Bot"')

    timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    branch = f"fix/securedeps-auto-remediation-{timestamp}"

    print(f"[1/4] Creando rama: {branch}")
    run(f"git checkout -b {branch}")

    print("[2/4] Haciendo commit...")
    run("git add app/requirements.txt")

    # Incluir métricas en el commit si existen
    if os.path.exists(metrics_path):
        run(f"git add {metrics_path}")
        print(f"  [INFO] Métricas incluidas en el commit")

    pkg_list = ", ".join(c["package"] for c in changes)
    run(f'git commit -m "fix(deps): auto-remediation of {len(changes)} vulnerable dependencies ({pkg_list})"')

    print("[3/4] Push de la rama...")
    remote = f"https://x-access-token:{github_token}@github.com/{repo}.git"
    run(f"git remote set-url origin {remote}")
    run(f"git push origin {branch}")

    print("[4/4] Creando Pull Request...")
    pr_body = create_pr_body(changes, timestamp)

    with open("/tmp/pr_body.md", "w") as f:
        f.write(pr_body)

    title = f"🔒 [SecureDeps] Auto-remediation: {len(changes)} vulnerable dependencies fixed"
    pr_url = run(
        f'gh pr create '
        f'--title "{title}" '
        f'--body-file /tmp/pr_body.md '
        f'--base {base_branch} '
        f'--head {branch}'
    )

    branch_file = os.environ.get("GITHUB_OUTPUT", "")
    if branch_file:
        with open(branch_file, "a") as f:
            f.write(f"pr_branch={branch}\n")

    print(f"\n PR creado: {pr_url}\n")


if __name__ == "__main__":
    main()
