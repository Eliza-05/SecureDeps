#!/usr/bin/env python3
"""
open_pr.py - Lee remediation-changes.json y abre un PR en GitHub
"""

import json
import os
import sys
import subprocess
from datetime import datetime, timezone


def run(cmd, check=True):
    """Run a command as a list of arguments (shell=False) to prevent injection."""
    result = subprocess.run(cmd, capture_output=True, text=True)
    if check and result.returncode != 0:
        print(f"[ERROR] {' '.join(cmd)}\n{result.stderr}")
        sys.exit(1)
    return result.stdout.strip()


def create_pr_body(changes, branch):
    rows = []
    for c in changes:
        old_ver = c["old"].split("==")[-1] if "==" in c["old"] else "N/A"
        new_ver = c["new"].split("==")[-1] if "==" in c["new"] else "N/A"
        emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(c.get("severity", ""), "⚪")
        rows.append(f"| {c['package']} | {old_ver} | {new_ver} | {emoji} {c.get('severity','')} | {c.get('vuln_id','')} |")

    table = "\n".join(rows)
    return f"""## 🔒 SecureDeps — Remediación Automática

**Rama:** {branch}

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
    changes_path = os.environ.get("CHANGES_OUTPUT", "remediation-changes.json")
    github_token = os.environ.get("GITHUB_TOKEN", "")
    repo         = os.environ.get("GITHUB_REPOSITORY", "")
    base_branch  = os.environ.get("BASE_BRANCH", "main")
    metrics_path = os.environ.get("METRICS_PATH", "metrics/security-metrics.json")
    run_id       = os.environ.get("GITHUB_RUN_ID", datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S"))

    with open(changes_path) as f:
        data = json.load(f)

    changes = data.get("changes", [])
    if not changes:
        print("[INFO] No hay cambios. No se crea PR.")
        sys.exit(0)

    print(f"[INFO] Creando PR para {len(changes)} paquete(s)")

    run(['git', 'config', 'user.email', 'securedeps-bot@github.com'])
    run(['git', 'config', 'user.name', 'SecureDeps Bot'])

    branch = f"fix/securedeps-auto-remediation-{run_id}"

    print(f"[1/3] Creando rama: {branch}")
    run(['git', 'checkout', '-b', branch])

    print("[2/3] Haciendo commit...")
    run(['git', 'add', 'app/'])

    if os.path.exists(metrics_path):
        run(['git', 'add', metrics_path])
        print("  [INFO] Métricas incluidas en el commit")

    pkg_list = ", ".join(c["package"] for c in changes)
    commit_msg = f"fix(deps): auto-remediation of {len(changes)} vulnerable dependencies ({pkg_list})"
    run(['git', 'commit', '-m', commit_msg])

    print("[3/3] Push y creación de PR...")
    remote = f"https://x-access-token:{github_token}@github.com/{repo}.git"
    run(['git', 'remote', 'set-url', 'origin', remote])
    run(['git', 'push', 'origin', branch])

    pr_body = create_pr_body(changes, branch)
    with open("/tmp/pr_body.md", "w") as f:
        f.write(pr_body)

    title = f"🔒 [SecureDeps] Auto-remediation: {len(changes)} vulnerable dependencies fixed"
    pr_url = run([
        'gh', 'pr', 'create',
        '--title', title,
        '--body-file', '/tmp/pr_body.md',
        '--base', base_branch,
        '--head', branch
    ])

    print(f"\n PR creado: {pr_url}\n")


if __name__ == "__main__":
    main()
