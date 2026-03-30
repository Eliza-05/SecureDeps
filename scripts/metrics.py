#!/usr/bin/env python3
"""
metrics.py - Registra métricas de seguridad y calcula MTTR
"""

import json
import os
import sys
from datetime import datetime, timezone


def load_existing_metrics(path):
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return {"records": []}


def save_metrics(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def register_detection(changes_path, metrics_path):
    """Registra el momento de detección y generación del PR."""
    with open(changes_path) as f:
        changes = json.load(f)

    if not changes.get("changes"):
        print("[INFO] No hay vulnerabilidades con fix. Nada que registrar.")
        return

    metrics = load_existing_metrics(metrics_path)
    now = datetime.now(timezone.utc).isoformat()
    run_id = os.environ.get("GITHUB_RUN_ID", "local")
    pr_branch = os.environ.get("PR_BRANCH", "unknown")

    for change in changes["changes"]:
        record = {
            "run_id": run_id,
            "pr_branch": pr_branch,
            "package": change["package"],
            "from_version": change["old"],
            "to_version": change["new"],
            "vuln_id": change["vuln_id"],
            "severity": change["severity"],
            "detected_at": changes.get("timestamp", now),
            "pr_created_at": now,
            "pr_validated_at": None,
            "status": "open"
        }
        metrics["records"].append(record)
        print(f"  [REGISTRADO] {change['package']} - {change['vuln_id']}")

    save_metrics(metrics_path, metrics)
    print(f"\n  Total registros acumulados: {len(metrics['records'])}")


def register_validation(pr_branch, metrics_path):
    """Marca el PR como validado y calcula MTTR."""
    metrics = load_existing_metrics(metrics_path)
    now = datetime.now(timezone.utc)

    updated = 0
    for record in metrics["records"]:
        if record.get("pr_branch") == pr_branch and record.get("status") == "open":
            record["pr_validated_at"] = now.isoformat()
            record["status"] = "validated"

            # Calcular MTTR en minutos
            detected = datetime.fromisoformat(record["detected_at"])
            delta = now - detected
            record["mttr_minutes"] = round(delta.total_seconds() / 60, 2)
            updated += 1
            print(f"  [VALIDADO] {record['package']} - MTTR: {record['mttr_minutes']} min")

    save_metrics(metrics_path, metrics)

    # Calcular MTTR promedio
    validated = [r for r in metrics["records"] if r.get("mttr_minutes") is not None]
    if validated:
        avg = round(sum(r["mttr_minutes"] for r in validated) / len(validated), 2)
        print(f"\n  MTTR promedio: {avg} minutos ({len(validated)} vulnerabilidades)")
    else:
        print("\n  Sin registros validados aún.")

    return updated


def print_summary(metrics_path):
    """Imprime resumen de todas las métricas."""
    metrics = load_existing_metrics(metrics_path)
    records = metrics.get("records", [])

    print(f"\n{'='*50}")
    print(f"  RESUMEN DE MÉTRICAS SecureDeps")
    print(f"{'='*50}")
    print(f"  Total vulnerabilidades registradas: {len(records)}")

    open_count = sum(1 for r in records if r.get("status") == "open")
    validated = [r for r in records if r.get("mttr_minutes") is not None]

    print(f"  PRs abiertos (pendientes): {open_count}")
    print(f"  PRs validados: {len(validated)}")

    if validated:
        avg = round(sum(r["mttr_minutes"] for r in validated) / len(validated), 2)
        min_mttr = min(r["mttr_minutes"] for r in validated)
        max_mttr = max(r["mttr_minutes"] for r in validated)
        print(f"  MTTR promedio: {avg} min")
        print(f"  MTTR mínimo:   {min_mttr} min")
        print(f"  MTTR máximo:   {max_mttr} min")

    print(f"{'='*50}\n")


def main():
    action = os.environ.get("METRICS_ACTION", "register")
    changes_path = os.environ.get("CHANGES_OUTPUT", "remediation-changes.json")
    metrics_path = os.environ.get("METRICS_PATH", "metrics/security-metrics.json")
    pr_branch = os.environ.get("PR_BRANCH", "unknown")

    print(f"\n=== SecureDeps — Métricas ({action}) ===\n")

    if action == "register":
        register_detection(changes_path, metrics_path)
    elif action == "validate":
        register_validation(pr_branch, metrics_path)
    elif action == "summary":
        print_summary(metrics_path)
    else:
        print(f"[ERROR] Acción desconocida: {action}")
        sys.exit(1)


if __name__ == "__main__":
    main()