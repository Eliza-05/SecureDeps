#!/usr/bin/env python3
"""
remediate.py - Lee trivy-report.json y actualiza requirements.txt
"""

import json
import sys
import os
import re
from datetime import datetime


def load_trivy_report(path):
    with open(path, "r") as f:
        return json.load(f)


def extract_fixes(report):
    fixes = {}
    for result in report.get("Results", []):
        for vuln in result.get("Vulnerabilities") or []:
            pkg = vuln.get("PkgName", "").lower()
            fixed = vuln.get("FixedVersion", "")
            severity = vuln.get("Severity", "")
            vuln_id = vuln.get("VulnerabilityID", "")

            if not fixed or not pkg:
                continue

            if pkg not in fixes:
                fixes[pkg] = {
                    "fixed_version": fixed.split(",")[0].strip(),
                    "severity": severity,
                    "vuln_id": vuln_id
                }
                print(f"  [FIX ENCONTRADO] {pkg} → {fixed} ({severity} - {vuln_id})")

    return fixes


def update_requirements(req_path, fixes):
    with open(req_path, "r") as f:
        lines = f.readlines()

    updated = []
    changes = []

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            updated.append(line)
            continue

        match = re.match(r"^([a-zA-Z0-9_\-]+)([=<>!].+)?$", stripped)
        if not match:
            updated.append(line)
            continue

        pkg_name = match.group(1).lower()

        if pkg_name in fixes:
            fix = fixes[pkg_name]
            new_version = fix["fixed_version"]
            new_line = f"{match.group(1)}=={new_version}\n"
            updated.append(new_line)
            changes.append({
                "package": match.group(1),
                "old": stripped,
                "new": new_line.strip(),
                "severity": fix["severity"],
                "vuln_id": fix["vuln_id"]
            })
            print(f"  [ACTUALIZADO] {stripped} → {new_line.strip()}")
        else:
            updated.append(line)

    with open(req_path, "w") as f:
        f.writelines(updated)

    return changes


def main():
    trivy_report  = os.environ.get("TRIVY_REPORT", "trivy-report.json")
    requirements  = os.environ.get("REQUIREMENTS_PATH", "app/requirements.txt")
    changes_out   = os.environ.get("CHANGES_OUTPUT", "remediation-changes.json")

    print("\n=== SecureDeps — Script de Remediación ===\n")

    if not os.path.exists(trivy_report):
        print(f"[ERROR] No se encontró el reporte: {trivy_report}")
        sys.exit(1)

    print(f"[1/3] Leyendo reporte: {trivy_report}")
    report = load_trivy_report(trivy_report)

    print("\n[2/3] Buscando fixes disponibles:")
    fixes = extract_fixes(report)

    if not fixes:
        print("\n[INFO] No hay fixes disponibles. Nada que remediar.")
        with open(changes_out, "w") as f:
            json.dump({"timestamp": datetime.utcnow().isoformat()+"Z", "total_fixes": 0, "changes": []}, f, indent=2)
        sys.exit(0)

    print(f"\n[3/3] Actualizando {requirements}:")
    changes = update_requirements(requirements, fixes)

    report_data = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "total_fixes": len(changes),
        "changes": changes
    }
    with open(changes_out, "w") as f:
        json.dump(report_data, f, indent=2)

    print(f"\n=== Remediación completada: {len(changes)} paquete(s) actualizado(s) ===\n")


if __name__ == "__main__":
    main()