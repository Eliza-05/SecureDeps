#!/usr/bin/env python3
"""
remediate.py - Lee trivy-report.json y actualiza requirements.txt
"""

import json
import sys
import os
import re
from datetime import datetime, timezone


def _parse_version_tuple(version):
    parts = []
    for token in re.findall(r"\d+", version):
        parts.append(int(token))
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])


def _extract_pinned_versions(lines):
    pinned = {}
    for line in lines:
        m = re.match(r"^\s*([a-zA-Z0-9_\-]+)\s*==\s*([^\s#]+)", line)
        if m:
            pinned[m.group(1).lower()] = m.group(2)
    return pinned


def _enforce_flask_werkzeug_compatibility(updated_lines, changes):
    """Ensure Flask/Werkzeug pins remain installable after remediation."""
    pinned = _extract_pinned_versions(updated_lines)
    flask_v = pinned.get("flask")
    werkzeug_v = pinned.get("werkzeug")

    if not flask_v or not werkzeug_v:
        return updated_lines, changes

    flask_t = _parse_version_tuple(flask_v)
    werk_t = _parse_version_tuple(werkzeug_v)

    required_werkzeug = None
    if flask_t >= (2, 3, 0) and flask_t < (3, 0, 0):
        required_werkzeug = "2.3.3"
    elif flask_t >= (3, 0, 0):
        required_werkzeug = "3.0.0"

    if not required_werkzeug:
        return updated_lines, changes

    req_t = _parse_version_tuple(required_werkzeug)
    if werk_t >= req_t:
        return updated_lines, changes

    normalized = []
    for line in updated_lines:
        if re.match(r"^\s*werkzeug\s*[=<>!]", line, re.IGNORECASE):
            normalized.append(f"werkzeug=={required_werkzeug}\n")
        else:
            normalized.append(line)

    changes.append({
        "package": "werkzeug",
        "old": f"werkzeug=={werkzeug_v}",
        "new": f"werkzeug=={required_werkzeug}",
        "severity": "COMPATIBILITY",
        "vuln_id": "FLASK_WERKZEUG_COMPAT"
    })
    print(f"  [COMPAT] werkzeug=={werkzeug_v} ajustado a werkzeug=={required_werkzeug} por compatibilidad con Flask {flask_v}")
    return normalized, changes


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

    updated, changes = _enforce_flask_werkzeug_compatibility(updated, changes)

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
            json.dump({"timestamp": datetime.now(timezone.utc).isoformat(), "total_fixes": 0, "changes": []}, f, indent=2)
        sys.exit(0)

    print(f"\n[3/3] Actualizando {requirements}:")
    changes = update_requirements(requirements, fixes)

    report_data = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_fixes": len(changes),
        "changes": changes
    }
    with open(changes_out, "w") as f:
        json.dump(report_data, f, indent=2)

    print(f"\n=== Remediación completada: {len(changes)} paquete(s) actualizado(s) ===\n")


if __name__ == "__main__":
    main()