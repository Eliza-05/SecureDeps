#!/usr/bin/env python3
"""
remediate.py - Lee trivy-report.json y actualiza el archivo de dependencias
Soporta: Python (requirements.txt), Node.js (package.json), Java (pom.xml)
"""

import json
import sys
import os
import re
from datetime import datetime, timezone


# ── UTILIDADES PYTHON ──────────────────────────────────────────────

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
    """Asegura compatibilidad entre Flask y Werkzeug después de la remediación."""
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
    print(f"  [COMPAT] werkzeug=={werkzeug_v} → werkzeug=={required_werkzeug} (compatibilidad Flask {flask_v})")
    return normalized, changes


# ── DETECCIÓN DE LENGUAJE ──────────────────────────────────────────

def detect_package_file(app_path):
    """Detecta automáticamente el archivo de dependencias del proyecto."""
    candidates = [
        (os.path.join(app_path, "requirements.txt"), "python"),
        (os.path.join(app_path, "package.json"),     "node"),
        (os.path.join(app_path, "pom.xml"),          "java"),
    ]
    for path, lang in candidates:
        if os.path.exists(path):
            print(f"  [DETECTADO] Lenguaje: {lang.upper()} → {path}")
            return path, lang
    return None, None


# ── EXTRACCIÓN DE FIXES ────────────────────────────────────────────

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


# ── PYTHON: requirements.txt ───────────────────────────────────────

def update_requirements_txt(req_path, fixes):
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


# ── NODE.JS: package.json ──────────────────────────────────────────

def update_package_json(pkg_path, fixes):
    with open(pkg_path, "r") as f:
        data = json.load(f)

    changes = []
    dep_sections = ["dependencies", "devDependencies", "peerDependencies"]

    for section in dep_sections:
        if section not in data:
            continue
        for pkg_name, current_version in list(data[section].items()):
            pkg_lower = pkg_name.lower()
            if pkg_lower in fixes:
                fix = fixes[pkg_lower]
                new_version = f"^{fix['fixed_version']}"
                old_str = f"{pkg_name}@{current_version}"
                new_str = f"{pkg_name}@{new_version}"
                data[section][pkg_name] = new_version
                changes.append({
                    "package": pkg_name,
                    "old": old_str,
                    "new": new_str,
                    "severity": fix["severity"],
                    "vuln_id": fix["vuln_id"]
                })
                print(f"  [ACTUALIZADO] {old_str} → {new_str}")

    with open(pkg_path, "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")

    return changes


# ── JAVA: pom.xml ──────────────────────────────────────────────────

def update_pom_xml(pom_path, fixes):
    with open(pom_path, "r") as f:
        content = f.read()

    changes = []

    for pkg_name, fix in fixes.items():
        pattern = rf'(<artifactId>{re.escape(pkg_name)}</artifactId>\s*<version>)([^<]+)(</version>)'
        match = re.search(pattern, content, re.IGNORECASE)
        if match:
            old_version = match.group(2).strip()
            new_version = fix["fixed_version"]
            if old_version != new_version:
                content = (
                    content[:match.start(2)]
                    + new_version
                    + content[match.end(2):]
                )
                changes.append({
                    "package": pkg_name,
                    "old": f"{pkg_name}=={old_version}",
                    "new": f"{pkg_name}=={new_version}",
                    "severity": fix["severity"],
                    "vuln_id": fix["vuln_id"]
                })
                print(f"  [ACTUALIZADO] {pkg_name} {old_version} → {new_version}")

    with open(pom_path, "w") as f:
        f.write(content)

    return changes


# ── MAIN ───────────────────────────────────────────────────────────

def main():
    trivy_report = os.environ.get("TRIVY_REPORT", "trivy-report.json")
    app_path     = os.environ.get("APP_PATH", "app")
    changes_out  = os.environ.get("CHANGES_OUTPUT", "remediation-changes.json")

    print("\n=== SecureDeps — Script de Remediación ===\n")

    if not os.path.exists(trivy_report):
        print(f"[ERROR] No se encontró el reporte: {trivy_report}")
        sys.exit(1)

    print(f"[1/4] Detectando lenguaje en: {app_path}")
    pkg_file, lang = detect_package_file(app_path)

    if not pkg_file:
        print(f"[ERROR] No se encontró requirements.txt, package.json ni pom.xml en {app_path}")
        sys.exit(1)

    print(f"\n[2/4] Leyendo reporte: {trivy_report}")
    with open(trivy_report) as f:
        report = json.load(f)

    print("\n[3/4] Buscando fixes disponibles:")
    fixes = extract_fixes(report)

    if not fixes:
        print("\n[INFO] No hay fixes disponibles. Nada que remediar.")
        with open(changes_out, "w") as f:
            json.dump({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "total_fixes": 0,
                "language": lang,
                "changes": []
            }, f, indent=2)
        sys.exit(0)

    print(f"\n[4/4] Actualizando {pkg_file}:")

    if lang == "python":
        changes = update_requirements_txt(pkg_file, fixes)
    elif lang == "node":
        changes = update_package_json(pkg_file, fixes)
    elif lang == "java":
        changes = update_pom_xml(pkg_file, fixes)
    else:
        print(f"[ERROR] Lenguaje no soportado: {lang}")
        sys.exit(1)

    report_data = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_fixes": len(changes),
        "language": lang,
        "changes": changes
    }
    with open(changes_out, "w") as f:
        json.dump(report_data, f, indent=2)

    print(f"\n=== Remediación completada: {len(changes)} paquete(s) actualizado(s) en {lang.upper()} ===\n")


if __name__ == "__main__":
    main()