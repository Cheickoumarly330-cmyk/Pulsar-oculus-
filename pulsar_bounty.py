import os, re, json, argparse
from pathlib import Path
from datetime import datetime

SKIP_FOLDERS = {'.git', 'node_modules', '.vscode', 'lib', 'out', 'cache', 'artifacts', 'dist', 'build'}

DETECTORS = {
    "REENTRANCY": r"\.call\{value:.*\}\(.*\)",
    "TX_ORIGIN": r"tx\.origin",
    "ACCESS_CONTROL": r"function\s+(withdraw|mint|transferOwnership)",
    "UNCHECKED_MINT": r"_mint\(",
    "WITHDRAWAL_PROTECTED": r"function\s+withdraw",
}

def scan_file(filepath: Path):
    findings = []
    try:
        content = filepath.read_text(errors='ignore')
        lines = content.split('\n')
        for i, line in enumerate(lines, 1):
            for vuln_type, pattern in DETECTORS.items():
                if re.search(pattern, line, re.IGNORECASE):
                    if "withdraw" in line.lower() and ("onlyOwner" in content or "require" in line):
                        severity = "LOW - Protected"
                    else:
                        severity = "HIGH" if vuln_type in ["REENTRANCY", "TX_ORIGIN"] else "MEDIUM"
                    findings.append({"file": str(filepath), "line": i, "type": vuln_type, "severity": severity, "code": line.strip()[:120]})
    except: pass
    return findings

def scan_folder(root_path):
    all_findings = []
    root = Path(root_path)
    files = [root] if root.is_file() else list(root.rglob("*.sol"))
    for f in files:
        if any(skip in str(f) for skip in SKIP_FOLDERS): continue
        if f.suffix == ".sol":
            print(f"[PULSAR] Scanning {f}...")
            all_findings.extend(scan_file(f))
    return all_findings

def export_reports(findings):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M")
    with open("rapport.json", "w") as jf: json.dump(findings, jf, indent=2)
    with open("rapport_SHERLOCK.md", "w") as mf:
        mf.write(f"# PULSAR Audit Report - {ts}\n\nTotal Findings: {len(findings)}\n\n| File | Line | Type | Severity | Code |\n|---|---|---|---|---|\n")
        for f in findings: mf.write(f"| {f['file']} | {f['line']} | {f['type']} | {f['severity']} | `{f['code']}` |\n")
    with open("rapport.txt", "w") as tf:
        for f in findings: tf.write(f"[{f['severity']}] {f['type']} at {f['file']}:{f['line']} - {f['code']}\n")
    print(f"\n[+] Rapports generes: rapport.json, rapport_SHERLOCK.md, rapport.txt")

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("path", nargs="?", default=".")
    args = p.parse_args()
    print(f"=== PULSAR V2.1 | Scanning {args.path} ===")
    results = scan_folder(args.path)
    export_reports(results)
    print(f"=== FINI: {len(results)} vulns ===")
PY
