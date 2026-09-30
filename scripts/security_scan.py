#!/usr/bin/env python3
"""Security scan script for ForenZX v5 codebase."""
import re
from pathlib import Path

SEARCH_PATTERNS = {
    "CRITICAL": [
        (r"DummyRegistry", "Hardcoded dummy registry"),
        (r"CASE_ACL_REGISTRY", "In-memory ACL registry"),
        (r'allow_origins=\s*\[\s*"\*"\s*\]', "Wildcard CORS with credentials"),
        (r"shell=True", "Shell injection vulnerability"),
        (r"os\.system", "Unsafe command execution"),
        (r"subprocess.*shell=True", "Unsafe shell execution"),
        (r"eval\(", "Code injection via eval"),
        (r"exec\(", "Code injection via exec"),
        (r"CHANGE_ME", "Hardcoded placeholder"),
        (r"INSECURE", "Insecure configuration"),
        (r'"latest"', "Unpinned Docker image tag"),
        (r"sample Pegasus", "Fake IOC bundle"),
    ],
    "HIGH": [
        (r'"\*"', "Wildcard in allow_origins"),
        (r"allow_credentials=True", "CORS with credentials"),
        (r"bash -c", "Shell command injection"),
        (r"sh -c", "Shell command injection"),
    ],
}


def scan_file(file_path: Path) -> list:
    """Scan a file for security issues."""
    findings = []

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line_num, line in enumerate(f, 1):
                for severity, patterns in SEARCH_PATTERNS.items():
                    for pattern, description in patterns:
                        try:
                            if re.search(pattern, line):
                                findings.append({
                                    "file": str(file_path),
                                    "line": line_num,
                                    "severity": severity,
                                    "description": description,
                                    "match": pattern
                                })
                        except Exception:
                            # Skip patterns that fail to compile
                            pass
    except Exception:
        pass

    return findings


def scan_directory(root_dir: Path) -> list:
    """Scan entire directory for security issues."""
    all_findings = []
    excluded_dirs = {".venv", "venv", ".git", "__pycache__", ".pytest_cache", ".ruff_cache", ".mypy_cache", "tests", "scripts"}

    for file_path in root_dir.rglob("*.py"):
        if any(part in excluded_dirs for part in file_path.parts):
            continue
        if file_path.name == "security_scan.py":
            continue
        all_findings.extend(scan_file(file_path))

    return all_findings


def print_findings(findings: list):
    """Print findings grouped by severity."""
    severity_order = ["CRITICAL", "HIGH"]

    for severity in severity_order:
        filtered = [f for f in findings if f["severity"] == severity]
        if filtered:
            print(f"\n{'=' * 70}")
            print(f"{severity} FINDINGS ({len(filtered)})")
            print('=' * 70)
            for f in filtered:
                print(f"  [{f['severity']}] {f['file']}:{f['line']} - {f['description']}")
                print(f"    Pattern: {f['match']}")
                print(f"    Line: {f.get('line_text', 'N/A')}")

    print(f"\n\nTotal findings: {len(findings)}")
    return len(findings)


if __name__ == "__main__":
    project_root = Path(__file__).parent.parent

    print("=" * 70)
    print("FORENZX v5 SECURITY SCAN")
    print("=" * 70)
    print(f"Scanning: {project_root}")

    findings = scan_directory(project_root)
    count = print_findings(findings)

    if count == 0:
        print("\n✓ No critical security findings detected!")
    else:
        print(f"\n✗ Found {count} security findings that need attention!")
