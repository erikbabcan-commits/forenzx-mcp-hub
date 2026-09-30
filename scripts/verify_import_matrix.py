#!/usr/bin/env python3
"""
Verify import matrix in completely isolated clean subprocess environments.
Each module is imported in a fresh Python interpreter without production secrets.
"""
import subprocess
import sys

MODULES = [
    "core.config",
    "core.utils.logger",
    "core.models.forensic",
    "core.acl",
    "core.vault",
    "core.threat_intel",
    "core.pack_registry",
    "core.jobs",
    "workers.isolation",
    "workers.pool",
    "packs.base",
    "packs.mobile_compromise.adapter",
    "core.server",
    "core.main",
]


def test_import_module(module_name: str) -> tuple[bool, str]:
    code = f"""
import os
os.environ.pop("JWT_SECRET_KEY", None)
os.environ.pop("SERVER_HMAC_SIGNING_KEY", None)
os.environ.pop("API_KEYS", None)
os.environ["ENVIRONMENT"] = "development"
import {module_name}
"""
    res = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
    )
    return (res.returncode == 0, res.stderr.strip())


def main():
    print("=" * 60)
    print("FORENZX v4 IMPORT MATRIX VERIFICATION")
    print("=" * 60)
    all_passed = True

    for mod in MODULES:
        ok, err = test_import_module(mod)
        if ok:
            print(f"{mod:<35} [OK]")
        else:
            print(f"{mod:<35} [FAIL]")
            if err:
                print(f"  Error: {err}")
            all_passed = False

    print("=" * 60)
    if all_passed:
        print("IMPORT MATRIX: ALL 14 MODULES [OK]")
        sys.exit(0)
    else:
        print("IMPORT MATRIX: SOME MODULES FAILED")
        sys.exit(1)


if __name__ == "__main__":
    main()
