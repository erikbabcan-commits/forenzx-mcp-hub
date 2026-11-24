#!/usr/bin/env python3
"""Run synthetic authorization and Hub regressions in disposable storage."""

import os
import subprocess
import sys
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix="forenzx-reporter-check-") as temporary:
    env = dict(os.environ, ENVIRONMENT="test", MCP_AUTO_HEALTH_ENABLED="false", PACKS_DIR=str(root / "packs"))
    for key, relative in {
        "DATA_DIR": "data",
        "DATABASE_PATH": "db.sqlite",
        "BACKUPS_DIR": "backups",
        "VAULT_BASE_DIR": "vault",
        "SCRATCH_BASE_DIR": "scratch",
        "THREAT_INTEL_DIR": "intel",
    }.items():
        env[key] = str(Path(temporary) / relative)
    checks = sys.argv[1:] or ["tests/security", "tests/unit", "tests/integration", "-q"]
    raise SystemExit(subprocess.run([sys.executable, "-m", "pytest", *checks], cwd=root, env=env).returncode)
