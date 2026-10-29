"""Exercise the actual scanner process, not a duplicated matching rule."""

import shutil
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.parametrize("source, expected", [("value = 1\n", 0), ("eval(input())\n", 1)])
def test_scanner_exit_tracks_findings(tmp_path, source, expected):
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    scanner = scripts / "security_scan.py"
    shutil.copyfile(Path(__file__).resolve().parents[2] / "scripts/security_scan.py", scanner)
    core = tmp_path / "core"
    core.mkdir()
    (core / "synthetic.py").write_text(source)
    result = subprocess.run([sys.executable, str(scanner)], capture_output=True, text=True)
    assert result.returncode == expected
    assert ("Total findings: 0" in result.stdout) == (expected == 0)
