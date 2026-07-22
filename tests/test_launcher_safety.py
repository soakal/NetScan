"""Cross-platform launcher safety regressions."""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import stat
import subprocess


ROOT = Path(__file__).resolve().parents[1]


def test_run_sh_creates_private_config(tmp_path):
    shutil.copy2(ROOT / "run.sh", tmp_path / "run.sh")
    shutil.copy2(ROOT / "config.example.yaml", tmp_path / "config.example.yaml")
    os.chmod(tmp_path / "run.sh", 0o755)

    result = subprocess.run(
        ["bash", str(tmp_path / "run.sh")],
        input="1\n\n0\n",
        text=True,
        capture_output=True,
        timeout=10,
        env={**os.environ, "TERM": "dumb"},
    )
    assert result.returncode == 0, result.stderr
    mode = stat.S_IMODE((tmp_path / "config.yaml").stat().st_mode)
    assert mode & 0o077 == 0


def test_windows_demo_does_not_serve_after_seed_failure():
    launcher = (ROOT / "run.bat").read_text()
    demo = launcher.split(":demo", 1)[1].split(":profiles", 1)[0]
    assert "python run.py demo\nif errorlevel 1 (" in demo.replace("\r\n", "\n")
    assert "Demo seed failed. Not starting the report server." in demo


def test_docs_do_not_recommend_running_launcher_as_root():
    running = (ROOT / "RUNNING.md").read_text()
    assert "sudo ./run.sh" not in running
