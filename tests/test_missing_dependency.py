"""A missing required dependency (flask for `serve`, requests for `scan`)
must produce a clean, actionable error -- not a raw traceback. This matters
most for run.bat users, who see stderr in a plain console window with no
Python experience and no way to interpret a stack trace.

Other test modules already import netscan.correlate/netscan.enrich (and
transitively requests) at collection time, so sys.modules must be evicted
for the whole dependent chain before blocking an import -- otherwise the
already-cached module is reused and the ModuleNotFoundError never fires."""
from __future__ import annotations

import builtins
import sys

import run as run_mod


def _evict(*module_names):
    """Remove modules (if present) from sys.modules so the next import
    re-executes their top-level code. Not restored afterward: later tests
    that need an evicted module simply re-import it fresh."""
    for name in module_names:
        sys.modules.pop(name, None)


def _block_import(monkeypatch, blocked_name):
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == blocked_name:
            raise ModuleNotFoundError(f"No module named {blocked_name!r}",
                                      name=blocked_name)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)


def test_missing_flask_gives_clean_error(tmp_path, monkeypatch, capsys):
    cfg = tmp_path / "config.yaml"
    cfg.write_text("targets: []\n")
    _evict("flask", "netscan.web", "netscan.web.app")
    _block_import(monkeypatch, "flask")

    monkeypatch.setattr(
        "sys.argv", ["run.py", "serve", "-c", str(cfg)])
    rc = run_mod.main()

    assert rc == 1
    err = capsys.readouterr().err
    assert "missing required dependency 'flask'" in err
    assert "pip install -r requirements.txt" in err
    assert "Traceback" not in err


def test_missing_requests_gives_clean_error(tmp_path, monkeypatch, capsys):
    cfg = tmp_path / "config.yaml"
    cfg.write_text("targets: [\"10.0.0.1\"]\n")
    _evict("requests", "netscan.correlate", "netscan.enrich")
    _block_import(monkeypatch, "requests")

    monkeypatch.setattr(
        "sys.argv", ["run.py", "scan", "-c", str(cfg)])
    rc = run_mod.main()

    assert rc == 1
    err = capsys.readouterr().err
    assert "missing required dependency 'requests'" in err
    assert "pip install -r requirements.txt" in err
    assert "Traceback" not in err


def test_missing_flask_states_what_and_why(tmp_path, monkeypatch, capsys):
    """The prompt must say what's being installed and why -- not just that
    something is missing."""
    cfg = tmp_path / "config.yaml"
    cfg.write_text("targets: []\n")
    _evict("flask", "netscan.web", "netscan.web.app")
    _block_import(monkeypatch, "flask")
    monkeypatch.setattr(run_mod, "_stdin_is_tty", lambda: False)

    monkeypatch.setattr("sys.argv", ["run.py", "serve", "-c", str(cfg)])
    run_mod.main()

    err = capsys.readouterr().err
    assert "web report" in err  # the *why*
    assert "pip" in err and "requirements.txt" in err  # the *what*


def test_non_tty_never_prompts_or_installs(tmp_path, monkeypatch, capsys):
    cfg = tmp_path / "config.yaml"
    cfg.write_text("targets: []\n")
    _evict("flask", "netscan.web", "netscan.web.app")
    _block_import(monkeypatch, "flask")
    monkeypatch.setattr(run_mod, "_stdin_is_tty", lambda: False)

    calls = []
    monkeypatch.setattr(run_mod.subprocess, "run",
                        lambda *a, **kw: calls.append((a, kw)))
    monkeypatch.setattr("builtins.input",
                        lambda *a: (_ for _ in ()).throw(AssertionError(
                            "must not prompt when stdin is not a tty")))

    monkeypatch.setattr("sys.argv", ["run.py", "serve", "-c", str(cfg)])
    rc = run_mod.main()

    assert rc == 1
    assert calls == []  # pip never invoked


def test_tty_declines_install(tmp_path, monkeypatch, capsys):
    cfg = tmp_path / "config.yaml"
    cfg.write_text("targets: []\n")
    _evict("flask", "netscan.web", "netscan.web.app")
    _block_import(monkeypatch, "flask")
    monkeypatch.setattr(run_mod, "_stdin_is_tty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda *_a: "n")

    calls = []
    monkeypatch.setattr(run_mod.subprocess, "run",
                        lambda *a, **kw: calls.append((a, kw)))

    monkeypatch.setattr("sys.argv", ["run.py", "serve", "-c", str(cfg)])
    rc = run_mod.main()

    assert rc == 1
    assert calls == []
    assert "Not installing" in capsys.readouterr().err


def test_tty_accepts_install_and_retries_once(tmp_path, monkeypatch, capsys):
    """Confirming the install must trigger exactly one retry of the failed
    command, using sys.executable -m pip against requirements.txt.

    Patches cmd_serve itself (rather than fighting real import machinery)
    so the test exercises main()'s retry-loop logic in isolation: raise
    ModuleNotFoundError('flask') on the first call, succeed on the second --
    exactly what a real "import failed, pip installed it, retry works" run
    looks like from main()'s point of view."""
    cfg = tmp_path / "config.yaml"
    cfg.write_text("targets: []\n")

    call_count = {"n": 0}

    def fake_cmd_serve(args):
        call_count["n"] += 1
        if call_count["n"] == 1:
            raise ModuleNotFoundError("No module named 'flask'", name="flask")
        return 0
    monkeypatch.setattr(run_mod, "cmd_serve", fake_cmd_serve)

    monkeypatch.setattr(run_mod, "_stdin_is_tty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda *_a: "y")

    calls = []

    class _Result:
        returncode = 0

    def fake_run(argv, **kw):
        calls.append(argv)
        return _Result()
    monkeypatch.setattr(run_mod.subprocess, "run", fake_run)

    monkeypatch.setattr("sys.argv", ["run.py", "serve", "-c", str(cfg)])
    rc = run_mod.main()

    assert call_count["n"] == 2  # failed once, retried once
    assert len(calls) == 1  # pip invoked exactly once
    assert calls[0][:3] == [sys.executable, "-m", "pip"]
    assert "requirements.txt" in calls[0][-1]
    assert rc == 0


def test_pip_failure_falls_back_to_clean_error(tmp_path, monkeypatch, capsys):
    cfg = tmp_path / "config.yaml"
    cfg.write_text("targets: []\n")
    _evict("flask", "netscan.web", "netscan.web.app")
    _block_import(monkeypatch, "flask")
    monkeypatch.setattr(run_mod, "_stdin_is_tty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda *_a: "y")

    class _Result:
        returncode = 1
    monkeypatch.setattr(run_mod.subprocess, "run", lambda *a, **kw: _Result())

    monkeypatch.setattr("sys.argv", ["run.py", "serve", "-c", str(cfg)])
    rc = run_mod.main()

    assert rc == 1
    err = capsys.readouterr().err
    assert "automatic install failed" in err
    assert "Traceback" not in err


def test_auto_install_flag_skips_prompt(tmp_path, monkeypatch, capsys):
    cfg = tmp_path / "config.yaml"
    cfg.write_text("targets: []\n")
    _evict("flask", "netscan.web", "netscan.web.app")
    _block_import(monkeypatch, "flask")
    monkeypatch.setattr(run_mod, "_stdin_is_tty", lambda: True)
    monkeypatch.setattr("builtins.input",
                        lambda *a: (_ for _ in ()).throw(AssertionError(
                            "must not prompt when --auto-install is passed")))

    class _Result:
        returncode = 1  # fail fast, we're only checking the prompt is skipped
    monkeypatch.setattr(run_mod.subprocess, "run", lambda *a, **kw: _Result())

    monkeypatch.setattr(
        "sys.argv", ["run.py", "--auto-install", "serve", "-c", str(cfg)])
    run_mod.main()  # must not raise from the input() stub above
