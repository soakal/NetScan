"""`serve --debug` must refuse to bind the Werkzeug debugger to a
network-facing host (the interactive debugger is an RCE endpoint)."""
import argparse

import pytest

import run as run_mod


def _args(config=None, debug=False):
    return argparse.Namespace(config=config, debug=debug)


def _write_cfg(tmp_path, web_host):
    p = tmp_path / "config.yaml"
    p.write_text(f"targets: []\nweb_host: {web_host}\nweb_port: 8000\n")
    return str(p)


def test_debug_refused_on_non_localhost_host(tmp_path, capsys):
    cfg = _write_cfg(tmp_path, "0.0.0.0")
    rc = run_mod.cmd_serve(_args(config=cfg, debug=True))
    assert rc == 2
    err = capsys.readouterr().err
    assert "refusing to start" in err
    assert "--debug" in err


def test_debug_refused_on_lan_ip(tmp_path):
    cfg = _write_cfg(tmp_path, "192.0.2.10")
    assert run_mod.cmd_serve(_args(config=cfg, debug=True)) == 2


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "::1"])
def test_debug_allowed_on_localhost(tmp_path, monkeypatch, host):
    """With a localhost bind, the guard passes and the app is started."""
    cfg = _write_cfg(tmp_path, host)
    started = {}

    class FakeApp:
        def run(self, host, port, debug):
            started.update(host=host, port=port, debug=debug)

    import netscan.web
    monkeypatch.setattr(netscan.web, "create_app", lambda db: FakeApp())
    rc = run_mod.cmd_serve(_args(config=cfg, debug=True))
    assert rc == 0
    assert started == {"host": host, "port": 8000, "debug": True}


def test_no_debug_unaffected_by_host(tmp_path, monkeypatch):
    """Without --debug, a non-localhost bind still works (intentional expose)."""
    cfg = _write_cfg(tmp_path, "0.0.0.0")

    class FakeApp:
        def run(self, host, port, debug):
            assert debug is False

    import netscan.web
    monkeypatch.setattr(netscan.web, "create_app", lambda db: FakeApp())
    assert run_mod.cmd_serve(_args(config=cfg, debug=False)) == 0
