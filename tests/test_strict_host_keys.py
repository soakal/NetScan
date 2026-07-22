"""strict_host_keys: config parsing and SSH host-key policy selection."""
import pytest

from netscan.config import load_config
from netscan import credentialed


def test_config_default_and_parse(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text("targets: []\n")
    assert load_config(str(p)).strict_host_keys is True
    p.write_text("targets: []\nstrict_host_keys: false\n")
    assert load_config(str(p)).strict_host_keys is False
    p.write_text("targets: []\nstrict_host_keys: true\n")
    assert load_config(str(p)).strict_host_keys is True


@pytest.mark.skipif(not credentialed._HAVE_PARAMIKO, reason="paramiko not installed")
@pytest.mark.parametrize("strict", [False, True])
def test_scan_ssh_host_key_policy(monkeypatch, strict):
    import paramiko

    recorded = {}

    class FakeClient:
        def set_missing_host_key_policy(self, policy):
            recorded["policy"] = policy

        def load_system_host_keys(self):
            recorded["loaded_known_hosts"] = True

        def connect(self, *a, **kw):
            raise OSError("no network in tests")

        def close(self):
            pass

    monkeypatch.setattr(paramiko, "SSHClient", FakeClient)
    from netscan.config import Credential
    cred = Credential(name="t", type="ssh", username="u", password="p")
    res = credentialed.scan_ssh({"ip": "192.0.2.1"}, cred, strict_host_keys=strict)
    assert not res.ok  # connect always fails in the fake; policy is what we test
    if strict:
        assert isinstance(recorded["policy"], paramiko.RejectPolicy)
        assert recorded.get("loaded_known_hosts") is True
    else:
        assert isinstance(recorded["policy"], paramiko.AutoAddPolicy)
        assert "loaded_known_hosts" not in recorded


def test_strict_winrm_rejects_http_before_connect(monkeypatch):
    from netscan.config import Credential

    called = False

    class FakeWinrm:
        @staticmethod
        def Session(*args, **kwargs):
            nonlocal called
            called = True
            raise AssertionError("must not connect over HTTP in strict mode")

    monkeypatch.setattr(credentialed, "_HAVE_WINRM", True)
    monkeypatch.setattr(credentialed, "winrm", FakeWinrm)
    cred = Credential(
        name="w", type="winrm", username="u", password="p", scheme="http"
    )
    result = credentialed.scan_winrm(
        {"ip": "192.0.2.10"}, cred, strict_host_keys=True
    )
    assert not result.ok
    assert "requires WinRM over HTTPS" in result.error
    assert called is False
