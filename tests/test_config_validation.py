"""Config validation: booleans, target lists, nmap option injection, key paths."""
from __future__ import annotations

import os

import pytest

from netscan.config import Config, Credential, load_config
from netscan.scanner import _expand_targets, _validate_scan_scope


def test_bool_string_false_is_false(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text("targets: []\ncredentialed: \"false\"\nvt_check_host_ips: \"false\"\n")
    cfg = load_config(str(p))
    assert cfg.credentialed is False
    assert cfg.vt_check_host_ips is False


def test_strict_host_keys_defaults_true(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text("targets: []\n")
    assert load_config(str(p)).strict_host_keys is True
    p.write_text("targets: []\nstrict_host_keys: false\n")
    assert load_config(str(p)).strict_host_keys is False


def test_scalar_target_becomes_list(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text("targets: 10.0.0.5\n")
    assert load_config(str(p)).targets == ["10.0.0.5"]


def test_rejects_dash_prefixed_targets(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text("targets: ['-sV', '10.0.0.1']\n")
    with pytest.raises(ValueError, match="must not start with"):
        load_config(str(p))


def test_rejects_dash_prefixed_exclude(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text("targets: ['10.0.0.1']\nexclude: ['--script']\n")
    with pytest.raises(ValueError, match="must not start with"):
        load_config(str(p))


@pytest.mark.parametrize("value", [
    "127.0.0.1 --script vuln",
    "host.example --script=vuln",
    "127.0.0.1,evil.example",
    "host.example;--script=vuln",
])
def test_rejects_embedded_nmap_options(tmp_path, value):
    p = tmp_path / "c.yaml"
    p.write_text(f"targets: [{value!r}]\n")
    with pytest.raises(ValueError, match="no whitespace/options|invalid host"):
        load_config(str(p))


def test_accepts_supported_host_tokens(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text(
        "targets: [10.0.0.1, 10.0.0.0/30, 10.0.0.5-10, host.example]\n"
    )
    assert load_config(str(p)).targets == [
        "10.0.0.1", "10.0.0.0/30", "10.0.0.5-10", "host.example",
    ]


def test_key_file_expands_tilde(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    # expanduser uses HOME on Linux
    p = tmp_path / "c.yaml"
    p.write_text(
        "targets: []\n"
        "credentials:\n"
        "  - name: t\n"
        "    type: ssh\n"
        "    username: u\n"
        "    key_file: ~/.ssh/scan_key\n"
    )
    cfg = load_config(str(p))
    assert cfg.credentials[0].key_file == os.path.join(str(home), ".ssh", "scan_key")


def test_expand_targets_rejects_huge_cidr():
    with pytest.raises(ValueError, match="refusing more than"):
        _expand_targets(["10.0.0.0/8"])


def test_scope_cap_runs_before_nmap_backend():
    with pytest.raises(ValueError, match="refusing more than"):
        _validate_scan_scope(["10.0.0.0/8"])


def test_direct_config_target_injection_is_rejected():
    with pytest.raises(ValueError, match="no whitespace/options"):
        _validate_scan_scope(Config(
            targets=["127.0.0.1 --script vuln"]
        ).targets)


def test_expand_targets_small_cidr_ok():
    ips = _expand_targets(["10.0.0.0/30"])
    assert ips == ["10.0.0.1", "10.0.0.2"]


def test_winrm_disabled_by_default_ignores_winrm_creds(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text(
        "targets: []\n"
        "credentials:\n"
        "  - name: w\n"
        "    type: winrm\n"
        "    username: u\n"
        "    password: p\n"
        "  - name: l\n"
        "    type: ssh\n"
        "    username: u\n"
        "    password: p\n"
    )
    cfg = load_config(str(p))
    assert cfg.winrm_enabled is False
    assert [c.type for c in cfg.credentials] == ["ssh"]


def test_winrm_enabled_keeps_winrm_creds(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text(
        "targets: []\n"
        "winrm_enabled: true\n"
        "credentials:\n"
        "  - name: w\n"
        "    type: winrm\n"
        "    username: u\n"
        "    password: p\n"
    )
    cfg = load_config(str(p))
    assert cfg.winrm_enabled is True
    assert [c.type for c in cfg.credentials] == ["winrm"]


def test_secrets_are_redacted_from_dataclass_repr():
    cred = Credential(
        name="windows", type="winrm", username="u", password="secret-password"
    )
    cfg = Config(
        nvd_api_key="nvd-secret",
        vt_api_key="vt-secret",
        msrc_api_key="msrc-secret",
        credentials=[cred],
    )
    rendered = repr(cfg)
    for secret in ("secret-password", "nvd-secret", "vt-secret", "msrc-secret"):
        assert secret not in rendered
