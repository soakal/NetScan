"""MSRC correlate fail-closed behavior for unknown Windows products."""
from netscan.msrc import correlate, product_keys_for


def _sample_parsed():
    return {
        "products": {
            "p10": "Windows 10 Version 22H2 for x64-based Systems",
            "p11": "Windows 11 Version 23H2 for x64-based Systems",
        },
        "supersedes": {},
        "vulns": [
            {
                "cve": "CVE-2099-1001",
                "title": "Sample",
                "cvss": {"score": 9.8},
                "severity": {"value": "Critical"},
                "fixes": [
                    {"kb": "5034441", "product_ids": ["p10"]},
                    {"kb": "5034442", "product_ids": ["p11"]},
                ],
            }
        ],
    }


def test_product_keys_for_known_and_unknown():
    assert "windows 10" in product_keys_for("Microsoft Windows 10 Pro")
    assert product_keys_for("Some Appliance OS") == []


def test_correlate_fail_closed_without_product_keys():
    parsed = _sample_parsed()
    # Unknown OS caption -> empty keys -> must not match every Windows fix.
    res = correlate(parsed, [], installed_kbs=[])
    assert res == {"missing": [], "patched": []}


def test_correlate_fail_closed_when_keys_miss_products():
    parsed = _sample_parsed()
    # Recognized caption family that isn't in this corpus.
    res = correlate(parsed, ["windows server 2022"], installed_kbs=[])
    assert res == {"missing": [], "patched": []}


def test_correlate_matches_known_product():
    parsed = _sample_parsed()
    res = correlate(parsed, ["windows 10"], installed_kbs=[])
    assert [m["cve_id"] for m in res["missing"]] == ["CVE-2099-1001"]
    assert res["patched"] == []

    patched = correlate(parsed, ["windows 10"], installed_kbs=["KB5034441"])
    assert patched["missing"] == []
    assert [m["cve_id"] for m in patched["patched"]] == ["CVE-2099-1001"]
