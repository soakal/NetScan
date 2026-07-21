"""Weakness taxonomy: CWE id -> human name, and CWE -> OWASP Top 10:2025 family.

This is the part of Hadrian's OpenHack that translates onto a network scanner.
OpenHack itself is whitebox *source* review and uses no CVE feed; what it does
contribute is a clean way to classify issues by *root-cause weakness family*
(OWASP Top 10:2025 + MITRE CWE) instead of only listing individual CVEs.

Every NVD CVE record carries one or more CWE ids, so we can pivot the same
findings by weakness type and OWASP family for free — giving the report a third
lens alongside "by device" and "by CVE".

Notes / honesty:
  * The OWASP-2025 family names below mirror the expert families published in
    OpenHack's README. The CWE->family mapping is a curated best-effort for the
    CWEs most commonly seen on networked services; unmapped CWEs fall into
    "Unclassified". It is a prioritization aid, not an authoritative mapping.
  * CWE names cover the common set; anything missing renders as the bare id.
"""
from __future__ import annotations

# --- OWASP Top 10:2025 families (names per OpenHack expert registry) ----------
OWASP_2025 = {
    "A01": "A01:2025 Broken Access Control",
    "A02": "A02:2025 Security Misconfiguration",
    "A03": "A03:2025 Software Supply Chain Failures",
    "A04": "A04:2025 Cryptographic Failures",
    "A05": "A05:2025 Injection",
    "A06": "A06:2025 Insecure Design",
    "A07": "A07:2025 Authentication Failures",
    "A08": "A08:2025 Software or Data Integrity Failures",
    # OpenHack also runs standalone CWE-family experts outside the Top 10:
    "MEM": "CWE-119 Memory/Buffer Boundary Errors",
    "INFO": "CWE-200 Sensitive Information Exposure",
    "PATH": "CWE-22/434 Path Traversal & Unrestricted Upload",
    "DOS": "CWE-770 Unrestricted Resource Consumption",
    "NA": "Unclassified",
}

# Most network CVE findings are "outdated software with a known CVE", which maps
# most naturally to the supply-chain / outdated-components family.
DEFAULT_FAMILY = "A03"

# --- CWE id -> short name (common set) ----------------------------------------
CWE_NAMES = {
    20: "Improper Input Validation",
    22: "Path Traversal",
    78: "OS Command Injection",
    79: "Cross-site Scripting (XSS)",
    77: "Command Injection",
    89: "SQL Injection",
    94: "Code Injection",
    119: "Improper Restriction of Operations within Memory Buffer",
    120: "Buffer Copy without Checking Size (Classic Buffer Overflow)",
    125: "Out-of-bounds Read",
    134: "Uncontrolled Format String",
    190: "Integer Overflow or Wraparound",
    200: "Exposure of Sensitive Information",
    255: "Credentials Management Errors",
    264: "Permissions, Privileges, and Access Controls",
    269: "Improper Privilege Management",
    276: "Incorrect Default Permissions",
    284: "Improper Access Control",
    287: "Improper Authentication",
    295: "Improper Certificate Validation",
    306: "Missing Authentication for Critical Function",
    310: "Cryptographic Issues",
    311: "Missing Encryption of Sensitive Data",
    319: "Cleartext Transmission of Sensitive Information",
    326: "Inadequate Encryption Strength",
    327: "Use of a Broken or Risky Cryptographic Algorithm",
    330: "Use of Insufficiently Random Values",
    345: "Insufficient Verification of Data Authenticity",
    352: "Cross-Site Request Forgery (CSRF)",
    362: "Race Condition",
    384: "Session Fixation",
    400: "Uncontrolled Resource Consumption",
    401: "Missing Release of Memory (Memory Leak)",
    404: "Improper Resource Shutdown or Release",
    415: "Double Free",
    416: "Use After Free",
    426: "Untrusted Search Path",
    434: "Unrestricted Upload of File with Dangerous Type",
    476: "NULL Pointer Dereference",
    494: "Download of Code Without Integrity Check",
    502: "Deserialization of Untrusted Data",
    522: "Insufficiently Protected Credentials",
    532: "Insertion of Sensitive Information into Log File",
    552: "Files or Directories Accessible to External Parties",
    565: "Reliance on Cookies without Validation/Integrity",
    601: "Open Redirect",
    611: "XML External Entity (XXE)",
    613: "Insufficient Session Expiration",
    620: "Unverified Password Change",
    639: "Authorization Bypass Through User-Controlled Key (IDOR)",
    640: "Weak Password Recovery Mechanism",
    668: "Exposure of Resource to Wrong Sphere",
    732: "Incorrect Permission Assignment for Critical Resource",
    770: "Allocation of Resources Without Limits or Throttling",
    787: "Out-of-bounds Write",
    798: "Use of Hard-coded Credentials",
    829: "Inclusion of Functionality from Untrusted Control Sphere",
    862: "Missing Authorization",
    863: "Incorrect Authorization",
    908: "Use of Uninitialized Resource",
    915: "Improperly Controlled Modification of Object Attributes",
    917: "Expression Language Injection",
    918: "Server-Side Request Forgery (SSRF)",
    1188: "Insecure Default Initialization of Resource",
    1321: "Prototype Pollution",
}

# --- CWE id -> OWASP 2025 family ----------------------------------------------
_CWE_TO_FAMILY = {
    # A01 Broken Access Control (OWASP folds SSRF/CWE-918 here in 2025)
    22: "PATH", 284: "A01", 264: "A01", 269: "A01", 276: "A01", 552: "A01",
    639: "A01", 668: "A01", 732: "A01", 862: "A01", 863: "A01", 918: "A01",
    # A02 Security Misconfiguration
    16: "A02", 1188: "A02", 1321: "A02", 611: "A02",
    # A03 Software Supply Chain Failures (outdated/vulnerable components)
    1104: "A03", 1395: "A03",
    # A04 Cryptographic Failures
    295: "A04", 310: "A04", 311: "A04", 319: "A04", 326: "A04", 327: "A04",
    330: "A04",
    # A05 Injection
    20: "A05", 77: "A05", 78: "A05", 79: "A05", 89: "A05", 90: "A05",
    91: "A05", 94: "A05", 917: "A05", 134: "A05",
    # A07 Authentication Failures
    255: "A07", 287: "A07", 306: "A07", 384: "A07", 522: "A07", 565: "A07",
    613: "A07", 620: "A07", 640: "A07", 798: "A07",
    # A08 Software or Data Integrity Failures
    345: "A08", 494: "A08", 502: "A08", 829: "A08", 915: "A08",
    # Standalone CWE-family experts
    119: "MEM", 120: "MEM", 125: "MEM", 190: "MEM", 401: "MEM", 404: "MEM",
    415: "MEM", 416: "MEM", 476: "MEM", 787: "MEM", 908: "MEM",
    200: "INFO", 532: "INFO",
    434: "PATH",
    400: "DOS", 770: "DOS",
}


def cwe_name(cwe_id: str | int) -> str:
    n = _cwe_num(cwe_id)
    if n is None:
        return str(cwe_id)
    return CWE_NAMES.get(n, f"CWE-{n}")


def owasp_family_for(cwe_id: str | int | None) -> tuple[str, str]:
    """Return (family_key, family_name) for a CWE. Unknown CWE on a network
    finding defaults to the supply-chain/outdated-components family."""
    n = _cwe_num(cwe_id)
    if n is None:
        return DEFAULT_FAMILY, OWASP_2025[DEFAULT_FAMILY]
    key = _CWE_TO_FAMILY.get(n, DEFAULT_FAMILY)
    return key, OWASP_2025[key]


def _cwe_num(cwe_id: str | int | None) -> int | None:
    if cwe_id is None:
        return None
    if isinstance(cwe_id, int):
        return cwe_id
    s = str(cwe_id).upper().replace("CWE-", "").strip()
    return int(s) if s.isdigit() else None
