"""Audit engine: filesystem-driven evidence collection + control evaluation.

Each audit scans a target path (file or directory) and evaluates a list of
controls (signing, licensing, secrets hygiene, SBOM presence, etc.).
"""

import hashlib
import json
import os
import pathlib
import re
import datetime


DEFAULT_CONTROLS = [
    ("SIG", "artifact signed",        "high"),
    ("LIC", "license present",        "medium"),
    ("DSC", "model card present",     "medium"),
    ("SEC", "no embedded secrets",    "high"),
    ("SBM", "SBOM auditable",         "low"),
    ("TST", "test suite present",     "low"),
    ("DSX", "dataset documentation",  "medium"),
    ("VER", "model versioning",        "low"),
]

_SECRET_PATTERNS = [
    re.compile(r"(?:API[_-]?KEY|SECRET|PASSWORD)\s*[:=]\s*['\"][^'\"]{8,}", re.I),
    re.compile(r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----", re.I),
    re.compile(r"ghp_[A-Za-z0-9]{36}", re.I),  # GitHub PAT
]

_SBOM_NAMES = {"sbom.json", "sbom.csv", "sneppx-shield-sbom.json", "SBOM.json"}


class AuditReport:
    def __init__(self, target):
        self.target = pathlib.Path(target)
        self.evidence = {}
        self.controls = []

    # -- evidence ----------------------------------------------------------

    def collect_evidence(self):
        e = {
            "target": str(self.target),
            "is_file": self.target.is_file(),
            "is_dir": self.target.is_dir(),
            "exists": self.target.exists(),
        }
        if self.target.is_file():
            e["file_size"] = self.target.stat().st_size
            e["file_sha256"] = file_sha256(self.target)
        if self.target.is_dir():
            e["dir_entries"] = len(list(self.target.iterdir()))
            e["has_readme"] = _any_file_matches(self.target, {r"readme\b.*", r"model_card\b.*"})
            e["has_license"] = _any_file_matches(self.target, {"license", "licence", "copying"})
            e["has_tests"] = any(p.is_dir() and p.name == "tests" for p in self.target.iterdir())
            e["has_sbom"] = _any_file_matches(self.target, _SBOM_NAMES)
            e["has_signature"] = any(p.suffix == ".sig" for p in self.target.iterdir())
            e["secret_patterns"] = _scan_secrets(self.target)
            e["has_version_file"] = _any_file_matches(self.target, {"version", "changelog", "changes", "history"})
            e["has_changelog"] = _any_file_matches(self.target, {"changelog", "changes", "history"})
        elif self.target.is_file():
            e["has_readme"] = False
            e["has_license"] = False
            e["has_tests"] = False
            e["has_sbom"] = False
            e["has_signature"] = (self.target.with_suffix(".sig")).exists()
            e["secret_patterns"] = _scan_secrets_file(self.target)
        self.evidence = e
        return e

    # -- evaluation --------------------------------------------------------

    def evaluate_controls(self, evidence=None, control_ids=None):
        evidence = evidence or self.evidence
        ids = {c[0] for c in control_ids} if control_ids else None
        results = []
        for cid, name, severity in DEFAULT_CONTROLS:
            if ids and cid not in ids:
                continue
            status, detail = _eval_single(cid, evidence)
            results.append({"id": cid, "name": name, "severity": severity,
                            "status": status, "detail": detail})
        self.controls = results
        return results

    def rating(self, controls=None):
        controls = controls or self.controls
        passed = sum(1 for c in controls if c["status"] == "pass")
        total = len(controls)
        if total == 0:
            return "review"
        ratio = passed / total
        if ratio >= 0.75:
            return "pass"
        if ratio >= 0.5:
            return "review"
        return "fail"

    # -- render ------------------------------------------------------------

    def render_markdown(self, controls=None, timestamp=None):
        controls = controls or self.controls
        ts = timestamp or datetime.datetime.utcnow().isoformat()
        rating = self.rating(controls)
        passed = sum(1 for c in controls if c["status"] == "pass")
        total = len(controls)
        lines = [
            "# AI Security Audit Report",
            f"Date: {ts}",
            f"Target: `{self.target}`",
            f"Rating: **{rating}** ({passed}/{total} passed)",
            "",
            "## Evidence",
            "```json",
            json.dumps(self.evidence, indent=2, default=str),
            "```",
            "",
            "## Controls",
            "| ID | Control | Severity | Status |",
            "|----|---------|----------|--------|",
        ]
        for c in controls:
            emoji = {"pass": "✅", "fail": "❌", "review": "⚠️"}.get(c["status"], "")
            lines.append(f"| {c['id']} | {c['name']} | {c['severity']} | {emoji} {c['status']} |")
            if c.get("detail"):
                lines.append(f"| | `{c['detail']}` | | |")
        lines.append("")
        lines.append(f"Generated by `sneppx-audits` ({ts})")
        return "\n".join(lines)

    def render_json(self, controls=None):
        return json.dumps({
            "target": str(self.target),
            "rating": self.rating(controls),
            "controls": controls or self.controls,
            "evidence": self.evidence,
        }, indent=2, default=str)


# -- helper functions ------------------------------------------------------

def file_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _any_file_matches(directory, patterns):
    for entry in directory.iterdir():
        name_lower = entry.name.lower()
        for pat in patterns:
            if re.search(pat, name_lower):
                return True
    return False


def _scan_secrets(directory):
    findings = []
    for path in directory.rglob("*"):
        if path.is_file() and path.suffix in {".py", ".cfg", ".toml", ".env", ".sh"}:
            findings.extend(_scan_secrets_file(path))
    return findings


def _scan_secrets_file(path):
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    findings = []
    for i, line in enumerate(text.splitlines(), 1):
        for pat in _SECRET_PATTERNS:
            if pat.search(line):
                findings.append(f"{path}:{i}")
                break
    return findings


def _eval_single(cid, e):
    if cid == "SIG":
        if e.get("has_signature"):
            return "pass", None
        return "fail", "no .sig file"
    if cid == "LIC":
        if e.get("has_license"):
            return "pass", None
        return "fail", "no LICENSE file"
    if cid == "DSC":
        if e.get("has_readme"):
            return "pass", None
        return "fail", "no README/model_card"
    if cid == "SEC":
        secrets = e.get("secret_patterns", [])
        if not secrets:
            return "pass", None
        return "fail", f"{len(secrets)} secret(s) detected"
    if cid == "SBM":
        if e.get("has_sbom"):
            return "pass", None
        return "review", "no SBOM"
    if cid == "TST":
        if e.get("has_tests"):
            return "pass", None
        return "review", "no tests/"
    if cid == "DSX":
        if e.get("has_readme") or e.get("has_license"):
            return "pass", None
        return "review", "no documentation found"
    if cid == "VER":
        if e.get("has_version_file") or e.get("has_changelog"):
            return "pass", None
        return "review", "no version file or changelog"
    if cid == "KMS":
        if e.get("kms_key_id") and e.get("key_rotation_enabled"):
            return "pass", None
        issues = []
        if not e.get("kms_key_id"):
            issues.append("no kms_key_id")
        if not e.get("key_rotation_enabled"):
            issues.append("key rotation not enabled")
        return "fail", "; ".join(issues)
    return "review", "unknown control"


def merge_evidence(evidence_list):
    """Merge evidence from multiple audit targets into a single dict.

    For boolean keys, uses OR (any target has it -> True).
    For list keys (like secret_patterns), concatenates.
    """
    if not evidence_list:
        return {}
    merged = {}
    bool_keys = {"has_readme", "has_license", "has_tests", "has_sbom",
                 "has_signature", "has_version_file", "has_changelog"}
    list_keys = {"secret_patterns"}
    for ev in evidence_list:
        for k, v in ev.items():
            if k in bool_keys:
                merged[k] = merged.get(k, False) or bool(v)
            elif k in list_keys:
                merged[k] = merged.get(k, []) + list(v)
            elif k not in merged:
                merged[k] = v
    return merged