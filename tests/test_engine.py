import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from sneppx_audits.engine import AuditReport, file_sha256  # noqa: E402


def _good_project(tmp):
    d = tmp / "good"
    d.mkdir()
    (d / "model.bin").write_bytes(b"model")
    (d / "LICENSE").write_text("MIT", encoding="utf-8")
    (d / "model_card.md").write_text("# Model card", encoding="utf-8")
    (d / "model.bin.sig").write_text("{}", encoding="utf-8")
    (d / "sbom.json").write_text("{}", encoding="utf-8")
    t = d / "tests"
    t.mkdir()
    (t / "test_model.py").write_text("pass", encoding="utf-8")
    return d


def _bad_project(tmp):
    d = tmp / "bad"
    d.mkdir()
    (d / "app.py").write_text('API_KEY="sk-abcdefgh12345678"\n', encoding="utf-8")
    return d


def test_good_project(tmp_path):
    d = _good_project(tmp_path)
    r = AuditReport(d)
    e = r.collect_evidence()
    assert e["has_signature"] is True
    assert e["has_license"] is True
    assert e["has_tests"] is True
    controls = r.evaluate_controls()
    assert r.rating(controls) == "pass"
    assert all(c["status"] == "pass" for c in controls)
    md = r.render_markdown(controls)
    assert "# AI Security Audit Report" in md


def test_bad_project(tmp_path):
    d = _bad_project(tmp_path)
    r = AuditReport(d)
    e = r.collect_evidence()
    assert len(e["secret_patterns"]) >= 1
    controls = r.evaluate_controls()
    assert r.rating(controls) in {"fail", "review"}


def test_selective_controls(tmp_path):
    d = _good_project(tmp_path)
    r = AuditReport(d)
    r.collect_evidence()
    controls = r.evaluate_controls(control_ids=[("LIC",)])
    assert len(controls) == 1
    assert controls[0]["status"] == "pass"


def test_file_sha256(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"hello")
    digest = file_sha256(f)
    import hashlib
    assert digest == hashlib.sha256(b"hello").hexdigest()


def test_report_json(tmp_path):
    d = _good_project(tmp_path)
    r = AuditReport(d)
    r.collect_evidence()
    controls = r.evaluate_controls()
    j = json.loads(r.render_json(controls))
    assert j["rating"] == "pass"