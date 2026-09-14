import argparse
import pathlib
import sys

from sneppx_audits.engine import AuditReport


def main(argv=None):
    parser = argparse.ArgumentParser(prog="sneppx-audits", description="AI security audit tool")
    parser.add_argument("--version", action="version", version="sneppx-audits 0.1.0")
    parser.add_argument("target", help="file or directory to audit")
    parser.add_argument("--controls", default=None, help="comma-separated control IDs to run, e.g. SIG,LIC,SEC")
    parser.add_argument("--format", choices=["markdown", "json"], default="markdown")
    parser.add_argument("--out", help="write report to this file instead of stdout")
    parser.add_argument("--strict", action="store_true", help="exit non-zero when rating != pass")
    args = parser.parse_args(argv)

    control_ids = None
    if args.controls:
        control_ids = [c.strip() for c in args.controls.split(",") if c.strip()]

    target = pathlib.Path(args.target)
    if not target.exists():
        print(f"error: target not found: {target}", file=sys.stderr)
        return 2

    report = AuditReport(target)
    report.collect_evidence()
    controls = report.evaluate_controls(control_ids=control_ids or None)

    if args.format == "json":
        text = report.render_json(controls)
    else:
        text = report.render_markdown(controls)

    if args.out:
        pathlib.Path(args.out).write_text(text, encoding="utf-8")
        print(f"report written -> {args.out}")
    else:
        print(text)

    rating = report.rating(controls)
    if args.strict and rating != "pass":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())