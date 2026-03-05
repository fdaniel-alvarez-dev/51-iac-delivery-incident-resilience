from __future__ import annotations

import argparse
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, List, Optional, Sequence

from .engine import Engine, Finding, Severity


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _read_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def _write_text(path: Path, text: str) -> None:
    _ensure_dir(path.parent)
    path.write_text(text, encoding="utf-8")


def _repo_root(default: Optional[str] = None) -> Path:
    if default:
        return Path(default).resolve()
    return Path.cwd().resolve()


@dataclass(frozen=True)
class Inputs:
    desired_iac: Path
    current_iac: Path
    pipeline: Path
    incident: Path


def _resolve_inputs(examples_dir: Path) -> Inputs:
    desired_iac = examples_dir / "iac" / "desired_state.json"
    current_iac = examples_dir / "iac" / "current_state.json"
    pipeline = examples_dir / "cicd" / "pipeline.json"
    incident = examples_dir / "incidents" / "incident.json"
    return Inputs(desired_iac=desired_iac, current_iac=current_iac, pipeline=pipeline, incident=incident)


def _validate_examples_exist(inputs: Inputs) -> List[str]:
    missing = []
    for label, path in [
        ("desired IaC snapshot", inputs.desired_iac),
        ("current IaC snapshot", inputs.current_iac),
        ("CI/CD pipeline", inputs.pipeline),
        ("incident timeline", inputs.incident),
    ]:
        if not path.exists():
            missing.append(f"Missing {label}: {path}")
    return missing


def _render_report(findings: Sequence[Finding], meta: dict) -> str:
    by_sev: dict[Severity, list[Finding]] = {s: [] for s in Severity}
    for f in findings:
        by_sev[f.severity].append(f)

    def section(title: str) -> str:
        return f"\n## {title}\n"

    lines: list[str] = []
    lines.append(f"# Portfolio Proof Report\n")
    lines.append(f"- Generated (UTC): `{meta['generated_utc']}`")
    lines.append(f"- Examples: `{meta['examples_dir']}`")
    lines.append("")
    lines.append("This report maps directly to the three business pain points:")
    lines.append("")
    lines.append("1. Infrastructure drift & fragile automation (IaC guardrails + drift detection)")
    lines.append("2. Delivery friction (CI/CD reliability + safe release patterns)")
    lines.append("3. Reliability under on-call pressure (incident readiness + runbooks)")

    lines.append(section("Validation Summary"))
    lines.append(f"- Total findings: **{len(findings)}**")
    lines.append(f"- Critical: **{len(by_sev[Severity.CRITICAL])}**")
    lines.append(f"- High: **{len(by_sev[Severity.HIGH])}**")
    lines.append(f"- Medium: **{len(by_sev[Severity.MEDIUM])}**")
    lines.append(f"- Low: **{len(by_sev[Severity.LOW])}**")

    lines.append(section("Findings"))
    if not findings:
        lines.append("- No findings. (This is unusual for a realistic system.)")
        return "\n".join(lines).rstrip() + "\n"

    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
        items = by_sev[sev]
        if not items:
            continue
        lines.append(f"\n### {sev.value}")
        for f in items:
            lines.append(f"- **{f.code}** — {f.title}")
            lines.append(f"  - Scope: `{f.scope}`")
            if f.evidence:
                lines.append(f"  - Evidence: {f.evidence}")
            if f.recommendation:
                lines.append(f"  - Recommendation: {f.recommendation}")
            if f.runbook:
                lines.append(f"  - Runbook: `{f.runbook}`")

    lines.append(section("Next Steps (what I would do in the role)"))
    lines.append("- Wire these checks into CI so risky changes fail before merge.")
    lines.append("- Replace offline snapshots with real data sources (Terraform plan/state, cloud inventory, k8s APIs).")
    lines.append("- Add SLOs + alert quality gates and link incidents to automated guardrails.")

    return "\n".join(lines).rstrip() + "\n"


def cmd_report(args: argparse.Namespace) -> int:
    repo_root = _repo_root(args.repo_root)
    examples_dir = (repo_root / args.examples).resolve()
    artifacts_dir = (repo_root / args.artifacts).resolve()

    inputs = _resolve_inputs(examples_dir)
    missing = _validate_examples_exist(inputs)
    if missing:
        for m in missing:
            print(m)
        return 2

    desired = _read_json(inputs.desired_iac)
    current = _read_json(inputs.current_iac)
    pipeline = _read_json(inputs.pipeline)
    incident = _read_json(inputs.incident)

    engine = Engine(
        desired_iac=desired,
        current_iac=current,
        pipeline=pipeline,
        incident=incident,
        repo_root=str(repo_root),
    )
    findings = engine.run()

    meta = {"generated_utc": _utc_now_iso(), "examples_dir": str(examples_dir)}
    report = _render_report(findings, meta=meta)

    out_path = artifacts_dir / "report.md"
    _write_text(out_path, report)
    print(f"Wrote {out_path}")
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    repo_root = _repo_root(args.repo_root)
    examples_dir = (repo_root / args.examples).resolve()
    inputs = _resolve_inputs(examples_dir)
    missing = _validate_examples_exist(inputs)
    if missing:
        for m in missing:
            print(m)
        return 2

    desired = _read_json(inputs.desired_iac)
    current = _read_json(inputs.current_iac)
    pipeline = _read_json(inputs.pipeline)
    incident = _read_json(inputs.incident)

    engine = Engine(
        desired_iac=desired,
        current_iac=current,
        pipeline=pipeline,
        incident=incident,
        repo_root=str(repo_root),
    )
    findings = engine.run()

    failing = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
    if args.strict:
        failing = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)]

    if not failing:
        return 0

    print("Validation failed. Blocking findings:")
    for f in failing:
        print(f"- {f.severity.value}: {f.code} — {f.title} ({f.scope})")
    return 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="portfolio_proof",
        description="Offline policy-as-code demo for IaC, CI/CD, and incident readiness.",
    )
    p.add_argument("--repo-root", default=None, help="Override repo root (default: CWD).")
    sub = p.add_subparsers(dest="cmd", required=True)

    pr = sub.add_parser("report", help="Generate artifacts/report.md from examples.")
    pr.add_argument("--examples", default="examples", help="Examples directory (relative to repo root).")
    pr.add_argument("--artifacts", default="artifacts", help="Artifacts directory (relative to repo root).")
    pr.set_defaults(func=cmd_report)

    pv = sub.add_parser("validate", help="Exit non-zero if key controls fail.")
    pv.add_argument("--examples", default="examples", help="Examples directory (relative to repo root).")
    pv.add_argument("--strict", action="store_true", help="Fail on Medium findings too.")
    pv.set_defaults(func=cmd_validate)
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    os.environ.pop("GITHUB_TOKEN", None)  # guardrail: never accidentally print it via env dumps
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))
