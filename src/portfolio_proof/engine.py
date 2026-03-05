from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


class Severity(Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


@dataclass(frozen=True)
class Finding:
    code: str
    title: str
    severity: Severity
    scope: str
    evidence: str = ""
    recommendation: str = ""
    runbook: str = ""


def _get(d: dict, path: str, default: Any = None) -> Any:
    cur: Any = d
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


class Engine:
    def __init__(
        self,
        *,
        desired_iac: dict,
        current_iac: dict,
        pipeline: dict,
        incident: dict,
        repo_root: str,
    ) -> None:
        self.desired_iac = desired_iac
        self.current_iac = current_iac
        self.pipeline = pipeline
        self.incident = incident
        self.repo_root = Path(repo_root)

    def run(self) -> List[Finding]:
        findings: List[Finding] = []
        findings.extend(self._check_iac_drift_and_guardrails())
        findings.extend(self._check_cicd_reliability_and_release_safety())
        findings.extend(self._check_incident_readiness())
        return findings

    # -------------------------------------------------------------------------
    # Pain point 1: Infrastructure drift & fragile automation (IaC)
    # -------------------------------------------------------------------------
    def _check_iac_drift_and_guardrails(self) -> List[Finding]:
        f: List[Finding] = []

        desired_clusters = _get(self.desired_iac, "kubernetes_clusters", []) or []
        current_clusters = _get(self.current_iac, "kubernetes_clusters", []) or []

        desired_by = {c.get("name"): c for c in desired_clusters if isinstance(c, dict) and c.get("name")}
        current_by = {c.get("name"): c for c in current_clusters if isinstance(c, dict) and c.get("name")}

        missing = sorted(set(desired_by) - set(current_by))
        if missing:
            f.append(
                Finding(
                    code="IAC_DRIFT_MISSING_CLUSTER",
                    title="Desired Kubernetes clusters missing from current state",
                    severity=Severity.HIGH,
                    scope="iac/kubernetes",
                    evidence=f"Missing clusters: {', '.join(missing)}",
                    recommendation="Ensure clusters are created via IaC and converge current state to desired.",
                    runbook="docs/runbooks/iac-drift-and-change-control.md",
                )
            )

        for name, desired in desired_by.items():
            current = current_by.get(name)
            if not current:
                continue
            if desired.get("version") != current.get("version"):
                f.append(
                    Finding(
                        code="IAC_DRIFT_K8S_VERSION",
                        title="Kubernetes version drift detected",
                        severity=Severity.HIGH,
                        scope=f"iac/kubernetes/{name}",
                        evidence=f"desired={desired.get('version')} current={current.get('version')}",
                        recommendation="Pin versions and upgrade with a controlled plan (blue/green or surge).",
                        runbook="docs/runbooks/iac-drift-and-change-control.md",
                    )
                )
            if bool(desired.get("private_api")) and not bool(current.get("private_api")):
                f.append(
                    Finding(
                        code="IAC_GUARDRAIL_PRIVATE_API",
                        title="Cluster API endpoint should be private",
                        severity=Severity.MEDIUM,
                        scope=f"iac/kubernetes/{name}",
                        evidence="desired private_api=true but current private_api=false",
                        recommendation="Restrict Kubernetes API exposure; route access through VPN/bastion with auditing.",
                        runbook="docs/runbooks/iac-drift-and-change-control.md",
                    )
                )

        desired_tf = _get(self.desired_iac, "toolchain.terraform_required_version", "")
        current_tf = _get(self.current_iac, "toolchain.terraform_required_version", "")
        if desired_tf and current_tf and desired_tf != current_tf:
            f.append(
                Finding(
                    code="IAC_TOOLCHAIN_VERSION",
                    title="Terraform required version differs from desired baseline",
                    severity=Severity.MEDIUM,
                    scope="iac/toolchain",
                    evidence=f"desired={desired_tf} current={current_tf}",
                    recommendation="Standardize and enforce toolchain versions in CI to reduce environment drift.",
                    runbook="docs/runbooks/iac-drift-and-change-control.md",
                )
            )

        if not bool(_get(self.current_iac, "toolchain.providers_pinned", False)):
            f.append(
                Finding(
                    code="IAC_PROVIDERS_NOT_PINNED",
                    title="Terraform providers are not pinned",
                    severity=Severity.HIGH,
                    scope="iac/toolchain",
                    evidence="providers_pinned=false",
                    recommendation="Pin provider versions to avoid surprise diffs and brittle automation across environments.",
                    runbook="docs/runbooks/iac-drift-and-change-control.md",
                )
            )

        # Edge and data guardrails (Cloudflare + MongoDB) to mirror the JD focus areas.
        desired_waf = bool(_get(self.desired_iac, "edge.cloudflare.waf_enabled", False))
        current_waf = bool(_get(self.current_iac, "edge.cloudflare.waf_enabled", False))
        if desired_waf and not current_waf:
            f.append(
                Finding(
                    code="EDGE_WAF_DISABLED",
                    title="WAF expected but disabled at the edge",
                    severity=Severity.HIGH,
                    scope="edge/cloudflare",
                    evidence="desired waf_enabled=true but current waf_enabled=false",
                    recommendation="Enable WAF and enforce TLS strict mode to reduce exploit and misrouting risk.",
                    runbook="docs/runbooks/iac-drift-and-change-control.md",
                )
            )

        desired_tls = _get(self.desired_iac, "edge.cloudflare.tls_mode", "")
        current_tls = _get(self.current_iac, "edge.cloudflare.tls_mode", "")
        if desired_tls and current_tls and desired_tls != current_tls:
            f.append(
                Finding(
                    code="EDGE_TLS_MODE_DRIFT",
                    title="TLS mode drift detected at the edge",
                    severity=Severity.MEDIUM,
                    scope="edge/cloudflare",
                    evidence=f"desired={desired_tls} current={current_tls}",
                    recommendation="Use strict TLS to prevent downgrade and origin spoofing scenarios.",
                    runbook="docs/runbooks/iac-drift-and-change-control.md",
                )
            )

        desired_vpn = bool(_get(self.desired_iac, "network.vpn_required", False))
        current_vpn = bool(_get(self.current_iac, "network.vpn_required", False))
        if desired_vpn and not current_vpn:
            f.append(
                Finding(
                    code="NET_VPN_REQUIRED",
                    title="VPN requirement not enforced for administrative access",
                    severity=Severity.MEDIUM,
                    scope="network/access",
                    evidence="desired vpn_required=true but current vpn_required=false",
                    recommendation="Enforce VPN/bastion access paths for admin surfaces (k8s API, DB admin, proxies).",
                    runbook="docs/runbooks/iac-drift-and-change-control.md",
                )
            )

        desired_redirect = bool(_get(self.desired_iac, "network.reverse_proxy.http_to_https_redirect", False))
        current_redirect = bool(_get(self.current_iac, "network.reverse_proxy.http_to_https_redirect", False))
        if desired_redirect and not current_redirect:
            f.append(
                Finding(
                    code="NET_HTTP_TO_HTTPS",
                    title="Reverse proxy should enforce HTTP→HTTPS redirect",
                    severity=Severity.MEDIUM,
                    scope="network/reverse_proxy",
                    evidence="http_to_https_redirect=false",
                    recommendation="Enforce HTTPS and redirect HTTP to reduce downgrade and cookie leakage risk.",
                    runbook="docs/runbooks/iac-drift-and-change-control.md",
                )
            )

        desired_backup = bool(_get(self.desired_iac, "data.mongodb.backup_enabled", False))
        current_backup = bool(_get(self.current_iac, "data.mongodb.backup_enabled", False))
        if desired_backup and not current_backup:
            f.append(
                Finding(
                    code="DATA_BACKUP_DISABLED",
                    title="MongoDB backups expected but disabled",
                    severity=Severity.CRITICAL,
                    scope="data/mongodb",
                    evidence="backup_enabled=false",
                    recommendation="Enable automated backups and validate restores; define RPO/RTO and monitor backup health.",
                    runbook="docs/runbooks/incident-response-and-mttr.md",
                )
            )

        required_tags = set(_get(self.desired_iac, "tags_required", []) or [])
        observed_tags = set(_get(self.current_iac, "observed_tags", []) or [])
        missing_tags = sorted(required_tags - observed_tags)
        if missing_tags:
            f.append(
                Finding(
                    code="IAC_METADATA_MISSING",
                    title="Required ownership/metadata tags missing",
                    severity=Severity.MEDIUM,
                    scope="iac/metadata",
                    evidence=f"Missing tags: {', '.join(missing_tags)}",
                    recommendation="Enforce tagging/labels for ownership, environment parity, and auditability.",
                    runbook="docs/runbooks/iac-drift-and-change-control.md",
                )
            )

        return f

    # -------------------------------------------------------------------------
    # Pain point 2: Delivery friction (CI/CD)
    # -------------------------------------------------------------------------
    def _check_cicd_reliability_and_release_safety(self) -> List[Finding]:
        f: List[Finding] = []
        stages = self.pipeline.get("stages", [])
        if not isinstance(stages, list):
            stages = []

        def stage(name: str) -> Optional[dict]:
            for s in stages:
                if isinstance(s, dict) and s.get("name") == name:
                    return s
            return None

        for required in ["build", "test", "deploy"]:
            if stage(required) is None:
                f.append(
                    Finding(
                        code="CICD_MISSING_STAGE",
                        title=f"Pipeline stage missing: {required}",
                        severity=Severity.HIGH,
                        scope="cicd/pipeline",
                        evidence=f"stages={', '.join([str(s.get('name')) for s in stages if isinstance(s, dict)])}",
                        recommendation="Define explicit build/test/deploy boundaries to reduce hidden coupling and flaky releases.",
                        runbook="docs/runbooks/cicd-flakiness-and-release-safety.md",
                    )
                )

        for s in stages:
            if not isinstance(s, dict):
                continue
            timeout = s.get("timeout_minutes")
            if not isinstance(timeout, int) or timeout <= 0:
                f.append(
                    Finding(
                        code="CICD_TIMEOUTS",
                        title="Stage timeouts are missing or invalid",
                        severity=Severity.MEDIUM,
                        scope=f"cicd/stage/{s.get('name', 'unknown')}",
                        evidence=f"timeout_minutes={timeout!r}",
                        recommendation="Add timeouts so hangs fail fast and do not block delivery.",
                        runbook="docs/runbooks/cicd-flakiness-and-release-safety.md",
                    )
                )

        build = stage("build") or {}
        if bool(build.get("produces_artifact")) and not bool(build.get("artifact_immutable")):
            f.append(
                Finding(
                    code="CICD_MUTABLE_ARTIFACT",
                    title="Build artifacts should be immutable",
                    severity=Severity.HIGH,
                    scope="cicd/build",
                    evidence="artifact_immutable=false",
                    recommendation="Use content-addressed artifacts or versioned images to prevent ‘it changed after tests’.",
                    runbook="docs/runbooks/cicd-flakiness-and-release-safety.md",
                )
            )

        test = stage("test") or {}
        if not bool(test.get("flaky_test_quarantine")):
            f.append(
                Finding(
                    code="CICD_FLAKY_TESTS",
                    title="No mechanism to quarantine or track flaky tests",
                    severity=Severity.MEDIUM,
                    scope="cicd/test",
                    evidence="flaky_test_quarantine=false",
                    recommendation="Add quarantine/labeling and track flake rate to keep pipelines reliable.",
                    runbook="docs/runbooks/cicd-flakiness-and-release-safety.md",
                )
            )
        if isinstance(test.get("parallelism"), int) and test.get("parallelism", 1) < 2:
            f.append(
                Finding(
                    code="CICD_LOW_PARALLELISM",
                    title="Test parallelism is low (delivery friction risk)",
                    severity=Severity.LOW,
                    scope="cicd/test",
                    evidence=f"parallelism={test.get('parallelism')}",
                    recommendation="Parallelize tests and cache dependencies to shorten feedback loops.",
                    runbook="docs/runbooks/cicd-flakiness-and-release-safety.md",
                )
            )

        deploy = stage("deploy") or {}
        strategy = str(deploy.get("strategy", ""))
        if strategy not in {"canary", "progressive", "blue-green"}:
            f.append(
                Finding(
                    code="CICD_RELEASE_STRATEGY",
                    title="Release strategy is risky (no canary/progressive delivery)",
                    severity=Severity.HIGH,
                    scope="cicd/deploy",
                    evidence=f"strategy={strategy!r}",
                    recommendation="Use canary/progressive delivery to reduce blast radius.",
                    runbook="docs/runbooks/cicd-flakiness-and-release-safety.md",
                )
            )

        rollback_plan = str(deploy.get("rollback_plan", "")).strip()
        if not rollback_plan:
            f.append(
                Finding(
                    code="CICD_ROLLBACK_MISSING",
                    title="Rollback plan is missing",
                    severity=Severity.HIGH,
                    scope="cicd/deploy",
                    evidence="rollback_plan is empty",
                    recommendation="Document and test rollback. Make it a first-class pipeline capability.",
                    runbook="docs/runbooks/cicd-flakiness-and-release-safety.md",
                )
            )

        rel = self.pipeline.get("release", {})
        if isinstance(rel, dict) and not bool(rel.get("requires_approval")):
            f.append(
                Finding(
                    code="CICD_NO_APPROVAL",
                    title="No release approval/guardrail configured",
                    severity=Severity.LOW,
                    scope="cicd/release",
                    evidence="requires_approval=false",
                    recommendation="Add lightweight approvals or policy checks for high-risk deploys (prod, schema changes).",
                    runbook="docs/runbooks/cicd-flakiness-and-release-safety.md",
                )
            )

        return f

    # -------------------------------------------------------------------------
    # Pain point 3: Reliability under on-call pressure (incidents)
    # -------------------------------------------------------------------------
    def _check_incident_readiness(self) -> List[Finding]:
        f: List[Finding] = []
        timeline = self.incident.get("timeline", [])
        if not isinstance(timeline, list) or len(timeline) < 3:
            f.append(
                Finding(
                    code="INC_TIMELINE_THIN",
                    title="Incident timeline is too thin for fast recovery",
                    severity=Severity.MEDIUM,
                    scope="incident/timeline",
                    evidence=f"events={len(timeline) if isinstance(timeline, list) else 'invalid'}",
                    recommendation="Capture detection, acknowledge, mitigation, and resolution timestamps consistently.",
                    runbook="docs/runbooks/incident-response-and-mttr.md",
                )
            )

        comms = self.incident.get("communications", {})
        status_updates = 0
        if isinstance(comms, dict):
            status_updates = int(comms.get("status_page_updates", 0) or 0)
        if status_updates < 1:
            f.append(
                Finding(
                    code="INC_COMMS_MISSING",
                    title="No customer-facing status updates recorded",
                    severity=Severity.MEDIUM,
                    scope="incident/communications",
                    evidence=f"status_page_updates={status_updates}",
                    recommendation="Define an update cadence and keep stakeholders informed to reduce confusion and toil.",
                    runbook="docs/runbooks/incident-response-and-mttr.md",
                )
            )

        expected = self.incident.get("runbooks_expected", [])
        if not isinstance(expected, list) or not expected:
            f.append(
                Finding(
                    code="INC_RUNBOOKS_UNSPECIFIED",
                    title="Incident does not reference expected runbooks",
                    severity=Severity.HIGH,
                    scope="incident/runbooks",
                    evidence="runbooks_expected missing/empty",
                    recommendation="Link incidents to runbooks so responders can execute known-good steps quickly.",
                    runbook="docs/runbooks/incident-response-and-mttr.md",
                )
            )
            return f

        missing = []
        for rb in expected:
            if not isinstance(rb, str) or not rb.strip():
                continue
            if not (self.repo_root / rb).exists():
                missing.append(rb)
        if missing:
            f.append(
                Finding(
                    code="INC_RUNBOOKS_MISSING",
                    title="Expected runbooks referenced but missing on disk",
                    severity=Severity.HIGH,
                    scope="incident/runbooks",
                    evidence=f"Missing: {', '.join(missing)}",
                    recommendation="Ensure runbooks are versioned, accessible, and reviewed like code.",
                    runbook="docs/runbooks/incident-response-and-mttr.md",
                )
            )

        post = self.incident.get("post_incident", {})
        if isinstance(post, dict) and not bool(post.get("rca_completed", False)):
            f.append(
                Finding(
                    code="INC_RCA_NOT_DONE",
                    title="RCA not completed (risk of repeat incidents)",
                    severity=Severity.LOW,
                    scope="incident/post_incident",
                    evidence="rca_completed=false",
                    recommendation="Complete RCA and convert action items into enforced guardrails and tests.",
                    runbook="docs/runbooks/incident-response-and-mttr.md",
                )
            )
        if isinstance(post, dict) and int(post.get("action_items_count", 0) or 0) < 3:
            f.append(
                Finding(
                    code="INC_ACTION_ITEMS_THIN",
                    title="Too few post-incident action items to reduce recurrence",
                    severity=Severity.LOW,
                    scope="incident/post_incident",
                    evidence=f"action_items_count={int(post.get('action_items_count', 0) or 0)}",
                    recommendation="Aim for 3–7 concrete items: guardrails, alerts, and safe rollout improvements.",
                    runbook="docs/runbooks/incident-response-and-mttr.md",
                )
            )

        return f
