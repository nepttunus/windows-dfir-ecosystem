from __future__ import annotations

import csv
import json
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


@dataclass
class Finding:
    severity: str
    title: str
    description: str
    evidence: list[str]
    score: int = 0
    category: str = "general"
    confidence: str = "medium"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def load_json(path: Path) -> Any:
    if not path.exists():
        return None
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def load_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def first_existing(base: Path, candidates: list[str]) -> Path | None:
    for candidate in candidates:
        target = base / candidate
        if target.exists():
            return target
    return None


def collect_case_data(case_path: Path) -> dict[str, Any]:
    summary_path = first_existing(case_path, ["00_case/summary.json"])
    system_path = first_existing(case_path, ["01_system/computer_info.json"])
    processes_path = first_existing(case_path, ["04_execution/processes.csv"])
    services_path = first_existing(case_path, ["04_execution/services.csv"])
    tasks_path = first_existing(case_path, ["03_persistence/scheduled_tasks.csv"])
    defenders_path = first_existing(case_path, ["07_security/defender_threats.json"])
    defender_status_path = first_existing(case_path, ["07_security/defender_status.json"])
    listeners_path = first_existing(case_path, ["05_network/tcp_listeners.csv"])
    run_keys_path = first_existing(case_path, ["03_persistence/run_keys.csv"])
    recent_files_path = first_existing(case_path, ["08_timeline/recent_files.csv"])
    wmi_subscriptions_path = first_existing(case_path, ["03_persistence/wmi_subscriptions.json"])
    usb_history_path = first_existing(case_path, ["01_system/usb/usbstor.json"])

    return {
        "summary": load_json(summary_path) if summary_path else {},
        "computer_info": load_json(system_path) if system_path else {},
        "processes": load_csv(processes_path) if processes_path else [],
        "services": load_csv(services_path) if services_path else [],
        "tasks": load_csv(tasks_path) if tasks_path else [],
        "defender_threats": load_json(defenders_path) if defenders_path else [],
        "defender_status": load_json(defender_status_path) if defender_status_path else {},
        "tcp_listeners": load_csv(listeners_path) if listeners_path else [],
        "run_keys": load_csv(run_keys_path) if run_keys_path else [],
        "recent_files": load_csv(recent_files_path) if recent_files_path else [],
        "wmi_subscriptions": load_json(wmi_subscriptions_path) if wmi_subscriptions_path else {},
        "usb_history": load_json(usb_history_path) if usb_history_path else [],
    }


def suspicious_path(value: str | None) -> bool:
    if not value:
        return False
    test = str(value).lower()
    suspects = [
        "\\appdata\\",
        "\\users\\public\\",
        "\\temp\\",
        "\\programdata\\",
        "\\downloads\\",
        "\\recycle.bin\\",
    ]
    return any(token in test for token in suspects)


def encoded_powershell(value: str | None) -> bool:
    if not value:
        return False
    test = str(value).lower()
    return (
        ("powershell" in test and "-enc" in test)
        or ("frombase64string" in test)
        or ("iex" in test)
        or ("downloadstring" in test)
    )


def contains_lolbin(value: str | None) -> str | None:
    if not value:
        return None
    test = str(value).lower()
    lolbins = [
        "rundll32",
        "regsvr32",
        "mshta",
        "wscript",
        "cscript",
        "bitsadmin",
        "certutil",
        "psexec",
    ]
    for item in lolbins:
        if item in test:
            return item
    return None


def suspicious_listener_port(value: str | None) -> bool:
    if not value:
        return False
    return str(value) in {
        "31337",
        "4444",
        "5555",
        "6666",
        "7777",
        "8081",
        "8444",
        "9001",
        "1337",
    }


def _evidence_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if str(item).strip()]
    return [str(value)]


def _wmi_present(wmi_data: Any) -> bool:
    if not wmi_data:
        return False
    if isinstance(wmi_data, dict):
        for key in ("Filters", "Consumers", "Bindings"):
            items = wmi_data.get(key) or []
            if isinstance(items, list) and items:
                return True
    return False


def _wmi_evidence(wmi_data: Any) -> list[str]:
    evidence: list[str] = []
    if isinstance(wmi_data, dict):
        filters = wmi_data.get("Filters") or []
        consumers = wmi_data.get("Consumers") or []
        bindings = wmi_data.get("Bindings") or []
        evidence.append(f"Filters={len(filters)}")
        evidence.append(f"Consumers={len(consumers)}")
        evidence.append(f"Bindings={len(bindings)}")
    return evidence


def _add_finding(findings: list[Finding], finding: Finding) -> None:
    findings.append(finding)


def build_findings(data: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []

    defender_threats = data.get("defender_threats") or []
    if isinstance(defender_threats, dict):
        defender_threats = [defender_threats]

    if defender_threats:
        evidence = []
        for item in defender_threats[:10]:
            threat = item.get("ThreatName") or item.get("ThreatID") or "Unknown threat"
            path = item.get("Resources") or item.get("Path") or item.get("InitialDetectionTime")
            evidence.append(f"{threat}: {path}")
        _add_finding(
            findings,
            Finding(
                severity="high",
                title="Microsoft Defender detections present",
                description="The endpoint reported active or historical Defender detections. Review remediation state, affected paths, and related execution/persistence artefacts.",
                evidence=evidence,
                score=95,
                category="detection",
                confidence="high",
            ),
        )

    for task in data.get("tasks", []) or []:
        action = task.get("Actions", "") or ""
        name = f"{task.get('TaskPath', '')}{task.get('TaskName', '')}"

        if encoded_powershell(action):
            _add_finding(
                findings,
                Finding(
                    severity="high",
                    title="Scheduled task with encoded PowerShell",
                    description=f"Scheduled task {name} contains an encoded PowerShell style action.",
                    evidence=[action],
                    score=90,
                    category="persistence",
                    confidence="high",
                ),
            )
        elif suspicious_path(action):
            _add_finding(
                findings,
                Finding(
                    severity="medium",
                    title="Scheduled task executing from suspicious path",
                    description=f"Scheduled task {name} launches from a user-writable or suspicious location.",
                    evidence=[action],
                    score=70,
                    category="persistence",
                    confidence="medium",
                ),
            )

        lolbin = contains_lolbin(action)
        if lolbin:
            _add_finding(
                findings,
                Finding(
                    severity="medium",
                    title="Scheduled task invokes LOLBin",
                    description=f"Scheduled task {name} invokes a known living-off-the-land binary.",
                    evidence=[action],
                    score=72,
                    category="execution",
                    confidence="medium",
                ),
            )

    for service in data.get("services", []) or []:
        path_name = service.get("PathName", "") or service.get("ExecutablePath", "") or ""
        service_name = service.get("Name") or service.get("DisplayName") or "Unknown service"

        if encoded_powershell(path_name):
            _add_finding(
                findings,
                Finding(
                    severity="high",
                    title="Service command line includes encoded PowerShell",
                    description=f"Service {service_name} has a PowerShell-encoded execution pattern.",
                    evidence=[path_name],
                    score=88,
                    category="execution",
                    confidence="high",
                ),
            )
        elif suspicious_path(path_name):
            _add_finding(
                findings,
                Finding(
                    severity="medium",
                    title="Service executable path looks suspicious",
                    description=f"Service {service_name} points to a user-writable or suspicious location.",
                    evidence=[path_name],
                    score=68,
                    category="persistence",
                    confidence="medium",
                ),
            )

        lolbin = contains_lolbin(path_name)
        if lolbin:
            _add_finding(
                findings,
                Finding(
                    severity="medium",
                    title="Service command uses LOLBin",
                    description=f"Service {service_name} appears to launch via a living-off-the-land binary.",
                    evidence=[path_name],
                    score=70,
                    category="execution",
                    confidence="medium",
                ),
            )

    for item in data.get("run_keys", []) or []:
        value = item.get("ValueData", "") or ""
        key = item.get("RegistryPath", "") or ""

        if encoded_powershell(value):
            _add_finding(
                findings,
                Finding(
                    severity="high",
                    title="Run key with encoded PowerShell",
                    description="A Run/RunOnce persistence entry contains encoded PowerShell.",
                    evidence=[f"{key} => {value}"],
                    score=90,
                    category="persistence",
                    confidence="high",
                ),
            )
        elif suspicious_path(value):
            _add_finding(
                findings,
                Finding(
                    severity="medium",
                    title="Run key points to suspicious path",
                    description="A Run/RunOnce persistence entry points to a suspicious or user-writable location.",
                    evidence=[f"{key} => {value}"],
                    score=72,
                    category="persistence",
                    confidence="medium",
                ),
            )

        lolbin = contains_lolbin(value)
        if lolbin:
            _add_finding(
                findings,
                Finding(
                    severity="medium",
                    title="Run key invokes LOLBin",
                    description="A Run/RunOnce persistence entry appears to launch a living-off-the-land binary.",
                    evidence=[f"{key} => {value}"],
                    score=74,
                    category="execution",
                    confidence="medium",
                ),
            )

    listeners = data.get("tcp_listeners", []) or []
    unusual = []
    highly_suspicious = []
    for row in listeners:
        local_port = row.get("LocalPort", "")
        owning_process = row.get("OwningProcess", "")
        local_addr = row.get("LocalAddress", "")
        entry = f"{local_addr}:{local_port} pid={owning_process}"
        if local_port and local_port not in {"80", "443", "3389", "445", "139", "135"}:
            unusual.append(entry)
        if suspicious_listener_port(local_port):
            highly_suspicious.append(entry)

    if unusual:
        _add_finding(
            findings,
            Finding(
                severity="low",
                title="Non-standard TCP listeners identified",
                description="The collector identified TCP listeners outside a small common-port allowlist. This is not necessarily malicious but may require analyst review.",
                evidence=unusual[:20],
                score=45,
                category="network",
                confidence="low",
            ),
        )

    if highly_suspicious:
        _add_finding(
            findings,
            Finding(
                severity="medium",
                title="Potentially suspicious listener ports observed",
                description="The collector identified listeners on ports commonly associated with implants, backdoors, or operator tooling.",
                evidence=highly_suspicious[:20],
                score=78,
                category="network",
                confidence="medium",
            ),
        )

    defender_status = data.get("defender_status") or {}
    if defender_status:
        if defender_status.get("RealTimeProtectionEnabled") is False:
            _add_finding(
                findings,
                Finding(
                    severity="medium",
                    title="Defender real-time protection disabled",
                    description="Microsoft Defender real-time protection was not enabled at collection time.",
                    evidence=[json.dumps(defender_status, ensure_ascii=False)],
                    score=60,
                    category="security_posture",
                    confidence="high",
                ),
            )
        sig_age = defender_status.get("AntivirusSignatureAge")
        if isinstance(sig_age, int) and sig_age > 7:
            _add_finding(
                findings,
                Finding(
                    severity="low",
                    title="Defender signatures appear stale",
                    description="Defender signatures look older than seven days.",
                    evidence=[f"AntivirusSignatureAge={sig_age}"],
                    score=30,
                    category="security_posture",
                    confidence="medium",
                ),
            )

    wmi_subscriptions = data.get("wmi_subscriptions") or {}
    if _wmi_present(wmi_subscriptions):
        _add_finding(
            findings,
            Finding(
                severity="medium",
                title="WMI subscriptions present",
                description="WMI event filters, consumers, or bindings were observed and should be reviewed for persistence.",
                evidence=_wmi_evidence(wmi_subscriptions),
                score=75,
                category="persistence",
                confidence="medium",
            ),
        )

    usb_history = data.get("usb_history") or []
    if isinstance(usb_history, list) and usb_history:
        evidence = [str(item.get("DeviceKey") or item.get("Path") or item) for item in usb_history[:10]]
        _add_finding(
            findings,
            Finding(
                severity="low",
                title="USB storage history present",
                description="USB storage device history was present on the endpoint and may be useful during triage.",
                evidence=evidence,
                score=20,
                category="user_activity",
                confidence="low",
            ),
        )

    compromise_indicators = 0
    for finding in findings:
        if finding.title == "Microsoft Defender detections present":
            compromise_indicators += 1
        if finding.category == "persistence" and finding.severity in {"high", "medium"}:
            compromise_indicators += 1
        if finding.title == "Potentially suspicious listener ports observed":
            compromise_indicators += 1
        if finding.title == "WMI subscriptions present":
            compromise_indicators += 1

    if compromise_indicators >= 2:
        confidence = "high" if compromise_indicators >= 3 else "medium"
        severity = "high" if compromise_indicators >= 3 else "medium"
        score = 92 if compromise_indicators >= 3 else 80
        _add_finding(
            findings,
            Finding(
                severity=severity,
                title="Probable compromise indicators cluster",
                description="Multiple findings across detection, persistence, and/or network activity suggest elevated compromise likelihood and warrant analyst escalation.",
                evidence=[f"indicator_count={compromise_indicators}"],
                score=score,
                category="correlation",
                confidence=confidence,
            ),
        )

    deduped: list[Finding] = []
    seen = set()
    for finding in findings:
        key = (
            finding.severity,
            finding.title,
            finding.category,
            tuple(sorted(set(finding.evidence))),
        )
        if key not in seen:
            seen.add(key)
            deduped.append(finding)

    deduped.sort(key=lambda f: ({"high": 3, "medium": 2, "low": 1}.get(f.severity, 0), f.score), reverse=True)
    return deduped


def build_executive_summary(data: dict[str, Any], findings: list[Finding]) -> str:
    summary = data.get("summary") or {}
    case_id = summary.get("CaseId", "UNKNOWN-CASE")
    host = summary.get("Hostname", "UNKNOWN-HOST")
    profile = summary.get("Profile", "UNKNOWN")
    detections = len(data.get("defender_threats") or [])
    tasks = len(data.get("tasks") or [])
    services = len(data.get("services") or [])
    listeners = len(data.get("tcp_listeners") or [])

    sev_order = {"high": 3, "medium": 2, "low": 1}
    highest = "none"
    if findings:
        highest = sorted((f.severity for f in findings), key=lambda s: sev_order.get(s, 0), reverse=True)[0]

    severity_counts = Counter(f.severity for f in findings)
    category_counts = Counter(f.category for f in findings)

    lines = [
        f"# Executive Summary — {case_id}",
        "",
        f"- Host: **{host}**",
        f"- Profile: **{profile}**",
        f"- Defender detections returned: **{detections}**",
        f"- Scheduled tasks collected: **{tasks}**",
        f"- Services collected: **{services}**",
        f"- TCP listeners collected: **{listeners}**",
        f"- Highest finding severity: **{highest.upper()}**",
        "",
        "## Finding distribution",
        "",
        f"- High: **{severity_counts.get('high', 0)}**",
        f"- Medium: **{severity_counts.get('medium', 0)}**",
        f"- Low: **{severity_counts.get('low', 0)}**",
        "",
    ]

    if category_counts:
        top_categories = category_counts.most_common(5)
        lines.extend([
            "## Top categories",
            "",
        ])
        for category, count in top_categories:
            lines.append(f"- **{category}**: {count}")
        lines.append("")

    if findings:
        lines.extend([
            "## Key findings",
            "",
        ])
        for finding in findings[:8]:
            lines.append(f"- **{finding.severity.upper()}** — {finding.title}: {finding.description}")
        lines.append("")

    lines.extend([
        "## Analyst note",
        "",
        "This report is based on triage artefacts and heuristic detections. It supports, but does not replace, detailed forensic examination.",
    ])
    return "\n".join(lines)
