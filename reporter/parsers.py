from __future__ import annotations

import csv
import json
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any


@dataclass
class Finding:
    severity: str
    title: str
    description: str
    evidence: list[str]

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
    summary_path = first_existing(case_path, [
        "00_case/summary.json",
    ])
    system_path = first_existing(case_path, [
        "01_system/computer_info.json",
    ])
    processes_path = first_existing(case_path, [
        "04_execution/processes.csv",
    ])
    services_path = first_existing(case_path, [
        "04_execution/services.csv",
    ])
    tasks_path = first_existing(case_path, [
        "03_persistence/scheduled_tasks.csv",
    ])
    defenders_path = first_existing(case_path, [
        "07_security/defender_threats.json",
    ])
    defender_status_path = first_existing(case_path, [
        "07_security/defender_status.json",
    ])
    listeners_path = first_existing(case_path, [
        "05_network/tcp_listeners.csv",
    ])
    run_keys_path = first_existing(case_path, [
        "03_persistence/run_keys.csv",
    ])

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
    }


def suspicious_path(value: str | None) -> bool:
    if not value:
        return False
    test = value.lower()
    suspects = [
        r"\appdata\\",
        r"\users\public\\",
        r"\temp\\",
        r"\programdata\\",
        r"\downloads\\",
        r"\recycle.bin\\",
    ]
    return any(token in test for token in suspects)


def encoded_powershell(value: str | None) -> bool:
    if not value:
        return False
    test = value.lower()
    return ("powershell" in test and "-enc" in test) or ("frombase64string" in test)


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
        findings.append(
            Finding(
                severity="high",
                title="Microsoft Defender detections present",
                description="The endpoint reported active or historical Defender detections. Review remediation state, affected paths, and related execution/persistence artefacts.",
                evidence=evidence,
            )
        )

    for task in data.get("tasks", []):
        action = task.get("Actions", "") or ""
        name = f"{task.get('TaskPath', '')}{task.get('TaskName', '')}"
        if encoded_powershell(action):
            findings.append(
                Finding(
                    severity="high",
                    title="Scheduled task with encoded PowerShell",
                    description=f"Scheduled task {name} contains an encoded PowerShell style action.",
                    evidence=[action],
                )
            )
        elif suspicious_path(action):
            findings.append(
                Finding(
                    severity="medium",
                    title="Scheduled task executing from suspicious path",
                    description=f"Scheduled task {name} launches from a user-writable or suspicious location.",
                    evidence=[action],
                )
            )

    for service in data.get("services", []):
        path_name = service.get("PathName", "") or service.get("ExecutablePath", "") or ""
        service_name = service.get("Name") or service.get("DisplayName") or "Unknown service"
        if encoded_powershell(path_name):
            findings.append(
                Finding(
                    severity="high",
                    title="Service command line includes encoded PowerShell",
                    description=f"Service {service_name} has a PowerShell-encoded execution pattern.",
                    evidence=[path_name],
                )
            )
        elif suspicious_path(path_name):
            findings.append(
                Finding(
                    severity="medium",
                    title="Service executable path looks suspicious",
                    description=f"Service {service_name} points to a user-writable or suspicious location.",
                    evidence=[path_name],
                )
            )

    for item in data.get("run_keys", []):
        value = item.get("ValueData", "") or ""
        key = item.get("RegistryPath", "") or ""
        if encoded_powershell(value):
            findings.append(
                Finding(
                    severity="high",
                    title="Run key with encoded PowerShell",
                    description="A Run/RunOnce persistence entry contains encoded PowerShell.",
                    evidence=[f"{key} => {value}"],
                )
            )
        elif suspicious_path(value):
            findings.append(
                Finding(
                    severity="medium",
                    title="Run key points to suspicious path",
                    description="A Run/RunOnce persistence entry points to a suspicious or user-writable location.",
                    evidence=[f"{key} => {value}"],
                )
            )

    listeners = data.get("tcp_listeners", [])
    unusual = []
    for row in listeners:
        local_port = row.get("LocalPort", "")
        owning_process = row.get("OwningProcess", "")
        local_addr = row.get("LocalAddress", "")
        if local_port and local_port not in {"80", "443", "3389", "445", "139", "135"}:
            unusual.append(f"{local_addr}:{local_port} pid={owning_process}")
    if unusual:
        findings.append(
            Finding(
                severity="low",
                title="Non-standard TCP listeners identified",
                description="The collector identified TCP listeners outside a small common-port allowlist. This is not necessarily malicious but may require analyst review.",
                evidence=unusual[:20],
            )
        )

    defender_status = data.get("defender_status") or {}
    if defender_status:
        if defender_status.get("RealTimeProtectionEnabled") is False:
            findings.append(
                Finding(
                    severity="medium",
                    title="Defender real-time protection disabled",
                    description="Microsoft Defender real-time protection was not enabled at collection time.",
                    evidence=[json.dumps(defender_status, ensure_ascii=False)],
                )
            )
        sig_age = defender_status.get("AntivirusSignatureAge")
        if isinstance(sig_age, int) and sig_age > 7:
            findings.append(
                Finding(
                    severity="low",
                    title="Defender signatures appear stale",
                    description="Defender signatures look older than seven days.",
                    evidence=[f"AntivirusSignatureAge={sig_age}"],
                )
            )

    deduped: list[Finding] = []
    seen = set()
    for finding in findings:
        key = (finding.severity, finding.title, tuple(finding.evidence))
        if key not in seen:
            seen.add(key)
            deduped.append(finding)
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
    ]

    if findings:
        lines.append("## Key findings")
        lines.append("")
        for finding in findings[:10]:
            lines.append(f"- **{finding.severity.upper()}** — {finding.title}: {finding.description}")
    else:
        lines.append("No heuristic findings were raised by the current parsing rules. Manual review is still required.")
    lines.append("")
    lines.append("## Analyst note")
    lines.append("")
    lines.append("This report is based on triage artefacts and simple heuristics. It supports, but does not replace, detailed forensic examination.")
    return "\n".join(lines)
