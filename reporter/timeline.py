from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _normalize_ts(value: Any) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    if not text:
        return ""
    text = text.replace("Z", "+00:00")
    for candidate in (text, text.split(".")[0]):
        try:
            dt = datetime.fromisoformat(candidate)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        except Exception:
            pass
    return str(value)


def _row(ts: Any, source: str, category: str, severity: str, summary: str, details: str) -> dict[str, str]:
    return {
        "TimestampUtc": _normalize_ts(ts),
        "Source": source,
        "Category": category,
        "Severity": severity.lower(),
        "Summary": summary,
        "Details": details,
    }


def build_timeline(case_path: Path, data: dict[str, Any], findings: list[dict[str, Any]] | None = None) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []

    summary = data.get("summary") or {}
    collected_at = summary.get("CollectedAtUtc") or ""
    if collected_at:
        rows.append(_row(
            collected_at,
            "collector",
            "collection",
            "low",
            "Case collection completed",
            f"CaseId={summary.get('CaseId', '')} Hostname={summary.get('Hostname', '')} Profile={summary.get('Profile', '')}",
        ))

    defender_threats = data.get("defender_threats") or []
    if isinstance(defender_threats, dict):
        defender_threats = [defender_threats]

    for item in defender_threats:
        ts = item.get("InitialDetectionTime") or item.get("LastThreatStatusChangeTime") or collected_at
        threat = item.get("ThreatName") or item.get("ThreatID") or "Unknown threat"
        resource = item.get("Resources") or item.get("Path") or ""
        rows.append(_row(
            ts,
            "defender",
            "detection",
            "high",
            f"Microsoft Defender detection: {threat}",
            str(resource),
        ))

    for task in data.get("tasks", []) or []:
        ts = collected_at
        name = f"{task.get('TaskPath', '')}{task.get('TaskName', '')}"
        details = task.get("Actions", "") or ""
        sev = "medium" if details else "low"
        rows.append(_row(
            ts,
            "scheduled_task",
            "persistence",
            sev,
            f"Scheduled task observed: {name}",
            details,
        ))

    for service in data.get("services", []) or []:
        ts = collected_at
        name = service.get("Name") or service.get("DisplayName") or "Unknown service"
        path = service.get("PathName", "") or service.get("ExecutablePath", "") or ""
        state = service.get("State", "") or ""
        rows.append(_row(
            ts,
            "service",
            "execution",
            "low",
            f"Service observed: {name} ({state})",
            path,
        ))

    for item in data.get("run_keys", []) or []:
        ts = collected_at
        key = item.get("RegistryPath", "") or ""
        value = item.get("ValueData", "") or ""
        rows.append(_row(
            ts,
            "run_key",
            "persistence",
            "medium",
            "Run key persistence entry observed",
            f"{key} => {value}",
        ))

    for row in data.get("tcp_listeners", []) or []:
        ts = row.get("CreationTime") or collected_at
        addr = row.get("LocalAddress", "") or ""
        port = row.get("LocalPort", "") or ""
        pid = row.get("OwningProcess", "") or ""
        rows.append(_row(
            ts,
            "tcp_listener",
            "network",
            "low",
            f"TCP listener observed on {addr}:{port}",
            f"pid={pid}",
        ))

    recent_files = data.get("recent_files") or []
    for item in recent_files[:500]:
        ts = item.get("LastWriteTime") or item.get("CreationTime") or item.get("LastAccessTime") or collected_at
        path = item.get("FullName", "") or ""
        rows.append(_row(
            ts,
            "filesystem",
            "file_activity",
            "low",
            "Recent file observed",
            path,
        ))

    if findings:
        for finding in findings[:50]:
            rows.append(_row(
                collected_at,
                "findings_engine",
                finding.get("category", "finding"),
                finding.get("severity", "low"),
                finding.get("title", "Finding"),
                " ; ".join(finding.get("evidence", [])[:5]),
            ))

    rows.sort(key=lambda x: (x["TimestampUtc"] or "9999-12-31T23:59:59Z", x["Severity"]), reverse=False)
    return rows


def write_timeline_csv(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["TimestampUtc", "Source", "Category", "Severity", "Summary", "Details"],
        )
        writer.writeheader()
        writer.writerows(rows)


def write_timeline_json(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8")
