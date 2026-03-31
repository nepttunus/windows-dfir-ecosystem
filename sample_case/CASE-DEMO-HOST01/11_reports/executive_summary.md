# Executive Summary — CASE-DEMO-HOST01

- Host: **HOST01**
- Profile: **Incident**
- Defender detections returned: **1**
- Scheduled tasks collected: **1**
- Services collected: **1**
- TCP listeners collected: **1**
- Highest finding severity: **HIGH**

## Key findings

- **HIGH** — Microsoft Defender detections present: The endpoint reported active or historical Defender detections. Review remediation state, affected paths, and related execution/persistence artefacts.
- **HIGH** — Scheduled task with encoded PowerShell: Scheduled task \Updater contains an encoded PowerShell style action.
- **LOW** — Non-standard TCP listeners identified: The collector identified TCP listeners outside a small common-port allowlist. This is not necessarily malicious but may require analyst review.

## Analyst note

This report is based on triage artefacts and simple heuristics. It supports, but does not replace, detailed forensic examination.