# Executive Summary — CASE-DEMO-HOST01

- Host: **HOST01**
- Profile: **Incident**
- Defender detections returned: **1**
- Scheduled tasks collected: **1**
- Services collected: **1**
- TCP listeners collected: **1**
- Highest finding severity: **HIGH**

## Finding distribution

- High: **3**
- Medium: **3**
- Low: **1**

## Top categories

- **persistence**: 3
- **network**: 2
- **detection**: 1
- **correlation**: 1

## Key findings

- **HIGH** — Microsoft Defender detections present: The endpoint reported active or historical Defender detections. Review remediation state, affected paths, and related execution/persistence artefacts.
- **HIGH** — Probable compromise indicators cluster: Multiple findings across detection, persistence, and/or network activity suggest elevated compromise likelihood and warrant analyst escalation.
- **HIGH** — Scheduled task with encoded PowerShell: Scheduled task \Updater contains an encoded PowerShell style action.
- **MEDIUM** — Potentially suspicious listener ports observed: The collector identified listeners on ports commonly associated with implants, backdoors, or operator tooling.
- **MEDIUM** — Run key points to suspicious path: A Run/RunOnce persistence entry points to a suspicious or user-writable location.
- **MEDIUM** — Service executable path looks suspicious: Service BadSvc points to a user-writable or suspicious location.
- **LOW** — Non-standard TCP listeners identified: The collector identified TCP listeners outside a small common-port allowlist. This is not necessarily malicious but may require analyst review.

## Analyst note

This report is based on triage artefacts and heuristic detections. It supports, but does not replace, detailed forensic examination.