# Windows DFIR Evidence Ecosystem

Windows-first forensic triage and reporting toolkit built for incident response, evidence preservation, and analyst-friendly reporting.

This repository gives you two operating modes:

1. **Standalone mode** — run a portable PowerShell collector on a Windows endpoint, then generate a report and screenshots locally.
2. **Velociraptor mode** — use a custom Velociraptor artifact to run the same collector at scale, including in offline collector workflows.

## What it does

- Collects Windows triage evidence into a structured case folder
- Preserves hashes and basic chain-of-custody metadata
- Exports key event logs (`Security`, `System`, `Application`, `PowerShell Operational`, `Defender Operational`, `TaskScheduler Operational`)
- Collects:
  - system context
  - processes, services, drivers
  - scheduled tasks
  - local users/groups
  - network state
  - installed software
  - persistence locations
  - Microsoft Defender status and detections
  - common user artefacts (Recent, Jump Lists, browser history files where accessible)
- Builds:
  - `summary.json`
  - `findings.json`
  - `executive_summary.md`
  - `report.html`
  - optional `report.pdf`
  - evidence screenshots (`PNG`) for reports

## Repository layout

```text
collector/windows/                     PowerShell collector
reporter/                             Python parsers + report generator
velociraptor/artifacts/               Custom Velociraptor artifact YAML
docs/                                 Architecture and operations notes
tests/                                Basic parser tests
.github/workflows/                    GitHub Actions validation
```

## Quick start

### 1) Collect evidence on a Windows host

Open an elevated PowerShell console:

```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
.\collector\windows\Invoke-DFIREvidenceCollector.ps1 `
  -CaseId CASE-2026-0001-HOST01 `
  -OutputRoot C:\DFIR `
  -Profile Incident `
  -MaxDays 14
```

This creates a case folder such as:

```text
C:\DFIR\CASE-2026-0001-HOST01\
```

and, unless `-NoZip` is used, also:

```text
C:\DFIR\CASE-2026-0001-HOST01.zip
```

### 2) Build the report

Create and activate a Python virtual environment, then install dependencies:

```powershell
python -m venv .venv
. .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
playwright install chromium
```

Generate the report:

```powershell
python -m reporter.report_builder `
  --case-path C:\DFIR\CASE-2026-0001-HOST01 `
  --render-pdf `
  --take-screenshots
```

Outputs are written under:

```text
C:\DFIR\CASE-2026-0001-HOST01\11_reports\
```

## Velociraptor integration

The custom artifact in `velociraptor/artifacts/Custom.Windows.DFIR.EvidenceCollector.yaml` wraps the same collector script. Velociraptor artifacts can package VQL and external tools, and offline collectors can bundle required tools automatically. See the official Velociraptor documentation for artifact packaging, external tools, and offline collector creation. citeturn625741view0turn539791search1turn832275search0

### Suggested workflow

- Import the custom artifact into Velociraptor
- Either:
  - run it directly against endpoints, or
  - include it in an offline collector build
- Upload the resulting case ZIP or collection ZIP back to your evidence store / Velociraptor server
- Use the Python reporter locally for enriched forensic reporting

## Operational notes

- Run as local administrator whenever possible.
- This tool is intended for **forensic triage and reporting**, not full dead-box acquisition.
- `wevtutil` is used to export Windows event logs; Microsoft documents it for retrieving, querying, exporting, archiving, and clearing logs. citeturn625741view3
- Microsoft documents `Get-MpThreatDetection` as a way to retrieve active and past Defender detections, which this toolkit uses for security context. citeturn625741view2
- Rebuild Velociraptor offline collectors when your server is upgraded; the Velociraptor docs explicitly recommend rebuilding collectors to maintain compatibility and get fixes. citeturn832275search1turn832275search0

## Case folder layout

```text
CASE-2026-0001-HOST01/
├── 00_case/
├── 01_system/
├── 02_logs/
├── 03_persistence/
├── 04_execution/
├── 05_network/
├── 06_user_activity/
├── 07_security/
├── 08_timeline/
├── 09_findings/
├── 10_screenshots/
├── 11_reports/
└── 99_share_with_chatgpt/
```

## GitHub recommendations

Recommended repo settings:

- enable branch protection on `main`
- require pull request review for detection logic changes
- store large sample cases outside the repo
- keep third-party binaries out of source control
- use GitHub Releases for versioned collector packs

## Limitations

- Does not perform full memory capture
- Does not replace forensic imaging
- Browser and locked file collection depends on local permissions and file locks
- Some evidence sources vary between Windows versions and EDR configurations

## License

MIT
