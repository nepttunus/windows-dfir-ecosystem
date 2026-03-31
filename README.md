# Windows DFIR Evidence Ecosystem

Windows-first DFIR triage and reporting toolkit for incident response, evidence preservation, and analyst-friendly reporting.

This project gives you two operating modes:

1. **Standalone mode**  
   Run a portable PowerShell collector on a Windows endpoint and build a local forensic report.

2. **Velociraptor mode**  
   Use a custom Velociraptor artifact to run the same collector at scale, including offline collector workflows.

---

## What it does

- Collects Windows triage evidence into a structured case folder
- Preserves hashes and basic chain-of-custody metadata
- Exports key event logs:
  - Security
  - System
  - Application
  - PowerShell Operational
  - Defender Operational
  - TaskScheduler Operational
- Collects:
  - system context
  - processes, services, drivers
  - scheduled tasks
  - local users and groups
  - network state
  - installed software
  - persistence locations
  - Microsoft Defender status and detections
  - common user artefacts
- Builds:
  - `summary.json`
  - `findings.json`
  - `executive_summary.md`
  - `report.html`
  - optional `report.pdf`
  - screenshots for reports

---

## Repository layout

```text
collector/windows/                     PowerShell collector
reporter/                             Python parsers + report generator
velociraptor/artifacts/               Custom Velociraptor artifact YAML
docs/                                 Project documentation
tests/                                Basic parser tests
sample_case/                          Demo case for report validation
.github/workflows/                    GitHub Actions
Quick start
1) Reporter setup on macOS / Linux
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m pip install pytest
python -m playwright install chromium
2) Validate the reporting pipeline
python -m pytest
python -m reporter.report_builder \
  --case-path sample_case/CASE-DEMO-HOST01 \
  --render-pdf \
  --take-screenshots
3) Open the demo report on macOS
open sample_case/CASE-DEMO-HOST01/11_reports/report.html
Manual evidence collection on Windows

Open an elevated PowerShell console:

Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
.\collector\windows\Invoke-DFIREvidenceCollector.ps1 `
  -CaseId CASE-2026-0001-HOST01 `
  -OutputRoot C:\DFIR `
  -Profile Incident `
  -MaxDays 14

Expected output:

C:\DFIR\CASE-2026-0001-HOST01\
C:\DFIR\CASE-2026-0001-HOST01.zip
Build a report from a real case
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m pip install pytest
python -m playwright install chromium

python -m reporter.report_builder `
  --case-path C:\DFIR\CASE-2026-0001-HOST01 `
  --render-pdf `
  --take-screenshots

Outputs are written under:

C:\DFIR\CASE-2026-0001-HOST01\11_reports\
Velociraptor installation on macOS (Apple Silicon)

Create a working directory:

mkdir -p ~/tools/velociraptor
cd ~/tools/velociraptor

Download the binary:

curl -L -o velociraptor https://github.com/Velocidex/velociraptor/releases/download/v0.76/velociraptor-v0.76.1-darwin-arm64
chmod +x velociraptor

Confirm the binary:

./velociraptor version

Start the local GUI:

./velociraptor gui

This is the fastest way to learn the interface locally before deploying a real server/client setup.

Velociraptor artifact integration

The custom artifact is stored here:

velociraptor/artifacts/Custom.Windows.DFIR.EvidenceCollector.yaml
Important

Update the url: value in the artifact so it points to the real GitHub raw path of your collector script.

Expected pattern:

https://raw.githubusercontent.com/<github-user>/<repo-name>/main/collector/windows/Invoke-DFIREvidenceCollector.ps1

Example:

https://raw.githubusercontent.com/nepttunus/windows-dfir-ecosystem/main/collector/windows/Invoke-DFIREvidenceCollector.ps1
Import the artifact into Velociraptor
Open the Velociraptor GUI
Go to View Artifacts
Click New Artifact
Paste the full YAML content of:
velociraptor/artifacts/Custom.Windows.DFIR.EvidenceCollector.yaml
Save the artifact
Launch against one Windows lab endpoint

Use:

CaseId = CASE-LAB-001
Profile = Incident
MaxDays = 14
Recommended rollout
Test manually on one Windows host
Validate the report pipeline
Import the artifact into Velociraptor
Run it on one Windows lab endpoint
Review uploads and returned files
Only then scale to more endpoints
Only after that move into offline collector workflows
Case folder layout
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


Operational notes
Run as local administrator whenever possible
This tool is intended for forensic triage and reporting, not full dead-box acquisition
Browser and locked file collection depends on permissions and file locks
Some artefact coverage varies by Windows version and EDR configuration
Rebuild offline collectors after Velociraptor server upgrades or artifact changes
Documentation
Overview
Local Usage
Velociraptor Step by Step
Offline Collector
Troubleshooting
GitHub recommendations
Protect the main branch
Require review for detection logic changes
Keep large evidence samples outside the repo
Do not store third-party binaries in source control
Use GitHub Releases for packaged collector versions
Limitations
Does not
