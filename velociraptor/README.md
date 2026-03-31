# Velociraptor Integration

This folder contains the custom artifact used to run the Windows DFIR collector through Velociraptor.

## Main artifact

- `artifacts/Custom.Windows.DFIR.EvidenceCollector.yaml`

## Parameters

- `CaseId` — case identifier used for the collection output
- `Profile` — collection profile (`Lite`, `Incident`, `Ransomware`, `Persistence`, `Full`)
- `MaxDays` — number of days for time-scoped collection logic
- `IncludeBrowserArtefacts` — collect browser artefacts when enabled
- `IncludeMemory` — create placeholder logic for memory collection when enabled
- `IncludeYara` — create placeholder logic for YARA collection when enabled
- `ZipSharePackage` — create the reduced package under `99_share_with_internal_or_controlled_ai`

## Import into Velociraptor

1. Open the Velociraptor GUI
2. Go to **View Artifacts**
3. Click **New Artifact**
4. Paste the content of:
   `velociraptor/artifacts/Custom.Windows.DFIR.EvidenceCollector.yaml`
5. Save the artifact

## Launch recommendation

Start with one Windows lab endpoint only.

Suggested first run:
- `CaseId = CASE-LAB-001`
- `Profile = Incident`
- `MaxDays = 14`
- `IncludeBrowserArtefacts = false`
- `IncludeMemory = false`
- `IncludeYara = false`
- `ZipSharePackage = true`

## Expected outputs

The collector should return a case directory with:
- `00_case`
- `01_system`
- `02_logs`
- `03_persistence`
- `04_execution`
- `05_network`
- `06_user_activity`
- `07_security`
- `08_timeline`
- `09_findings`
- `10_screenshots`
- `11_reports`
- `12_memory` when requested
- `99_share_with_internal_or_controlled_ai`

## Operational notes

- Validate the artifact in normal client-server mode first
- Only later move to offline collector workflows
- Rebuild offline collectors after artifact changes
- Keep the GitHub raw URL aligned with the real repository path
