# Overview

## Purpose

This project provides a Windows-first DFIR evidence collection and triage ecosystem with:
- PowerShell evidence collector
- Python report builder
- HTML/PDF/screenshots reporting
- Velociraptor integration via custom artifact

## Main workflows

### Standalone workflow
1. Run the PowerShell collector on a Windows endpoint.
2. Review the generated case directory.
3. Build the report with the Python reporter.
4. Share the reduced case package for analysis.

### Velociraptor workflow
1. Import the custom artifact into Velociraptor.
2. Launch the artifact against a Windows endpoint.
3. Collect the uploaded output.
4. Build or review reports from the returned case data.

## Repository structure

- `collector/windows/` — Windows evidence collection scripts
- `reporter/` — report generation logic
- `velociraptor/artifacts/` — custom Velociraptor artifact definitions
- `sample_case/` — demo case for validating the reporting pipeline
- `docs/` — project documentation
