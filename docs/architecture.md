# Architecture

## Components

### 1. Endpoint collector (PowerShell)
Runs on Windows endpoints with minimal dependencies and writes a structured case directory.

### 2. Case package
Creates:
- structured evidence folders
- metadata
- SHA256 manifest
- optional evidence ZIP

### 3. Reporting engine (Python)
Parses collected outputs and produces:
- findings
- executive summary
- HTML report
- PDF report
- screenshots

### 4. Velociraptor integration
A custom client artifact wraps the same collector so the workflow is identical whether you run:
- standalone on a host
- from a Velociraptor client
- from a Velociraptor offline collector

## Design goals

- Windows-first
- portable
- explainable outputs
- chain-of-custody friendly metadata
- easy GitHub versioning
- works both manually and with Velociraptor

## Not in scope

- full disk acquisition
- full memory acquisition
- stealth or anti-evasion collection
- remote administration outside normal IR workflows
