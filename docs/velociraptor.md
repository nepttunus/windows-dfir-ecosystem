# Velociraptor notes

Velociraptor artifacts are YAML wrappers around VQL and can also package external tools, making them a good fit for wrapping a PowerShell collector. Official docs describe artifacts as reusable units that can encapsulate VQL and external tools, and explain that offline collectors can bundle required tools automatically. citeturn625741view0turn539791search1turn832275search0

## Recommended use

### Server / fleet mode
- Import the custom artifact
- Run against a client or hunt
- Upload resulting case ZIP and JSON outputs

### Offline collector mode
- Build an offline collector
- Include `Custom.Windows.DFIR.EvidenceCollector`
- Optionally configure destination upload (ZIP archive, SMB, SFTP, Azure SAS, S3, etc.), all of which are documented by Velociraptor for offline collectors. citeturn832275search0

## Important operational guidance

- Rebuild offline collectors after Velociraptor upgrades to avoid compatibility drift. The official troubleshooting docs explicitly recommend rebuilding them when the server is upgraded. citeturn832275search1
- For air-gapped environments, pre-populate tool dependencies instead of relying on GitHub download at build time. The offline collector docs explain this with `Server.Utils.UploadTools`. citeturn832275search0
- Keep the collector script in a versioned GitHub repo or upload it directly into Velociraptor’s tool inventory.
