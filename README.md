# Azure Sentinel Cloud Honeypot & Global Threat Map

Deployed an exposed Windows VM honeypot in Azure to attract global adversaries. Ingested over 14,000+ brute-force logs via Log Analytics, parsed geo-coordinates with PowerShell, and visualized attack origins on interactive Sentinel workbooks.

## Files

- `ingest-geo.ps1` – PowerShell script to parse Windows Security logs (EventID 4625) and enrich with IP geolocation using free ipapi.com.
- `honeypot-workbook.json` – Azure Sentinel workbook JSON for visualizing attack map.
- `detection-rules.kql` – Sample KQL detection rules for brute force and suspicious logons.
- `architecture.png` – Diagram (placeholder).

## Setup

1. Deploy a Windows VM honeypot in Azure with public RDP enabled (for demo only).
2. Configure Log Analytics agent to forward Security events.
3. Run `ingest-geo.ps1` via Azure Automation or scheduled task to enrich logs with geo data.
4. Import workbook into Sentinel.
5. Use detection rules to create alerts.

## License

MIT