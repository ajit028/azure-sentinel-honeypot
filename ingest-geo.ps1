<# 
.SYNOPSIS
    Enrich Windows Security EventLog (EventID 4625) with IP geolocation data.
.DESCRIPTION
    Reads the Security event log for failed RDP logons (EventID 4625), extracts the source IP,
    queries ipapi.com for geolocation, and outputs enriched events to a CSV or custom log.
.NOTES
    Author: Ajit Nayak
    Requires: PowerShell 5.1+, internet access to ipapi.com
#>

param(
    [string]$LogName = 'Security',
    [int]$EventID = 4625,
    [string]$OutputPath = "$PSScriptRoot\geo-enriched-events.csv",
    [int]$LookbackHours = 24
)

# Ensure output directory exists
$outputDir = Split-Path $OutputPath -Parent
if (-not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir | Out-Null
}

# Calculate timestamp for filtering
$startTime = (Get-Date).AddHours(-$LookbackHours)

# Get failed logon events
$events = Get-WinEvent -FilterHashtable @{
    LogName   = $LogName
    ID        = $EventID
    StartTime = $startTime
} -ErrorAction SilentlyContinue

if (-not $events) {
    Write-Host "No EventID $EventID events found in the last $LookbackHours hours." -ForegroundColor Yellow
    exit
}

# Initialize results array
$results = @()

foreach ($evt in $events) {
    # Extract IP address from the event (insertion strings)
    $ip = $evt.Properties[0].Value # Usually Source Network Address
    if (-not $ip -or $ip -eq '-') {
        continue
    }

    # Skip private/reserved IPs (optional)
    if ($ip -match '^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)') {
        continue
    }

    try {
        # Call ipapi.com for JSON geolocation (free tier, limit 30 req/min)
        $geo = Invoke-RestMethod -Uri "https://ipapi.com/$ip/json/" -TimeoutSec 10 -ErrorAction Stop
        $result = [pscustomobject]@{
            TimeCreated   = $evt.TimeCreated
            EventID       = $evt.Id
            SourceIP      = $ip
            Country       = $geo.country_name
            Region        = $geo.region
            City          = $geo.city
            Latitude      = $geo.latitude
            Longitude     = $geo.longitude
            ISP           = $geo.org
            EventData     = $evt.ToXml() # Optional: store raw XML
        }
        $results += $result
        Write-Host "Processed $ip -> $($geo.city), $($geo.country_name)" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to get geo data for $ip: $_"
        # Still add basic info without geo
        $results += [pscustomobject]@{
            TimeCreated   = $evt.TimeCreated
            EventID       = $evt.Id
            SourceIP      = $ip
            Country       = 'Unknown'
            Region        = 'Unknown'
            City          = 'Unknown'
            Latitude      = $null
            Longitude     = $null
            ISP           = 'Unknown'
            EventData     = $evt.ToXml()
        }
    }

    # Respect rate limit: pause between requests
    Start-Sleep -Milliseconds 200
}

# Export to CSV
$results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
Write-Host "Exported $($results.Count) enriched events to $OutputPath" -ForegroundColor Cyan

# Optional: Also output to a custom log file for Sentinel ingestion via custom log collector
$logPath = "$PSScriptRoot\honeypot-geo.log"
$results | ConvertTo-Json -Depth 4 | Out-File -FilePath $logPath -Encoding UTF8
Write-Host "Also saved JSON log to $logPath for custom log ingestion." -ForegroundColor Cyan