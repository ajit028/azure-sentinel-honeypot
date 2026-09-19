<#
.SYNOPSIS
    Enrich Windows Security EventLog (EventID 4625) with IP geolocation data using redundant APIs.

.DESCRIPTION
    This script reads failed RDP logon events from Windows Security Event Log (EventID 4625),
    enriches them with geolocation intelligence using ipapi.com as primary and ip-api.com as fallback,
    applies rate-limiting and retry logic, and outputs the results in both CSV and JSON formats
    suitable for ingestion into Microsoft Sentinel via Custom Logs or Log Analytics Agent.

.PARAMETER LogName
    Name of the Windows Event Log to query (default: 'Security').

.PARAMETER EventID
    Event ID to filter for (default: 4625 for failed logons).

.PARAMETER LookbackHours
    Number of hours to look back for events (default: 24).

.PARAMETER OutputFolder
    Directory where output files will be saved (default: script directory).

.PARAMETER PrimaryApi
    Primary geolocation API to use (ipapi.com or ip-api.com) (default: ipapi.com).

.PARAMETER FallbackApi
    Fallback geolocation API if primary fails (default: ip-api.com).

.PARAMETER RateLimitDelay
    Delay in milliseconds between API calls to respect rate limits (default: 100).

.PARAMETER MaxRetries
    Maximum number of retry attempts for failed API calls (default: 3).

.PARAMETER TimeoutSeconds
    Timeout in seconds for each API request (default: 10).

.PARAMETER IncludePrivateIPs
    Switch to include private/reserved IP addresses in enrichment (default: excluded).

.EXAMPLE
    .\ingest-geo.ps1 -LookbackHours 6 -OutputFolder ".\output"

    Enriches failed logon events from the last 6 hours and saves output to .\output\

.EXAMPLE
    .\ingest-geo.ps1 -PrimaryApi ip-api.com -FallbackApi ipapi.com -RateLimitDelay 50

    Uses ip-api.com as primary with 50ms delay between calls.

.NOTES
    Author: Ajit Nayak
    Version: 2.0.0
    Requires: PowerShell 5.1+, internet access to geolocation APIs
    Tested on: Windows Server 2019/2022, Windows 10/11 Enterprise
    License: MIT

#>

[CmdletBinding()]
param(
    [string]$LogName = 'Security',
    [int]$EventID = 4625,
    [int]$LookbackHours = 24,
    [string]$OutputFolder = $PSScriptRoot,
    [ValidateSet('ipapi.com', 'ip-api.com')]
    [string]$PrimaryApi = 'ipapi.com',
    [ValidateSet('ipapi.com', 'ip-api.com')]
    [string]$FallbackApi = 'ip-api.com',
    [int]$RateLimitDelay = 100,
    [int]$MaxRetries = 3,
    [int]$TimeoutSeconds = 10,
    [switch]$IncludePrivateIPs
)

#region Helper Functions

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = 'INFO'
    )
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Write-Host "[$timestamp] [$Level] $Message"
}

function Test-NetworkConnectivity {
    try {
        $response = Test-Connection -ComputerName '8.8.8.8' -Count 1 -Quiet -TimeoutSeconds 3
        return $response
    } catch {
        return $false
    }
}

function Is-PrivateIP {
    param([string]$IPAddress)
    try {
        $ip = [System.Net.IPAddress]::Parse($IPAddress)
        $bytes = $ip.GetAddressBytes()
        
        # Check for private IP ranges
        if ($bytes.Length -eq 4) { # IPv4
            $a = $bytes[0]
            $b = $bytes[1]
            
            # 10.0.0.0/8
            if ($a -eq 10) { return $true }
            # 172.16.0.0/12
            if ($a -eq 172 -and $b -ge 16 -and $b -le 31) { return $true }
            # 192.168.0.0/16
            if ($a -eq 192 -and $b -eq 168) { return $true }
            # 127.0.0.0/8 (loopback)
            if ($a -eq 127) { return $true }
            # 169.254.0.0/16 (link-local)
            if ($a -eq 169 -and $b -eq 254) { return $true }
        }
        return $false
    } catch {
        return $false # If parsing fails, treat as public to avoid losing data
    }
}

function Get-GeolocationData {
    param(
        [string]$IPAddress,
        [string]$ApiEndpoint
    )
    
    $uri = switch ($ApiEndpoint) {
        'ipapi.com' { "https://ipapi.com/$IPAddress/json/" }
        'ip-api.com' { "http://ip-api.com/json/$IPAddress?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query" }
    }
    
    for ($retry = 0; $retry -lt $MaxRetries; $retry++) {
        try {
            Write-Log "Querying $ApiEndpoint for $IPAddress (attempt $($retry + 1))" 'DEBUG'
            
            $response = Invoke-RestMethod -Uri $uri -Method Get -TimeoutSec $TimeoutSeconds -ErrorAction Stop
            
            if ($ApiEndpoint -eq 'ipapi.com') {
                # Standardize ipapi.com response format
                $result = @{
                    status = if ($response.error) { 'fail' } else { 'success' }
                    message = if ($response.error) { $response.error.reason } { '' }
                    country = $response.country_name
                    countryCode = $response.country_code
                    region = $response.region_code
                    regionName = $response.region
                    city = $response.city
                    zip = $response.postal
                    lat = $response.latitude
                    lon = $response.longitude
                    timezone = $response.timezone
                    isp = $response.org
                    org = $response.org
                    as = $response.asn
                    asname = ""
                    reverse = $response.hostname
                    mobile = $false
                    proxy = $false
                    hosting = $false
                    query = $IPAddress
                }
            } elseif ($ApiEndpoint -eq 'ip-api.com') {
                # ip-api.com already returns standardized format
                $result = $response
            }
            
            if ($result.status -eq 'success') {
                Write-Log "Successfully retrieved geolocation for $IPAddress" 'DEBUG'
                return $result
            } else {
                Write-Log "API returned error for $IPAddress: $($result.message)" 'WARN'
                if ($retry -lt ($MaxRetries - 1)) {
                    Start-Sleep -Milliseconds $RateLimitDelay
                }
            }
        } catch {
            Write-Log "Request failed for $IPAddress (attempt $($retry + 1)): $($_.Exception.Message)" 'WARN'
            if ($retry -lt ($MaxRetries - 1)) {
                Start-Sleep -Milliseconds $RateLimitDelay
            }
        }
    }
    
    Write-Log "Failed to get geolocation for $IPAddress after $MaxRetries attempts" 'ERROR'
    return @{
        status = 'fail'
        message = 'Max retries exceeded'
        country = 'Unknown'
        countryCode = 'XX'
        region = ''
        regionName = 'Unknown'
        city = 'Unknown'
        zip = ''
        lat = 0
        lon = 0
        timezone = 'Unknown'
        isp = 'Unknown'
        org = 'Unknown'
        as = ''
        asname = ''
        reverse = ''
        mobile = $false
        proxy = $false
        hosting = $false
        query = $IPAddress
    }
}

function Get-FailedLogonEvents {
    param(
        [string]$LogName,
        [int]$EventID,
        [int]$LookbackHours
    )
    
    Write-Log "Retrieving EventID $EventID from $LogName for last $LookbackHours hours"
    
    $startTime = (Get-Date).AddHours(-$LookbackHours)
    
    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName   = $LogName
            ID        = $EventID
            StartTime = $startTime
        } -ErrorAction Stop
        
        Write-Log "Found $($events.Count) failed logon events"
        return $events
    } catch {
        Write-Log "Failed to query event log: $($_.Exception.Message)" 'ERROR'
        return @()
    }
}

function Export-EnrichedEvents {
    param(
        [object[]]$Events,
        [string]$OutputFolder
    )
    
    if (-not (Test-Path $OutputFolder)) {
        try {
            New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
            Write-Log "Created output directory: $OutputFolder"
        } catch {
            Write-Log "Failed to create output directory: $($_.Exception.Message)" 'ERROR'
            throw
        }
    }
    
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $csvPath = Join-Path $OutputFolder "failed_logons_enriched_$timestamp.csv"
    $jsonPath = Join-Path $OutputFolder "failed_logons_enriched_$timestamp.json"
    
    $enrichedEvents = @()
    $total = $Events.Count
    $processed = 0
    
    Write-Log "Starting enrichment of $total events..."
    
    foreach ($evt in $Events) {
        $processed++
        
        # Progress indicator every 10 events or at completion
        if ($processed % 10 -eq 0 -or $processed -eq $total) {
            $percent = [math]::Round(($processed / $total) * 100, 1)
            Write-Progress -Activity "Enriching IP addresses" -Status "$processed/$total ($percent%)" -PercentComplete $percent
        }
        
        # Extract IP address (Property 0 is usually Source Network Address)
        $ipAddress = $evt.Properties[0].Value
        
        if (-not $ipAddress -or $ipAddress -eq '-') {
            Write-Log "Skipping event with empty IP address" 'DEBUG'
            continue
        }
        
        # Skip private IPs unless explicitly requested
        if (-not $IncludePrivateIPs -and (Is-PrivateIP $ipAddress)) {
            Write-Log "Skipping private IP: $ipAddress" 'DEBUG'
            continue
        }
        
        # Determine API order (try primary first, then fallback)
        $apiOrder = @($PrimaryApi, $FallbackApi) | Where-Object { $_ -ne $null } | Select-Object -Unique
        
        $geoData = $null
        foreach ($api in $apiOrder) {
            $geoData = Get-GeolocationData -IPAddress $ipAddress -ApiEndpoint $api
            if ($geoData.status -eq 'success') {
                break
            }
            # If primary failed and we have a fallback, try it
            if ($api -eq $PrimaryApi -and $FallbackApi) {
                continue
            }
            break
        }
        
        # Build enriched event object
        $enrichedEvent = [ordered]@{
            TimeGenerated      = $evt.TimeCreated.ToString('o')
            EventID            = $evt.Id
            SourceIP           = $ipAddress
            Country            = $geoData.country
            CountryCode        = $geoData.countryCode
            Region             = $geoData.regionName
            City               = $geoData.city
            Latitude           = [double]$geoData.lat
            Longitude          = [double]$geoData.lon
            ISP                = $geoData.isp
            Organization       = $geoData.org
            ASNumber           = $geoData.as
            TimeZone           = $geoData.timezone
            TargetAccount      = $evt.Properties[5].Value # Target User Name
            WorkstationName    = $evt.Properties[6].Value # Workstation Name
            LogonType          = $evt.Properties[8].Value # Logon Type
            AuthenticationInfo = $evt.Properties[11].value # Authentication Package Name
        }
        
        $enrichedEvents += [pscustomobject]$enrichedEvent
        
        # Rate limiting between API calls
        if ($processed -lt $total) {
            Start-Sleep -Milliseconds $RateLimitDelay
        }
    }
    
    Write-Progress -Activity "Enriching IP addresses" -Completed
    
    # Export to CSV
    try {
        $enrichedEvents | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        Write-Log "Exported CSV to: $csvPath"
    } catch {
        Write-Log "Failed to export CSV: $($_.Exception.Message)" 'ERROR'
        throw
    }
    
    # Export to JSON
    try {
        $enrichedEvents | ConvertTo-Json -Depth 4 | Out-File -FilePath $jsonPath -Encoding UTF8
        Write-Log "Exported JSON to: $jsonPath"
    } catch {
        Write-Log "Failed to export JSON: $($_.Exception.Message)" 'ERROR'
        throw
    }
    
    return @{
        CSVPath = $csvPath
        JSONPath = $jsonPath
        Count = $enrichedEvents.Count
    }
}

#endregion Helper Functions

#region Main Execution

try {
    Write-Log "=== Azure Sentinel Honeypot Log Enrichment Started ==="
    Write-Log "Parameters: LogName='$LogName', EventID=$EventID, LookbackHours=$LookbackHours"
    Write-Log "Primary API: $PrimaryApi, Fallback API: $FallbackApi"
    Write-Log "Rate Limit: $RateLimitDelay ms, Max Retries: $MaxRetries"
    
    # Test network connectivity
    if (-not (Test-NetworkConnectivity)) {
        Write-Log "No network connectivity detected. Please check your internet connection." 'ERROR'
        exit 1
    }
    
    # Get failed logon events
    $failedEvents = Get-FailedLogonEvents -LogName $LogName -EventID $EventID -LookbackHours $LookbackHours
    
    if (-not $failedEvents) {
        Write-Log "No failed logon events found. Exiting." 'WARN'
        exit 0
    }
    
    # Enrich and export events
    $result = Export-EnrichedEvents -Events $failedEvents -OutputFolder $OutputFolder
    
    Write-Log "=== Enrichment Complete ==="
    Write-Log "Processed: $($result.Count) events"
    Write-Log "CSV Output: $($result.CSVPath)"
    Write-Log "JSON Output: $($result.JSONPath)"
    
    exit 0
} catch {
    Write-Log "Script failed with error: $($_.Exception.Message)" 'ERROR'
    Write-Log $_.Exception.StackTrace 'DEBUG'
    exit 1
}

#endregion Main Execution