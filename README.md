# Azure Sentinel Cloud Honeypot & Threat Intelligence Platform

![Azure](https://img.shields.io/badge/Cloud-Microsoft%20Azure-0089D6?style=for-the-badge&logo=microsoft-azure&logoColor=white)
![Sentinel](https://img.shields.io/badge/SIEM-Microsoft%20Sentinel-0078D4?style=for-the-badge&logo=microsoft&logoColor=white)
![PowerShell](https://img.shields.io/badge/Automation-PowerShell-5391FE?style=for-the-badge&logo=powershell&logoColor=white)
![KQL](https://img.shields.io/badge/Query-Kusto%20KQL-7FBA00?style=for-the-badge&logo=azure-devops&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)

A production-grade cloud security telemetry pipeline and SIEM honeypot built on **Microsoft Azure**. This project deploys an exposed Windows virtual machine acting as a honeypot, extracts real-time failed Windows logon events (Event ID 4625), enriches them with geolocation intelligence via redundant IP APIs, ingests them into **Microsoft Sentinel**, and visualizes global brute-force attacks through custom KQL analytics rules, threat hunting queries, and interactive Sentinel Workbooks.

---

## 🏛️ Architecture

```mermaid
graph TD
    subgraph Internet [Attacker Landscape]
        A1[Global Threat Actors] -->|RDP Brute Force :3389| B1
    end

    subgraph Azure_Cloud [Microsoft Azure Cloud]
        subgraph Honeypot_VM [Windows Server Honeypot]
            B1[NSG / Public IP] --> B2[Windows Security Event Log]
        end

        subgraph Ingestion_Pipeline [Telemetry Pipeline]
            B2 -->|PowerShell Script| C1[IP Geolocation APIs<br/>ipapi.com / ip-api.com]
            C1 -->|Enriched JSON / CSV| C2[Log Analytics Workspace]
        end

        subgraph SIEM_SOC [Microsoft Sentinel SOC]
            C2 --> D1[KQL Analytics Rules<br/>Brute Force & Geo-Anomaly]
            C2 --> D2[Advanced Hunting Queries]
            D1 --> D3[Attack Map Workbook<br/>Global Visualization]
        end
    end

    style Internet fill:#ffe6e6,stroke:#ff4d4d,stroke-width:2px
    style Azure_Cloud fill:#e6f2ff,stroke:#0078D4,stroke-width:2px
    style Honeypot_VM fill:#fff,stroke:#333,stroke-width:1px
    style Ingestion_Pipeline fill:#fff,stroke:#333,stroke-width:1px
    style SIEM_SOC fill:#e6ffed,stroke:#28a745,stroke-width:2px
```

---

## 🚀 What This Project Does

1. **Exposes a Controlled Honeypot**: Deploys an Azure Windows VM with an open Network Security Group (NSG) on port 3389 (RDP) to naturally attract brute-force attempts, credential stuffing, and unauthorized reconnaissance scans from global threat actors.
2. **Automated Log Extraction & Geo-Enrichment**: Executes a robust PowerShell automation pipeline (`ingest-geo.ps1`) that parses local Windows Security Event logs (specifically Event ID 4625 - Failed Logon), queries multi-source IP geolocation intelligence APIs with automatic failover and rate-limiting, and structures the output into enriched CSV and JSON payloads.
3. **SIEM Telemetry & KQL Analytics**: Ingests enriched logs into Microsoft Sentinel, powering automated detection rules for brute-force thresholds, geographic anomalies, impossible travel, and successful authentications following attack chains.
4. **Interactive SOC Dashboard**: Visualizes live global attack origins, top attacking ASNs/countries, and target account distributions via custom Microsoft Sentinel Workbooks and Kusto Query Language (KQL).

---

## 📋 Step-by-Step Deployment Guide

### Prerequisites
- An active **Microsoft Azure Subscription**.
- Azure CLI installed and authenticated (`az login`).
- PowerShell 7+ for running ingestion scripts.

### Step 1: Deploy Infrastructure via ARM Template
Deploy the Windows honeypot VM, Log Analytics Workspace, and Microsoft Sentinel integration using Azure CLI:

```bash
az group create --name rg-sentinel-honeypot-prod --location eastus
az deployment group create \
  --resource-group rg-sentinel-honeypot-prod \
  --template-file deploy/azuredeploy.json \
  --parameters adminUsername="honeypotAdmin" adminPassword="ComplexPassword123!"
```

### Step 2: Configure Sentinel Data Connectors & Analytics
1. Navigate to the Azure Portal and open your deployed **Microsoft Sentinel** instance.
2. Enable the **Security Events** data connector to collect Windows Event ID 4625.
3. Import the KQL detection rules located in `kql/` into Sentinel **Analytics**.
4. Deploy the Attack Map Workbook from `workbooks/attack-map-workbook.json`.

### Step 3: Run the Geolocation Ingestion Pipeline
Execute the PowerShell ingestion script to process logs and enrich with threat intelligence:

```powershell
powershell -ExecutionPolicy Bypass -File .\ingest-geo.ps1 -LogPath "C:\SecurityLogs\failed_logins.csv" -OutputFolder ".\output"
```

---

## 📊 Sample KQL Queries

### 1. Brute-Force Threshold Alert (>10 failures in 5 minutes)
```kusto
SecurityEvent
| where EventID == 4625
| summarize FailureCount = count(), TargetAccounts = make_set(TargetUserName), IpAddresses = make_set(IpAddress) by IpAddress, bin(TimeGenerated, 5m)
| where FailureCount > 10
| extend AttackingIP = IpAddress
| project TimeGenerated, AttackingIP, FailureCount, TargetAccounts
| sort by FailureCount desc
```

### 2. Top Attacking Countries Dashboard Query
```kusto
SecurityEvent
| where EventID == 4625
| evaluate ipv4_lookup(GeoLite2Country, IpAddress, Network)
| summarize AttackCount = count() by Country, State, City, Latitude, Longitude
| top 20 by AttackCount desc
```

---

## 🛡️ MITRE ATT&CK Mapping

| Technique ID | Tactic | Description | Detection KQL / Rule |
| :--- | :--- | :--- | :--- |
| **T1110.001** | Credential Access | Brute Force: Password Guessing | `brute-force-detection.kql` (>10 failures / 5m) |
| **T1078** | Defense Evasion / Initial Access | Valid Accounts: Default Accounts | `hunting-queries.kql` (Off-hours / unusual source) |
| **T1110.003** | Credential Access | Password Spraying | `hunting-queries.kql` (Same password, multi-accounts) |
| **T1589.001** | Reconnaissance | Gather Victim Identity Info: Email/Account Names | Target account enumeration via Event ID 4625 |

---

## 🧰 Technologies Used

- ![Azure](https://img.shields.io/badge/Microsoft_Azure-0089D6?style=flat&logo=microsoft-azure&logoColor=white) **Microsoft Azure** (Virtual Machines, NSGs, Virtual Networks)
- ![Sentinel](https://img.shields.io/badge/Microsoft_Sentinel-0078D4?style=flat&logo=microsoft&logoColor=white) **Microsoft Sentinel & Log Analytics** (SIEM, Custom Logs, Workbooks)
- ![PowerShell](https://img.shields.io/badge/PowerShell-5391FE?style=flat&logo=powershell&logoColor=white) **PowerShell 7** (Log parsing, API enrichment, automation)
- ![KQL](https://img.shields.io/badge/Kusto_KQL-7FBA00?style=flat&logo=azure-devops&logoColor=white) **Kusto Query Language** (Threat hunting, analytics, telemetry filtering)
- ![Git](https://img.shields.io/badge/Git-F05032?style=flat&logo=git&logoColor=white) **Git & GitHub** (Version control & portfolio showcase)

---

## 👨💻 Author

**Ajit Nayak**  
*Cybersecurity Aspirant & SOC Analyst*  

- Portfolio: [ajit028.github.io](https://ajit028.github.io)
- LinkedIn: [linkedin.com/in/ajit028](https://linkedin.com/in/ajit028)
- GitHub: [github.com/ajit028](https://github.com/ajit028)

---

## 📄 License

Distributed under the **MIT License**. See `LICENSE` for more information.