# Incident Response Playbook: RDP Brute-Force and Credential Access

## Overview
This playbook defines the standardized Incident Response (IR) procedure for handling RDP brute-force attacks and credential access incidents detected via the Azure Sentinel Honeypot architecture. It follows the SANS and NIST 6-step Incident Response framework:
1. Preparation
2. Identification
3. Containment
4. Eradication
5. Recovery
6. Lessons Learned

---

## 1. Preparation
- **Prerequisites:** Ensure Azure Sentinel, Windows Security Event Forwarding (Sysmon / Security Events 4625, 4624), and Honeypot logging are properly configured.
- **Access Control:** Restrict access to Sentinel workspaces, incident management tickets, and containment scripts (e.g., automated Logic Apps / Playbooks).
- **Baseline Tuning:** Regularly review KQL detection thresholds and watchlist intelligence to reduce false positives.

---

## 2. Identification
- **Trigger:** Alert fired from `kql/analytics-rule-brute-force.json` or anomalous authentication spikes.
- **Triage Steps:**
  - Query Microsoft Sentinel for recent authentication failures (`SecurityEvent` where `EventID == 4625` and `LogonProcessName` or `IpAddress`).
  - Extract attacker indicators: Source IP addresses, targeted user accounts, brute-force frequency, and geographic origin.
  - Correlate with threat intelligence feeds (`threat-intel/ioc-feed.json`) to determine if the attacking IP belongs to known botnets or commercial proxy networks.

---

## 3. Containment
- **Immediate Actions:**
  - Isolate compromised endpoints or honeypot sensors via Network Security Groups (NSGs) or Azure Firewall rules.
  - Block malicious source IPs at the perimeter firewall / Azure Front Door / WAF.
  - Disable or force password resets for compromised user accounts.
- **Short-Term Containment:** Revoke active user sessions and token grants across Azure AD / Entra ID if applicable.

---

## 4. Eradication
- **System Cleansing:**
  - Terminate unauthorized RDP sessions and background malicious processes/persistence mechanisms (scheduled tasks, registry run keys, web shells).
  - Verify integrity of system binaries and user account configurations.
- **Patch & Harden:** Ensure Network Level Authentication (NLA) is enforced, change non-standard RDP ports if applicable, and restrict RDP exposure via Just-In-Time (JIT) VM access.

---

## 5. Recovery
- **Restoration:**
  - Reconnect cleaned assets to the network under strict monitoring.
  - Validate normal service availability for legitimate users.
- **Post-Incident Monitoring:** Maintain enhanced log collection and watchlists for the affected assets for at least 14 days following recovery.

---

## 6. Lessons Learned
- **Post-Incident Review (PIR):** Conduct a team debrief within 5 business days of incident closure.
- **Playbook & Detection Tuning:** Update KQL rules, thresholds, and automated playbooks based on lessons learned.
- **Documentation:** File complete forensic artifacts and incident metrics into the central knowledge base.
