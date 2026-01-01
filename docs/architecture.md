# 🏗️ Architecture Overview

This document provides a detailed overview of the Azure Sentinel SOC Lab architecture.

---

## High-Level Architecture

```
                                    ┌──────────────────────────────────────┐
                                    │           INTERNET                    │
                                    │   (Attackers / Threat Actors)         │
                                    └──────────────────┬───────────────────┘
                                                       │
                                                       │ Attacks (RDP, SSH, SMB)
                                                       ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                                    AZURE SUBSCRIPTION                                     │
│                                                                                          │
│  ┌───────────────────────────────────────────────────────────────────────────────────┐  │
│  │                            RESOURCE GROUP: SOC-Lab-RG                              │  │
│  │                                                                                    │  │
│  │  ┌─────────────────────┐       ┌─────────────────────┐                            │  │
│  │  │   VIRTUAL NETWORK   │       │   NETWORK SECURITY  │                            │  │
│  │  │   10.0.0.0/16       │       │   GROUP (NSG)       │                            │  │
│  │  │                     │       │                     │                            │  │
│  │  │  ┌───────────────┐  │       │  • Allow RDP (3389) │                            │  │
│  │  │  │ Subnet        │  │       │  • Allow SSH (22)   │                            │  │
│  │  │  │ 10.0.1.0/24   │  │       │  • NSG Flow Logs    │                            │  │
│  │  │  └───────┬───────┘  │       └─────────────────────┘                            │  │
│  │  └──────────┼──────────┘                                                          │  │
│  │             │                                                                      │  │
│  │             ▼                                                                      │  │
│  │  ┌─────────────────────┐                                                          │  │
│  │  │   WINDOWS VM        │                                                          │  │
│  │  │   (Honeypot)        │                                                          │  │
│  │  │                     │                                                          │  │
│  │  │  • Windows 10/11    │         ┌─────────────────────┐                          │  │
│  │  │  • RDP Enabled      │────────▶│  LOG ANALYTICS      │                          │  │
│  │  │  • Public IP        │  Logs   │  WORKSPACE          │                          │  │
│  │  │  • Security Events  │         │                     │                          │  │
│  │  └─────────────────────┘         │  • SecurityEvent    │                          │  │
│  │                                  │  • Syslog           │                          │  │
│  │                                  │  • SigninLogs       │                          │  │
│  │  ┌─────────────────────┐         │  • AzureActivity    │                          │  │
│  │  │   AZURE AD          │────────▶│  • NSG Flow Logs    │                          │  │
│  │  │                     │  Logs   │                     │                          │  │
│  │  │  • Sign-in Logs     │         └──────────┬──────────┘                          │  │
│  │  │  • Audit Logs       │                    │                                      │  │
│  │  └─────────────────────┘                    │                                      │  │
│  │                                             ▼                                      │  │
│  │                              ┌─────────────────────────┐                          │  │
│  │                              │    AZURE SENTINEL       │                          │  │
│  │                              │    (SIEM / SOAR)        │                          │  │
│  │                              │                         │                          │  │
│  │                              │  ┌─────────────────┐    │                          │  │
│  │                              │  │ Data Connectors │    │                          │  │
│  │                              │  └────────┬────────┘    │                          │  │
│  │                              │           │             │                          │  │
│  │                              │           ▼             │                          │  │
│  │                              │  ┌─────────────────┐    │                          │  │
│  │                              │  │ Analytics Rules │    │     ┌────────────────┐   │  │
│  │                              │  │ (KQL Queries)   │────┼────▶│  LOGIC APPS    │   │  │
│  │                              │  └─────────────────┘    │     │  (Playbooks)   │   │  │
│  │                              │           │             │     │                │   │  │
│  │                              │           ▼             │     │ • Block IP     │   │  │
│  │                              │  ┌─────────────────┐    │     │ • Send Alert   │   │  │
│  │                              │  │ Incidents       │    │     │ • Enrich Data  │   │  │
│  │                              │  └─────────────────┘    │     └────────────────┘   │  │
│  │                              │           │             │            │             │  │
│  │                              │           ▼             │            ▼             │  │
│  │                              │  ┌─────────────────┐    │     ┌────────────────┐   │  │
│  │                              │  │ Workbooks       │    │     │ NOTIFICATIONS  │   │  │
│  │                              │  │ (Dashboards)    │    │     │ • Email        │   │  │
│  │                              │  └─────────────────┘    │     │ • Teams        │   │  │
│  │                              │                         │     └────────────────┘   │  │
│  │                              └─────────────────────────┘                          │  │
│  │                                                                                    │  │
│  └───────────────────────────────────────────────────────────────────────────────────┘  │
│                                                                                          │
│                           ┌─────────────────────────────────┐                           │
│                           │     THREAT INTELLIGENCE         │                           │
│                           │                                 │                           │
│                           │  • VirusTotal API               │                           │
│                           │  • AbuseIPDB API                │                           │
│                           │  • ipgeolocation.io             │                           │
│                           └─────────────────────────────────┘                           │
│                                                                                          │
└───────────────────────────────────────────────────────────────────────���─────────────────┘
```

---

## Component Details

### 1. Honeypot VM (Windows)

| Property | Value |
|----------|-------|
| **Purpose** | Attract and log attack attempts |
| **OS** | Windows 10/11 or Windows Server 2019 |
| **Size** | Standard_B1s (1 vCPU, 1 GB RAM) |
| **Public IP** | Yes (to attract attackers) |
| **Open Ports** | RDP (3389) |
| **Logging** | Windows Security Events forwarded to Log Analytics |

**What it captures:**
- Failed/successful RDP login attempts (Event ID 4625, 4624)
- Account lockouts (Event ID 4740)
- Process creation (Event ID 4688)
- PowerShell execution (Event ID 4104)

### 2. Log Analytics Workspace

| Property | Value |
|----------|-------|
| **Purpose** | Central log storage and querying |
| **Retention** | 30 days (free tier) |
| **Daily Cap** | 5 GB/day (free tier) |

**Data Tables:**
| Table | Source | Description |
|-------|--------|-------------|
| `SecurityEvent` | Windows VM | Windows Security logs |
| `SigninLogs` | Azure AD | User sign-in activity |
| `AuditLogs` | Azure AD | Directory changes |
| `AzureActivity` | Azure | Resource operations |

### 3. Azure Sentinel

| Property | Value |
|----------|-------|
| **Purpose** | SIEM and SOAR capabilities |
| **Free Tier** | 10 GB/day for 31 days |

**Components:**
- **Data Connectors** - Ingest logs from various sources
- **Analytics Rules** - KQL-based threat detection
- **Incidents** - Correlated alerts for investigation
- **Workbooks** - Custom dashboards and visualizations
- **Playbooks** - Automated response via Logic Apps
- **Hunting** - Proactive threat hunting queries

### 4. Logic Apps (Playbooks)

| Playbook | Trigger | Action |
|----------|---------|--------|
| Block-MaliciousIP | High severity incident | Update NSG to block IP |
| Enrich-ThreatIntel | New incident | Query VirusTotal/AbuseIPDB |
| Notify-SOC | Medium+ incident | Send email/Teams message |

### 5. Threat Intelligence Integration

| Service | Purpose | Free Tier |
|---------|---------|-----------|
| **VirusTotal** | File/URL/IP reputation | 500 requests/day |
| **AbuseIPDB** | IP reputation database | 1,000 checks/day |
| **ipgeolocation.io** | Attacker location mapping | 1,000 requests/day |

---

## Data Flow

```
1. ATTACK OCCURS
   └─▶ Attacker attempts RDP brute force on honeypot VM

2. LOGGING
   └─▶ Windows Security Event Log records failed login (Event ID 4625)
   └─▶ Log Analytics Agent forwards event to workspace

3. DETECTION
   └─▶ Azure Sentinel analytics rule evaluates incoming logs
   └─▶ KQL query matches pattern (10+ failed logins in 5 min)
   └─▶ Alert generated

4. CORRELATION
   └─▶ Multiple alerts grouped into single Incident
   └─▶ MITRE ATT&CK tactics assigned (T1110 - Brute Force)

5. AUTOMATION
   └─▶ Logic App playbook triggered
   └─▶ IP enriched with VirusTotal data
   └─▶ Geolocation added via ipgeolocation.io
   └─▶ IP blocked in NSG (if confirmed malicious)

6. NOTIFICATION
   └─▶ SOC team notified via email/Teams
   └─▶ Incident ready for investigation

7. VISUALIZATION
   └─▶ Attack appears on world map workbook
   └─▶ Metrics updated in security dashboard
```

---

## Network Architecture

```
                    INTERNET
                        │
                        ▼
              ┌─────────────────┐
              │   Public IP     │
              │   (Honeypot)    │
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │      NSG        │
              │  ┌───────────┐  │
              │  │ Inbound   │  │
              │  │ RDP: 3389 │  │
              │  │ Allow All │  │
              │  └───────────┘  │
              │  ┌───────────┐  │
              │  │ Outbound  │  │
              │  │ Allow All │  │
              │  └───────────┘  │
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │  Virtual Network│
              │  10.0.0.0/16    │
              │                 │
              │  ┌───────────┐  │
              │  │  Subnet   │  │
              │  │10.0.1.0/24│  │
              │  └─────┬─────┘  │
              └────────┼────────┘
                       │
                       ▼
              ┌─────────────────┐
              │   Windows VM    │
              │   (Honeypot)    │
              │   10.0.1.4      │
              └─────────────────┘
```

---

## Security Considerations

### ⚠️ Important Notes

1. **This is a honeypot** - It's intentionally vulnerable
2. **Isolate the VM** - Don't connect to production resources
3. **Monitor costs** - Set budget alerts
4. **Don't store sensitive data** - This VM will be attacked
5. **Regular cleanup** - Delete resources when not in use

### Best Practices Implemented

- ✅ Dedicated resource group for easy cleanup
- ✅ NSG flow logs for network visibility
- ✅ Auto-shutdown to reduce costs
- ✅ Budget alerts configured
- ✅ Minimal VM size (B1s)

---

## Scaling Considerations

For production environments, consider:

| Enhancement | Purpose |
|-------------|---------|
| Multiple honeypots | Different attack surfaces (Linux, web apps) |
| Azure Firewall | Centralized network security |
| Private endpoints | Secure Log Analytics ingestion |
| Dedicated cluster | Higher performance for large data volumes |
| Sentinel repositories | GitOps for rule management |

---

[← Back to Main README](../README.md)
