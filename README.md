# 🛡️ Azure Sentinel SOC Lab

[![Azure](https://img.shields.io/badge/Azure-Sentinel-0078D4?logo=microsoft-azure)](https://azure.microsoft.com/services/microsoft-sentinel/)
[![KQL](https://img.shields.io/badge/Language-KQL-blue)](https://docs.microsoft.com/azure/data-explorer/kusto/query/)
[![MITRE ATT&CK](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-red)](https://attack.mitre.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A hands-on Security Operations Center (SOC) lab featuring **Azure Sentinel SIEM** with custom KQL detection rules, Logic Apps automation, threat intelligence integration, and MITRE ATT&CK mapping.

> 🎯 **Purpose:** Build practical SOC analyst skills through real-world threat detection and incident response scenarios.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Features](#features)
- [Technologies Used](#technologies-used)
- [Attack Detection Scenarios](#attack-detection-scenarios)
- [Project Structure](#project-structure)
- [Setup Guide](#setup-guide)
- [KQL Detection Rules](#kql-detection-rules)
- [Automation Playbooks](#automation-playbooks)
- [Dashboards & Workbooks](#dashboards--workbooks)
- [Threat Hunting](#threat-hunting)
- [Cost Management](#cost-management)
- [Screenshots](#screenshots)
- [Future Enhancements](#future-enhancements)
- [Resources](#resources)
- [License](#license)

---

## 🔍 Overview

This project implements an enterprise-grade SIEM solution using Microsoft Azure Sentinel to detect, investigate, and respond to cyber threats in real-time.

### What This Lab Demonstrates:

| Skill | Description |
|-------|-------------|
| **SIEM Configuration** | Deploy and configure Azure Sentinel workspace |
| **Log Analysis** | Ingest and analyze security logs from multiple sources |
| **Threat Detection** | Create custom analytics rules using KQL |
| **Incident Response** | Investigate and respond to security incidents |
| **Automation (SOAR)** | Automate response with Logic Apps playbooks |
| **Threat Hunting** | Proactively hunt for threats using KQL queries |
| **Visualization** | Build security dashboards and workbooks |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              AZURE CLOUD                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐          │
│  │  Windows VM     │    │   Azure AD      │    │  Network        │          │
│  │  (Honeypot)     │    │   Sign-in Logs  │    │  Security Group │          │
│  │  RDP Exposed    │    │                 │    │  Flow Logs      │          │
│  └────────┬────────┘    └────────┬────────┘    └────────┬────────┘          │
│           │                      │                      │                    │
│           └──────────────────────┼──────────────────────┘                    │
│                                  │                                           │
│                                  ▼                                           │
│                    ┌─────────────────────────┐                               │
│                    │   LOG ANALYTICS         │                               │
│                    │   WORKSPACE             │                               │
│                    │   (Data Collection)     │                               │
│                    └────────────┬────────────┘                               │
│                                 │                                            │
│                                 ▼                                            │
│                    ┌─────────────────────────┐                               │
│                    │   AZURE SENTINEL        │                               │
│                    │   (SIEM/SOAR)           │                               │
│                    │                         │                               │
│                    │  ┌─────────────────┐    │                               │
│                    │  │ Analytics Rules │    │    ┌─────────────────┐        │
│                    │  │ (KQL Detection) │────┼───▶│ Logic Apps      │        │
│                    │  └─────────────────┘    │    │ (Auto Response) │        │
│                    │                         │    └─────────────────┘        │
│                    │  ┌─────────────────┐    │             │                 │
│                    │  │ Workbooks       │    │             ▼                 │
│                    │  │ (Dashboards)    │    │    ┌─────────────────┐        │
│                    │  └─────────────────┘    │    │ Email/Teams     │        │
│                    │                         │    │ Notifications   │        │
│                    │  ┌─────────────────┐    │    └─────────────────┘        │
│                    │  │ Threat Intel    │    │                               │
│                    │  │ (VirusTotal,    │    │                               │
│                    │  │  AbuseIPDB)     │    │                               │
│                    │  └─────────────────┘    │                               │
│                    └─────────────────────────┘                               │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘

                    ┌─────────────────────────┐
                    │   EXTERNAL ATTACKERS    │
                    │   (Internet)            │
                    │   - RDP Brute Force     │
                    │   - Port Scanning       │
                    │   - Credential Attacks  │
                    └─────────────────────────┘
```

📄 **Detailed architecture documentation:** [docs/architecture.md](docs/architecture.md)

---

## ✨ Features

### 🔐 Detection Capabilities

| Attack Type | Detection Method | MITRE ATT&CK |
|-------------|------------------|--------------|
| RDP Brute Force | Failed login threshold + Geolocation | T1110.001 |
| Password Spray | Multiple accounts, same password pattern | T1110.003 |
| Impossible Travel | Login from distant locations in short time | T1078 |
| Privilege Escalation | Sensitive role assignments | T1078.004 |
| Suspicious PowerShell | Encoded commands, downloads | T1059.001 |
| Data Exfiltration | Unusual outbound data transfers | T1041 |
| Malware Indicators | Known malicious IPs/domains | T1071 |
| Account Enumeration | Multiple failed logins, different accounts | T1087 |

### ⚡ Automation (SOAR)

| Playbook | Trigger | Action |
|----------|---------|--------|
| Block-MaliciousIP | High severity alert | Add IP to NSG block list |
| Enrich-Alert-ThreatIntel | Any alert | Query VirusTotal & AbuseIPDB |
| Notify-SOCTeam | Medium+ severity | Send Teams/Email notification |
| Isolate-Compromised-VM | Confirmed compromise | Restrict VM network access |
| Create-Incident-Ticket | New incident | Create ticket (ServiceNow/Jira) |

### 📊 Dashboards & Workbooks

- **Security Overview** - High-level security posture
- **Attack World Map** - Geographic visualization of attacks
- **RDP Monitoring** - Failed/successful RDP attempts
- **User Activity** - Azure AD sign-in analytics
- **Incident Metrics** - MTTR, incident trends, SLA tracking

---

## 🛠️ Technologies Used

| Technology | Purpose |
|------------|---------|
| **Azure Sentinel** | Cloud-native SIEM & SOAR platform |
| **Log Analytics** | Log ingestion and storage |
| **KQL** | Query language for detection rules |
| **Logic Apps** | Automated incident response workflows |
| **Azure AD** | Identity and access logs |
| **Azure VMs** | Honeypot deployment |
| **NSG Flow Logs** | Network traffic analysis |
| **PowerShell** | Automation scripts |
| **VirusTotal API** | Threat intelligence enrichment |
| **AbuseIPDB API** | IP reputation checking |

---

## 🎯 Attack Detection Scenarios

### 1. RDP Brute Force Attack
```
Attacker → Multiple failed RDP logins → Sentinel detects pattern → 
Alert generated → Logic App blocks IP → SOC notified
```

### 2. Suspicious Azure AD Sign-in
```
User login from new country → Impossible travel detected → 
Risk flagged → Conditional Access triggered → Alert created
```

### 3. Privilege Escalation
```
User added to Global Admin → Sentinel detects sensitive change → 
High severity alert → Immediate notification → Investigation initiated
```

---

## 📁 Project Structure

```
azure-sentinel-soc-lab/
├── 📄 README.md                          # Project overview (you are here)
├── 📁 docs/
│   ├── 01-azure-setup.md                 # Azure Sentinel workspace setup
│   ├── 02-honeypot-deployment.md         # Windows VM honeypot configuration
│   ├── 03-data-connectors.md             # Connecting log sources
│   ├── 04-detection-rules.md             # Creating analytics rules
│   ├── 05-automation-playbooks.md        # Logic Apps setup guide
│   ├── 06-workbooks-dashboards.md        # Building visualizations
│   ├── 07-threat-hunting.md              # Hunting queries and techniques
│   ├── 08-cost-management.md             # Budget alerts and optimization
│   └── architecture.md                   # Detailed architecture docs
├── 📁 kql-queries/
│   ├── 📁 detection-rules/               # Analytics rule KQL queries
│   │   ├── rdp-brute-force.kql
│   │   ├── password-spray.kql
│   │   ├── impossible-travel.kql
│   │   ├── privilege-escalation.kql
│   │   ├── suspicious-powershell.kql
│   │   └── malware-indicators.kql
│   ├── 📁 hunting-queries/               # Threat hunting KQL
│   │   ├── unusual-login-times.kql
│   │   ├── rare-processes.kql
│   │   └── lateral-movement.kql
│   └── 📁 workbook-queries/              # Dashboard KQL queries
│       ├── security-overview.kql
│       └── attack-map.kql
├── 📁 scripts/
│   ├── 📁 powershell/
│   │   ├── Export-FailedRDPLogs.ps1      # RDP log extraction
│   │   ├── Get-GeoLocation.ps1           # IP geolocation lookup
│   │   └── Setup-LogForwarding.ps1       # Configure log forwarding
│   └── 📁 setup/
│       └── deploy-honeypot.ps1           # Automated VM deployment
├── 📁 playbooks/
│   └── 📁 logic-apps/
│       ├── block-malicious-ip.json       # IP blocking playbook
│       ├── enrich-threat-intel.json      # TI enrichment playbook
│       └── notify-soc-team.json          # Notification playbook
├── 📁 workbooks/
│   └── security-dashboard.json           # Workbook template
├── 📁 images/
│   ├── architecture-diagram.png
│   └── 📁 screenshots/
│       ├── sentinel-dashboard.png
│       ├── attack-map.png
│       └── incident-investigation.png
└── 📄 LICENSE
```

---

## 🚀 Setup Guide

### Prerequisites

- Azure subscription with Sentinel access (Azure Student $100 credit works!)
- VS Code with Azure extensions
- PowerShell 7+
- Git

### Quick Start

| Phase | Guide | Time |
|-------|-------|------|
| 1 | [Azure Sentinel Setup](docs/01-azure-setup.md) | 30 min |
| 2 | [Deploy Honeypot VM](docs/02-honeypot-deployment.md) | 45 min |
| 3 | [Connect Data Sources](docs/03-data-connectors.md) | 30 min |
| 4 | [Create Detection Rules](docs/04-detection-rules.md) | 1 hour |
| 5 | [Setup Automation](docs/05-automation-playbooks.md) | 1 hour |
| 6 | [Build Dashboards](docs/06-workbooks-dashboards.md) | 45 min |
| 7 | [Threat Hunting](docs/07-threat-hunting.md) | 1 hour |

📖 **Full setup guide:** [docs/01-azure-setup.md](docs/01-azure-setup.md)

---

## 📊 KQL Detection Rules

### Example: RDP Brute Force Detection

```kql
// Detect RDP brute force attempts (10+ failed logins in 5 minutes)
SecurityEvent
| where EventID == 4625
| where LogonType == 10  // RDP logon
| summarize 
    FailedAttempts = count(),
    Accounts = make_set(TargetUserName),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated)
    by IPAddress = IpAddress, bin(TimeGenerated, 5m)
| where FailedAttempts >= 10
| extend 
    AttackDuration = LastAttempt - FirstAttempt,
    Severity = case(
        FailedAttempts >= 50, "High",
        FailedAttempts >= 25, "Medium",
        "Low"
    )
| project 
    TimeGenerated,
    IPAddress,
    FailedAttempts,
    Accounts,
    AttackDuration,
    Severity
```

📁 **All detection rules:** [kql-queries/detection-rules/](kql-queries/detection-rules/)

---

## ⚡ Automation Playbooks

### Block Malicious IP Workflow

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Sentinel  │────▶│ Logic App   │────▶│ Check       │────▶│ Block IP    │
│   Alert     │     │ Triggered   │     │ Reputation  │     │ in NSG      │
└─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
                                                                   │
                                                                   ▼
                                                            ┌─────────────┐
                                                            │ Notify SOC  │
                                                            │ Team        │
                                                            └─────────────┘
```

📁 **All playbooks:** [playbooks/logic-apps/](playbooks/logic-apps/)

---

## 💰 Cost Management

This project is designed to run within Azure Student $100 credits.

### Estimated Monthly Cost

| Resource | Cost | Notes |
|----------|------|-------|
| Log Analytics | FREE | First 5GB/day free |
| Azure Sentinel | FREE | First 10GB/day (31 days trial) |
| Windows VM (B1s) | ~$8-10 | Use auto-shutdown! |
| Storage | ~$1-2 | Minimal usage |
| **Total** | **~$10-15/month** | Well within $100 credit |

### Cost Saving Tips

- ✅ Enable VM auto-shutdown (saves 50%+)
- ✅ Use B1s VM size (smallest)
- ✅ Set budget alerts at $20, $50, $80
- ✅ Delete resources when not in use
- ✅ Monitor costs daily during setup

📖 **Detailed cost guide:** [docs/08-cost-management.md](docs/08-cost-management.md)

---

## 📸 Screenshots

### Security Dashboard
*Coming soon - Will show real attack data visualization*

### Attack World Map
*Coming soon - Geographic distribution of attackers*

### Incident Investigation
*Coming soon - Alert triage and investigation workflow*

---

## 🔮 Future Enhancements

- [ ] Linux honeypot integration
- [ ] File Integrity Monitoring (FIM)
- [ ] Custom threat intelligence feeds
- [ ] UEBA (User Entity Behavior Analytics)
- [ ] Automated reporting (weekly/monthly)
- [ ] Integration with ticketing systems

---

## 📚 Resources

### Official Documentation
- [Azure Sentinel Documentation](https://docs.microsoft.com/azure/sentinel/)
- [KQL Reference](https://docs.microsoft.com/azure/data-explorer/kusto/query/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)

### Learning Paths
- [Microsoft Learn - Azure Sentinel](https://docs.microsoft.com/learn/paths/security-ops-sentinel/)
- [SC-200 Certification Path](https://docs.microsoft.com/certifications/exams/sc-200)

### Community
- [Azure Sentinel GitHub](https://github.com/Azure/Azure-Sentinel)
- [KQL Cafe](https://www.kqlcafe.com/)

---

## 🤝 Contributing

Contributions are welcome! Feel free to:
- Report bugs
- Suggest new detection rules
- Improve documentation
- Add new automation playbooks

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👤 Author

**oznekcyber**

- GitHub: [@oznekcyber](https://github.com/oznekcyber)

---

<p align="center">
  <b>Built for learning SOC analyst skills through hands-on experience</b><br>
  ⭐ Star this repo if you find it helpful!
</p>
