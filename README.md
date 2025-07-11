# Threat Hunting & Incident Response Lab

A structured Threat Hunting and Incident Response (IR) lab designed for hands‑on learning with Microsoft Sentinel and Defender for Endpoint. This lab simulates realistic detection, investigation, and response workflows against common attacker TTPs, making it ideal for blue‑team training, purple‑team exercises, and portfolio demonstration.

---

## Objectives

1. **Build a Proactive Hunt Workflow**   
2. **Execute Reactive IR Playbooks**  
3. **Document and Share**  

---

## Lab Architecture

| Tool                | Role                                                         | Details                          |
|--------------------------|--------------------------------------------------------------|----------------------------------|
| Microsoft Sentinel       | SIEM / SOAR                                                  | Log Analytics workspace + alerts |
| Defender for Endpoint    | EDR on all Windows hosts                                     | Advanced Hunting enabled        |
| Azure VM           | Endpoint under threat hunt                                   | Windows 10 Pro                  |

---

## Technologies Used

- **Kusto Query Language (KQL)** for log queries  
- **Microsoft Sentinel** for analytics rules and playbooks  
- **Microsoft Defender for Endpoint** for endpoint telemetry and response  
- **Microsoft Azure** for VM's creation

---

## Lab Key Features

- **7‑Step Threat Hunting Framework** embedded in each scenario  
- **MITRE ATT&CK Mapping** for all simulated adversary behaviors  
- **Reusable KQL Snippets** for rapid deployment into Sentinel  

---

## Scenario Overview
- Read each scenario’s detailed procedure in the corresponding Markdown file.

1. **TH Scenario 1** – [Data Exfiltration from PIP'd employee](/ThreatHunting/Scenario1-DataExfiltration/Scenario1-DataExfiltration.md)
2. **TH Scenario 2** – [Suspicious/Unauthorized Tor Usage](/ThreatHunting/Scenario2-UnauthorizedTORUsage/Scenario2-UnauthorizedTORUsage.md )
3. **IR Scenario 1** – [Internet‑Facing Brute‑Force](/IncidentResponse/Scenario1-BruteForce/Scenario1-BruteForce.md)
4. **IR Scenario 2** – [Suspicious web request](/IncidentResponse/Scenario1-BruteForce/Scenario2-SuspiciousPowershell/)
    
> [!NOTE]
> The scenarios and structure provided are examples. Be sure to create your own and improve upon them as needed.

---

## Attack / Hunt Flow (Example)

1. **Preparation** – Form hypothesis based on anomalies.  
2. **Data Collection** – Ensure ingestion of required tables.  
3. **Analysis** – Run KQL to surface anomalies.  
4. **Investigation** – Pivot to process/file logs, map to MITRE TTPs.  
5. **Containment** – Isolate hosts via Defender for Endpoint.  
6. **Eradication** – Remove malicious artifacts, rebuild if necessary.  
7. **Recovery & Improvement** – Restore systems, update detection rules, document lessons learned.

## Disclaimer

> [!NOTE] 
> This lab is for educational purposes. Never run these techniques or queries against environments where you do not have explicit permission.


