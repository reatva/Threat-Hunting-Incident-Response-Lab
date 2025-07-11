# Scenario 1 – Data Exfiltration via 7‑Zip & PowerShell

## 1. Preparation  
**Goal:** Define what to look for—insider data theft signs on a PIP’d employee’s device.  
**Hypothesis:** John Doe may silently install compression tools (7‑Zip) via PowerShell to archive sensitive files and then exfiltrate them over the network.

---

## 2. Data Collection  
**Sources Ingested:**  
- `DeviceFileEvents` (file creations, moves)  
- `DeviceProcessEvents` (process launches, command lines)  
- `DeviceNetworkEvents` (outbound connections)  

**Ensure logs are available** for the time window around suspected activity.

---

## 3. Data Analysis  
1. **Zip File Creations**  
   ```
   DeviceFileEvents
   | where DeviceName == "windows-ado"
   | where FileName endswith ".zip"
   ```
   Found normal backups and one archive at 2025‑07‑09T05:35:07.2808726Z.

   ![Alt text](/imgs/dataquery1.png)


2. **Process Correlation (±2 min)**
   ```
   let VM="windows-ado";
   let t=datetime(2025-07-09T05:35:07.2808726Z);
   DeviceProcessEvents
   | where DeviceName==VM and Timestamp between (t-2m .. t+2m)
   | project Timestamp, FileName, ProcessCommandLine, InitiatingProcessCommandLine
   | order by Timestamp desc
   ```
   Detected a PowerShell script that silently installed 7‑Zip, then ran it to archive employee data.

   ![Alt text](/imgs/dataquery2.png)

3. **Network Correlation (±2 min)**
   ```
   DeviceNetworkEvents
   | where DeviceName=="windows-ado" and Timestamp between (t-2m .. t+2m)
   | project Timestamp, ActionType, RemoteIP, RemotePort, InitiatingProcessCommandLine
   | order by Timestamp
   ```
   Immediately after zipping, the host connected to an external IP—indicating exfiltration.

   ![Alt text](/imgs/dataquery3.png)

## 4. Investigation
- **Validate Archive Contents**:
   Log in to windows-ado and inspect the PowerShell script; confirm it targeted sensitive file paths.
-**Scope Assessment**: 
   Search for other .zip creations with similar patterns or times on sibling endpoints.
- **MITRE Mapping**:

|TTP's | Details |
|------|---------|
| T1560.001 | Archive Collected Data (7‑Zip)|
| T1059.001 | PowerShell Execution |
| T1048 | Exfiltration Over Alternative Protocol |

## 5. Response Recommendations
> Although this is a hunt, not a full IR response, propose these controls to prevent recurrence:
- **Alerting:** Create Sentinel analytics for:
   - Silent installs of 7z.exe via PowerShell.
   - PowerShell commands writing to sensitive folders then launching outbound connections.
- **Containment Controls:**
   - Quarantine endpoints exhibiting both archive‐and‐connect patterns.
- **User Controls:**
   - Restrict or monitor PowerShell use by non‑IT accounts.
   - Enforce application allow‑lists to block unauthorized compression tools.

## 6. Documentation
- Record Queries & Findings: Save the above KQL snippets, timestamps, and observations.
- Report: Share your timeline and MITRE mapping with stakeholders.
- Playbook Update: Incorporate this hunt into your quarterly threat‑hunt playbook.

## 7. Improvement
- Tune Baselines: Establish normal archival behavior patterns to reduce noise.
- Enhance Telemetry: Enable script‑block logging to capture inline PowerShell installs.
- Periodic Reviews: Audit endpoints for unattended PowerShell module installations and compressed archives.

> [!NOTE]
> These recommendations are illustrative and should be tailored to your organization’s specific environment, policies, and risk tolerance.
