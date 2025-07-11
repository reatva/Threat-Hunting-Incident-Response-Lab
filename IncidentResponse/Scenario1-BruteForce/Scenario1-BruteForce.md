# Scenario 1 – Brute‑Force Attack Detection & Response

Simulated incident response for a password‑spraying brute‑force attack against an exposed VM, following NIST SP 800‑61 guidelines.
![Alt text](/imgs/bruteforcemap.png)
---

## 1. Preparation  
- **Roles & Procedures:** Defined IR team responsibilities, escalation paths, and communication plan.  
- **Tools & Training:** Ensured Microsoft Sentinel analytics, Defender for Endpoint, and playbooks are operational and staff are trained on KQL and IR workflows.

---

## 2. Detection & Analysis  

### 2.1 Analytics Rule Configuration  
- **Objective:** Alert on >10 failed logon attempts by a single user within 2 hours, indicating password spraying or account enumeration.  
- **Example Rule Screenshots:**  
    _Password Spraying test to generate log noise_ 

    ![Alt text](/imgs/passwordspraying.png)

    _KQL query in Log Analytics Workspace_  

    ![Alt text](/imgs/bruteforcerule.png)

### 2.2 Incident Trigger  
- **Rule:**  
  ```
  DeviceLogonEvents
  | where DeviceName == "windows-ado"
  | where ActionType == "LogonFailed"
  | where TimeGenerated >= ago(2h)
  | summarize TotalFailures = count() by DeviceName, RemoteIP, ActionType
  | where TotalFailures >= 10
  ```
  ![Alt text](/imgs/rulecreation.png)

### 2.3 Investigation Findings

    Host: windows-ado
    Remote IP: 119.18.0.58
    Total Failures: 37
    Verification Query:

    ```
    DeviceLogonEvents
	| where RemoteIP in("119.18.0.58")
	| where ActionType != "LogonFailed"
    ```
## 3. Containment, Eradication & Recovery

- **Containment**:
    - Isolated windows-ado via Defender for Endpoint isolation.
    - Locked down NSG to allow RDP only from trusted IPs (e.g., home office).

- **Eradication**:
    - Ran full antimalware scan—no persistent malware found.
    - Rotated any exposed credentials and enforced account lockout policies.

- **Recovery**:
    - Restored NSG to allow normal operations with hardened rules.
    - Re-enabled RDP for approved operators.
    - Verified no further failed logon spikes.

## 4. Post‑Incident Activities
- **Lessons Learned Workshop:** Reviewed attack vector and detection latency.
- **Policy Update:** Mandated account lockout threshold (5 failures → 30 min lock).
- **Playbook Tuning:** Added a step to automatically enrich incidents with geolocation and known‑bad IP intelligence.

## 5. MITRE ATT&CK Mapping
| Tactic | Technique | ID | Notes | 
|--------|-----------|----|-------|
| Credential Access |	Brute Force	| T1110 |	Multiple failed logon attempts from single IP |
| Initial Access | External Remote Services	| T1133	| Attempts via exposed RDP/SMB | 

## 6. Recommendations & Next Steps
- **Expand NSG Hardening:** Apply default deny for all management ports.
- **Enable MFA:** Require multi‑factor authentication for all RDP and console logins.
- **Monitor Account Lockouts:** Alert on rapid lockout events across multiple accounts.
- **Periodic IR Drills:** Simulate brute‑force scenarios quarterly.

> [!NOTE]
> These recommendations are illustrative and should be tailored to your organization’s specific environment, policies, and risk tolerance and technical environment.
