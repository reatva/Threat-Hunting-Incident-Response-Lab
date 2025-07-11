# Scenario 2 – Unauthorized TOR Browser Usage

## 1. Preparation  
**Goal:** Detect and investigate any use of TOR browsers on corporate endpoints to bypass security controls.  
**Context:** Network logs show encrypted traffic to known TOR entry nodes, and anonymous tips suggest employees are accessing restricted sites.  

**Hypothesis:** A non‑admin user may download and run a portable TOR browser via PowerShell to evade monitoring.

---

## 2. Data Collection  
Ensure telemetry is ingested for the following tables over the suspected timeframe:

- **DeviceFileEvents** 
- **DeviceProcessEvents**  
- **DeviceNetworkEvents** 

---

## 3. Data Analysis  
1. **Installer Download & File Copies**  
   ```
   DeviceFileEvents
   | where DeviceName == "windows-ado"
   | where InitiatingProcessAccountName == "labuser"
   | where FileName has "tor"
   | project Timestamp, FileName, FolderPath
   | order by Timestamp desc
   ```
   Found TOR installer download at 2025‑07‑11T02:19:19Z and multiple TOR files copied to Desktop, including tor-shipping-list at 02:42:07Z.
   
   ![Alt text](/imgs/torquery1.png)

2. **Silent Installation**
    ```
    DeviceProcessEvents
    | where DeviceName == "windows-ado"
    | where ProcessCommandLine has "tor-browser"
    | where FileName != "firefox.exe"
    | project Timestamp, FileName, ProcessCommandLine
    ```
    Detected silent install of tor‑browser‑windows‑x86_64‑portable‑14.5.4.exe at 02:20:43Z.

    ![Alt text](/imgs/torquery2.png)

3. **Browser Lunch**
    ```
    DeviceProcessEvents
    | where DeviceName == "windows-ado"
    | where FileName in ("tor.exe","firefox.exe")
    | project Timestamp, FileName, ProcessCommandLine
    | order by Timestamp asc
    ```
    Observed firefox.exe and tor.exe at 02:21:52Z.

    ![Alt text](/imgs/torquery3.png)

4. **Outbound TOR Connection**
    ```
    DeviceNetworkEvents
    | where DeviceName == "windows-ado"
    | where ActionType == "ConnectionSuccess"
    | where InitiatingProcessCommandLine has "tor"
    | project Timestamp, RemoteIP, RemotePort
    ```
    Established connection to TOR node 185.129.61.10 at 02:21:57Z.

    ![Alt text](/imgs/torquery4.png)

## 4. Investigation & TTP Mapping
|Tactic |	Technique |	ID | 
|-------|-------------|----|
|Execution |	PowerShell	| T1059.001 | 
|Discovery	| Archive Collected Data (portable browser unpack)|	T1560.001 |

## 5. Response Recommendations
- **Containment**
    - Quarantine windows-ado.
    - Terminate all TOR‐related processes.

- **Eradication**
    - Delete TOR binaries, installer files, and tor-shipping-list.
    - Uninstall any system‑level TOR components.

- **Remediation & Recovery**
    - Reimage or thoroughly clean the host.
    - Reset labuser credentials and revoke any unauthorized sessions.

- **Network & Policy Controls**
    - Block known TOR node IP ranges at perimeter firewall.
    - Enforce application whitelisting to prevent portable browser execution.

- **Detection & Monitoring**
    - PowerShell commands installing or running tor-browser.
    - File creations with tor*.exe by non‑admin accounts.
    - Network connections matching TOR entry node lists.



## 6. Documentation
- Record all KQL queries, timestamps, and findings in your hunt notebook.
- Share a concise timeline and TTP mapping with management.

## 7. Improvement
- Tune detection baselines for normal application installs vs. unauthorized unpacking.
- Implement stricter controls on PowerShell module installations.
- Periodically audit user directories for unapproved executables.

> [!NOTE]
> These recommendations are illustrative and should be tailored to your organization’s specific environment, policies, and risk tolerance.
