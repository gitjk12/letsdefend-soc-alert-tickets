# SOC134 – Suspicious WMI Activity

**Platform:** LetsDefend | **Severity:** Critical | **Classification:** True Positive | **Date:** March 7, 2021
**Host:** Desktop-Anderson (`172.16.17.54`, Windows 10) | **User:** Anderson | **File:** `exec.bat` | **Event ID:** 71

## Summary

The alert flagged `exec.bat` for suspicious WMI activity on Desktop-Anderson. The endpoint logs don't show the batch file running, but they reveal an earlier compromise: in December 2020 the host ran recon commands and sent Anderson's and the Administrator's passwords to `161.35.41.241:4444`, a DigitalOcean IP flagged as malicious. The host was accessed and its credentials stolen.

<img width="1648" height="449" alt="01-alert-details" src="https://github.com/user-attachments/assets/33106613-fb94-4cef-975e-b01e4987a3bd" />


## Investigation

### 1. Terminal History

On Dec 19, 2020 the host ran a standard recon sequence: `hostname`, `net user` and `whoami` (09:15–09:17), then `tasklist`, `net user anderson` and `ping 172.16.20.1` (11:18–11:21). The second group lines up with the connections to the attacker IP.

<img width="1468" height="556" alt="02-terminal-history" src="https://github.com/user-attachments/assets/f0d79cc5-5e31-4b4f-8d6e-d8a0d090304c" />


### 2. Network Action

The host connected to `161.35.41.241` every minute from 11:18 to 11:21, the same window as the recon commands. The other destinations match normal browsing (TechCrunch, GitHub).

<img width="1390" height="617" alt="03-network-action" src="https://github.com/user-attachments/assets/b3f0f6f6-3901-40c7-b2db-3f2337d4f2b4" />


### 3. Proxy Log – Credential Exfiltration

A proxy log shows `172.16.17.54` sending data to `161.35.41.241:4444` (port 4444 is Metasploit's default). Base64-decoding the payload gives:

```
Passlist:
Anderson:ander12son!
Administrator:mys3r3tP@ss!.
```

<img width="1454" height="332" alt="04-proxy-log" src="https://github.com/user-attachments/assets/a82896a8-5724-4101-b592-d1726fa311c5" />


### 4. Threat Intelligence

- **161.35.41.241:** 4/92 vendors on VirusTotal flag it (phishing, malware, malicious). AS14061, DigitalOcean.
- **exec.bat:** 1/61 detections (Kaspersky: `UDS:Trojan.Script.Agent`), community score -58.

<img width="1916" height="1012" alt="05-virustotal-ip" src="https://github.com/user-attachments/assets/9fd6c313-28b2-4036-a230-fd20f339a882" />

<img width="1915" height="1012" alt="06-virustotal-exec-bat" src="https://github.com/user-attachments/assets/119491ac-f891-4fa8-a676-0aea1122ede0" />


### 5. Gaps

- **Initial access:** not identified in the available logs. Outlook and Adobe Reader running on the host are consistent with a phishing PDF, but there's no evidence for it.
- **exec.bat / WMI:** the file and its WMI activity appear only in the alert. No execution evidence was found in the process list or terminal history.

## Artifacts

| Type | Indicator |
|------|-----------|
| Attacker IP | `161.35.41.241:4444` (AS14061, DigitalOcean) |
| File | `exec.bat` (52 B) |
| MD5 | `50459310eded4c520ab5c9e3626a9300` |
| SHA-256 | `be77e6113a985dc305be15ec419411bb840b69f8652d33fa919ae5c797b3ea85` |
| Compromised accounts | `Anderson`, `Administrator` |

## Response and Recommendations

Contain Desktop-Anderson, reset the Anderson and Administrator passwords (and any accounts sharing them), block `161.35.41.241`, and check other hosts for connections to it. Escalate to Tier 2 to identify the initial access vector.

## Conclusion

**True Positive – Host Accessed.** Desktop-Anderson ran attacker recon commands and exfiltrated local credentials to a malicious external IP in December 2020. The March 2021 WMI alert shows the attacker likely still had a foothold, though its exact impact isn't visible in the logs.

**MITRE ATT&CK:** T1047 (WMI), T1033 (System Owner/User Discovery), T1087.001 (Local Account Discovery), T1057 (Process Discovery), T1041 (Exfiltration Over C2 Channel), T1204 (User Execution)
