# SOC112 – Traffic to Blacklisted IP

**Platform:** LetsDefend | **Severity:** Critical | **Classification:** True Positive | **Date:** January 31, 2021 **Host:** `Jack` (`172.16.17.21`) | **User:** `jack2021` | **Destination:** `193.239.147.32`

## Summary

An obfuscated PowerShell command on Jack's host downloaded and ran a batch file, `a.bat`, from a shortened link. About 45 minutes later, PowerShell on the same host requested an executable, `OBBBOP.exe`, from a blacklisted IP, and the proxy allowed it. This is a two-stage infection: a small script first, then a second payload.

![01-alert-details](screenshots/01-alert-details.png)

## Timeline

| Time (+03:00) | Event |
| ------------- | ----- |
| 10:15 | Obfuscated PowerShell downloads `a.bat` from `http://rebrand.ly/WdBPApoMACRO` |
| 10:16 | `powershell -w 1 ./a.bat` runs it in a hidden window |
| 10:17 | `cmd.exe /c C:/Users/admin/Documents/a.bat` runs it again |
| 11:02 | PowerShell requests `http://193.239.147.32/OBBBOP.exe`, allowed |

*Log Management records the 11:02 request as 03:02; the sources display time differently.

## Investigation

### 1. Request Analysis

- **URL:** `http://193.239.147.32/OBBBOP.exe`
- **User-Agent:** `Mozilla/5.0 (Windows NT 10.0; Microsoft Windows 10.0.15063; en-US) PowerShell/6.0.0`
- **Device Action:** Allowed

The User-Agent shows the request came from PowerShell, not a browser. Users don't normally download executables from a bare IP address with PowerShell; this pattern usually means a script is pulling down a payload.

### 2. Log Analysis

A Log Management search for `193.239.147.32` returned two events from `172.16.17.21`: a firewall connection to port 80 at 03:02:19 and a proxy `GET` for `OBBBOP.exe` at 03:02:59. Jack's host reached the malicious IP, so the playbook answer is **Accessed**.

![02-logs-proxy-firewall](screenshots/02-logs-proxy-firewall.png)

### 3. Endpoint Analysis

Terminal History shows what happened before the alert. The first command is deliberately obfuscated to evade detection: `^` characters break up `powershell` for cmd, backticks break up `New-Object` and `WebClient` for PowerShell, and `Down+loadFile` splits the method name. `-w 1` hides the window. It downloads `a.bat` from a URL shortener whose path includes "MACRO," suggesting a malicious Office macro started the chain. The batch file then runs twice.

The `OBBBOP.exe` request comes after `a.bat` ran and uses PowerShell, which fits `a.bat` fetching the second stage. Terminal History doesn't show `OBBBOP.exe` executing.

![03-endpoint-terminal-history](screenshots/03-endpoint-terminal-history.png)

### 4. IP Analysis

VirusTotal flags `193.239.147.32` 13/92 (Orange, AS5511, GB), with malicious, malware, and phishing labels from vendors including ESET, Fortinet, Sophos, and BitDefender.

![04-virustotal-ip](screenshots/04-virustotal-ip.png)

## Playbook Answers

| Question | Answer |
| -------- | ------ |
| Has anyone accessed the IP/URL/domain? | Accessed |
| Analyze URL address | Malicious |

![05-playbook-answers](screenshots/05-playbook-answers.png)

## Artifacts

| Type | Indicator |
| ---- | --------- |
| Malicious IP | `193.239.147.32` |
| URL | `http://193.239.147.32/OBBBOP.exe` |
| URL | `http://rebrand.ly/WdBPApoMACRO` |
| Files | `a.bat`, `OBBBOP.exe` |
| Host | `Jack` (`172.16.17.21`) |

## Response

Contain `172.16.17.21`, block `193.239.147.32` and the rebrand.ly link, check the Processes tab for `OBBBOP.exe` execution, and look for the Office document or email that launched the macro.

## Conclusion

**True Positive.** A macro-launched script downloaded and ran `a.bat` on Jack's host, which was followed by a PowerShell download of `OBBBOP.exe` from a known-malicious IP.

**MITRE ATT&CK:** T1059.001 (PowerShell), T1059.003 (Windows Command Shell), T1027 (Obfuscated Files or Information), T1105 (Ingress Tool Transfer)
