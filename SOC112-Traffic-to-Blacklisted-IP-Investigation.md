# SOC112 – Traffic to Blacklisted IP

**Platform:** LetsDefend | **Severity:** Critical | **Classification:** True Positive | **Date:** January 31, 2021 **Host:** `Jack` (`172.16.17.21`) | **User:** `jack2021` | **Destination:** `193.239.147.32`

## Summary

PowerShell on Jack's host requested an executable, `OBBBOP.exe`, from a blacklisted IP. The proxy allowed the request, so the file was likely downloaded to the host.

<img width="1596" height="569" alt="01-alert-details" src="https://github.com/user-attachments/assets/9803b145-90bb-47a8-a357-9026885449d7" />


## Investigation

### 1. Request Analysis

- **URL:** `http://193.239.147.32/OBBBOP.exe`
- **User-Agent:** `Mozilla/5.0 (Windows NT 10.0; Microsoft Windows 10.0.15063; en-US) PowerShell/6.0.0`
- **Device Action:** Allowed

The User-Agent shows the request came from PowerShell, not a browser. Users don't normally download executables from a bare IP address with PowerShell; this pattern usually means a script is pulling down a payload. The plain HTTP connection and random-looking filename add to that.

### 2. Log Analysis

A Log Management search for `193.239.147.32` returned two events, both from `172.16.17.21` on source port `23112`:

| Time (log) | Source | Event |
| ---------- | ------ | ----- |
| 03:02:19 | Firewall | `172.16.17.21` → `193.239.147.32:80` connection |
| 03:02:59 | Proxy | `GET http://193.239.147.32/OBBBOP.exe` |

The firewall entry shows the host opening the connection, and the proxy entry shows the file request over it. Jack's host reached the malicious IP, so the playbook answer is **Accessed**.

*The alert shows 11:02 (+03:00); the alert and Log Management display time differently.

<img width="1590" height="794" alt="02-logs-proxy-firewall" src="https://github.com/user-attachments/assets/65131d70-ff77-4dd1-ba2a-17c15b968de6" />


### 3. IP Analysis

VirusTotal flags `193.239.147.32` 13/92 (Orange, AS5511, GB), with malicious, malware, and phishing labels from vendors including ESET, Fortinet, Sophos, and BitDefender.

<img width="1909" height="983" alt="03-virustotal-ip" src="https://github.com/user-attachments/assets/47432407-204e-44a1-8a68-03b7cd9b3160" />


## Playbook Answers

| Question | Answer |
| -------- | ------ |
| Has anyone accessed the IP/URL/domain? | Accessed |
| Analyze URL address | Malicious |

<img width="1540" height="433" alt="04-playbook-answers" src="https://github.com/user-attachments/assets/edb13898-07b2-48e6-9d94-4084093389b2" />


## Artifacts

| Type | Indicator |
| ---- | --------- |
| Malicious IP | `193.239.147.32` |
| URL | `http://193.239.147.32/OBBBOP.exe` |
| File | `OBBBOP.exe` |
| Host | `Jack` (`172.16.17.21`) |

## Response

Contain `172.16.17.21`, block `193.239.147.32`, and check the host for `OBBBOP.exe` and whether it ran. Review the host's Terminal History to find what launched PowerShell.

## Conclusion

**True Positive.** PowerShell on Jack's host downloaded an executable from a known-malicious IP, and the proxy allowed it.

**MITRE ATT&CK:** T1059.001 (PowerShell), T1105 (Ingress Tool Transfer)
