# SOC176 – RDP Brute Force Detected

**Platform:** LetsDefend | **Severity:** Medium | **Classification:** True Positive | **Date:** March 7, 2024 **Host:** `Matthew` (`172.16.17.148`) | **Attacker:** `218.92.0.56`

## Summary

An external IP brute-forced RDP on Matthew's host, cycling through common usernames (`sysadmin`, `admin`, `guest`) before hitting the valid account `Matthew`. After a series of failed attempts, it logged in successfully at 03:44:59. The firewall allowed the traffic, so the attacker gained an interactive session on the host.

![01-alert-details](screenshots/01-alert-details.png)

## Timeline

| Time (log) | Event |
| ---------- | ----- |
| 03:44:16 – 03:44:56 | Repeated 4625 failures for `guest`, `sysadmin`, `admin` (`0xC000006D`, unknown user or bad password) |
| 03:44:57 | 4625 failure for `Matthew` (`0xC000006A`, valid user, wrong password) |
| 03:44:59 | **4624 success** for `Matthew`, Logon Type 10 (RemoteInteractive / RDP) |

*The alert shows 11:44 (+03:00); the alert and Log Management display time differently.

## Investigation

**Logs:** A search for `218.92.0.56` returned 30 events, all to `172.16.17.148:3389`. Firewall entries confirm the RDP traffic was allowed. The error code change on `Matthew` (`0xC000006D` to `0xC000006A`) shows the attacker found a real account, and the 4624 two seconds later confirms the password was guessed. Only one target host was involved.

![02-logs-failed-logons](screenshots/02-logs-failed-logons.png)
![03-logs-failed-logons-2](screenshots/03-logs-failed-logons-2.png)
![04-logs-successful-logon](screenshots/04-logs-successful-logon.png)

**IP reputation:** VirusTotal flags `218.92.0.56` 5/92 (Chinanet, AS4134, CN), with malicious, malware, and phishing labels.

![05-virustotal-ip](screenshots/05-virustotal-ip.png)

## Artifacts

| Type | Indicator |
| ---- | --------- |
| Attacker IP | `218.92.0.56` |
| Target | `172.16.17.148:3389` (Matthew) |
| Compromised account | `Matthew` |

## Response

Contain `172.16.17.148`, reset Matthew's password, block `218.92.0.56`, and review the host's Terminal History for activity after 03:44:59. RDP should not be exposed to the internet; restrict it behind a VPN and enforce account lockout and MFA.

## Conclusion

**True Positive.** A brute-force attack from `218.92.0.56` guessed Matthew's password and opened an RDP session on the host.

**MITRE ATT&CK:** T1110 (Brute Force), T1078 (Valid Accounts)
