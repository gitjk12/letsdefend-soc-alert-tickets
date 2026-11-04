# SOC119 – Proxy – Malicious Executable File Detected (EventID 83)

**Severity:** Medium | **Type:** Proxy | **MITRE:** T1204 – User Execution
**Event Time:** 2021-03-21 13:02:11 (+03:00)
**Verdict:** Non-malicious download (ticket closed as True Positive)

## Alert Summary
Proxy flagged an executable download by user **Susie** (SusieHost, 172.16.17.5) via Chrome on Windows.
- **URL:** hxxps://www.win-rar[.]com/postdownload.html?&L=0&Version=32bit
- **Destination:** 51.195.68.163 (win-rar.com), port 443
- **Device Action:** Allowed

![Alert details](screenshots/01-alert-details.png)

## Investigation
**Log Management:** One event to 51.195.68.163, matching the alert (chrome.exe, 172.16.17.5:43213 → 443). No other traffic to the IP.

![Log management](screenshots/02-log-management.png)

**VirusTotal (URL):** 0/93 detections. Official WinRAR download page on win-rar.com, resolving to the same IP (51.195.68.163).

![VirusTotal URL scan](screenshots/03-virustotal-url.png)

**VirusTotal (IP):** 51.195.68.163 is 0/92, OVH SAS (AS16276, France). Shared hosting IP; 9 detected files are linked to it, which is common for hosting providers and not tied to this URL.

![VirusTotal IP scan](screenshots/04-virustotal-ip.png)

**Endpoint (SusieHost):** EDR agent was down, so no process, network, or terminal telemetry was available. Could not confirm whether the file executed, and no file hash was available to check.

![Endpoint agent down](screenshots/05-endpoint-agent-down.png)

## Conclusion
User downloaded WinRAR from the vendor's official site. The alert correctly fired on an executable download, but the URL and destination show no malicious indicators. No containment needed. Limitation: with the agent down and no hash, the verdict relies on the domain and reputation only; the agent outage should be raised with the endpoint team.

![Closed ticket](screenshots/06-closed-ticket.png)
