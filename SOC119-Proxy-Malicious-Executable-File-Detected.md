# SOC119 – Proxy – Malicious Executable File Detected (EventID 83)

**Severity:** Medium | **Type:** Proxy | **MITRE:** T1204 – User Execution
**Event Time:** 2021-03-21 13:02:11 (+03:00)
**Verdict:** Non-malicious download (ticket closed as True Positive)

## Alert Summary
Proxy flagged an executable download by user **Susie** (SusieHost, 172.16.17.5) via Chrome on Windows.
- **URL:** hxxps://www.win-rar[.]com/postdownload.html?&L=0&Version=32bit
- **Destination:** 51.195.68.163 (win-rar.com), port 443
- **Device Action:** Allowed

<img width="1545" height="538" alt="01-alert-details" src="https://github.com/user-attachments/assets/9aeaeb4c-7c8b-4fb5-9931-21a77d50ea47" />


## Investigation
**Log Management:** One event to 51.195.68.163, matching the alert (chrome.exe, 172.16.17.5:43213 → 443). No other traffic to the IP.

<img width="1569" height="782" alt="02-log-management" src="https://github.com/user-attachments/assets/2b1957ac-3767-468b-b96c-86c267deebe0" />


**VirusTotal (URL):** 0/93 detections. Official WinRAR download page on win-rar.com, resolving to the same IP (51.195.68.163).

<img width="1906" height="990" alt="03-virustotal-url" src="https://github.com/user-attachments/assets/ba9e899a-de39-416d-9a3d-1f7f7afdae36" />


**VirusTotal (IP):** 51.195.68.163 is 0/92, OVH SAS (AS16276, France). Shared hosting IP; 9 detected files are linked to it, which is common for hosting providers and not tied to this URL.

<img width="1907" height="992" alt="04-virustotal-ip" src="https://github.com/user-attachments/assets/b4fc76d4-2e18-478a-afeb-ae9bcab93897" />


**Endpoint (SusieHost):** EDR agent was down, so no process, network, or terminal telemetry was available. Could not confirm whether the file executed, and no file hash was available to check.

<img width="1218" height="494" alt="05-endpoint-agent-down" src="https://github.com/user-attachments/assets/442de66a-a894-4a61-89b9-6253a46d0e93" />


## Conclusion
User downloaded WinRAR from the vendor's official site. The alert correctly fired on an executable download, but the URL and destination show no malicious indicators. No containment needed. Limitation: with the agent down and no hash, the verdict relies on the domain and reputation only; the agent outage should be raised with the endpoint team.

<img width="1414" height="543" alt="06-closed-ticket" src="https://github.com/user-attachments/assets/b5f31e68-c466-47f0-85a8-3c6604063a18" />

