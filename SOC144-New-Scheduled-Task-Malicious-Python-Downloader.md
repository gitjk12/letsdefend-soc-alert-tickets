# SOC144 – New Scheduled Task Created

**Platform:** LetsDefend | **Severity:** Critical | **Classification:** True Positive | **Date:** May 14, 2021
**Host:** Helena (`172.16.17.36`, Windows 10) | **User:** Helena | **File:** `Sorted-Algorithm.py` | **Event ID:** 91

## Summary

User Helena downloaded a Python project from GitHub and ran `Sorted-Algorithm.py`. The script looks like a harmless sorting demo, but it also downloads a payload from `92.27.116.104` and creates a daily scheduled task to run it. Proxy logs confirm the host contacted that IP, and terminal history shows the scheduled task being created. The file was not quarantined, so the host was contained.

![01-alert-details](01-alert-details.png)

## The Attack

The script hides malicious code inside working, legitimate-looking code. It prints ASCII art and sorts some lists, then downloads a file from a remote server and registers it as a **scheduled task**, a common persistence technique: the payload runs again every day, even after a reboot, without the user doing anything.

## Timeline

| Time (endpoint) | Event                                                                                          |
|-----------------|------------------------------------------------------------------------------------------------|
| 15:20:18        | Browsed `github.com/skulpt/skulpt`                                                             |
| 15:21:34        | Downloaded `github.com/pythonguru2021x/Sorted-Algorithm/archive/refs/heads/master.zip`         |
| 15:22           | `python.exe C:/Users/Helena/Downloads/Sorted-Algorithm.py`                                     |
| 15:22:02        | Connection `172.16.17.36:55221` → `92.27.116.104:80`                                           |
| 15:22:22        | **Alert:** SOC144 – New scheduled task created                                                 |
| 15:23           | `SCHTASKS /CREATE /SC DAILY /TN DailyRoutine /TR C:/Windows/Temp/x86_x64_setup.exe`            |
| 17:13 – 17:16   | `ipconfig`, `ipconfig /all`                                                                    |

*Proxy log times are 7 hours behind endpoint and alert time; converted above for consistency.

## Investigation

### 1. Endpoint Analysis

The process list shows `python.exe` (MD5 `7f5fd6921a7b942aab26a7e16c80909b`, a user-installed Python 3.7 interpreter) running `Sorted-Algorithm.py` from the Downloads folder. Terminal history shows the script ran at 15:22 and a scheduled task named **DailyRoutine** pointing to `C:/Windows/Temp/x86_x64_setup.exe` was created one minute later. An innocuous name and an executable in a Temp folder are typical signs of malicious persistence.

![02-endpoint-processes](02-endpoint-processes.png)
![03-terminal-history](03-terminal-history.png)

### 2. Log Analysis

A proxy search for `172.16.17.36` returned 5 events. On May 13 the user visited a Coursera Python lecture and a LinkedIn profile. On May 14 they downloaded the `Sorted-Algorithm` repository as a ZIP from GitHub, and less than a minute later the host connected to `92.27.116.104` on port 80. That outbound connection is the payload download, so the C2 playbook answer is **Accessed**.

![04-proxy-logs](04-proxy-logs.png)

### 3. Threat Intelligence

VirusTotal has the file under SHA-256 `255392992bf103d218466399d670300453a69f24398b02f316a74826c1f95a82`. Only 2/62 vendors detect it (Kaspersky: `Trojan-Downloader.Python.Agent.ci`), but it is labeled `downloader.python` with **downloader** and **trojan** categories, and VirusTotal's code analysis describes exactly the download-and-schedule behavior seen on the endpoint. The low detection rate is expected: the script's malicious part is just a few lines among normal code. Its only contacted IP, `92.27.116.104` (AS13285, GB), is flagged by 6/92 vendors.

![05-virustotal-detection](05-virustotal-detection.png)
![06-virustotal-relations](06-virustotal-relations.png)

### 4. Containment

The device action was **Allowed** and nothing indicates the file was quarantined, so Helena was contained.

![07-host-contained](07-host-contained.png)

## Artifacts

| Type             | Indicator                                                                              |
|------------------|----------------------------------------------------------------------------------------|
| File (MD5)       | `65d880c7f474720dafb84c1e93c51e11` (`Sorted-Algorithm.py`)                             |
| File (SHA-256)   | `255392992bf103d218466399d670300453a69f24398b02f316a74826c1f95a82`                     |
| Download URL     | `https://github.com/pythonguru2021x/Sorted-Algorithm/archive/refs/heads/master.zip`    |
| C2 / Payload IP  | `92.27.116.104` (port 80)                                                              |
| Scheduled Task   | `DailyRoutine` → `C:/Windows/Temp/x86_x64_setup.exe`                                   |

## Response and Recommendations

Helena was contained. Next steps: delete the `DailyRoutine` task and `C:/Windows/Temp/x86_x64_setup.exe`, analyze that payload, block `92.27.116.104` and the GitHub repository URL, check other hosts for connections to the same IP, and review the `ipconfig` commands at 17:13–17:16 to rule out follow-up attacker activity. Remind users not to run code downloaded from unknown repositories.

## Conclusion

**True Positive.** A trojanized Python script disguised as a sorting algorithm downloaded a payload from `92.27.116.104` and created a daily scheduled task for persistence. The malware was not quarantined, and the host was contained.

![08-playbook-results](08-playbook-results.png)

**MITRE ATT&CK:** T1204.002 (User Execution: Malicious File), T1105 (Ingress Tool Transfer), T1053.005 (Scheduled Task)
