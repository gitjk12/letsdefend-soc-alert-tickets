# SOC145 – Ransomware Detected

**Platform:** LetsDefend | **Severity:** Critical | **Classification:** True Positive | **Date:** May 23, 2021 **Host:** `172.16.17.88` (MarkPRD) | **User:** `MarkGuna`

## Summary

SOC145 fired on `ab.exe` (775.50 KB) on MarkPRD, and the device action was Allowed. VirusTotal identifies the file as Avaddon ransomware (61/70). The file is on the host alongside `wmic.exe` and `bcdedit.exe`, tools ransomware commonly uses to delete backups and disable recovery. No C2 traffic was found. The ransomware was not quarantined, so the host is compromised.

![01-alert-details](images/SOC145/01-alert-details.png)

## Investigation

### 1. File Analysis

VirusTotal flags the hash 61/70 with the label `ransomware.avaddon/delshad`. Vendors including ESET, Fortinet, and ClamAV name it Avaddon. The sample's contacted domains and IPs are all 0/92 and are mostly Microsoft and Amazon infrastructure, so there is no clear C2.

![02-virustotal-detection](images/SOC145/02-virustotal-detection.png)

![03-virustotal-relations](images/SOC145/03-virustotal-relations.png)

### 2. Endpoint Analysis

The process list shows `ab.exe` along with `wmic.exe` and `bcdedit.exe`. Avaddon uses these to delete shadow copies and turn off Windows recovery. Command lines weren't recorded, so this is consistent with that behavior but not confirmed. Network Action shows no connections.

![04-endpoint-processes](images/SOC145/04-endpoint-processes.png)

![05-endpoint-network](images/SOC145/05-endpoint-network.png)

### 3. Log Analysis

Log Management has two proxy events for `172.16.17.88`, both before the alert date and unrelated to `ab.exe`. No C2 traffic was found, so the playbook answer is **Not Accessed**.

![06-logs-proxy](images/SOC145/06-logs-proxy.png)

## Artifacts

| Type | Indicator |
|------|-----------|
| File Name | `ab.exe` |
| MD5 | `0b486fe0503524cfe4726a4022fa6a68` |
| SHA256 | `1228d0f04f0ba82569fc1c0609f9fd6c377a91b9ea44c1e7f9f84b2b90552da2` |
| Family | Avaddon ransomware |

## Conclusion

**True Positive.** `ab.exe` is Avaddon ransomware, and it ran on MarkPRD without being blocked. Contain the host, block the hash, and restore from backup. Separately review the older 2020-08-29 proxy event, where a `.doc` spawned PowerShell to reach `thuening.de`.

**MITRE ATT&CK:** T1204 (User Execution), T1486 (Data Encrypted for Impact), T1490 (Inhibit System Recovery)
