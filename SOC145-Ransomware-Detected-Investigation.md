# SOC145 – Ransomware Detected

**Platform:** LetsDefend | **Severity:** Critical | **Classification:** True Positive | **Date:** May 23, 2021 **Host:** `172.16.17.88` (MarkPRD) | **User:** `MarkGuna`

## Summary

SOC145 fired on `ab.exe` (775.50 KB) on MarkPRD, and the device action was Allowed. VirusTotal identifies the file as Avaddon ransomware (61/70). The file is on the host alongside `wmic.exe` and `bcdedit.exe`, tools ransomware commonly uses to delete backups and disable recovery. No C2 traffic was found. The ransomware was not quarantined, so the host is compromised.

<img width="1650" height="329" alt="01-alert-details" src="https://github.com/user-attachments/assets/a0161a64-6506-4782-bff3-536ad3cbd53c" />


## Investigation

### 1. File Analysis

VirusTotal flags the hash 61/70 with the label `ransomware.avaddon/delshad`. Vendors including ESET, Fortinet, and ClamAV name it Avaddon. The sample's contacted domains and IPs are all 0/92 and are mostly Microsoft and Amazon infrastructure, so there is no clear C2.

<img width="1919" height="1015" alt="02-virustotal-detection" src="https://github.com/user-attachments/assets/10ea9d6d-09f4-46d3-b856-52bcbf101b33" />


<img width="1918" height="1016" alt="03-virustotal-relations" src="https://github.com/user-attachments/assets/937b4252-3dd7-4f30-8c8d-ff321c1915fd" />


### 2. Endpoint Analysis

The process list shows `ab.exe` along with `wmic.exe` and `bcdedit.exe`. Avaddon uses these to delete shadow copies and turn off Windows recovery. Command lines weren't recorded, so this is consistent with that behavior but not confirmed. Network Action shows no connections.

<img width="1623" height="904" alt="04-endpoint-processes" src="https://github.com/user-attachments/assets/ea63434c-8cc8-4e24-b6d7-08296c1fb747" />


<img width="1356" height="850" alt="05-endpoint-network" src="https://github.com/user-attachments/assets/614d1748-4c4a-40b9-9621-17878171629a" />


### 3. Log Analysis

Log Management has two proxy events for `172.16.17.88`, both before the alert date and unrelated to `ab.exe`. No C2 traffic was found, so the playbook answer is **Not Accessed**.

<img width="1618" height="607" alt="06-logs-proxy" src="https://github.com/user-attachments/assets/0b0848bc-d02e-43dd-b052-f3c9dcce2d0e" />


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
