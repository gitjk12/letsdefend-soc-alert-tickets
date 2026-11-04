# SOC170 – Passwd Found in Requested URL – Possible LFI Attack (EventID 120)

**Severity:** High | **Type:** Web Attack | **Difficulty:** Easy
**Event Time:** 2022-03-01 10:10:41 (+03:00)
**Verdict:** True Positive – malicious LFI attempt, unsuccessful, no escalation
**MITRE:** T1190 Exploit Public-Facing Application

## Alert Summary
An external IP sent a path traversal request to read `/etc/passwd` from web server **WebServer1006** (172.16.17.13).
- **Source:** 106.55.45.162
- **Request:** GET `https://172.16.17.13/?file=../../../../etc/passwd`
- **User-Agent:** Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1) – outdated IE 6 string, common in scanners
- **Device Action:** Allowed

<img width="1523" height="554" alt="01-alert-details" src="https://github.com/user-attachments/assets/5d3374ea-61fe-4b92-9af0-ee9c48c0a091" />


## Investigation
**Log Management:** One firewall event from 106.55.45.162:49028 → 172.16.17.13:443 with the traversal payload in the `file` parameter. The server returned **HTTP 500** with a **response size of 0**, so no file contents were sent back.

<img width="1511" height="575" alt="02-log-management" src="https://github.com/user-attachments/assets/653467e2-d515-43d8-a3ac-da6db52f7818" />

<img width="607" height="125" alt="03-request-url" src="https://github.com/user-attachments/assets/061945d9-254a-4419-8749-6e06b8133716" />

<img width="997" height="523" alt="04-http-response-status" src="https://github.com/user-attachments/assets/fdf75eec-1e24-4be0-87cc-3460864470f5" />
<img width="853" height="440" alt="05-http-response-size" src="https://github.com/user-attachments/assets/37662e43-d9c6-4c27-b595-38a71de33583" />


**VirusTotal (IP):** 106.55.45.162 is 0/92 but has a −7 community score and 30+ community comments. Hosted on Tencent Cloud (AS45090, China).

<img width="1903" height="988" alt="06-virustotal-ip" src="https://github.com/user-attachments/assets/c89a77f6-c6ac-4d35-b061-5e820c164848" />


**Endpoint:** WebServer1006 runs **Windows Server 2019**. `/etc/passwd` is a Linux file and doesn't exist on this host, which matches the failed response.

<img width="1066" height="553" alt="07-endpoint-info" src="https://github.com/user-attachments/assets/0f947d9d-1380-42aa-987b-25cd51729b5a" />


## Conclusion
Malicious LFI attempt from the internet using path traversal. It failed: the target is Windows, the server returned 500, and no data was returned. No compromise, so no Tier 2 escalation.

**Recommended actions:** Block 106.55.45.162. Validate and sanitize the `file` parameter on the web application.

## Playbook Results
| Step | Answer | Result |
|---|---|---|
| Understand Why the Alert Was Triggered | Next | ✓ |
| Collect Data | Next | ✓ |
| Examine HTTP Traffic | Next | ✓ |
| Is Traffic Malicious? | Malicious | ✓ |
| What Is the Attack Type? | Other | ✗ (correct: LFI & RFI) |
| Check If It Is a Planned Test | Not Planned | ✓ |
| What Is the Direction of Traffic? | Internet → Company Network | ✓ |
| Check Whether the Attack Was Successful | Next | ✓ |
| Was the Attack Successful? | No | ✓ |
| Do You Need Tier 2 Escalation? | No | ✓ |

**Lesson learned:** `../` sequences in a file parameter are path traversal used for local file inclusion. The attack type is LFI even when the attempt fails.
