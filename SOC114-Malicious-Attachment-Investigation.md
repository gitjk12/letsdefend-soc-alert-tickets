# SOC114 – Malicious Attachment Detected

**Platform:** LetsDefend | **Severity:** High | **Classification:** True Positive | **Date:** January 31, 2021
**Host:** `172.16.17.45` | **User:** `richard@letsdefend.io`

## Summary

Richard received an "Invoice" email with a password-protected attachment, and the mail gateway allowed it. The attachment is an Excel file that exploits CVE-2017-11882. About 27 minutes after delivery, the Equation Editor process (`EQNEDT32.EXE`), launched from Excel, downloaded `network.exe` from `andaluciabeach.net`, and the proxy allowed the request. The attachment was opened and the exploit ran, so the host is compromised.

<img width="1572" height="525" alt="01-alert-details" src="https://github.com/user-attachments/assets/b40cf651-47cf-4826-9bd9-efb1c1afc5d9" />


## The Attack

**CVE-2017-11882** is a memory corruption bug in Microsoft Office's legacy Equation Editor (`EQNEDT32.EXE`). A crafted document embeds a malicious equation object; when the document opens, Office loads Equation Editor and the exploit runs code with no macros and no further clicks.

The usual payload is a small downloader that fetches a second-stage executable from the attacker's server. In a normal environment, Equation Editor never makes network connections, so `EQNEDT32.EXE` downloading an `.exe` is a strong sign of exploitation.

## Timeline

| Time (email/proxy) | Event                                                                                                         |
|--------------------|---------------------------------------------------------------------------------------------------------------|
| 07:48:30           | "Invoice" email from `accounting@cmail.carleton.ca` (SMTP `49.234.43.39`) delivered to Richard, allowed*       |
| 08:15:45           | `172.16.17.45` (`EQNEDT32.EXE`, parent `excel.exe`) requests `http://andaluciabeach.net/image/network.exe` (`5.135.143.133:443`), allowed |

*The alert shows 15:48:30 (+03:00) for the same email; the alert and the Email Security / Log Management sources record time differently.

## Investigation

### 1. Email Analysis

- **Sender:** `accounting@cmail.carleton.ca`
- **Recipient:** `richard@letsdefend.io`
- **Sender IP:** `49.234.43.39`
- **Subject:** Invoice
- **Attachment:** `c9ad9506bcccfaa987ff9fc11b91698d` (password: `infected`)
- **Device Action:** Allowed

The body is a generic invoice lure for "shopping you have done," with no order details or business context. `cmail.carleton.ca` is Carleton University's real student mail domain, so this is likely a compromised or abused account rather than a spoofed look-alike.

<img width="1547" height="657" alt="02-email-security" src="https://github.com/user-attachments/assets/8cacb52c-4893-4117-b2d3-a163b838a5be" />


### 2. Attachment Analysis

VirusTotal flagged the attachment 36/61 and tagged it `cve-2017-11882`, `exploit`, and `executes-dropped-file`. The file is an Excel workbook (`.xlsx`, 2.12 MB).

The Relations tab lists the network activity seen when the sample runs:

- `http://andaluciabeach.net/image/network.exe` (8/93), the second-stage download
- `http://www.andaluciabeach.net/` (1/93)
- Dynamic DNS domains on Dynu and No-IP (`sytes.net`), commonly used for C2
- `pastebin.com`, often used to host payloads or configuration
- `nexus.officeapps.live.com`, normal Office traffic

<img width="1886" height="922" alt="03-virustotal-attachment-relations" src="https://github.com/user-attachments/assets/f0766ef3-ecbd-4cd8-b802-a2f4be93ffba" />


### 3. Log Analysis

Searching the attachment hash in Log Management returned nothing, as expected, since network logs record URLs and IPs, not file hashes. Searching for the contacted URL `http://andaluciabeach.net/image/network.exe` found one proxy event: an allowed request from `172.16.17.45:53948` to `5.135.143.133:443`. The process was `EQNEDT32.EXE` with parent `excel.exe`, which matches CVE-2017-11882 exploitation. An internal device reached the C2, so the playbook answer is **Accessed**.

<img width="1573" height="779" alt="04-logs-proxy-c2-access" src="https://github.com/user-attachments/assets/0119f629-e4e8-44e9-b4fe-5295713b09da" />


### 4. Verdict Reasoning

| Clue                                       | Meaning                                                        |
|--------------------------------------------|----------------------------------------------------------------|
| Generic "Invoice" lure, no order details   | Social engineering to get the attachment opened                |
| Password-protected attachment              | Hides the file from mail-gateway scanning                      |
| 36/61 on VirusTotal, tagged CVE-2017-11882  | Known malicious exploit document                               |
| `excel.exe` → `EQNEDT32.EXE`               | Equation Editor launched by the document, the exploit path     |
| `EQNEDT32.EXE` downloading `network.exe`   | Exploit succeeded and fetched a second-stage payload           |
| Proxy action Allowed                       | The payload request was not blocked                            |

## Artifacts

| Type            | Indicator                                                          |
|-----------------|--------------------------------------------------------------------|
| Sender          | `accounting@cmail.carleton.ca`                                     |
| SMTP IP         | `49.234.43.39`                                                     |
| MD5             | `c9ad9506bcccfaa987ff9fc11b91698d`                                 |
| SHA256          | `44e65a641fb970031c5efed324676b5018803e0a768608d3e186152102615795` |
| C2 URL          | `http://andaluciabeach.net/image/network.exe`                      |
| C2 IP           | `5.135.143.133`                                                    |
| Email Subject   | Invoice                                                            |

## Response and Recommendations

`172.16.17.45` must be contained and the email deleted from Richard's mailbox. Next steps: check the host for `network.exe` and any process or persistence it created, search logs for other hosts contacting `andaluciabeach.net`, `5.135.143.133`, or the dynamic DNS domains, block those indicators at the proxy and firewall, search other mailboxes for the same sender or subject, reset Richard's credentials, and patch or remove Equation Editor across Office installs. Report the abused `cmail.carleton.ca` account to Carleton rather than blocking the whole domain.

## Conclusion

**True Positive.** A phishing email delivered an Excel exploit for CVE-2017-11882. Richard opened it, Equation Editor ran the exploit, and the host downloaded a second-stage executable from `andaluciabeach.net`. The host is compromised and requires containment and remediation.

**MITRE ATT&CK:** T1566.001 (Spearphishing Attachment), T1204.002 (User Execution: Malicious File), T1203 (Exploitation for Client Execution), T1105 (Ingress Tool Transfer)
