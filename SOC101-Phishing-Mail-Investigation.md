# SOC101 – Phishing Mail Detected

**Platform:** LetsDefend | **Severity:** Medium | **Classification:** True Positive | **Date:** April 4, 2021
**Host:** `172.16.17.88` | **User:** `mark@letsdefend.io`

## Summary

A phishing email with the subject "Its a Must have for your Phone" was delivered to Mark from a free Gmail address. The mail gateway allowed it. About ten minutes after delivery, Mark's machine opened the link in the email, `http://nuangaybantiep.xyz`, through Chrome, and the proxy allowed the connection. Because the user reached the malicious domain, the alert is a true positive and the host requires containment.

<img width="1555" height="543" alt="01-alert-details" src="https://github.com/user-attachments/assets/398384b1-11e8-45e9-9401-6966ffcd0077" />


## The Attack

**Phishing** uses a convincing email to get a user to open a link or attachment. This one uses a generic product lure ("Check out this product!") and a sender with no relationship to the company, aiming to get the user to click before thinking.

The link points to a newly registered `.xyz` domain. Cheap, disposable domains like this are commonly used to host malware downloads or command-and-control (C2) infrastructure, and are often abandoned after a single campaign.

## Timeline

| Time (email/proxy) | Event                                                                                     |
|--------------------|-------------------------------------------------------------------------------------------|
| 16:00:15           | Email from `lethuyan852@gmail.com` (SMTP `146.56.195.192`) delivered to Mark, allowed*     |
| 16:10:10           | `172.16.17.88` opens `http://nuangaybantiep.xyz` (`192.64.119.190:80`) via `chrome.exe`, allowed |

*The alert shows 23:00:15 (+03:00) for the same email; the alert and the Email Security / Log Management sources record time differently.

## Investigation

### 1. Email Analysis

- **Sender:** `lethuyan852@gmail.com`
- **Recipient:** `mark@letsdefend.io`
- **Sender IP:** `146.56.195.192`
- **Subject:** Its a Must have for your Phone
- **Device Action:** Allowed

The sender uses a free webmail account with no connection to LetsDefend. The subject and body are a generic product pitch with no business context, and the message directs the user to an external link. These are standard phishing traits.

<img width="1902" height="928" alt="02-email-security" src="https://github.com/user-attachments/assets/8a7c42c2-dc15-436e-a519-909339a6534e" />


### 2. URL Analysis

VirusTotal flagged `http://nuangaybantiep.xyz/` 1/93 (Chong Lua Dao: Malicious). alphaMountain.ai, Forcepoint ThreatSeeker, and LevelBlue rated it Suspicious, and Forcepoint categorizes it as "elevated exposure."

The low score does not clear the domain. VirusTotal's first submission was **2021-04-04 01:03:24 UTC**, the same day the email was sent, so the domain was brand new at the time of the attack and had not yet built a reputation.

<img width="1908" height="966" alt="03-virustotal-detection" src="https://github.com/user-attachments/assets/92b63d25-f4e3-4caf-afaa-43631da68d82" />

<img width="1914" height="941" alt="04-virustotal-details" src="https://github.com/user-attachments/assets/c070e3a0-08e5-47b3-9a51-a4a2a5dbbd1d" />


### 3. Log Analysis

A Log Management search for `http://nuangaybantiep.xyz` found one proxy event: an allowed GET from `172.16.17.88:39483` to `192.64.119.190:80`. The process was `chrome.exe` with parent `explorer.exe`, meaning a user opened the link in the browser rather than an automated scanner fetching it. An internal device reached the URL, so the playbook answer is **Accessed**.

<img width="1544" height="758" alt="05-logs-proxy-c2-access" src="https://github.com/user-attachments/assets/4a97b423-b917-4a77-9007-03e75f2cc875" />


### 4. Verdict Reasoning

| Clue                                        | Meaning                                                           |
|---------------------------------------------|-------------------------------------------------------------------|
| Free Gmail sender, no business relationship | Not a legitimate vendor or internal contact                       |
| Generic product lure in subject and body    | Social engineering with no business purpose                       |
| Newly seen `.xyz` domain                    | First VirusTotal submission on the day of the attack               |
| Vendor flags (1 malicious, 3 suspicious)    | Early reputation hits despite the domain's age                    |
| `chrome.exe` → `nuangaybantiep.xyz`, allowed | Mark clicked the link ten minutes after delivery                  |

## Artifacts

| Type          | Indicator                          |
|---------------|------------------------------------|
| Sender        | `lethuyan852@gmail.com`            |
| SMTP IP       | `146.56.195.192`                   |
| URL           | `http://nuangaybantiep.xyz`        |
| C2 IP         | `192.64.119.190`                   |
| Email Subject | Its a Must have for your Phone     |

## Response and Recommendations

The email was deleted from Mark's mailbox and `172.16.17.88` was contained. Next steps: review the host for anything downloaded or executed after 16:10:10, search logs for further connections to `192.64.119.190` from any host, block the sender, SMTP IP, domain, and C2 IP at the mail gateway and proxy, search other mailboxes for the same sender or subject, and reset Mark's credentials if anything was entered on the site.

## Conclusion

**True Positive.** A phishing email lured Mark into opening a newly registered malicious domain, and the proxy log confirms the connection from his host. The email was removed and the host contained to prevent further compromise.

**MITRE ATT&CK:** T1566.002 (Phishing: Spearphishing Link), T1204.001 (User Execution: Malicious Link)
