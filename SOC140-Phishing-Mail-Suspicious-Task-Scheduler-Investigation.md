# SOC140 – Phishing Mail Detected – Suspicious Task Scheduler

**Platform:** LetsDefend | **Severity:** Medium | **Classification:** True Positive | **Date:** March 21, 2021
**Sender:** `aaronluo@cmail.carleton.ca` | **Recipient:** `mark@letsdefend.io` | **SMTP Address:** `189.162.189.159`

## Summary

An external sender emailed a password-protected attachment to an internal user under a COVID-19 vaccine lure. Multiple security vendors flag the attachment as malware or phishing, and the sending IP does not belong to the sender domain's mail provider. The email security gateway blocked the message before delivery, so the alert was closed as a true positive with no mailbox cleanup required.

![01-alert-details](PASTE-IMAGE-URL)

## The Attack

**Phishing with a malicious attachment** delivers malware by convincing the recipient to open a file. Attackers lean on urgent or timely topics, such as COVID-19 vaccines in early 2021, to get the victim to act before thinking.

**Password-protected archives** are a common evasion technique. Email security tools can't scan the contents of an encrypted zip, so the attacker includes the password in the email body and lets the victim unlock it.

**Scheduled task persistence**, which this detection rule is named for, is a common next step once the file runs. The malware registers a Windows scheduled task so it relaunches automatically, surviving reboots and user logoffs.

## Timeline

| Time (alert) | Event                                                                                         |
|--------------|-----------------------------------------------------------------------------------------------|
| 12:26:57     | Email from `189.162.189.159` to `mark@letsdefend.io` with a malicious attachment, blocked\*   |

\*The Email Security entry shows 05:26:57 for the same message; the alert and mail log record time in different time zones.

## Investigation

### 1. Alert Analysis

- **Sender:** `aaronluo@cmail.carleton.ca`
- **Recipient:** `mark@letsdefend.io`
- **SMTP Address:** `189.162.189.159`
- **Subject:** `COVID19 Vaccine`
- **Device Action:** Blocked

### 2. Email Analysis

![02-email-contents](PASTE-IMAGE-URL)

The body reads "Hey, did you read breaking news about Covid-19. Open it now!" followed by the password `infected`.

- The message has no greeting, signature, or context tying the sender to the recipient.
- "Open it now!" creates urgency, a standard social-engineering tactic.
- The attachment is a password-protected archive, which keeps the gateway from inspecting its contents.

### 3. Sender IP Analysis

![03-mx-lookup](PASTE-IMAGE-URL)

An MX lookup on `cmail.carleton.ca` shows the domain's mail is hosted by Microsoft 365:

| Record   | Value                                                      |
|----------|------------------------------------------------------------|
| Hostname | `cmail-carleton-ca.mail.eo.outlook.com`                    |
| IP       | `52.101.190.0` (Microsoft Corporation, AS8075)             |
| Provider | Microsoft Office                                           |

Legitimate mail from this domain would come from Microsoft's mail infrastructure. The sender IP, `189.162.189.159`, doesn't match the domain's mail servers and isn't in Microsoft's address space, which suggests the sender address was spoofed or the email was sent from infrastructure the domain hasn't authorized.

The same lookup shows the domain publishes a DMARC record but doesn't enforce a quarantine or reject policy, so receiving servers aren't instructed to stop spoofed mail from this domain.

*Note: MX records list where a domain receives mail. The domain's SPF record, which lists authorized sending IPs, is the more precise check for outbound mail.*

### 4. Attachment Analysis

![04-virustotal-detection](PASTE-IMAGE-URL)

- **Attachment MD5:** `72c812cf21909a48eb9cceb9e04b865d`
- **Archive password:** `infected`

VirusTotal analysis of the attachment's LetsDefend download link returned **10/93** detections:

| Verdict    | Vendors                                          |
|------------|--------------------------------------------------|
| Malware    | BitDefender, Fortinet, G-Data, Lionic, VIPRE     |
| Malicious  | Forcepoint ThreatSeeker, Webroot                 |
| Phishing   | Kaspersky, SafeToOpen, Sophos                    |
| Suspicious | CyRadar, ESET, Gridinsoft                        |

The download link is LetsDefend's file-hosting URL, so its domain and IP are not attacker indicators.

### 5. Verdict Reasoning

Any one clue could have an innocent explanation, since people do send zipped files. Together they tell a consistent story:

| Clue                                       | Meaning                                                   |
|--------------------------------------------|-----------------------------------------------------------|
| COVID-19 vaccine subject, "Open it now!"   | Timely lure plus urgency to push the user to act          |
| Password-protected attachment (`infected`) | Hides the contents from email scanning                    |
| 10/93 VirusTotal detections                | Multiple vendors classify the file as malware or phishing |
| Sender IP outside the domain's mail provider | Spoofed or unauthorized sending infrastructure          |

The detection rule worked as designed: the email carried a malicious attachment, making this a **true positive**. Because the gateway blocked it, the email never reached the recipient.

## Artifacts

| Type            | Indicator                          |
|-----------------|------------------------------------|
| Sender Address  | `aaronluo@cmail.carleton.ca`       |
| SMTP IP         | `189.162.189.159`                  |
| Attachment MD5  | `72c812cf21909a48eb9cceb9e04b865d` |
| Email Subject   | `COVID19 Vaccine`                  |

## Response and Recommendations

No containment was required, and the email did not need to be deleted because it was never delivered. Recommended: block the sender address and SMTP IP at the email gateway, add the attachment hash to blocklists, and make sure the gateway flags inbound mail whose sending IP fails the sender domain's SPF check. Users should also be reminded that password-protected attachments from unknown senders are a common malware delivery method.

## Conclusion

**True Positive.** A COVID-19-themed phishing email carrying a password-protected malicious attachment was sent to `mark@letsdefend.io` from an IP that does not belong to the sender domain's mail provider. The email gateway blocked the message before delivery, so no compromise occurred.

**MITRE ATT&CK:** T1566.001 (Phishing: Spearphishing Attachment), T1053.005 (Scheduled Task/Job: Scheduled Task, per the detection rule)
