# SOC143 – Password Stealer Detected

**Platform:** LetsDefend | **Severity:** Medium | **Classification:** True Positive | **Date:** April 26, 2021
**Sender:** `bill@microsoft.com` | **User:** `ellie@letsdefend.io`

## Summary

A spoofed email from `bill@microsoft.com` delivered a password-protected zip containing an HTML credential-phishing page that impersonated a Microsoft login. The email was deleted, and no evidence showed the attachment was opened or credentials were submitted.

[DRAG 01-alert-details.png HERE]

## The Attack

**HTML attachment phishing** sends the fake login page as a file instead of a link. When the victim opens it, the page renders locally in the browser, so URL filters and link scanners never see a malicious website. Any credentials typed into the form are sent to the attacker.

The **password-protected zip** (password `infected`) adds another layer: email gateways can't scan inside an encrypted archive, so the HTML file passes through unexamined.

## Timeline

| Time (alert) | Event |
| --- | --- |
| 23:03:14 | Email delivered from `bill@microsoft.com` to `ellie@letsdefend.io`, device action Allowed |
| — | Email deleted from the mailbox |

*Email Security shows 16:03:14; it is 7 hours behind the alert time (+03:00).

## Investigation

### 1. Email Analysis

- **From:** `bill@microsoft.com` (sender IP `180.76.101.229`)
- **Subject:** "."
- **Body:** Empty
- **Attachment:** `bd05664f01205fa90774f42468a8743a.zip` (password `infected`)
- **Gateway action:** Deleted

The sender address claims to be Microsoft, but the sending IP is not Microsoft infrastructure, so the sender is spoofed. A one-character subject, an empty body, and an encrypted attachment are all common phishing traits.

[DRAG 02-email-security.png HERE]

### 2. Attachment Analysis

The zip contains `Ellie@letsdefend.io_63963965Application.HTML`, a fake Microsoft login page personalized with the recipient's address. VirusTotal flagged it as malicious (27/60), with detections including `phishing.hidden/akgpp` and `Trojan.HTML.Hidden.2.Gen`.

[DRAG 03-virustotal-html.png HERE]

The download URL scored 6/92, but that result reflects LetsDefend's download wrapper page (`text/html`, 2.24 KB), not the attachment itself.

[DRAG 04-virustotal-url.png HERE]

Most of the file's contacted hosts were background traffic any browser generates in a sandbox, identified by their Autonomous System numbers:

| AS | Owner | Examples |
| --- | --- | --- |
| 8068 | Microsoft | `business.bing.com`, Edge telemetry |
| 15169 | Google | `encrypted-tbn0.gstatic.com` |
| 20940 | Akamai | CDN |
| — | Local multicast | `239.255.255.250` (SSDP) |
| 19679 | **Dropbox** | `dl.dropboxusercontent.com`, `162.125.3.15`, `162.125.8.15` |

Dropbox stood out: a clean browser has no reason to contact Dropbox's file-download domain, and it was the only domain with vendor detections (3/92). The page most likely loaded phishing content from it. Because Dropbox is a legitimate service, its IPs were treated as leads to check rather than confirmed malicious indicators.

[DRAG 05-virustotal-relations.png HERE]

### 3. Endpoint and Log Analysis

Endpoint Security has no host matching Ellie, so there was no device to inspect or contain.

[DRAG 06-endpoint-security.png HERE]

Log Management searches across all time returned 0 events for the sender address, the sender IP, and the contacted Dropbox IP. No traffic shows the attachment being opened.

[DRAG 07-logs-sender-address.png HERE]

[DRAG 08-logs-sender-ip.png HERE]

[DRAG 09-logs-dropbox-ip.png HERE]

## Indicators of Compromise

| Type | Indicator |
| --- | --- |
| Sender Address | `bill@microsoft.com` (spoofed) |
| Sender IP | `180.76.101.229` |
| Attachment URL | `https://files-ld.s3.us-east-2.amazonaws.com/bd05664f01205fa90774f42468a8743a.zip` |
| Zip MD5 | `bd05664f01205fa90774f42468a8743a` |
| HTML SHA-256 | `58c45547bccce5eb16d84bae13eb0c2813ffe03e34eae622b65468a6b289ca37` |

## Response and Recommendations

The email was deleted from the mailbox. Next steps: block the sender IP and attachment hashes at the email gateway, enforce SPF, DKIM, and DMARC checks to stop spoofed Microsoft senders, and train users that Microsoft never sends login pages as attachments. If Ellie's account becomes reachable, reset her credentials as a precaution.

## Conclusion

**True Positive.** The email was malicious: a spoofed Microsoft sender delivering a credential-phishing page. The email was deleted, and no logs or endpoint activity showed the attachment was opened, so the outcome is **Not Opened** with no confirmed compromise.

**MITRE ATT&CK:** T1566.001 (Spearphishing Attachment), T1656 (Impersonation), T1027.013 (Encrypted/Encoded File)
