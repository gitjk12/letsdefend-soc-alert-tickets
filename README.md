# SOC143 – Password Stealer Detected (Event ID 90) – Incident Report

**Platform:** LetsDefend · **Report date:** 2026-10-19

The email was malicious, but there is no evidence the attachment was opened. The alert is a true positive with no confirmed impact.

| Field | Value |
| --- | --- |
| Alert | SOC143 – Password Stealer Detected |
| Event ID | 90 |
| Event time | 2021-04-26 23:03:14 (+03:00) |
| Severity | Medium |
| Verdict | True Positive |
| Attachment opened | Not Opened |

## Summary

A spoofed email from `bill@microsoft.com` was delivered to `ellie@letsdefend.io` on 2021-04-26. It came from SMTP IP `180.76.101.229`, which is not Microsoft infrastructure. The subject was a single ".", the body was empty, and it carried a password-protected zip attachment (password: infected).

The alert shows the device action as Allowed. Email Security now shows the message as Deleted.

![SOC143 alert details](images/01-alert-details.png)

![Email in Email Security, action Deleted](images/02-email-security.png)

## Analysis

The attachment is a credential-phishing HTML page that VirusTotal flags as malicious (27/60 vendors). The zip (MD5 `bd05664f01205fa90774f42468a8743a`) contains `Ellie@letsdefend.io_63963965Application.HTML` (SHA-256 `58c45547bccce5eb16d84bae13eb0c2813ffe03e34eae622b65468a6b289ca37`), a fake Microsoft login page. Detections include phishing.hidden/akgpp and Trojan.HTML.Hidden.2.Gen.

![VirusTotal: HTML attachment, 27/60 detections](images/03-virustotal-html.png)

The download link was also scanned. Its 6/92 result reflects the LetsDefend download wrapper page, not the attachment itself.

![VirusTotal: attachment download URL, 6/92](images/04-virustotal-url.png)

The file's contacted hosts were mostly browser and OS background traffic (Microsoft, Google, Akamai, SSDP). The only notable contact was Dropbox (`dl.dropboxusercontent.com`, 162.125.3.15, 162.125.8.15), likely used to load phishing content.

![VirusTotal: contacted domains and IPs](images/05-virustotal-relations.png)

## Scope

No evidence shows the attachment was opened or credentials were submitted. Endpoint Security has no host matching Ellie, so there is no device to inspect or contain.

![Endpoint Security: no match for "ellie"](images/06-endpoint-security.png)

Log Management searches across all time returned 0 events for the sender address, the sender IP (180.76.101.229) and the Dropbox IP the attachment contacted (162.125.3.15).

![Log Management: 0 events for bill@microsoft.com](images/07-logs-sender-address.png)

![Log Management: 0 events for sender IP 180.76.101.229](images/08-logs-sender-ip.png)

![Log Management: 0 events for Dropbox IP 162.125.3.15](images/09-logs-dropbox-ip.png)

## Actions and recommendations

- The email was deleted from the recipient's mailbox.
- Block sender IP `180.76.101.229` and the attachment hash at the email gateway.
- If Ellie's account becomes reachable, reset her credentials as a precaution and provide phishing-awareness training.
- Enforce SPF, DKIM and DMARC checks to stop spoofed Microsoft senders.

## Artifacts

| Type | Value | Comment |
| --- | --- | --- |
| E-mail Sender | bill@microsoft.com | Spoofed sender |
| IP Address | 180.76.101.229 | SMTP / sender IP |
| URL Address | `hxxps://files-ld.s3.us-east-2.amazonaws[.]com/bd05664f01205fa90774f42468a8743a.zip` | Attachment download link (defanged) |
| MD5 Hash | bd05664f01205fa90774f42468a8743a | Malicious zip attachment |
