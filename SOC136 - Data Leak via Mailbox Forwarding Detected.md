# SOCXXX – Rule Name

**Platform:** LetsDefend | **Severity:** High | **Classification:** True Positive | **Date:** March 7, 2021
**Sender:** `katharine@letsdefend.io` | **Recipient:** `katharine.isabell@yandex.ru` | **[SMTP Address]:** `172.16.20.3`

## Summary

An email was sent from katharine@letsdefend.io to katharine.isabell@yandex.ru containing what seem to be username/password combinations. Given the fact that Katharine's last log in predates the email, it's likely that a mail forwarding rule was set up, forwarding mail from katharine@letsdefend.io to katharine.isabell@yandex.ru. Additionally, Yandex.ru is a Russian domain and outside the organization's control. The email was blocked from leaving the network. This was classified as a true positive. 

<img width="1622" height="391" alt="01-alert-details" src="https://github.com/user-attachments/assets/1e088b52-9062-4ac1-b8ea-9ac1e4cdd8f5" />


## The Attack

<!-- Explain the attack technique in plain terms, as if to someone new to security. -->

## Timeline

| Time (alert) | Event |
|--------------|---------------------------------------------------------------------------------------------|
| 17:31:39     | Email from `172.16.20.3` to `katharine.isabell@yandex.ru` containing data leak, blocked\*   |

## Investigation

### 1. Alert Analysis

- **Sender:** `katharine@letsdefend.io`
- **Recipient:** `katharine.isabell@yandex.ru`
- **SMTP Address:** `172.16.20.3`
- **Subject:** `Blank`
- **Device Action:** Blocked

### 2. Email Analysis

<img width="1259" height="675" alt="02-email-contents" src="https://github.com/user-attachments/assets/bd23940f-df8d-49ea-95b0-57f331df9109" />

The body reads "root:Q@6PY4jF john:4\@sMpH/ bill:Pxt5\p6V admin:Y[H6mBu_". 
- The message has no greeting or signs of normal conversation.
- It merely contains username/password combinations, some being privileged, which Katharine would likely not send to anyone, let alone a foreign domain.
- Domain is foreign and outside the organization.

### 3. Endpoint Data

<img width="1385" height="678" alt="ja" src="https://github.com/user-attachments/assets/d5b3ce40-b419-462a-bd2e-d4320618b791" />
<img width="1324" height="461" alt="03-browser-history" src="https://github.com/user-attachments/assets/d1285ee7-241a-4b4a-a96d-a13424cd1035" />
<img width="1318" height="633" alt="04-endpoint-terminal-history" src="https://github.com/user-attachments/assets/a9024f86-c71f-4f99-af69-09742aba09bb" />


 - Last login predates the email by a week.
 - Checked browser history and terminal history and found no activity near March 7.

### 4. Verdict Reasoning

<!-- Tie the clues together. -->

| Clue | Meaning |
|------|---------|
|      |         |

## Artifacts

<!-- Real indicators only: IPs, domains, hashes, addresses, URLs. Leave out lab infrastructure. -->

| Type | Indicator |
|------|-----------|
|      |           |

## Response and Recommendations

<!-- What was done (containment, deletion, or none needed and why), then what should happen next. -->

## Conclusion

<!-- Verdict in bold, then 1–2 sentences restating the key evidence. -->

**MITRE ATT&CK:**
