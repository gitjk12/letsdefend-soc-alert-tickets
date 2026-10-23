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
|--------------|-------|
| 17:31:39     | Email from '172.16.20.3' to 'katharine.isabell@yandex.ru' containing data leak, blocked\*   |

## Investigation

### 1. Alert Analysis

- **Sender:** `katharine@letsdefend.io`
- **Recipient:** `katharine.isabell@yandex.ru`
- **SMTP Address:** `172.16.20.3`
- **Subject:** `Blank`
- **Device Action:** Blocked

### 2. [Evidence Area] Analysis

<!-- One section per thing you checked: email, payload, logs, endpoint, IP reputation, file hash.
     Show the evidence first, then say what it means. Note what each check can't prove. -->

### 3. [Evidence Area] Analysis

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
