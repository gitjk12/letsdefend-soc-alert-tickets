# SOC166 – Javascript Code Detected in Requested URL

**Platform:** LetsDefend | **Severity:** Medium | **Classification:** True Positive | **Date:** February 26, 2022
**Source:** `112.85.42.13` | **Target:** `172.16.17.17` (WebServer1002) | **Event ID:** 116

## Summary

An external IP sent a series of cross-site scripting (XSS) payloads to the `q` search parameter on WebServer1002. Every payload returned an empty response (0 bytes), so no script was reflected back onto a page. The attack was malicious but **unsuccessful**, so no Tier 2 escalation was needed.
<img width="1632" height="346" alt="01-alert-details" src="https://github.com/user-attachments/assets/65b563e0-68fb-4e1c-8123-ed4c2b5b891a" />


## The Attack

**XSS** tricks a website into including an attacker's JavaScript in a page, so it runs in a visitor's browser. Payloads like `alert(1)` and `prompt(8)` are harmless tests: if a popup appears, the site is vulnerable.

## Timeline

| Time (log) | Request (`/search/?q=` unless noted)          | Size | Status |
|------------|-----------------------------------------------|------|--------|
| 10:34:34   | `/` (homepage)                                | 1024 | 200    |
| 10:35:10   | `/about-us/`                                  | 3531 | 200    |
| 10:45:43   | `test`                                        | 885  | 200    |
| 10:46:23   | `<img src=q onerror=prompt(8)>`               | —    | —      |
| 10:46:36   | `prompt(8)`                                   | 0    | 302    |
| 10:50:09   | `<script>for((i)in(self))eval(i)(1)</script>` | 0    | —      |
| 10:53:40   | `<svg><script ?>alert(1)`                     | 0    | —      |
| 10:56:55   | `<script>javascript:alert(1)</script>` (alerted) | 0 | —      |

*Log Management is 8 hours behind the alert time (18:56:46 +03:00). Dashes are values cut off in the log view.

## Investigation

### 1. Log Analysis

The attacker first browsed the homepage and About Us page, then ran a normal search for `test`, all returning real content with 200. Next came five XSS payloads in about ten minutes, each returning **0 bytes**. Since the server sent back nothing, there was no page for the script to run in. The varied payloads show deliberate probing.

<img width="1571" height="529" alt="02-log-management" src="https://github.com/user-attachments/assets/c8434f5e-bc58-42dc-80f2-bf9775e96431" />


### 2. Threat Intelligence

VirusTotal shows `112.85.42.13` on **AS4837 (China Unicom)** with 0/92 detections, one "suspicious" rating, and a community score of −15. The request content is the stronger evidence.

<img width="1913" height="1014" alt="03-virustotal-ip" src="https://github.com/user-attachments/assets/91507971-b7cc-431e-bbe5-052c5ee58459" />


### 3. Planned Test Check

No notice of a planned test was found. Result: **Not Planned**.

## Artifacts

| Type        | Indicator                                                               |
|-------------|-------------------------------------------------------------------------|
| Attacker IP | `112.85.42.13` (AS4837, China Unicom)                                   |
| Alerted URL | `https://172.16.17.17/search/?q=<script>javascript:alert(1)</script>`   |

## Response

Block `112.85.42.13` and make sure the search page encodes user input before displaying it.

## Conclusion

**True Positive.** An external IP probed WebServer1002's search function with XSS payloads. All returned empty responses, so the attack was malicious but unsuccessful.

<img width="1412" height="305" alt="04-playbook-results" src="https://github.com/user-attachments/assets/d34473c6-e336-410b-909f-e518c3816406" />


**MITRE ATT&CK:** T1190 (Exploit Public-Facing Application)
