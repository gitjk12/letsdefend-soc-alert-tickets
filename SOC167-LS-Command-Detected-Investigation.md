# SOC167 – LS Command Detected in Requested URL

**Platform:** LetsDefend | **Severity:** High | **Classification:** False Positive | **Date:** February 27, 2022 **Source:** `172.16.17.46` (EliotPRD) | **Destination:** `188.114.96.15` (letsdefend.io) | **Event ID:** 117

## Summary

The rule fired because the requested URL contained the letters "ls", but they were the end of the word "skills" in a LetsDefend blog search. Logs and browser history show only normal blog browsing, so the alert was closed as a false positive.

<img width="1651" height="364" alt="soc167-01-alert-details" src="https://github.com/user-attachments/assets/4748304e-8cf8-41e5-992f-b69b738e184e" />


## The Attack

**Command injection** sneaks operating system commands into input a web application passes to the server's shell. `ls` lists files on Linux, so attackers often send it first to test whether injection works, usually behind a separator like `;ls`, `|ls` or `$(ls)`.

## Timeline

| Time (alert) | Event |
|--------------|-------|
| 00:36:04 | `172.16.17.46` sends `GET https://letsdefend.io/blog/?s=skills`, allowed, HTTP 200* |

*The proxy log shows 16:36:03 for the same request; the log sources record time differently.

## Investigation

### 1. URL Analysis

```
https://letsdefend.io/blog/?s=skills
```

- `/blog/?s=` is WordPress's standard site search parameter.
- `skills` is the search term, and its last two letters matched the rule.
- No command separator (`;`, `|`, `&&`, `$()`) is present, so nothing could be executed.

### 2. Log Analysis

A Log Management search for `172.16.17.46` returned 7 proxy events, all GET requests to letsdefend.io blog articles on SOC analyst careers, each with HTTP 200 and a normal response size. Browser history on EliotPRD matches the same 7 URLs, showing a user reading articles over about 35 minutes.

<img width="1064" height="409" alt="soc167-02-browser-history" src="https://github.com/user-attachments/assets/408faa44-cdc5-4fb2-9175-77ce100598bf" />


<img width="1684" height="623" alt="soc167-03-logs-source-address" src="https://github.com/user-attachments/assets/ab6e8ffb-e4f7-4229-ae4c-bdbe09e76d9c" />


### 3. Verdict Reasoning

| Clue | Meaning |
|------|---------|
| "ls" inside "skills" | Substring match, not a command |
| No injection characters | Nothing for a shell to execute |
| Outbound to letsdefend.io | A user browsing, not an attack on our server |
| Logs match browser history | Human reading pattern, no scanning |

The outdated Firefox 24 user agent is unusual but not malicious on its own.

## Artifacts

| Type | Indicator |
|------|-----------|
| Source IP | `172.16.17.46` (EliotPRD) |
| Request URL | `https://letsdefend.io/blog/?s=skills` |

## Response and Recommendations

No containment was required. Recommended: tune SOC167 to match `ls` only after a command separator or at a word boundary, which would stop ordinary words like "skills" and "tools" from triggering it.

## Conclusion

**False Positive.** The letters "ls" at the end of a blog search for "skills" triggered the rule. All traffic from the host was normal browsing, with no sign of command injection.

**MITRE ATT&CK (technique detected):** T1190 (Exploit Public-Facing Application)
