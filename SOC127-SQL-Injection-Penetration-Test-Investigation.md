# SOC127 – SQL Injection Detected

**Platform:** LetsDefend | **Severity:** Medium | **Classification:** False Positive | **Date:** February 14, 2021
**Source:** `172.16.20.5` (PentestMachine) | **Target:** `172.16.20.4` (gitServer) | **User:** `kali`

## Summary

An internal host sent a UNION-based SQL injection request to the internal git server, and the firewall allowed it. The payload was genuine, but every detail of the source points to an authorized penetration test, so the alert was closed as a false positive with no containment required.

[DRAG alert-details screenshot HERE]

## The Attack

**SQL injection** inserts database commands into input the application passes to its database. If the application doesn't sanitize that input, the attacker's query runs alongside the real one.

**UNION-based SQL injection** uses the `UNION SELECT` keyword to attach a second query to the original, so results from another table come back in the page's response. Attackers typically start with probes like `SELECT 1,2,3,4` to learn how many columns the original query returns before pulling real data.

## Timeline

| Time (alert) | Event |
| --- | --- |
| 13:05:12 | `172.16.20.5` sends a SQL injection GET request to `172.16.20.4:443`, allowed* |

*The firewall log shows 05:01:25 for the same request; the log sources record time differently.

## Investigation

### 1. Alert Analysis

- **Source:** `172.16.20.5` (hostname `PentestMachine`)
- **Destination:** `172.16.20.4` (hostname `gitServer`)
- **Username:** `kali`
- **User Agent:** `Penetration Test - Do not Contain`
- **Device Action:** Allowed

Both hosts are internal, so the traffic never crossed the network perimeter.

### 2. Payload Analysis

```
https://172.16.20.4/?id=1 and (1,2,3,4) = (SELECT * from db.users UNION SELECT 1,2,3,4 LIMIT 1)
```

- `id=1` is the legitimate parameter the injection is appended to.
- `UNION SELECT 1,2,3,4` probes how many columns the query returns, the first step of a UNION-based attack.
- `SELECT * from db.users` targets the users table, where account names and password hashes are typically stored.
- `LIMIT 1` keeps the result to a single row.

No legitimate user sends SQL statements in a URL parameter, so the payload is malicious in nature. Third-party tools returned no results because the destination is a private internal IP.

### 3. Log Analysis

A Log Management search for `172.16.20.5` found exactly one matching request: an allowed GET to `172.16.20.4:443` with the same payload. The log contains no HTTP status code or response size, so it shows the request reached gitServer but not whether the injection succeeded.

[DRAG log-management screenshot HERE]

Other activity from the same host fits a penetration-testing machine: a download of the BloodHound Active Directory mapping tool (2021-03-15) and SSH connections to port 22 on several internal hosts (2021-06-13).

### 4. Verdict Reasoning

Any one clue could be faked, since a user agent is just a text string. Together they tell a consistent story:

| Clue | Meaning |
| --- | --- |
| Hostname `PentestMachine` | A machine named for its role |
| Username `kali` | Default user of Kali Linux, the standard pentesting OS |
| User agent `Penetration Test - Do not Contain` | The tester labeling their own traffic for the SOC |
| Internal → internal | No external attacker involved |

The detection rule worked as designed: the payload was real SQL injection. Because the activity came from an authorized tester, it posed no threat, which makes this a **benign true positive**, closed in LetsDefend as a false positive.

## Artifacts

| Type | Indicator |
| --- | --- |
| Source IP | `172.16.20.5` (PentestMachine, authorized test) |
| Request URL | `https://172.16.20.4/?id=1 and (1,2,3,4) = (SELECT * from db.users UNION SELECT 1,2,3,4 LIMIT 1)` |

## Response and Recommendations

No containment was required. Recommended: confirm the test scope with the penetration testing team, have testers notify the SOC before engagements so alerts can be matched to approved activity, and use the test results to check whether gitServer's `id` parameter is vulnerable to SQL injection.

## Conclusion

**False Positive.** A genuine SQL injection payload was sent from `PentestMachine` to `gitServer`, but the source host, username, user agent, and internal-only traffic identify it as an authorized penetration test. No compromise or response was needed.

**MITRE ATT&CK (technique tested):** T1190 (Exploit Public-Facing Application)
