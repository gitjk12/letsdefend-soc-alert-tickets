# SOC165 – Possible SQL Injection Payload Detected

**Platform:** LetsDefend | **Severity:** High | **Classification:** True Positive | **Date:** February 25, 2022
**Source:** `167.99.169.17` | **Target:** `172.16.17.18` (WebServer1001) | **Event ID:** 115

## Summary

An external IP sent a series of SQL injection probes to the `q` search parameter on WebServer1001. The firewall permitted the traffic, but every injection attempt returned **HTTP 500** with an identical response size, showing the payloads broke the query without returning data. Endpoint history shows no follow-up activity. The attack was malicious but **unsuccessful**, so no Tier 2 escalation or containment was needed.

![01-alert-details](01-alert-details.png)

## The Attack

**SQL injection** inserts database syntax into user input that the application passes to its database. The alerted payload decodes to:

```
" OR 1 = 1 -- -
```

The `"` closes the string in the original query, `OR 1 = 1` makes the condition always true, and `-- -` comments out the rest of the query. If it worked, the search would return every row in the table.

## Timeline

| Time (log) | Request (`/search/?q=`, decoded) | Size  | Response |
|------------|----------------------------------|-------|----------|
| 03:30:15   | `/` (homepage visit)             | 3547  | 200      |
| 03:32:31   | `' OR '1`                        | 948   | 500      |
| 03:32:55   | `'`                              | 948   | 500      |
| 03:33:12   | `' OR 'x'='x`                    | 948   | 500      |
| 03:33:51   | `1' ORDER BY 3--+`               | 948   | 500      |
| 03:34:32   | `" OR 1 = 1 -- -` (alerted request) | 948 | 500      |

*Log Management is 8 hours behind the alert time (11:34:32 +03:00).

## Investigation

### 1. Traffic Direction

The source `167.99.169.17` is a public IP; the destination `172.16.17.18` is a private (RFC 1918) address belonging to WebServer1001. Direction: **Internet → Company Network**.

### 2. Threat Intelligence

VirusTotal shows `167.99.169.17` on **AS14061 (DigitalOcean)**, a cloud hosting range commonly used for rented attack infrastructure. 2/92 vendors flag it as malicious (phishing) and 2 as suspicious. The lookup reflects current reputation rather than reputation at the time of the attack, so the request content is the stronger evidence.

![02-virustotal-ip](02-virustotal-ip.png)

### 3. Log Analysis

A search for `167.99.169.17` as the source returned 6 events. After an initial homepage visit (200, 3547 bytes), the attacker cycled through classic injection tests: a lone quote, tautologies (`OR '1`, `OR 'x'='x`, `OR 1 = 1`), and an `ORDER BY` column-count probe. All five returned **500** with the same **948-byte** response, meaning the server errored out and leaked no data. The sequence of varied payloads within about two minutes points to deliberate probing rather than a user typo.

![03-log-management](03-log-management.png)

### 4. Planned Test Check

No email or notice of a scheduled penetration test or vulnerability scan was found. Result: **Not Planned**.

### 5. Endpoint Analysis

WebServer1001's terminal history contains only three commands from 01.02.2022 (`cd web-root`, `docker-compose ... build`, `docker-compose ... up`), weeks before the attack. Nothing was executed on the host around the alert time, consistent with a failed attempt.

![04-endpoint-terminal-history](04-endpoint-terminal-history.png)

## Artifacts

| Type              | Indicator                                                        |
|-------------------|------------------------------------------------------------------|
| Attacker IP       | `167.99.169.17` (AS14061, DigitalOcean)                          |
| Alerted URL       | `https://172.16.17.18/search/?q=%22%20OR%201%20%3D%201%20--%20-` |
| User-Agent        | `Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1` |

## Response and Recommendations

No containment was required. Next steps: block `167.99.169.17` at the perimeter or WAF, confirm the `q` parameter uses parameterized queries, and suppress verbose 500 errors in favor of a generic error page so failed probes reveal nothing about the backend.

## Conclusion

**True Positive.** An external host on DigitalOcean ran a short SQL injection probing sequence against WebServer1001's search function. Every attempt returned HTTP 500 with no data, and the endpoint shows no post-attack activity. The attack was malicious but unsuccessful.

![05-playbook-results](05-playbook-results.png)

**MITRE ATT&CK:** T1190 (Exploit Public-Facing Application)
