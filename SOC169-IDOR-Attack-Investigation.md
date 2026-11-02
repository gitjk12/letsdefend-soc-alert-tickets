# SOC169 – Possible IDOR Attack Detected

**Platform:** LetsDefend | **Severity:** Medium | **Classification:** True Positive | **Date:** February 28, 2022 **Host:** `WebServer1005` (`172.16.17.15`) | **Attacker:** `134.209.118.137`

## Summary

An external IP sent five POST requests to `/get_user_info/`, changing `user_id` from 1 to 5 each time. The server answered with HTTP 200, meaning it returned user records without checking whether the requester was allowed to see them. This is an Insecure Direct Object Reference (IDOR): the attacker read other users' data by changing an ID.

![01-alert-details](screenshots/01-alert-details.png)

## Timeline

| Time (log) | Request | Result |
| ---------- | ------- | ------ |
| 14:45:00 | `POST /get_user_info/` `user_id=1` | 200 |
| 14:45:43 | `user_id=2` | 200 |
| 14:46:14 | `user_id=3` | 200 |
| 14:47:37 | `user_id=4` | 200 |
| 14:48:01 | `user_id=5` | 200 |

*The alert shows 22:48 (+03:00); the alert and Log Management display time differently.

## Investigation

### 1. Log Analysis

A search for `134.209.118.137` returned five firewall events, all allowed, to `172.16.17.15:443`. Each request uses the same endpoint and changes only `user_id`, stepping through accounts in order. The User-Agent (MSIE 6.0 on Windows XP) is outdated and likely spoofed by a script.

![02-logs-requests](screenshots/02-logs-requests.png)

### 2. Request Analysis

The POST parameters show the ID being changed, and the server returned HTTP 200 instead of refusing with 401 or 403. A successful response for IDs that don't belong to the requester means the attack worked.

![03-post-parameters](screenshots/03-post-parameters.png)
![04-response-status](screenshots/04-response-status.png)

## Playbook Answers

| Question | Answer |
| -------- | ------ |
| Is traffic malicious? | Malicious |
| Attack type | IDOR |
| Planned test? | Not Planned |
| Direction of traffic | Internet → Company Network |
| Was the attack successful? | Yes |
| Tier 2 escalation? | Yes |

![05-playbook-answers](screenshots/05-playbook-answers.png)

## Artifacts

| Type | Indicator |
| ---- | --------- |
| Attacker IP | `134.209.118.137` |
| Target | `https://172.16.17.15/get_user_info/` (WebServer1005) |
| User-Agent | `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)` |

## Response

Escalate to Tier 2, block `134.209.118.137`, and notify the owners of user IDs 1–5 that their data was exposed. The fix is server-side: `/get_user_info/` must check that the logged-in user is authorized to view the requested ID.

## Conclusion

**True Positive.** The attacker enumerated user IDs 1–5 on `/get_user_info/` and received a successful response for each, exposing other users' information.

**MITRE ATT&CK:** T1190 (Exploit Public-Facing Application)
