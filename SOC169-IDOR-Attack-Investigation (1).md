# SOC169 – Possible IDOR Attack Detected

**Platform:** LetsDefend | **Severity:** Medium | **Classification:** True Positive | **Date:** February 28, 2022 **Host:** `WebServer1005` (`172.16.17.15`) | **Attacker:** `134.209.118.137`

## Summary

An external IP sent the same POST request to `https://172.16.17.15/get_user_info/` five times. The URL never changed; only the `user_id` POST parameter did, going from 1 to 5. The server answered with HTTP 200, meaning it returned user records without checking whether the requester was allowed to see them. This is an Insecure Direct Object Reference (IDOR): the attacker read other users' data by changing an ID.

<img width="1573" height="476" alt="01-alert-details" src="https://github.com/user-attachments/assets/6dc929c5-236d-4af2-931e-7b511e3b24dd" />


## Timeline

| Time (log) | Request URL | POST Parameter |
| ---------- | ----------- | -------------- |
| 14:45:00 | `https://172.16.17.15/get_user_info/` | `user_id=1` |
| 14:45:43 | `https://172.16.17.15/get_user_info/` | `user_id=2` |
| 14:46:14 | `https://172.16.17.15/get_user_info/` | `user_id=3` |
| 14:47:37 | `https://172.16.17.15/get_user_info/` | `user_id=4` |
| 14:48:01 | `https://172.16.17.15/get_user_info/` | `user_id=5` |

*The alert shows 22:48 (+03:00); the alert and Log Management display time differently.

## Investigation

### 1. Log Analysis

A search for `134.209.118.137` returned five firewall events, all allowed, to `172.16.17.15:443`. All five requests go to the same URL, `https://172.16.17.15/get_user_info/`; only the `user_id` in the POST body changes, stepping through accounts in order. The User-Agent (MSIE 6.0 on Windows XP) is outdated and likely spoofed by a script.

<img width="1565" height="792" alt="02-logs-requests" src="https://github.com/user-attachments/assets/02f26df6-8bc9-4489-83ff-aebafec47406" />


### 2. Request Analysis

The POST parameters show the ID being changed, and the server returned HTTP 200 instead of refusing with 401 or 403. A successful response for IDs that don't belong to the requester means the attack worked.

<img width="808" height="532" alt="03-post-parameters" src="https://github.com/user-attachments/assets/a03d2690-70bc-462b-9d47-e09f6d889838" />

<img width="849" height="409" alt="04-response-status" src="https://github.com/user-attachments/assets/b50556c3-b0cb-415c-80a7-4dd9ab17651d" />


## Playbook Answers

| Question | Answer |
| -------- | ------ |
| Is traffic malicious? | Malicious |
| Attack type | IDOR |
| Planned test? | Not Planned |
| Direction of traffic | Internet → Company Network |
| Was the attack successful? | Yes |
| Tier 2 escalation? | Yes |

<img width="1469" height="451" alt="05-playbook-answers" src="https://github.com/user-attachments/assets/b9c2b092-359d-4445-a4ad-c8deebbba774" />


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
