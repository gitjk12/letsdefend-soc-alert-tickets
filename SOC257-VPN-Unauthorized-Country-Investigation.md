# SOC257 – VPN Connection Detected from Unauthorized Country

**Platform:** LetsDefend | **Severity:** Low | **Classification:** True Positive | **Date:** February 13, 2024 **Target:** `vpn-letsdefend.io` (`33.33.33.33`) | **User:** `monica@letsdefend.io` | **Attacker:** `113.161.158.12`

## Summary

An IP in Vietnam tried to log in to the company VPN as Monica. The password was accepted, but all three attempts failed at the one-time code (OTP) step, so MFA blocked access. Monica's credentials are compromised, but the attacker never got in.

![01-alert-details](screenshots/01-alert-details.png)

## Timeline

| Time (log) | Event |
| ---------- | ----- |
| 17:59:07 | Firewall: connection to `33.33.33.33:52328`, a non-VPN port (probing) |
| 18:01:00 | `monica@letsdefend.io` login: **Incorrect OTP Code** |
| 18:02:00 | Incorrect OTP Code |
| 18:03:09 | Incorrect OTP Code |

*The alert shows 02:04 (+03:00) on February 13; the alert and Log Management display time differently.

## Investigation

### 1. Log Analysis

A search for `113.161.158.12` returned 21 firewall and proxy events. Each login appears twice: a proxy `POST` to `logon.html` and a firewall entry with the result. "Incorrect OTP Code" only appears after a correct password, so the attacker knows Monica's password but not her second factor. No successful login was recorded.

![02-logs-otp-failures](screenshots/02-logs-otp-failures.png)

### 2. IP Analysis

`113.161.158.12` is an external IP owned by VNPT Corp (AS45899), a Vietnamese ISP. VirusTotal flags it 4/92: BitDefender and G-Data (Phishing), Fortinet (Malware), and SOCRadar (Malicious), with alphaMountain.ai rating it Suspicious. The community score is -3. The low count still matters: the IP has a history of abuse reports, and the login came from a country Monica isn't authorized to connect from.

![03-virustotal-ip](screenshots/03-virustotal-ip.png)

## Artifacts

| Type | Indicator |
| ---- | --------- |
| Attacker IP | `113.161.158.12` |
| Target | `vpn-letsdefend.io` (`33.33.33.33:443`) |
| Compromised account | `monica@letsdefend.io` |

## Response

No isolation needed, since MFA stopped the login. Reset Monica's password, block `113.161.158.12`, confirm with Monica that she didn't share or approve any OTP, and find out how her password leaked (phishing, reuse).

## Conclusion

**True Positive.** An attacker from an unauthorized country used Monica's valid password on the VPN but was stopped by MFA.

**MITRE ATT&CK:** T1133 (External Remote Services), T1621 (MFA Request Generation), T1595 (Active Scanning)
