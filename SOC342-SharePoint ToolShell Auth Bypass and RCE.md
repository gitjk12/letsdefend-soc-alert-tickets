# SOC342 – CVE-2025-53770 SharePoint ToolShell Auth Bypass and RCE (EventID 320)

**Severity:** Critical | **Type:** Web Attack | **Difficulty:** Hard
**Event Time:** 2025-07-22 13:07:10 (+03:00)
**Verdict:** True Positive – successful exploitation, escalated to Tier 2
**MITRE:** T1190 Exploit Public-Facing Application · T1059 Command & Scripting Interpreter · T1505.003 Web Shell

## Alert Summary
An external IP sent a ToolShell exploit request to on-prem SharePoint server **SharePoint01** (172.16.20.17).
- **Source:** 107.191.58.76 (AS20473, The Constant Company)
- **Request:** POST `/_layouts/15/ToolPane.aspx?DisplayMode=Edit&a=/ToolPane.aspx` (Content-Length 7699)
- **Referer:** `/_layouts/SignOut.aspx`, the spoofed header that bypasses authentication
- **Device Action:** Allowed

<img width="1520" height="586" alt="01-alert-details" src="https://github.com/user-attachments/assets/02aba0ba-b4c2-4f77-8df0-bb2701443cf9" />


## Investigation
**Log Management:** One proxy event from 107.191.58.76:25332 → 172.16.20.17:443 matching the exploit URL. The Referer is set to SignOut.aspx, the ToolShell auth-bypass indicator.

<img width="1504" height="795" alt="02-log-management" src="https://github.com/user-attachments/assets/fe9a3458-9f0a-4b1c-aa4c-ff3ba29e4f7f" />

<img width="1179" height="726" alt="04-referer-signout" src="https://github.com/user-attachments/assets/37fd4536-692a-4b37-8b16-b9823055aff8" />


**VirusTotal (IP):** 107.191.58.76 is flagged by 8/92 vendors (malware, phishing, malicious); community score −9.

<img width="1915" height="987" alt="03-virustotal-ip" src="https://github.com/user-attachments/assets/3526a297-dfee-4773-b907-29a28c53671d" />


**Endpoint (SharePoint01):** The IIS worker process spawned a post-exploitation chain within seconds of the request.

| Time | PID | Process (parent) | Activity |
|---|---|---|---|
| 13:07:24 | 9876 | powershell.exe (w3wp.exe) | Hidden, base64-encoded command. Decodes to an ASPX page that dumps the server's MachineKey (ValidationKey, DecryptionKey) |
| 13:07:27 | 9901 | csc.exe (powershell.exe) | Compiles `C:\Windows\Temp\payload.cs` → `payload.exe` |
| 13:07:29 | 9910 | cmd.exe (csc.exe) | Writes web shell `...\16\TEMPLATE\LAYOUTS\spinstall0.aspx`, referencing `http://107.191.58.76/payload.exe` |
| 13:07:34 | 9920 | powershell.exe (cmd.exe) | Runs `MachineKeySection::GetApplicationConfig()` to read the machine keys |

At 13:08:04, SharePoint01 made an outbound connection back to 107.191.58.76.

<img width="1222" height="568" alt="05-encoded-powershell" src="https://github.com/user-attachments/assets/a97f88e2-1337-4640-b089-24256ef0914a" />

<img width="1039" height="507" alt="06-process-tree" src="https://github.com/user-attachments/assets/c7b1228c-8ee5-49ce-850d-713c938256be" />

<img width="1052" height="450" alt="08-terminal-history" src="https://github.com/user-attachments/assets/ef481ab9-82d6-47cb-83f1-4ee7fe3a9e3a" />

<img width="1190" height="556" alt="07-network-actions" src="https://github.com/user-attachments/assets/65fc8fcd-6da0-4d87-ae09-9c82fda6b280" />


## Conclusion
CVE-2025-53770 (ToolShell) was exploited successfully. The attacker bypassed authentication, achieved RCE through unsafe deserialization, dropped the `spinstall0.aspx` web shell, compiled a payload, and stole the ASP.NET machine keys. Stolen keys allow forged requests and continued access even after patching.

**Recommended actions:** Isolate SharePoint01. Block 107.191.58.76. Remove `spinstall0.aspx`, `payload.cs` and `payload.exe`. Rotate the ASP.NET machine keys and restart IIS. Apply Microsoft's CVE-2025-53770 patch. Hunt for other hosts contacting 107.191.58.76.

## Playbook Results
**Score:** 25 (91% success rate)

| Step | Answer | Result |
|---|---|---|
| Understand Why the Alert Was Triggered | Next | ✓ |
| Collect Data | Next | ✓ |
| Examine HTTP Traffic | Next | ✓ |
| Is Traffic Malicious? | Malicious | ✓ |
| What Is the Attack Type? | Command Injection | ✗ (correct: Other – unsafe deserialization and RCE) |
| Check If It Is a Planned Test | Not Planned | ✓ |
| What Is the Direction of Traffic? | Internet → Company Network | ✓ |
| Check Whether the Attack Was Successful | Next | ✓ |
| Was the Attack Successful? | Yes (HTTP 200) | ✓ |
| Containment | Next | ✓ |
| Do You Need Tier 2 Escalation? | Yes | ✓ |

**Lesson learned:** Command execution was the *result*, not the *vector*. The entry point was unsafe deserialization of the request body, so the attack type is "Other."
