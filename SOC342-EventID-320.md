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

![Alert details](screenshots/01-alert-details.png)

## Investigation
**Log Management:** One proxy event from 107.191.58.76:25332 → 172.16.20.17:443 matching the exploit URL. The Referer is set to SignOut.aspx, the ToolShell auth-bypass indicator.

![Log management](screenshots/02-log-management.png)
![Referer header](screenshots/04-referer-signout.png)

**VirusTotal (IP):** 107.191.58.76 is flagged by 8/92 vendors (malware, phishing, malicious); community score −9.

![VirusTotal IP](screenshots/03-virustotal-ip.png)

**Endpoint (SharePoint01):** The IIS worker process spawned a post-exploitation chain within seconds of the request.

| Time | PID | Process (parent) | Activity |
|---|---|---|---|
| 13:07:24 | 9876 | powershell.exe (w3wp.exe) | Hidden, base64-encoded command. Decodes to an ASPX page that dumps the server's MachineKey (ValidationKey, DecryptionKey) |
| 13:07:27 | 9901 | csc.exe (powershell.exe) | Compiles `C:\Windows\Temp\payload.cs` → `payload.exe` |
| 13:07:29 | 9910 | cmd.exe (csc.exe) | Writes web shell `...\16\TEMPLATE\LAYOUTS\spinstall0.aspx`, referencing `http://107.191.58.76/payload.exe` |
| 13:07:34 | 9920 | powershell.exe (cmd.exe) | Runs `MachineKeySection::GetApplicationConfig()` to read the machine keys |

At 13:08:04, SharePoint01 made an outbound connection back to 107.191.58.76.

![Encoded PowerShell](screenshots/05-encoded-powershell.png)
![Process tree](screenshots/06-process-tree.png)
![Terminal history](screenshots/08-terminal-history.png)
![Network actions](screenshots/07-network-actions.png)

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
