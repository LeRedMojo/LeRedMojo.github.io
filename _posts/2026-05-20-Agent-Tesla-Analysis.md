---
title: "Static analysis of an obfuscated Agent Tesla JavaScript dropper"
date: 2026-05-20 10:00:00 -0400
categories: [Malware analysis]
tags: [agent-tesla, email-security, phishing, YARA, malware, dropper]
---

## Executive Summary

This is a static analysis of an Agent Tesla JavaScript dropper variant recovered from MalwareBazaar. The sample is the initial stage of a multi-stage infection: a heavily obfuscated JavaScript file delivered via email that decodes and executes the Agent Tesla payload, a .NET keylogger and infostealer. This writeup covers the deobfuscation methodology, behavioral analysis, MITRE ATT&CK mapping, and a behavioral YARA rule I developed to detect this dropper class.

## Agent who?

Agent Tesla is a keylogger written in .NET that that saw significant distribution growth during 2020 and 2021 and remains widely used today. It remains a popular choice for malware distribution via email, due to its effectiveness and low cost on underground markets. It has the capability to exfiltrate data through FTP, SMTP, HTTP and Telegram. It is essential to monitor outbound traffic for the protocols Agent Tesla uses to exfiltrate data: FTP (ports 20-21), SMTP (ports 25, 465, 587), HTTPS, and Telegram bot API traffic to api.telegram.org.

## Sample Information

Filename: 6d60f9d8fb1f18a32661a5b4a9db33f3607707c29c26e36d5988b6cc6ad88c46.js
SHA 256: 6d60f9d8fb1f18a32661a5b4a9db33f3607707c29c26e36d5988b6cc6ad88c46
MD5: 00f92983bd768ab959bb0d17c18450d4
File size: 2 149 941 bytes
Source: MalwareBazaar
Family: Agent Tesla (JS dropper stage)

## Initial observation

Upon investigation, I found that the main code was a mess. It was showing as one whole line, which reduced readability and made our lives more complicated. Two patterns are immediately visible in the beautified code: heavy dead code injection designed to waste analyst time by leading investigations into dead-end function chains, and string array
rotation that hides every meaningful string behind indexed lookups
into a single large array. Both are signatures of obfuscator.io, 
a JavaScript obfuscation tool commonly used in malware delivery.

![Example of raw sample](/assets/img/AgentTeslaRawCode.png)

![Example of clean sample](/assets/img/AgentTeslaCleanCode.png)


## What is a dropper

A dropper is a small program designed for one purpose: deliver and execute the actual malware payload on a victim's system. Droppers do not perform the malicious activity themselves, they exist solely to set the stage for what comes next.

In this sample, the dropper is a JavaScript file delivered as an email 
attachment. When opened on Windows, the operating system executes JavaScript files via Windows Script Host (`wscript.exe`) automatically. The dropper then performs its job: decode the encoded Agent Tesla payload, write it to disk as a PowerShell script, establish persistence so the payload survives reboots, and execute the payload silently.

Separating the dropper from the payload is an evasion technique. The dropper is small, easily replaceable, and can be regenerated for each campaign.

## Static Analysis Methodology

Tools used: Remnux, js-beautify, synchrony, node, grep and a lot of patience

To make sense of all these hieroglyphs, here are the steps taken to improve understanding of them.

**Note:** always make a copy of the sample in case you mess up the structure of the malware when modifying it. To make sense of the code, it is essential to rename the variables according to their function. After identifying the functions that retrieve the indexes and prepare them for assembly, here is an example from many other cases:

![Raw code](/assets/img/AgentTeslaFunctionRawCollector.png)

![Clean code](/assets/img/AgentTeslaFunctionCleanCollector.png)

It is really tedious work manually but it helps a lot to better understand the flow of everything.

These indexes reference a variable that stores all the strings used by the malware.

![Variable that stores the elements](/assets/img/PayloadString.png)

## Deobfuscation

When I first attempted to execute the sample in a Node.js environment 
with stubbed WScript objects, the script terminated immediately. No 
payload activity. No interesting behavior. Just silent exit.

The block responsible:

{% raw %}
```javascript
var _0x2bb521 = _0x21bd,
    _0x56c4c9 = _0x21bd,
    _0x35b66f = _0x21bd,
    _0x3eb9ab = _0x21bd,
    _0x4284c5 = _0x21bd,
    _0xe4f745 = _0x21bd,
    _0x2d7e3a = _0x21bd,
    _0x50e273 = _0x21bd,
    strBase = _0x2bb521(0x30),
    blnResult, objDict;
try {
    objDict = new ActiveXObject(_0x2bb521(0x66) + _0x20984a(0x223)), objDict[_0x56c4c9(0x5)](_0x3eb9ab(0x2b));
} catch (_0x301cdb) {
    WScript[_0x56c4c9(0x78)](0x1);
}
```
{% endraw %}

At first this looked like routine initialization. The script creates 
a COM object, calls a method on it, and exits if anything fails. But 
the object being created, `Scripting.Dictionary` has no reason to fail 
on any real Windows system. It is a standard part of Windows scripting 
that exists everywhere wscript.exe runs.

The point of this block is not initialization. It is an environment 
check disguised as initialization.

![WScript.Quit(1) decoded](/assets/img/DecrpyedWScript.png)

With the kill switch commented out and the string table dumped, the rest 
of the sample could be read end-to-end. The behavioral profile that emerged maps cleanly to MITRE ATT&CK.

Three key functions made the obfuscation work in this sample. The first 
is the string array function, which returns a large array containing every string literal the program uses. The second is the accessor function, which takes a hex index and returns the string at that position. The third is the rotation function, which shifts the array indices by a constant 
offset at runtime so you cannot just count positions naively.

Once I identified these three, the strategy was clear: dump the full 
decoded string table, then use it as a lookup whenever I needed to read 
obfuscated code. What slowed me down was the alias pattern. The obfuscator creates dozens of variables that are all assigned the same accessor function. Variables like _0x1d6e1c, _0x3748ae, _0x340f2e all do exactly the same thing but look different in the code. Once I understood they were aliases, the code became readable.

## MITRE ATT&CK Mapping


**T1566.001 — Spearphishing Attachment:** The dropper is delivered as 
a JavaScript attachment in phishing emails, typically inside a 
compressed archive to bypass attachment filters.

**T1059.007 — JavaScript Execution:** Windows Script Host (wscript.exe) 
executes the .js file when the victim opens it, with no additional 
user interaction required.

**T1027.010 — Command Obfuscation:** The entire script is obfuscated 
using obfuscator.io's string array rotation, with all string literals 
moved into an encoded array and accessed via indexed function calls.

**T1140 — Deobfuscate/Decode Files:** The Agent Tesla payload is 
delivered base64-encoded and decoded at runtime using ADODB.Stream 
combined with the MSXML bin.base64 data type.

**T1059.001 — PowerShell:** The decoded payload is executed via 
PowerShell with full evasion flags: -ExecutionPolicy Bypass, 
-NonInteractive, -NoProfile, -WindowStyle Hidden.

**T1547.001 — Registry Run Keys:** Persistence established by writing 
to HKCU\Software\Microsoft\Windows\CurrentVersion\Run pointing to the 
dropped PowerShell payload.

**T1547.009 — Shortcut Modification:** Additional persistence via a 
.lnk shortcut created with TargetPath, WorkingDirectory, and Arguments 
configured to execute the payload at startup.

**T1497.001 — System Checks:** The dropper uses WMI (winmgmts:) to 
enumerate running processes and inspect their CommandLine properties, 
detecting analysis environments and security tools.

**T1562.001 — Disable or Modify Tools:** When the WMI enumeration 
detects target processes, the dropper actively terminates them with 
Terminate(0) calls, attempting to kill analysis tools and sandbox 
agents.

## My rule and its limitations

The reconstructed command this dropper builds and executes:

powershell.exe -ExecutionPolicy Bypass -NonInteractive -NoProfile 
-WindowStyle Hidden -File "C:\Temp\[12chars from yz01234567]_[timestamp].ps1"

The "yz01234567" charset is specific to this variant. Every payload 
filename uses only those characters plus a timestamp suffix, which gives 
defenders a useful indicator for file monitoring rules independent of 
YARA detection.

I wrote a YARA rule targeting the obfuscation pattern, the ADODB+base64 
decode chain, both persistence mechanisms, the WMI anti-analysis behavior, and the drop location indicators. The full rule is on GitHub:

[The rule](https://github.com/LeRedMojo/ThreatHunting/blob/main/YARA/Malware%20Email/AgentTeslaDropperStage1.yar)

What the YARA rule does not catch:
- Agent Tesla payloads delivered via other vectors such as Office, PDF or ISO.
- Variants using different obfuscation tools
- Variants with different drop paths or persistence
- The Agent Tesla payload itself, this rule detects the dropper only.

## Closing thoughts

Manual deobfuscation is a tedious but rewarding process. Working through this sample line by line gave me a deeper understanding of threat actors thought processes, and of why every dead code branch, every indirection and every COM object check exists. Automated tools failed to deobfuscate this sample completely; manual work was the only way to extract the full behavioural profile and build a meaningful detection rule.

The next step is to perform dynamic analysis in a Windows sandbox in order to extract and analyse the actual Agent Tesla payload that this dropper delivers. This will be the subject of a follow-up post.