---
title: "Unpacking the Agent Tesla native loader and finding C2 the hard way"
date: 2026-05-27 10:00:00 -0400
categories: [Malware analysis]
tags: [agent-tesla, email-security, phishing, YARA, malware, unpacking, process-hollowing]
---

## Executive Summary

This is a static and dynamic analysis of an Agent Tesla native loader stage recovered from the same campaign family as my previous JavaScript dropper writeup. Where the dropper was an obfuscated JS file that decoded a PowerShell payload, this sample is the next stage down: a native 64-bit Windows executable that unpacks an encrypted overlay and injects the Agent Tesla .NET core into a signed Microsoft binary via process hollowing. This writeup covers the unpacking methodology, the dead ends, the eventual pivot from static to dynamic analysis, the recovery of the SMTP configuration, MITRE ATT&CK mapping, and a structural YARA rule built to detect the loader stage of this family.

## Agent Tesla, again

Agent Tesla is a .NET keylogger and infostealer that has been a constant fixture in commodity malware distribution since 2020. It exfiltrates over SMTP, FTP, HTTP, or Telegram, and is widely sold on underground markets. My previous post covered the JavaScript dropper that delivers the loader, this post covers the loader itself and the .NET stealer it unpacks.

## Sample Information

Filename: AgentTesla.exe
SHA 256: 8A27732F805C8CB6A4F37443ED728CD5239DFFB6E3E12D02AA7E698B5FC3F23C
MD5: 846C7B1201CFEAC0CD48ECC080270F9F
File size: 1 027 779 bytes
Source: MalwareBazaar
Family: Agent Tesla (native loader stage)

## Initial triage

Detect It Easy reported the file as a 64-bit PE compiled with Visual Studio 2022 , GUI subsystem, and flagged a "compressed or packed data" heuristic on the overlay. The overlay sits at offset `0x000BE800`, is 247491 bytes long, and has entropy 7.999, which is essentially the theoretical maximum. Compressed data scores high on entropy. Encrypted data scores higher. A score this close to 8 means the bytes look indistinguishable from random.

![DIE output showing native PE64 with high-entropy overlay](/assets/img/AgentTeslaDieOutput.png)

PE-studio then gave the rest of the fingerprint: imphash `D4652FACE233FD6B259D63F8ABB6894F`, a manifest claiming the file is "Peridot.DesktopUtility", a file-name version field of "aethsync.dll", and imports including `bcrypt.dll`, `BCryptGenRandom`, and `AddVectoredExceptionHandler`. None of those strings match the executable's apparent purpose, and "Peridot.DesktopUtility" / "aethsync" are not products that exist in normal software. These are bespoke crypter artifacts and they became the anchors for the YARA rule later.

![PE-studio indicators](/assets/img/PEStudioAgentOutput.png)

## What is a packer

A packed executable has two parts: a stub, which is the loader that actually runs when Windows executes the file, and a packed payload, which is encrypted or compressed data appended to the file. When the file runs, the stub decrypts the payload into a fresh region of memory and transfers execution to it. The handoff is called the Original Entry Point (OEP) and finding it is the classic unpacking goal.

The reason packers exist is to defeat static analysis. The actual malicious code is never on disk in a readable form. Antivirus and YARA rules that look for the payload's strings will not find them in the packed file because they are encrypted bytes at that point. You have to either unpack statically or unpack dynamically.

In this sample, the loader is the visible PE structure ending at offset `0x000BE800`. Everything after that offset is the overlay: 247 KB of high-entropy data with no MZ header, no readable structure, and a first byte sequence of `42 EE FF C0 BB C6 03 00 14 DC 5F 21 32 2C 74 88` that looks like nothing at all. That is the payload, encrypted.

## Static Analysis Methodology

Tools used: Detect It Easy, PE-studio, FLOSS, CAPA, CyberChef, PowerShell, dnSpy, de4dot, x64dbg, hollows_hunter, FakeNet-NG, and a lot of patience.

The first move was string extraction with FLOSS, which is more thorough than `strings.exe` because it also recovers obfuscated stack strings and decoded constants. The output was around 14000 lines. Grepping for keywords like `api`, `ip`, `Smtp`, `ftp`, `Chrome`, `Mutex`, `schtasks`, and `Startup` surfaced runtime artifacts (`System.Private.CoreLib`, `System.Private.Reflection.Execution`, `System.Private.TypeLoader`) that suggested .NET despite the file being native C++. This is the fingerprint of **native AOT (Ahead-of-Time) compilation**: a .NET program compiled into a native executable that bundles the runtime into the binary. dnSpy and de4dot do not work on AOT binaries because there is no managed assembly to decompile, only native code.

CAPA was then run to map capabilities to MITRE ATT&CK. The output flagged Virtual Machine Detection (B0009), Timing/Delay Check via QueryPerformanceCounter (B0001.033), and Debugger Detection.

![CAPA output](/assets/img/CAPAAgentTesla.png)

## Extracting the overlay

Because the overlay is where the real malware lives, the next step was carving it out so it could be analysed in isolation. PowerShell does this with two file reads:

{% raw %}
```powershell
$path = "C:\Path\To\AgentTesla.exe"
$bytes = [System.IO.File]::ReadAllBytes($path)
$overlay = $bytes[0xBE800..($bytes.Length - 1)]
[System.IO.File]::WriteAllBytes("overlay.bin", $overlay)
```
{% endraw %}

DIE then reported that `overlay.bin` contained a "Raw Deflate stream at offset 0x19", which would have been very convenient if it were true. Stripping the first 25 bytes and feeding the rest through CyberChef's Raw Inflate, Zlib Inflate, and Gunzip all failed with allocation or signature errors. Feeding the entire `overlay.bin` produced the same failures.

![Overlay.bin DIE program](/assets/img/Overlaybin.png)

The conclusion: DIE was guessing. The overlay is not plain deflate. It is encrypted, and the key lives in the loader. Static analysis of the overlay alone will not recover the payload because there is no managed metadata to read and no compression to reverse without first decrypting.

## Dynamic unpacking with x64dbg

A packed malware sample runs in a predictable sequence: the stub executes, allocates a region of memory, decrypts the payload into it, changes the memory protection to executable, and transfers control. By breakpointing the Windows APIs the stub *must* call to do these things, you catch the unpacking in the act without needing to know any addresses ahead of time.

The classic first breakpoints:

{% raw %}
``` 
bp VirtualAlloc
bp BCryptDecrypt
```
{% endraw %}

`VirtualAlloc` allocates new memory regions and packers almost always use it to create the decryption buffer. `BCryptDecrypt` was added because PE-studio listed `bcrypt.dll` in the imports.

The first VirtualAlloc hit came from Thread Local Storage (TLS) callbacks, which are functions Windows runs automatically before a program's normal entry point, every time a thread starts.

Malware authors use TLS to hide anti-debug and anti-VM checks because they fire so early.

Stepping past these and resuming the run eventually landed at a meaningful VirtualAlloc call:

- RDX = 0x10000 (size: 64 KB)
- R8 = 0x202000 (`MEM_COMMIT | MEM_RESERVE`)
- R9 = 0x4 (`PAGE_READWRITE`, not executable)

The memory is allocated as read/write only. Packers usually allocate as read/write, write the decrypted bytes in, and then call `VirtualProtect` to flip the region to read/execute before jumping in. But before that fired, the process spawned a child and started writing memory into it.

![x64dbg at VirtualAlloc breakpoint](/assets/img/VirtualAllocRW.png)

## Process hollowing

A process change from the parent to a new PID, combined with writes into the new process's memory before any thread runs there, is the signature of **process hollowing** (MITRE T1055.012). The loader creates a legitimate signed Microsoft binary in a suspended state, unmaps its original code, writes its own decrypted payload into the carved-out memory, and resumes the thread. The child process now appears in Task Manager as the signed binary it was supposed to be, but is actually executing the malware.

It would go like:
1. Create suspended child (`CreateProcess` with `CREATE_SUSPENDED`)
2. `ZwUnmapViewOfSection` to carve out the original image
3. `NtMapViewOfSection` or `NtWriteVirtualMemory` to place the payload
4. `SetThreadContext` to point the child's thread at the payload's entry point
5. `NtResumeThread` to run it

![ZwUnmapViewOfSection breakpoint](/assets/img/ZwUnmapViewOfSection.png)

The child process turned out to be `jsc.exe` (PID 5840 in one run, different across runs), the **JScript compiler**, a signed Microsoft .NET LOLBIN that lives under `C:\Windows\Microsoft.NET\`. Hollowing into `jsc.exe` is a deliberate choice: the binary is signed by Microsoft, it loads the CLR (so a .NET payload runs naturally), and it is unusual enough that defenders may not have baseline data on its normal behavior.

With the loader program paused at NtResumeThread inside x64dbg, I executed hollows_hunter to target and scrape the decrypted Agent Tesla core payload out of the suspended jsc.exe child process before it could execute:

{% raw %}
``` bash
hollows_hunter.exe /imp 1
```
{% endraw %}

![Hollows_hunter child process](/assets/img/AgentTeslaHollows_Hunter.png)

## Hunting the SMTP config

In order to hunt the SMTP config I had to inspect the code through but it was never encrypted. It is sitting in plaintext string literals in a static initializer.

Along the way I found a JDownloader 2.0 credential-stealer module, a class that AES-decrypts the victim's stored JDownloader account files, which is what initially threw me off the C2 trail.

{% raw %}
```csharp
public static int SmtpPort = Convert.ToInt32("25");
public static bool SmtpSSL = Convert.ToBoolean("false");
public static string SmtpServer = "mail.onionmail.org";
public static string SmtpSender = "sendboxorigin@onionmail.org";
public static string SmtpPassword = "sendboxorigin12";
public static string SmtpReceiver = "originlogbox@onionmail.org";
public static string StartupRegName = "gnxLZ";
public static string StartupInstallationName = "gnxLZ.exe";
```
{% endraw %}

![Plain Text SMTP config and other malicious tool activation](/assets/img/PlainTextSMTPp1.png)

![Plain Text SMTP config and other malicious tool activation](/assets/img/PlainTextSMTPp2.png)

## Multi-stage IP discovery

FakeNet did capture one useful real-time IOC: a DNS request for `ip-api.com` from `jsc.exe`. Agent Tesla calls `ip-api.com` at startup to learn the victim's public IP for the email report. The DNS request confirmed the hollowed `jsc.exe` was the live Agent Tesla core. It did not, on its own, reveal the SMTP host.

![FakeNet capturing the ip-api.com lookup](/assets/img/FakeNetGotEm.png)

The takeaway from this stretch was that dynamic analysis is the higher-information path when the malware cooperates, and the lower-information path when it does not. The sample's CAPA-flagged anti-VM and timing checks meant dynamic confirmation kept stalling. Static, once I was searching for the right class, gave a complete answer in one click.

## MITRE ATT&CK Mapping

This sample chains a native loader stage with a hollowed .NET stealer payload, so the mapping spans both stages.

**T1027.002 — Software Packing:** The Agent Tesla .NET payload is encrypted in an overlay appended to the loader. The overlay shows 7.999 entropy and no readable structure.

**T1140 — Deobfuscate/Decode Files or Information:** The loader decrypts the overlay in memory at runtime using cryptographic primitives from `bcrypt.dll` (`BCryptGenRandom`, hashing via SHA1).

**T1622 — Debugger Evasion:** The loader registers vectored exception handlers (`AddVectoredExceptionHandler`) and uses TLS callbacks to run anti-analysis code before a debugger's normal entry-point breakpoint would fire.

**T1497.001 — System Checks:** CAPA flagged Virtual Machine Detection and timing-based environment checks via `QueryPerformanceCounter`, `GlobalMemoryStatusEx`, and `GetLogicalProcessorInformationEx`.

**T1055.012 — Process Hollowing:** The loader spawns `jsc.exe` (signed Microsoft .NET LOLBIN) in a suspended state, calls `ZwUnmapViewOfSection` to carve out the original image, writes the decrypted Agent Tesla .NET payload into the carved memory, calls `SetThreadContext` to redirect the entry point, and resumes the thread.

**T1036.005 — Masquerading: Match Legitimate Name or Location:** The loader hollows into a signed Microsoft binary so the running process appears legitimate to defenders inspecting process trees.

**T1547.001 — Registry Run Keys:** Persistence is via a Run key named `gnxLZ` pointing to `%appdata%\gnxLZ.exe` (recovered from the `StartupRegName` and `StartupInstallationName` config fields).

**T1614 — System Location Discovery:** The payload calls `ip-api.com` to determine the victim's public IP and country for inclusion in the exfiltration report. Confirmed dynamically via FakeNet DNS capture.

**T1056.001 — Keylogging, T1113 — Screen Capture, T1115 — Clipboard Data:** The payload contains `EnableKeylogger`, `EnableScreenLogger`, and `EnableClipboardLogger` configuration switches and corresponding capture routines (screenshots as `image/jpeg` with `yyyy_MM_dd_HH_mm_ss.jpeg` naming).

**T1555 — Credentials from Password Stores:** The payload contains application-specific credential stealer modules. The JDownloader module was inspected in detail; sibling modules for browsers, FTP clients (`_wsftpkey`), and Windows Credential Vault (`passwordVault`, `VaultEnumerateItems`) were observed but not unpacked.

**T1048.003 — Exfiltration Over Unencrypted Non-C2 Protocol:** Exfiltration uses SMTP on port 25 with `SmtpSSL = false`. The mail is sent from `sendboxorigin@onionmail.org` to `originlogbox@onionmail.org` via `mail.onionmail.org`.

## My rule and its limitations

The rule targets the native loader stage. It anchors on the unique crypter strings, the structural fingerprint (64-bit PE with a large high-entropy overlay), and the imphash as a confidence booster.

**Why the SMTP configuration is not in the rule.** The values `mail.onionmail.org`, `sendboxorigin@onionmail.org`, and `sendboxorigin12` would look like obvious detection candidates. They are deliberately omitted for two reasons.

First, they are not present in this file. The SMTP strings live in the unpacked .NET payload that exists only in memory after the loader has run. They cannot be matched in the file the YARA rule scans.

Second, even on the payload they are the wrong layer for a family-detection rule. C2 hostnames, mailboxes, and passwords are config: the operator can rotate any of them in seconds without changing a line of code.

## Closing thoughts

The interesting part of this analysis was not the final answer. Finding the SMTP credentials inside the static initializer took a minute once I searched for SmtpClient. The real value was the messy route there—the dead ends, the wrong hypotheses about the C2, and the stalled debug sessions. Every roadblock taught me something the working path never could have.

To track this specific engine, I have written a custom YARA rule targeting these structural features rather than fragile network domains. You can view the rule and the analysis artifacts on my GitHub: [The rule](https://github.com/LeRedMojo/ThreatHunting/blob/main/YARA/Malware/AgentTeslaEXE.yar)

Triaging these samples is a slow, methodical grind, but an incredibly rewarding one. I learn something new every single day, and this is just the beginning of a long journey. I'll be publishing more articles and deep-dives as I continue to break down complex malware to sharpen my reverse engineering baseline.