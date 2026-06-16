---
title: "Peeling a four-stage Snake Keylogger: from pixels to a Telegram bot token"
date: 2026-06-04 10:00:00 -0400
categories: [Malware analysis]
tags: [snake-keylogger, 404-keylogger, dotnet, confuserex, steganography, process-injection, unpacking, dnSpy, YARA, malware]
---

## Executive Summary

This is a static and dynamic analysis of a Snake Keylogger (also tracked as "404 Keylogger") sample that hides its real payload across four stacked stages. The outer file looks like a harmless C# "Gladiator" game. Underneath it is a steganographic loader that paints an entire .NET assembly into the pixels of an embedded image, a ConfuserEx-obfuscated injector, and finally the actual VB.NET stealer. This writeup walks the unpacking chain stage by stage, the anti-analysis traps that cost me the most time, the moment the live debugger stopped being useful, and the static decryption that handed over the operator's live Telegram bot token and chat ID. It closes with MITRE ATT&CK mapping and notes for a structural detection rule.

## Snake Keylogger, the commodity stealer that never dies

Snake Keylogger is a .NET keylogger and infostealer that has been sold on underground markets for years. It harvests keystrokes, clipboard, screenshots, and saved credentials from browsers and mail clients, then exfiltrates over SMTP, FTP, or Telegram depending on how the operator built it. This sample is interesting not because the family is novel, but because of the *delivery*: a multi-stage in-memory chain designed so that almost nothing malicious ever touches disk in readable form.

## Sample Information

Filename: SnakeKeyLogger.exe (orig. `ymxG.exe`)
SHA256: `2263046083f6f559100f194783e989d27b1a854977324c939734e877aa75a842`
File size: 1 015 KiB
Source: malware sample set
Family: Snake Keylogger / 404 Keylogger (.NET, multi-stage)

## Initial triage

Detect It Easy reported a 32-bit .NET assembly (MSIL/C#), GUI subsystem, built on .NET Framework v4.5, and flagged a "compressed or packed data" heuristic with `.text` section entropy of 7.639. PEStudio confirmed the .NET picture, showed the main library as `mscoree.dll` (the unmanaged bootstrapper that loads the CLR), and surfaced an internal version description of "Gladiator Maktabi". A noise-like resource that rendered as RGB static was the tell: high entropy plus a "picture" that looks like random colour means a payload is hidden inside the assembly, and the assembly itself is just a wrapper.

> **Habit:** high entropy + an odd noise "image" resource = a payload is embedded somewhere. Go into your decompiler expecting a loader, not the final logic.

![DIE output showing 32-bit .NET assembly with high-entropy .text section](/assets/img/HighEntropySnake.png)

![PEStudio showing mscoree.dll and the Gladiator description](/assets/img/FullValueSnake.png)

## A note on multi-stage .NET malware

A single-stage executable has its logic right there in the file. A multi-stage loader instead carries the real payload in an encrypted or encoded form, decodes it in memory at runtime, and hands execution to it without ever writing a readable copy to disk. Each handoff is a stage. The goal of unpacking is to follow the handoffs until you reach the final payload, dumping each stage as you go.

The reason this style exists is to defeat static analysis and antivirus. If the malicious strings only exist after three layers of in-memory decoding, a scanner looking at the file on disk sees nothing useful. You have to walk the chain.

This sample has four stages:

1. **Stage 1** - the visible "Gladiator" game, a steganographic loader.
2. **Stage 2** - `OptiMax.dll`, an AES-decrypted .NET loader, obfuscated with ConfuserEx, with anti-debug.
3. **Stage 3** - `System Optimizer Ultimate.dll`, a ConfuserEx injector that decrypts and launches the final payload.
4. **Stage 4** - the actual Snake Keylogger stealer (VB.NET).

## Tools used

dnSpy (32-bit build for the x86 payload), FLOSS, strings, FakeNet-NG, Procmon, Wireshark, and a great deal of patience.

## Stage 1: the loader hiding in plain sight

Opening the file in dnSpy, `Main` looked completely innocent: it sets up a Windows Form for a gladiator-themed game, builds a `DataSet`, checks whether a save file exists, and runs the form. No `Assembly.Load`, no resource reads, no crypto. That cleanliness is the signal, not the dead end, the loader is hidden somewhere that auto-runs.

My wrong move here was to search for the unpacking APIs by name. Searching `FromBase64String` finds the framework *definition*, not the code that *calls* it. The right move is the pivot that cracks the whole case: pick a dangerous framework API and run **Analyze → Used By**, filtering for the sample's own namespace.

> **Habit:** to find where malware uses a capability, never search the API name. Pivot from the framework API via Analyze → Used By and look only for callers in the sample's namespace.

`Convert.FromBase64String` → Used By → only framework callers, no Gladiator code. So base64 decoding is *not* used here. `Assembly.Load(byte[])` → Used By → a caller in the sample's namespace appears. That is the hit. Walking the chain upward:

```
Assembly.Load(byte[])
  ← AsosiyForma.InitializeComponent()
    ← AsosiyForma..ctor()
      ← Program.Main()
```

![Analyze Used By chain leading to InitializeComponent](/assets/img/AssemblyLoadSnake.png)

Reading the few non-boilerplate lines around the load revealed the mechanism:

```csharp
List<byte> list = ExtractPixelBytes(null, 0);   // image hardcoded to Resources.KILO, 96768 bytes
Assembly assembly = Assembly.Load(list.ToArray());   // reflective load from memory
Type type = assembly.GetExportedTypes()[0];          // first public type
... SC.Split("GladiatorSchool") ...                  // "76727376","676576" config seeds
Activator.CreateInstance(type, array2);              // run stage 2 via its constructor
```

`ExtractPixelBytes` walks the `KILO` bitmap and emits each pixel's R, G, and B values as raw bytes. That is why the resource looked like noise, it is an entire assembly painted into the pixels of an image. Steganography.

![ExtractPixelBytes reading pixels from the KILO resource](/assets/img/KiloSnake.png)

## Dumping stage 2

There is a universal way to grab the next stage without decoding any pixel math by hand: let the malware do it, then steal the result. I set a breakpoint on the `Assembly.Load(list.ToArray())` line. When it hit, the byte array was already populated. I saved that `byte[]`, verified it began with the `MZ` magic bytes (`4D 5A`) and was the expected ~96 KB, and re-opened it in a fresh dnSpy. It relabelled itself as `OptiMax.dll`.

> **Habit:** don't decode the unpack math by hand. Breakpoint the load, grab the cleartext bytes, confirm the `MZ` header, reopen. Repeat for each stage.

![MZ magic byte confirming stage 2 presences](/assets/img/ConfirmedExecutable.png)
![Saving the decrypted stage 2 byte array at the Assembly.Load breakpoint](/assets/img/OptiMaxDll.png)

## Stage 2: the anti-debug trap

Stage 2 did not start where I expected. Stage 1 launched it via `Activator.CreateInstance` with a three-string constructor, so I went hunting for a matching constructor and there wasn't one. The `<Module>` static constructor (`.cctor`) runs automatically the instant the assembly loads, before any normal entry point. That is where execution really began.

It led straight to a guard:

```csharp
if (Debugger.IsAttached) throw new Exception("Debugger Detected");
```

An anti-debug check (MITRE T1622) running on load. My first instinct was to patch it out in the IL, change the check to a `ret` and save the module. **This was a mistake, and it cost me hours...** Stage 2 folds the assembly's own public-key token into the key it uses to decrypt stage 3. The moment I edited and re-saved the module, the token changed, the decryption key changed, and stage 3 silently decrypted into garbage that failed to load, the process just exited cleanly with code 0. Every "fix" made it worse.

> **Habit:** for managed anti-debug, do not patch the IL if any downstream stage derives keys from the assembly's identity. Instead, neutralise the check at the *debugger* level. dnSpy's "Prevent code from detecting the debugger" options make `Debugger.IsAttached` return false at runtime without modifying a single byte. The assembly stays intact, the token stays valid, and the next stage decrypts correctly.

Turning on those options (plus "Debug files loaded from the process' memory", so breakpoints bind to the in-memory module rather than the disk copy) made the sample run straight into stage 3 with no IL edits at all.

![dnSpy options Prevent code from detecting the debugger](/assets/img/DebuggerPatch.png)

## Stage 2's obfuscation

Stage 2 is obfuscated with ConfuserEx. Method names are pure noise, and Win32 APIs are resolved at runtime from split string fragments (`"Virtual"+"Alloc"`) so they never appear as searchable literals. You cannot grep for them. The trick is to identify the API by its delegate signature instead of its name: a function taking `(address, size, allocationType, protect)` is `VirtualAlloc` no matter what the malware calls it.

Read as a set, the resolved APIs: `OpenProcess` + `VirtualAlloc` + `WriteProcessMemory` + `VirtualProtect` = **process injection**. The presence of `OpenProcess` against a remote process indicates injection into *another* process, which matches Snake's documented behaviour.

> **Habit:** don't analyse injection APIs one at a time. Recognise the quartet as a single behaviour.

## Stage 3: the injector, and finding the payload in memory

With anti-debug handled the clean way, execution flowed into stage 3, `System Optimizer Ultimate`. This stage is also ConfuserEx-obfuscated, and worse, it uses **exception-based control-flow flattening**, where the malware throws and catches framework exceptions as its normal looping mechanism. With dnSpy set to break on thrown exceptions, this looks like the program is crashing constantly; it isn't, it's just the obfuscator's control flow. Unchecking "Thrown" for CLR exceptions silenced the noise and let execution proceed.

Stage 3 turned out to be the injector. Paused inside it, the Locals window showed a local byte array of about 133 KB. Expanding it, the first two bytes were `4D 5A` `MZ`. The surrounding locals were classic injection setup: allocation sizes, an image base of `0x400000`, a dispatcher object. Stage 3 had decrypted an entire PE into memory and was preparing to inject it.

> **Habit:** the loader stages never need the C2. The payload does. Once you see an `MZ` byte array being prepared for injection, that array *is* the real malware.

![Stage 3 Locals showing the MZ byte array of the stage 4 payload](/assets/img/4thStageMz.png)

I right-clicked the byte array, saved it as `stage4.bin`, confirmed it started with `MZ`, and opened it in a fresh dnSpy.

## Stage 4: the actual stealer

`stage4.bin` was the real Snake Keylogger, a VB.NET stealer, internal name `lfwhUWZlmFnGhDYPudAJ.exe`, and obfuscated again with ConfuserEx-style symbol renaming. But this is where FLOSS earns its place. Running it on the dumped payload recovered the string table, and the family showed itself immediately:

- Exfiltration scaffolding for **Telegram** (`/sendMessage?chat_id=`, `&caption=`), **SMTP**, and **FTP**, with build-time placeholder flags like `$%TelegramDv$` and `$%SMTPDV$`.
- Recon endpoints `checkip.dyndns.org` and `https://reallyfreegeoip.org/xml/`.
- Persistence string `software\microsoft\windows\currentversion\run` and a self-delete stub (`/C choice /C Y /N /D Y /T 3 & Del`).
- Browser credential theft across the entire Chromium family (Login Data, Local State `encrypted_key`, AES-GCM via `BCryptDecrypt`) and Gecko family (`nss3.dll`, `PK11SDR_Decrypt`), plus Outlook, Foxmail, and Thunderbird.
- The family's own banner strings: "Snake Tracker" and a `\SnakeKeylogger\` working folder.

The capability picture was complete. But the *live* config, the actual Telegram token or SMTP password was not in the plaintext strings. It sat in a handful of encrypted Base64 blobs.

## The anti-analysis wall, and why the debugger stopped helping

Trying to debug `stage4.bin` directly hit a wall. The payload's static constructor threw a `TypeInitializationException` the instant it loaded. Decompiling the `.cctor` showed why: it enumerates running processes and **kills analysis tools by name**, the hardcoded list includes `wireshark`, `olydbg`, AV products, and dozens more and bails out if it sees an analysis environment. That, combined with the anti-VM and geo-IP checks, meant the sample would reach its initial public-IP lookup and then go silent. On a clean detonation under FakeNet, Wireshark saw the geo-IP DNS request and then nothing; the malware had decided it was being watched and refused to exfiltrate.

![The process-killer list inside the stage 4 static constructor](/assets/img/ProcessKillDetect.png)

## Finding C2 the static way: decrypt the config yourself

The config strings are decrypted by a single helper method. Opening it statically revealed the whole algorithm in plaintext, no need to run anything:

```csharp
public static string Decrypt(string ciphertext, string password)
{
    var md5 = new MD5CryptoServiceProvider();
    var des = new DESCryptoServiceProvider();
    byte[] key = new byte[8];
    byte[] hash = md5.ComputeHash(Encoding.ASCII.GetBytes(password));
    Array.Copy(hash, 0, key, 0, 8);          // DES key = first 8 bytes of MD5(password)
    des.Key = key;
    des.Mode = CipherMode.ECB;
    byte[] data = Convert.FromBase64String(ciphertext);
    return Encoding.ASCII.GetString(
        des.CreateDecryptor().TransformFinalBlock(data, 0, data.Length));
}
```

This is two separate steps:

- **MD5 is doing key derivation, not encryption.** DES needs a key that is exactly 8 bytes. A password string is the wrong size, so the malware hashes the password with MD5 (which always outputs 16 bytes) and takes the first 8 as the DES key. MD5's only job here is turning a password into bytes of the right length.
- **DES-ECB is doing the actual decryption.** DES is a symmetric cipher (same key encrypts and decrypts), and ECB is the simplest mode: each 8-byte block is handled independently, so there is no IV to worry about.
- **Base64 is just transport encoding.** The config is stored as a Base64 string, decoded back to raw encrypted bytes before DES ever runs. It provides no security.

The static constructor showed the password it passes in and the encrypted blobs it decrypts. I reimplemented the routine in Python:

{% raw %}
```python
import hashlib, base64
from Crypto.Cipher import DES

def snake_decrypt(b64, password):
    key = hashlib.md5(password.encode()).digest()[:8]
    raw = base64.b64decode(b64)
    pt = DES.new(key, DES.MODE_ECB).decrypt(raw)
    if pt and 1 <= pt[-1] <= 8: pt = pt[:-pt[-1]]
    return pt.decode('ascii', errors='replace')

pw = "BsrOkyiChvpfhAkipZAxnnChkMGkLnAiZhGMyrnJfULiDGkfTkrTELinhfkLkJrkDExMvkEUCxUkUGr"
print("token  :", snake_decrypt("vRbkGpvjk7mhZGndpGlaNEJ7rPJ4bsBj/cch+D36UinIEiSHgZAIlbK2MJ1N/Fbq", pw))
print("chat_id:", snake_decrypt("3aWu61XQ+VjOd9Y3cmaUzg==", pw))
```
{% endraw %}

Feeding it the encrypted blobs with the password from the static constructor produced:

```
8864131807:AAGKQ9vWQQpOrJtn6M_rFC_3jIHNInWaM2I   <- Telegram bot token
2076143622                                        <- Telegram chat ID
```

Decrypting the config blobs produced a Telegram bot token (<bot_id>:<auth> format) and a numeric chat ID. Combined with the /sendMessage?chat_id= and &caption= strings recovered by FLOSS, this identifies the exfiltration channel as the Telegram Bot API: the standard Snake pattern is a POST to `hxxps://api[.]telegram[.]org/bot<token>/sendMessage`. The token and chat ID are the operator's live destination, recovered statically without running the stealer.

## MITRE ATT&CK Mapping (CAPA)

This sample chains a steganographic loader, an obfuscated injector, and a credential-stealing payload, so the mapping spans the whole chain.

**T1027 - Obfuscated Files or Information:** Stages 2-4 are ConfuserEx-obfuscated with renamed symbols, proxy calls, and control-flow flattening.

**T1027.003 - Steganography:** Stage 1 hides the stage-2 assembly inside the pixel data of the `KILO` image resource, extracted via `ExtractPixelBytes`.

**T1140 - Deobfuscate/Decode Files or Information:** Each stage decrypts the next in memory. Stage 2 uses AES-256-CBC; the stage-4 config uses DES-ECB with an MD5-derived key.

**T1622 - Debugger Evasion:** Multiple stages check `Debugger.IsAttached` and throw. The stage-4 static constructor also terminates if analysis tools are detected.

**T1497.001 - Virtualization/Sandbox Evasion:** The payload enumerates and kills a hardcoded list of analysis and AV process names, and performs geo-IP checks before proceeding.

**T1055 - Process Injection:** Stage 3 resolves the `OpenProcess` / `VirtualAlloc` / `WriteProcessMemory` / `VirtualProtect` quartet and injects the decrypted stage-4 payload.

**T1129 - Shared Modules:** Execution of stage 2 begins in the `<Module>` static constructor rather than a conventional entry point.

**T1547.001 - Registry Run Keys:** Persistence via a Run key under `software\microsoft\windows\currentversion\run`.

**T1070.004 - File Deletion:** A `choice`-timer `cmd.exe` stub self-deletes the dropper.

**T1056.001 - Keylogging, T1113 — Screen Capture, T1115 — Clipboard Data:** The payload captures keystrokes (with `GetForegroundWindow`/`GetWindowText` for window context), screenshots, and clipboard contents.

**T1555.003 - Credentials from Web Browsers:** The payload decrypts saved logins from the Chromium family (AES-GCM via `BCryptDecrypt`) and the Gecko family (`PK11SDR_Decrypt`).

**T1555 - Credentials from Password Stores:** Modules target Outlook, Foxmail, and Thunderbird mail credentials.

**T1614 / T1016 - System Location & Network Configuration Discovery:** Recon via `checkip.dyndns.org` and `reallyfreegeoip.org`.

**T1567.002 - Exfiltration Over Web Service:** This build exfiltrates over the Telegram Bot API. (SMTP and FTP exfiltration paths are also present but unused in this build.)

## Indicators of Compromise

| Indicator | Value | Type |
|---|---|---|
| Sample SHA256 | `2263046083f6f559100f194783e989d27b1a854977324c939734e877aa75a842` | Hash |
| Stage 4 internal name | `lfwhUWZlmFnGhDYPudAJ.exe` | Artifact |
| Exfil channel | Telegram Bot API | TTP |
| Telegram bot token | `8864131807:AAGKQ9vWQQpOrJtn6M_rFC_3jIHNInWaM2I` | C2 credential |
| Telegram chat ID | `2076143622` | C2 destination |
| Recon | `checkip.dyndns.org`, `reallyfreegeoip.org` | Network |
| Persistence | Run key under `...\CurrentVersion\Run` | Registry |
| Config crypto | DES-ECB, key = MD5(password)[:8] | Detection routine |


## Closing thoughts

The satisfying part of this one was not the token at the end. Decrypting the config took a few lines of Python once I had the algorithm. The value was the route there: patching anti-debug the wrong way and breaking the next stage's decryption, drowning in exception-based control flow, fighting a process-killer that bailed the moment it saw my tools.

Here you can find my [YARA](https://github.com/LeRedMojo/ThreatHunting/blob/main/YARA/Malware/SnakeKeyLogger.yar) and [SIGMA](https://github.com/LeRedMojo/ThreatHunting/blob/main/SIGMA/malware/SnakeKeyLogger1.yaml) rule.