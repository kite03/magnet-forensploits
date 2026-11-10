# magnet-exploits

# CVE-2026-106772 (Others pending)

This is a repository documenting my experience discovering and attempting to responsibly disclose a variety of critical issues affecting software created by the digital forensics provider, Magnet Forensics. Magnet's public GitHub account hosts a repository containing a compiled binary for a proprietary software solution they sell, called FasTrak.

The purpose of this software is to provide forensic examiners a tool with which they can extract data from mobile devices that have already been accessed by another tool Magnet provides, GrayKey. From there, the software creates a backup of the full device filesystem, which can then be analysed by a specialised processing tool. I began reverse engineering it to understand how such a tool operates, with no intention of finding any of what is documented later in this report.

This report and accompanying repository assert that the FasTrak software lacks even the most basic security and sanitisation checks. Attackers can freely execute arbitrary system commands with Administrator privileges by simply changing certain device fields. This allows any code they desire to execute when their phone is connected to a computer that has the affected software running and an extraction is started. Because the software is entirely publicly available, it is an ideal target for an attacker. The commands execute silently, meaning a potential examiner would receive no warning that a payload has been executed.

[![Advisory 1 - Android RCE demonstration](assets/demo_adv1.gif)](rce-android-flow/README.md)

Further, this report documents my attempts to disclose these findings to Magnet Forensics privately before going public, and how they opted not to respond to my attempts to reach out, instead choosing to leave multiple unauthenticated remote code execution vulnerabilities in their software for over three months. This has forced me to release these findings publicly, as I have an ethical obligation to disclose these findings for the safety of the examiners and organisations relying on this software, who deserve to know the risk they are exposed to, and in the hope that public attention will prompt the fixes that private disclosure did not. If a serious threat actor were to discover the same flaws, which I emphasise was not difficult, given their simplicity and low complexity, significant damage could be caused for any organisation using this software.

A tool trusted to preserve evidentiary integrity having unauthenticated RCE or key-exposure issues undermines the chain of custody the whole workflow depends on. Because the exploits contained in this repository allow an attacker to take full control of a forensic workstation, they could change evidence files, tamper with their own evidence and potentially all previous evidence collected by the system. This raises serious implications for the integrity of any device the tool has handled and any legal proceeding that relied on it.

My research was conducted entirely as an outsider using only publicly available information. No prior access was required to achieve the results, and no terms of use or conditions were accepted or broken. There was no unauthorised access to any internal Magnet systems or tools outside of what has been left directly publicly available.

## Findings Index

Eight distinct issues are documented, each in its own directory accompanied by a writeup. Each of these vulnerabilities exploits a different mechanism present within the software.

> *Note: The PoC application used to actually demonstrate the vulnerabilities contained within this repository is currently being withheld. This is to hopefully minimise the amount of damage that could be caused by making these findings public.*

| Severity | Adv. | Finding | Weakness class |
|----------|:----:|---------|----------------|
| **Critical** | 1 | [Android RCE - command injection](rce-android-flow/README.md) | **CWE-78** OS Command Injection |
| **Critical** | 2 | [iOS RCE - command injection](rce-ios-flow/README.md) | **CWE-78** OS Command Injection |
| **High** | 3 | [Arbitrary file write - agent log path](arbitrary-file-write/README.md) | **CWE-73** External Control of File Name or Path |
| **High** | 4 | [Path traversal](path-traversal/README.md) | **CWE-22** Path Traversal |
| **High** | 5 | [Agent TLS accepts any certificate](tls-cert-validation/README.md) | **CWE-295** Improper Certificate Validation |
| **Medium–High** | 6 | [Denial of service - unvalidated agent messages](dos-agent-messages/README.md) | **CWE-248 / CWE-400** DoS (via CWE-20) |
| **Medium** | 7 | [Hardcoded credentials & embedded keys](hardcoded-secrets/README.md) | **CWE-798** Use of Hard-coded Credentials |
| **Medium** | 8 | [OAuth callback server - permissive origins](oauth-callback-server/README.md) | **CWE-346 / CWE-942** Origin Validation |

## Part One: Discovery

FasTrak is publicly downloadable without authentication from Magnet Forensics' own GitHub releases. Simply downloading the file from their releases page yields a full compiled copy of the application, and the installed application itself can be run without any login or licence check.

![Magnet FasTrak GitHub Repository](/assets/FasTrak-repo.png)

Following installation, a `/resources/` directory is created inside the FasTrak program folder containing `app.asar`, the packaged application bundle used by Electron/Node.js applications of this kind. Inspecting this archive revealed that it contains JavaScript source-map (`.map`) files alongside the compiled code.

![FasTrak resources folder](/assets/resources-folder.png)

Source maps are used for development-time debugging and are not intended to ship in production builds. Using freely available open-source tooling (in this case, the [reverse-sourcemap](https://github.com/davidkevork/reverse-sourcemap) utility), the entire client-side source code was reconstructed from these maps in its original, unminified form, with no decompilation necessary. The source code even includes comments.

![Source Code Reconstruction Showcase](/assets/reconstruction-showcase.png)

From this point, it was trivial to exploit the vulnerabilities within the software. The code also includes a comment containing the full name of a Magnet Forensics team member. This comment is not reproduced in this report, as even though it is public information, and despite the fact that I have tried to report these issues to the company itself, I do not feel comfortable sharing it in this report.

## Control Flow Chart
Below is a flow chart showcasing the program structure, with all of the vulnerable sections I was able to identify highlighted.

```mermaid
flowchart TD
    START([FasTrak launches])

    subgraph BOOT["Startup (main.ts)"]
      direction TB
      INIT["Configuration.initialize() · loadSettings()"]
      SSL["configureSSL() - load TLS key + cert from auth/<br/>injectFastrakAdbKeys() - swap in shipped ADB keys"]
      WIN["initializeMainWindow() - launch Electron renderer"]
      CMON["ConnectionMonitor.initialize()"]
    end
    START --> INIT --> SSL --> WIN --> CMON

    subgraph RENDER["Renderer (Electron / React)"]
      direction TB
      RAN["useAnalytics() - Datadog RUM + Amplitude init"]
      ROAUTH["OAuth sign-in: login() -> openExternal -> browser<br/>-> deep link / localhost callback server -> processCallback()"]
      RUI["Device list + extraction UI"]
    end
    WIN --> RAN --> RUI
    RAN --> ROAUTH --> RUI

    CMON --> QUERY["queryConnectedDevices() - polls every 1s"]
    QUERY --> ANDQ{"Android device?"}
    QUERY --> IOSQ{"iOS device?"}

    subgraph ANDPATH["Android acquisition"]
      direction TB
      AF["fetchConnectedAndroidDevices()<br/>adb devices -l -> isAlphaNumeric() filter"]
      AP["new AndroidConnection · openPort()<br/>adb -s id forward tcp:port tcp:AGENT_PORT"]
    end
    subgraph IOSPATH["iOS acquisition"]
      direction TB
      IF["fetchConnectedIOSDevices()<br/>idevice_id -l -> isAlphaNumeric() filter"]
      IP["new IOSConnection · openPort()<br/>spawn iproxy -u id ... (shell:true)"]
    end
    ANDQ -->|new id| AF --> AP --> TLS
    IOSQ -->|new id| IF --> IP --> TLS

    TLS["tls.connect(127.0.0.1, rejectUnauthorized:false)<br/>-> send RequestDeviceInformation"]
    AGENT[["On-device agent replies over TLS"]]
    TLS --> AGENT --> HM["DeviceConnection.handleMessage()<br/>socket 'data' -> buffer framing -> switch(type)"]

    HM --> MHELLO["hello: JSON.parse(content)<br/>-> handleRequestDeviceInformation()"]
    MHELLO --> HAND["Android: serial = SerialNumber"]
    MHELLO --> HIOS["iOS: serial = UniqueDeviceID"]
    HAND --> STORE
    HIOS --> STORE
    STORE["store gkserial / evidenceId / examinerName<br/>open agentLogStream (gkserial_serial.log) -> changeHandler()"]
    STORE -.-> RUI

    HM --> MLOG["Log msg -> agentLogStream.write()"]
    HM --> MBYE["Bye -> generateProgressReport()<br/>-> render-report-napi (Typst/Rust) -> PDF"]
    HM --> MREQ["RequestExtraction (from agent)<br/>-> extraction.initialize()"]

    RUI --> ESTART["Examiner starts extraction (IPC)<br/>-> send RequestExtraction to agent"]
    ESTART --> AGENT
    MREQ --> EXQ{"extraction class"}

    subgraph ANDEX["Android extraction"]
      direction TB
      AGDP["getDownloadFilePath() = dir + serial + type + .zip"]
      ASPAWN["spawn(stream_rx.exe, args, shell:true)"]
      AEXIT["on exit: optional keystore (aks) extraction"]
    end
    subgraph IOSEX["iOS extraction"]
      direction TB
      IGDP["getDownloadFilePath() (serial) · sendPings()"]
      ISPAWN["spawn(stream_rx.exe, args, shell:true)"]
      IEXIT["keychain post-proc: execFile PasswordGenerator /<br/>KeyProcessor.exe (shell:true) -> cleanup"]
    end
    EXQ -->|android| AGDP --> ASPAWN --> AEXIT
    EXQ -->|ios| IGDP --> ISPAWN --> IEXIT

    AEXIT --> DONE
    IEXIT --> DONE
    MBYE --> DONE
    DONE["Report PDF written -> optional Axiom / Automate (IPC)"]
    DONE --> EJECT["eject / Bye -> terminateConnection() · kill stream_rx / iproxy"]
    EJECT --> QUIT([App quit: taskkill · restoreSystemAdbKeys])

    A1["Advisory 1 · Android RCE - CWE-78 · Critical"]
    A2["Advisory 2 · iOS RCE - CWE-78 · Critical"]
    A3["Advisory 3 · Arbitrary file write - agent log path - CWE-73 · High"]
    A4["Advisory 4 · Path traversal - CWE-22 · High"]
    A5["Advisory 5 · Agent TLS accepts any certificate - CWE-295 · High"]
    A6["Advisory 6 · DoS - unvalidated agent messages - CWE-248 / CWE-400 · Medium-High"]
    A7["Advisory 7 · Hardcoded credentials and embedded keys - CWE-798 · Medium"]
    A8["Advisory 8 · OAuth callback server - permissive origins - CWE-346 / CWE-942 · Medium"]

    A1 -.-> ASPAWN
    A2 -.-> ISPAWN
    A3 -.-> STORE
    A4 -.-> AGDP
    A4 -.-> IGDP
    A5 -.-> TLS
    A6 -.-> HM
    A7 -.-> SSL
    A8 -.-> ROAUTH

    classDef crit fill:#7f1d1d,stroke:#ef4444,color:#fecaca
    classDef high fill:#9a3412,stroke:#f97316,color:#fed7aa
    classDef med fill:#854d0e,stroke:#eab308,color:#fde68a

    class A1,A2,ASPAWN,ISPAWN crit
    class A3,A4,A5,A6,AGDP,IGDP,TLS,HM,STORE high
    class A7,A8,SSL,ROAUTH med
```

## Disclosure Timeline
As soon as I found all of this, I contacted Magnet directly through their official support email. I didn't attach a report as I hadn't yet compiled my findings into a single document; my plan was simply to show them the vulnerable function code so they could deal with it as quickly as possible. I didn't ask for or expect money, or compensation of any kind.

![My first disclosure attempt](assets/disclosure-1.png)

I sent this email on the 2nd of August 2026. I know it arrived, because I received an automated confirmation saying that a ticket had been created and that they would be in touch soon.

After a couple of weeks of silence, on the 17th of August 2026, I sent a short follow-up, assuming the first email had simply been overlooked.

![My follow-up to the first email](assets/disclosure-2.png)

That went unanswered too. On the 13th of September 2026, I made one final attempt by email. Around the same time, I also filed for a CVE for one of the findings.

![My final email attempt at responsible disclosure](assets/disclosure-3.png)

That left me considering a simpler explanation: that my emails were being caught by some kind of spam filter. To rule this out, I signed up for an account on their website and raised a ticket from there. I had avoided doing this sooner because registration required my phone number, which could very easily deanonymise me. On the 8th of October 2026 I submitted this ticket.

![My support ticket](assets/disclosure-4.png)

The ticket describes my final email as telling them that I had already filed for a CVE; that email only warned that I would consider filing one.

I also raised a ticket with CERT/CC through VINCE on the 13th of October 2026. They replied, but could not get into contact with Magnet either, and this public disclosure has been co-ordinated with them.

![FasTrak source excerpt](assets/youre-winner.png)
