# CHAPS Remediation Guide

This document provides per-check remediation guidance for negative findings in a CHAPS report. For each check that can produce a `[-]` result, it describes what the finding means, why it matters, and how to fix it.

Entries are grouped by report section and ordered by check number to match the report layout. For the full check catalog, see [CHECKS.md](CHECKS.md). For interpreting report output, see [INTERPRETING_REPORTS.md](INTERPRETING_REPORTS.md).

**Important.** All remediations below modify system or security configuration. Validate each change in a non-production environment first, especially on ICS / OT systems where legacy applications may depend on weak settings (SMBv1, NTLMv1, old TLS, etc.). Coordinate with system and application owners before making changes on production systems.

## How to Apply Remediations

Three common mechanisms appear below:

- **Registry edits** (via `regedit.exe`, `reg add` from CMD, or `Set-ItemProperty` from PowerShell). Registry edits apply at the next reboot or immediately depending on the setting.
- **Group Policy** (via `gpedit.msc` local policy or a domain GPO). Preferred for managed environments because the policy is refreshed automatically.
- **Service / feature commands** (via `Set-Service`, `Disable-WindowsOptionalFeature`, `Set-SmbServerConfiguration`). Take effect immediately.

Where both a Group Policy path and a registry key are given, use the GPO in managed environments. Registry edits are the fallback for standalone systems.

---

## Section 1 — System Info Checks

### Check 4 — Auto Update Configuration

**Finding:** `[-] Windows AutoUpdate is not configured to automatically install updates`

**Why it matters:** Systems that do not install security updates remain vulnerable to publicly documented exploits.

**Remediate:**
- GPO: `Computer Configuration\Administrative Templates\Windows Components\Windows Update\Configure Automatic Updates` → **Enabled**, option **4 — Auto download and schedule the install**.
- Registry: `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU!AUOptions` = `4` (DWORD).

**ICS note:** Patching schedules for OT systems typically follow a maintenance window. Set `AUOptions=4` and configure the install schedule, or use WSUS to stage approved patches.

### Check 6 — BitLocker

**Finding:** `[-] BitLocker not detected on Operating System Volume or encryption is not complete`

**Why it matters:** Without full-disk encryption, a stolen or improperly disposed drive exposes all data.

**Remediate:**
- Enable the BitLocker feature: `Enable-WindowsOptionalFeature -Online -FeatureName BitLocker-All`.
- Enable BitLocker on the OS volume with a TPM: `Enable-BitLocker -MountPoint "C:" -TpmProtector`.
- Wait for encryption to complete: `Get-BitLockerVolume -MountPoint "C:"`.

Server editions require explicit installation of the BitLocker feature.

### Check 7 — AlwaysInstallElevated

**Finding:** `[-] Users can install software as NT AUTHORITY\SYSTEM`

**Why it matters:** With both the HKLM and HKCU `AlwaysInstallElevated` keys set to 1, any user can craft an MSI that runs as SYSTEM — trivial local privilege escalation.

**Remediate:** Remove or set to 0 both of:
- `HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer!AlwaysInstallElevated`
- `HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer!AlwaysInstallElevated`

GPO path: `Computer Configuration → Administrative Templates → Windows Components → Windows Installer → Always install with elevated privileges` → **Disabled**, AND the same under `User Configuration`.

### Check 8 — EMET / Exploit Protection

**Finding (Windows 10+):** `[-] System-wide DEP / ASLR / CFG not enabled`

**Why it matters:** DEP, ASLR, and Control Flow Guard are foundational exploit mitigations.

**Remediate:** Use `Set-ProcessMitigation -System -Enable DEP,SEHOP,BottomUp,ForceRelocateImages,CFG`. Default Windows 10+ configuration enables these; a negative finding suggests a security policy has disabled them.

### Check 9 — LAPS

**Finding:** `[-] Local Administrator Password Solution (LAPS) is not installed`

**Why it matters:** Without LAPS, local Administrator passwords tend to be identical across systems or not rotated, enabling lateral movement.

**Remediate:** Deploy Windows LAPS (built into Windows 10 21H2+ and Server 2019+) or legacy LAPS. See [Microsoft Windows LAPS documentation](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview).

### Check 10 — GPO Reprocessing

**Finding:** `[-] GPO settings are configured to only be applied after change`

**Why it matters:** If GPOs only reapply on change, locally-made changes that contradict policy persist until the next policy edit.

**Remediate:** Set `HKLM\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}!NoGPOListChanges` = `0`. GPO path: `Computer Configuration → Administrative Templates → System → Group Policy → Registry policy processing` → **Enabled**, and tick **Process even if the Group Policy objects have not changed**.

### Check 11 — Net Session Enumeration

**Finding:** `[-] SrvsvcSessionInfo registry key is not configured (Net Session Enumeration may be unrestricted)`

**Why it matters:** Unauthenticated users can enumerate active sessions, aiding reconnaissance and AD enumeration tools.

**Remediate:** Apply the "Net Cease" hardening — restrict the DefaultSecurity SDDL on `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity!SrvsvcSessionInfo` to exclude `Authenticated Users`. See [Net Cease hardening](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-restrict-clients-allowed-to-make-remote-sam-calls).

Additionally set `HKLM\SYSTEM\CurrentControlSet\Control\Lsa!RestrictRemoteSAM` to the SDDL that permits only specific administrator groups.

### Check 12 — AppLocker

**Finding:** `[-] AppLocker not configured to manage PowerShell scripts`

**Why it matters:** Without application allowlisting, unauthorized executables and scripts can run unchecked.

**Remediate:** Configure AppLocker rules via `Secpol.msc → Application Control Policies → AppLocker`. At a minimum, define rule collections for **Executable rules** and **Script rules**. In high-security environments prefer **Windows Defender Application Control (WDAC)** over AppLocker.

### Check 13 — Credential Guard / Device Guard

**Finding:** `[-] Credential Guard or HVCI service is not running`

**Why it matters:** Credential Guard isolates LSASS secrets in VBS, blocking Mimikatz-class credential theft.

**Remediate:** Requires UEFI, Secure Boot, TPM 2.0, and VBS-capable CPU. GPO path: `Computer Configuration → Administrative Templates → System → Device Guard → Turn On Virtualization Based Security` → **Enabled**, Credential Guard Configuration → **Enabled with UEFI lock**.

Validate with `msinfo32` (look for "Virtualization-based security: Running" and "Credential Guard: Running").

### Check 14 — MS Office Macros

**Finding:** `[-] Office <ver> <app> VBAWarnings is not set to restrict macros`

**Why it matters:** Macro-borne malware remains a top initial-access vector.

**Remediate:**
- Registry per app: `HKCU\Software\Microsoft\Office\<ver>\<app>\Security!VBAWarnings` = `3` (disable all except digitally signed) or `4` (disable all).
- Also set `BlockContentExecutionFromInternet` = `1` to block macros originating from internet-sourced files.
- GPO: deploy the Office ADMX templates and configure macro security under `User Configuration → Administrative Templates → Microsoft <App> <ver> → <App> Options → Security → Trust Center`.

### Check 15 — Sysmon

**Finding:** `[-] No Sysmon service detected. Consider deploying Sysmon for endpoint visibility.`

**Why it matters:** Sysmon provides granular process, network, and file event logging far beyond default Windows audit.

**Remediate:** Download Sysmon from [Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) and install with a vetted configuration:
```
Sysmon64.exe -accepteula -i <path-to-config.xml>
```
Curated configs include [SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config) and [Olaf Hartong's sysmon-modular](https://github.com/olafhartong/sysmon-modular). For ICS systems, ensure the config does not generate excessive events for industrial protocol traffic.

### Check 17 — Antivirus / EDR

**Finding:** `[-] Windows Defender Antivirus is not enabled` or `[-] <AV> definitions may be out of date`

**Why it matters:** No active antivirus means no runtime protection against known malware.

**Remediate:** Enable Windows Defender via `Set-MpPreference -DisableRealtimeMonitoring $false` (or deploy a third-party AV/EDR). Update signatures via `Update-MpSignature` or vendor-specific channels.

### Check 19 — UAC Configuration

**Finding:** `[-] UAC is disabled (EnableLUA: 0)` or `[-] UAC admin prompt may not be secure`

**Why it matters:** UAC is the primary defense against silent elevation. Disabled UAC means any process running as an admin user runs with full token.

**Remediate:**
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System!EnableLUA` = `1`
- `!ConsentPromptBehaviorAdmin` = `2` (prompt for consent on secure desktop)
- `!PromptOnSecureDesktop` = `1`
- `!FilterAdministratorToken` = `1` on sensitive systems
- GPO: `Computer Configuration → Windows Settings → Security Settings → Local Policies → Security Options → User Account Control: *`

Reboot required for `EnableLUA` changes.

### Check 20 — Account Policies

**Findings:**
- `[-] Account lockout threshold is not configured: Never`
- `[-] Minimum password length is too short: <n>`
- `[-] Guest account is enabled`
- `[-] Built-in Administrator account has not been renamed`

**Why it matters:** Weak or missing account policies enable password-spray attacks and unauthorized access via well-known accounts.

**Remediate:**
- `net accounts /lockoutthreshold:5 /lockoutduration:15 /minpwlen:14`
- Disable Guest: `net user Guest /active:no`
- Rename built-in Administrator (via `lusrmgr.msc` or GPO `Computer Configuration → Windows Settings → Security Settings → Local Policies → Security Options → Accounts: Rename administrator account`).

### Check 21 — Secure Boot

**Finding:** `[-] Secure Boot is not enabled`

**Why it matters:** Secure Boot prevents pre-OS malware (bootkits) by refusing to load unsigned boot code.

**Remediate:** Enable Secure Boot in UEFI firmware settings. Requires the disk to be GPT-partitioned and Windows installed in UEFI mode. Converting BIOS → UEFI may require `mbr2gpt.exe` and should be tested.

### Check 22 — LSA Protection

**Finding:** `[-] LSA Protection (RunAsPPL) is not enabled`

**Why it matters:** LSA Protection prevents non-protected processes from reading LSASS memory, blocking Mimikatz-class credential theft.

**Remediate:**
- `HKLM\SYSTEM\CurrentControlSet\Control\Lsa!RunAsPPL` = `1` (or `2` for UEFI lock on Windows 11 22H2+).
- Reboot required.
- On first boot after enabling, check Event Viewer → Windows Logs → System for LSA errors from drivers that cannot run as protected. Disable incompatible drivers or leave RunAsPPL off on that system.

### Check 23 — Risky Services

**Finding:** `[-] <service> service is RUNNING. Evaluate whether this service is needed.`

**Why it matters:** Each of these services is an attack surface:
- **Print Spooler** — PrintNightmare (CVE-2021-34527)
- **Remote Registry** — remote registry enumeration
- **SNMP** — community string enumeration
- **Telnet Server** — unencrypted remote shell
- **Remote Access** — routing/VPN services
- **.NET TCP Port Sharing** — WCF port sharing
- **Internet Connection Sharing** — network bridging

**Remediate:** Disable unneeded services:
```powershell
Stop-Service -Name Spooler -Force
Set-Service -Name Spooler -StartupType Disabled
```
Repeat for each unneeded service. **Always confirm the service is unused** before disabling: Print Spooler is required on any system that prints; SNMP is required where the monitoring system polls it.

---

## Section 2 — Security Checks

### Check 24 — SMB Server Configuration

**Findings:**
- `[-] SMBv1 is Enabled`
- `[-] SMBv1 Auditing is Disabled`
- `[-] SMB Server Require Security Signature is Disabled`
- `[-] SMB Server Encryption (EncryptData) is Disabled`

**Why it matters:** SMBv1 is obsolete and vulnerable (WannaCry / EternalBlue). SMB signing and encryption prevent relay and tampering attacks.

**Remediate:**
```powershell
# Disable SMBv1 server
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force

# Enable SMBv1 auditing (to catch clients that still try to use it)
Set-SmbServerConfiguration -AuditSmb1Access $true -Force

# Require signing
Set-SmbServerConfiguration -RequireSecuritySignature $true -Force

# Require encryption (SMB 3.x, Windows 8/Server 2012+)
Set-SmbServerConfiguration -EncryptData $true -Force
```
ICS note: Some legacy HMI or PLC vendor systems communicate using SMBv1. Audit first; disable only after confirming nothing depends on it.

### Check 25 — Anonymous Enumeration

**Findings:**
- `[-] RestrictAnonymous registry key is not configured`
- `[-] RestrictAnonymoussam registry key is not configured`

**Why it matters:** Anonymous SMB/SAM enumeration leaks user, group, and share information.

**Remediate:**
- `HKLM\SYSTEM\CurrentControlSet\Control\Lsa!RestrictAnonymous` = `1`
- `HKLM\SYSTEM\CurrentControlSet\Control\Lsa!RestrictAnonymousSAM` = `1`
- GPO: `Computer Configuration → Windows Settings → Security Settings → Local Policies → Security Options → Network access: Do not allow anonymous enumeration of SAM accounts and shares` → **Enabled**.

### Check 26 — Untrusted Fonts (Windows 10+)

**Finding:** `[-] Kernel MitigationOptions key is configured not to block`

**Why it matters:** Blocks untrusted font loading by kernel mode, mitigating certain exploit paths.

**Remediate:** `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel!MitigationOptions` — set the appropriate hex bitmask for font blocking. See [Block untrusted fonts](https://docs.microsoft.com/en-us/windows/security/threat-protection/block-untrusted-fonts-in-enterprise).

### Check 27 — ASR Rules

**Finding:** `[-] No Attack Surface Reduction rules configured.` (or `[-] ASR Rule <GUID>: Disabled`)

**Why it matters:** ASR rules block common attack techniques (Office macro child processes, credential theft from LSASS, obfuscated scripts).

**Remediate:** Configure ASR via `Set-MpPreference`:
```powershell
# Example: enable "Block credential stealing from the Windows local security authority subsystem"
Set-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 `
                 -AttackSurfaceReductionRules_Actions Enabled
```
See [ASR rules reference](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference) for the full list of GUIDs and actions.

### Check 28 — SMB Client Signing

**Findings:**
- `[-] SMB Client Require Security Signature is Disabled`
- `[-] SMB Client Enable Security Signature is Disabled`

**Why it matters:** SMB client signing prevents relay attacks against the client.

**Remediate:**
- `HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters!RequireSecuritySignature` = `1`
- `!EnableSecuritySignature` = `1`
- GPO: `Computer Configuration → Windows Settings → Security Settings → Local Policies → Security Options → Microsoft network client: Digitally sign communications (always)` → **Enabled**.

### Check 29 — TLS/SSL Protocol Configuration

**Finding:** `[-] <proto> Server is enabled (should be disabled)` — for SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1

**Why it matters:** Deprecated TLS/SSL protocols have known cryptographic weaknesses (POODLE, BEAST, etc.).

**Remediate:** Under `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\<proto>\Server`:
- Disable: `Enabled` = `0` (DWORD), `DisabledByDefault` = `1` (DWORD)
- Enable (for TLS 1.2 / 1.3): `Enabled` = `1`, `DisabledByDefault` = `0`

Also disable client-side by repeating under `\Client`. Reboot required. Test server-side applications (e.g., IIS, SQL Server, WSUS) for compatibility before disabling TLS 1.0/1.1 on production.

### Check 30 — Audit Policy

**Finding:** `[-] Audit policy for <subcategory>: No Auditing`

**Why it matters:** Without audit events, forensic investigation and detection are impossible.

**Remediate:**
```cmd
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable
auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable
```
For domain-managed systems, configure via GPO: `Computer Configuration → Windows Settings → Security Settings → Advanced Audit Policy Configuration`. See [Microsoft's recommended audit policy](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations).

---

## Section 3 — Authentication Checks

### Check 31 — RDP Deny

**Findings:**
- `[-] AllowRemoteRPC should be disabled to deny RDP: 1`
- `[-] fDenyTSConnections should be set to not allow remote connections: 0`

**Why it matters:** If RDP is not intended for this system, any exposure is unnecessary attack surface.

**Remediate:**
- To deny RDP entirely: `HKLM\System\CurrentControlSet\Control\Terminal Server!fDenyTSConnections` = `1`.
- Also set `!AllowRemoteRPC` = `0`.
- GPO: `Computer Configuration → Administrative Templates → Windows Components → Remote Desktop Services → Remote Desktop Session Host → Connections → Allow users to connect remotely by using Remote Desktop Services` → **Disabled**.

### Check 32 — Local Administrators

**Finding:** `[-] More than one account is in local Administrators group`

**Why it matters:** Multiple local admins mean more account compromise paths and harder accountability.

**Remediate:** Review membership (`net localgroup Administrators`). Remove service/user accounts that do not need local admin. Where domain admin access is needed, use a dedicated admin account or Just-In-Time (JIT) access via tools like PAM.

### Check 33 — NTLM Session Security

**Findings:**
- `[-] NtlmMinServerSec not configured. Recommend 0x20080030.`
- `[-] NtlmMinClientSec not configured. Recommend 0x20080030.`

**Why it matters:** `0x20080030` enforces NTLMv2 session security plus 128-bit encryption. Lower values allow weak protocols in the NTLM handshake.

**Remediate:**
- `HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0!NtlmMinServerSec` = `0x20080030` (DWORD).
- `!NtlmMinClientSec` = `0x20080030`.
- GPO: `Security Options → Network security: Minimum session security for NTLM SSP based (including secure RPC) <servers/clients>` → **Require NTLMv2 session security**, **Require 128-bit encryption**.

### Check 34 — LAN Manager Authentication

**Findings:**
- `[-] LmCompatibilityLevel not configured. Default may allow LM/NTLM.`
- `[-] NoLmHash registry key is not configured`

**Why it matters:** LM hashes are trivially crackable. LMCompatibilityLevel 5 refuses both LM and NTLMv1 entirely.

**Remediate:**
- `HKLM\System\CurrentControlSet\Control\Lsa!LmCompatibilityLevel` = `5`
- `HKLM\System\CurrentControlSet\Control\Lsa!NoLmHash` = `1`
- GPO: `Security Options → Network security: LAN Manager authentication level` → **Send NTLMv2 response only. Refuse LM & NTLM**.

### Check 35 — Cached Logons

**Finding:** `[-] CachedLogonsCount Is Not Set to 0 or 1`

**Why it matters:** Cached logon credentials can be extracted by an attacker with SYSTEM access and used for offline cracking.

**Remediate:**
- `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon!CachedLogonsCount` = `0` or `1` (REG_SZ containing `"0"` or `"1"`).
- Setting to 0 means no cached logons; users cannot authenticate if the domain is unreachable. Setting to 1 allows one cached logon. Choose based on the system's role.

### Check 36 — Interactive Login (LocalAccountTokenFilterPolicy)

**Finding:** `[-] LocalAccountTokenFilterPolicy Is Set`

**Why it matters:** When set to 1, this key disables remote UAC filtering — local admin accounts receive a full admin token over the network, enabling pass-the-hash.

**Remediate:**
- Remove or set to 0: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\system!LocalAccountTokenFilterPolicy`.
- Do the same in `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\policies\system` on 64-bit systems.

### Check 37 — WDigest

**Finding:** `[-] WDigest UseLogonCredential key is Enabled`

**Why it matters:** When enabled, WDigest caches cleartext passwords in LSASS memory — trivial extraction with Mimikatz.

**Remediate:** `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest!UseLogonCredential` = `0`. Disabled by default on Windows 8.1+ / Server 2012 R2+. An explicit `1` value means someone turned it back on and should be investigated.

### Check 38 — Restrict RPC Clients

**Finding:** `[-] RestrictRemoteClients registry key is not configured`

**Why it matters:** Restricts unauthenticated RPC clients, reducing attack surface.

**Remediate:** `HKLM\Software\Policies\Microsoft\Windows NT\Rpc!RestrictRemoteClients` = `1` (authenticated). GPO: `Computer Configuration → Administrative Templates → System → Remote Procedure Call → Restrict Unauthenticated RPC clients` → **Enabled**, **Authenticated**.

### Check 39 — RDP Network Level Authentication

**Findings:**
- `[-] RDP Network Level Authentication (NLA) is not required`
- `[-] RDP minimum encryption level is below High`

**Why it matters:** Without NLA, an attacker can exhaust resources or exploit pre-auth vulnerabilities (e.g., BlueKeep). Weak RDP encryption allows session interception.

**Remediate:**
- `HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp!UserAuthentication` = `1`
- `!MinEncryptionLevel` = `3` (High) or `4` (FIPS)
- GPO: `Computer Configuration → Administrative Templates → Windows Components → Remote Desktop Services → Remote Desktop Session Host → Security → Require user authentication for remote connections by using Network Level Authentication` → **Enabled**.

---

## Section 4 — Network Checks

### Check 41 — IPv6 Interfaces

**Finding:** `[-] Host IPv6 network interface assigned`

**Why it matters:** Unused IPv6 on a network without IPv6 monitoring creates a blind spot for DHCPv6 and router advertisement attacks.

**Remediate:** If IPv6 is not used in the environment, disable it on the adapter:
```powershell
Disable-NetAdapterBinding -Name "<adapter>" -ComponentID ms_tcpip6
```
If IPv6 is used, ensure monitoring covers IPv6 and accept the finding.

### Check 42 — WPAD

**Findings:**
- `[-] No WPAD entry detected. Should contain: wpad 255.255.255.255`
- `[-] WpadOverride registry key is configured to allow WPAD`
- `[-] WinHttpAutoProxySvc service is: Running`
- `[-] KB3165191 to harden WPAD is not installed`

**Why it matters:** Windows auto-discovers proxies via WPAD, vulnerable to LLMNR/NBNS spoofing for credential theft.

**Remediate:**
- Add `255.255.255.255 wpad` to `%SystemRoot%\System32\drivers\etc\hosts` (or block wpad DNS resolution at the DNS server).
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad!WpadOverride` = `1`.
- Disable the service: `Set-Service -Name WinHttpAutoProxySvc -StartupType Disabled` then `Stop-Service`.
- Apply KB3165191 (or a superseding cumulative update).

### Check 43 — WINS Configuration

**Findings:**
- `[-] DNSEnabledForWINSResolution is enabled`
- `[-] WINSEnableLMHostsLookup is enabled`

**Why it matters:** WINS and LMHosts lookup are legacy broadcast/resolution mechanisms exposed to poisoning attacks.

**Remediate:** On each network adapter (via adapter properties or registry): disable both. Via `netsh`:
```cmd
netsh interface ipv4 set dnsservers "<adapter>" source=dhcp
```
And in the adapter's TCP/IP → Advanced → WINS tab, uncheck both.

### Check 44 — LLMNR

**Finding:** `[-] DNSClient.EnableMulticast does not exist or is enabled`

**Why it matters:** LLMNR is spoofable on local networks, enabling credential theft.

**Remediate:** `HKLM\Software\policies\Microsoft\Windows NT\DNSClient!EnableMulticast` = `0`. GPO: `Computer Configuration → Administrative Templates → Network → DNS Client → Turn off multicast name resolution` → **Enabled**.

### Check 45 — Computer Browser Service

**Finding:** `[-] Computer Browser service is: Running`

**Why it matters:** Legacy NetBIOS browsing service, no longer needed on modern networks, and a known enumeration vector.

**Remediate:**
```powershell
Stop-Service -Name Browser -Force
Set-Service -Name Browser -StartupType Disabled
```

### Check 46 — NetBIOS over TCP/IP

**Finding:** `[-] NetBios is Enabled: <value>`

**Why it matters:** NetBIOS name service is spoofable (NBT-NS poisoning).

**Remediate:** Per adapter, set `HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_<GUID>!NetbiosOptions` = `2` (disable NetBIOS over TCP/IP). Can also be set on a DHCP server as a scope option, or in the adapter properties → TCP/IPv4 → Advanced → WINS → Disable NetBIOS over TCP/IP.

### Check 49 — TCP/IP Stack Hardening

**Findings:**
- `[-] IP source routing is not fully disabled`
- `[-] ICMP redirects are enabled`
- `[-] IRDP router discovery is enabled`

**Why it matters:** These legacy features allow attackers on the same network to redirect traffic.

**Remediate:** Under `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`:
- `!DisableIPSourceRouting` = `2` (highest protection)
- `!EnableICMPRedirect` = `0`
- `!PerformRouterDiscovery` = `0`

---

## Section 5 — PowerShell Checks

### Check 50 — PowerShell Versions

**Finding:** `[-] Current PowerShell Version is less than Version 5` or `[-] PowerShell Version 2 should be disabled`

**Why it matters:** PSv2 lacks the logging features of PSv5+ (script block logging, module logging) and is a documented downgrade attack vector.

**Remediate:** Disable the v2 engine:
```powershell
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2,MicrosoftWindowsPowerShellV2Root
```
Also uninstall .NET Framework 2.0/3.5 if no applications require it.

### Check 51 — PowerShell Language Mode

**Finding:** `[-] Execution Language Mode Is Not ConstrainedLanguage`

**Why it matters:** Full Language mode allows arbitrary .NET invocation from PowerShell, aiding malware.

**Remediate:** Configure AppLocker or WDAC in enforcement mode — PowerShell automatically switches to ConstrainedLanguage when a script-control policy is active. Manually setting `$ExecutionContext.SessionState.LanguageMode` is not durable.

### Checks 52, 53, 54, 55 — PowerShell Logging

**Findings:**
- `[-] EnableModuleLogging Is Not Set`
- `[-] EnableScriptBlockLogging Is Not Set`
- `[-] EnableTranscripting Is Not Set`
- `[-] EnableProtectedEventLogging Is Not Set`

**Why it matters:** PowerShell logging is the primary source of visibility into script-borne attacks.

**Remediate:** GPO path: `Computer Configuration → Administrative Templates → Windows Components → Windows PowerShell`:
- **Turn on Module Logging** → Enabled, Modules = `*`
- **Turn on PowerShell Script Block Logging** → Enabled (tick "Log script block invocation start / stop events" for deep logging)
- **Turn on PowerShell Transcription** → Enabled, specify an `OutputDirectory`
- **Turn on Protected Event Logging** → Enabled with a certificate for encryption

Equivalent registry keys under `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\*`.

### Check 56 — WinRM

**Findings:**
- `[-] WinRM Services is running and may be accepting connections`
- `[-] WinRM Firewall Rule <name> is enabled`

**Why it matters:** WinRM enables remote command execution; if not intentionally used, it's attack surface.

**Remediate:** If WinRM is not needed:
```powershell
Disable-PSRemoting -Force
Stop-Service -Name WinRM
Set-Service -Name WinRM -StartupType Disabled
Disable-NetFirewallRule -DisplayName "Windows Remote Management (HTTP-In)"
```
If WinRM is needed, restrict via:
- TrustedHosts: `Set-Item WSMan:\localhost\Client\TrustedHosts -Value <list>`
- IPsec policies or firewall rules limiting source IPs
- HTTPS-only listener with a real certificate

---

## Section 6 — Logging Checks

### Check 57 — Event Log Sizes

**Finding:** `[-] <log> max log size is smaller than <N> GB: <actual> GB`

**Why it matters:** Small log sizes roll over quickly, losing forensic evidence within hours or days.

**Remediate:** Via `wevtutil` (per log):
```cmd
wevtutil sl "Security" /ms:4294967296
```
(that's 4 GB in bytes). Or GPO: `Computer Configuration → Administrative Templates → Windows Components → Event Log Service → <Log> → Specify the maximum log file size (KB)`.

Recommended thresholds (from CHAPS defaults):
- Application, System, Security, Windows PowerShell: **≥ 4 GB**
- Operational logs (PowerShell, TerminalServices, TaskScheduler, SMBServer/Audit, Security-Netlogon, WinRM, WMI-Activity): **≥ 1 GB**

Also configure log forwarding (Windows Event Forwarding, Splunk/Elastic agent, Sysmon channel forwarding) so events survive even if local logs roll.

### Check 58 — Command-Line Auditing

**Finding:** `[-] ProcessCreationIncludeCmdLine_Enabled Is Not Set`

**Why it matters:** Without command-line auditing, process creation events (Event ID 4688) lack the command line, making malicious command reconstruction much harder.

**Remediate:** `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit!ProcessCreationIncludeCmdLine_Enabled` = `1`. GPO: `Computer Configuration → Administrative Templates → System → Audit Process Creation → Include command line in process creation events` → **Enabled**.

Also ensure **Process Creation** is audited under Advanced Audit Policy (see Check 30).

### Check 59 — Windows Script Host

**Findings:**
- `[-] WSH Setting Enabled key is Enabled`
- `[-] KB2871997 is not installed`

**Why it matters:** WSH (VBScript, JScript) is a common malware execution environment. KB2871997 hardens credential caching.

**Remediate:**
- Disable WSH: `HKLM\Software\Microsoft\Windows Script Host\Settings!Enabled` = `0` (DWORD).
- Install current Windows cumulative updates (which include KB2871997 or its successor).

---

## Remediation Priority

When the remediation backlog is long, apply fixes roughly in this priority order:

1. **Credential-theft vectors** — WDigest, LSA Protection, Cached Logons, NTLM session security, LocalAccountTokenFilterPolicy.
2. **Logging and visibility** — PowerShell logging (all four), Command-line auditing, Audit Policy, Event log sizes.
3. **Protocol hardening** — SMBv1, TLS/SSL, LAN Manager authentication, NTLM levels.
4. **Attack-surface reduction** — Risky services, RDP/WinRM configuration, LLMNR/NBNS/WPAD.
5. **OS-level exploit mitigations** — UAC, LSA Protection, Secure Boot, Credential/Device Guard, ASR Rules, AppLocker/WDAC.
6. **Compliance / account hygiene** — Account lockout, password policy, Guest account, Administrator rename, local admin count.
7. **Infrastructure** — BitLocker, Auto Update, Office macros, USB device review.

Prioritize credential-theft and logging first: those provide both hardening and the visibility to detect when attacks do land.
