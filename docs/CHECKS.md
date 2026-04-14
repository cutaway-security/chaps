# CHAPS Check Catalog

CHAPS performs 59 checks in a fixed canonical order across all three scripts. This document lists every check, organized by the six output sections, with a brief description of what each check verifies.

For remediation guidance when a check comes back negative, see [REMEDIATION.md](REMEDIATION.md).
For how to read the report output, see [INTERPRETING_REPORTS.md](INTERPRETING_REPORTS.md).

## Section 1 — System Info Checks (23 checks)

| # | Check | Verifies |
|---|---|---|
| 1 | System Information | OS name, version, build, architecture, workgroup |
| 2 | Windows Version | Short OS version string |
| 3 | User PATH | Current user's `PATH` environment variable |
| 4 | Auto Update Configuration | `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU!AUOptions` — should be 4 (scheduled install) |
| 5 | Missing / Installed Patches | Inventory of installed hotfixes; PSv3/v2 also query Microsoft Update for missing critical/important patches |
| 6 | BitLocker | Operating system volume encryption status |
| 7 | AlwaysInstallElevated | HKLM + HKCU `SOFTWARE\Policies\Microsoft\Windows\Installer!AlwaysInstallElevated` — should not both be 1 |
| 8 | EMET / Exploit Protection | Legacy EMET service on older Windows; system-wide DEP / ASLR / CFG on Windows 10+ |
| 9 | LAPS | Windows LAPS policy and/or legacy LAPS (`AdmPwd.dll`) presence |
| 10 | GPO Reprocessing | `NoGPOListChanges` under the GP `{35378EAC-...}` key — should be 0 (reapply on refresh) |
| 11 | Net Session Enumeration | `SrvsvcSessionInfo` DefaultSecurity and `RestrictRemoteSAM` registry keys |
| 12 | AppLocker | AppLocker policy configuration (CMD: info-only, requires PowerShell) |
| 13 | Credential Guard / Device Guard | `Win32_DeviceGuard.SecurityServicesConfigured` and `SecurityServicesRunning` |
| 14 | MS Office Macros | `HKCU\Software\Microsoft\Office\<ver>\<app>\Security!VBAWarnings` and `BlockContentExecutionFromInternet` |
| 15 | Sysmon | Sysmon service (Sysmon, Sysmon64, SysmonDrv) presence and status |
| 16 | USB Devices | Connected USB and PnP devices inventory |
| 17 | Antivirus / EDR | `root\SecurityCenter2.AntiVirusProduct` on workstations; `Get-MpComputerStatus` fallback on servers |
| 18 | Software Inventory | Installed programs from `HKLM\...\Uninstall` (avoids slow `Win32_Product`) |
| 19 | UAC Configuration | `EnableLUA`, `ConsentPromptBehaviorAdmin`, `PromptOnSecureDesktop`, `FilterAdministratorToken` |
| 20 | Account Policies | `net accounts` output (password policy, lockout threshold); Guest account status; Administrator account rename |
| 21 | Secure Boot | UEFI Secure Boot state via `Confirm-SecureBootUEFI` or `HKLM\SYSTEM\...\SecureBoot\State!UEFISecureBootEnabled` |
| 22 | LSA Protection | `HKLM\SYSTEM\CurrentControlSet\Control\Lsa!RunAsPPL` — should be 1 (or 2 with UEFI lock) |
| 23 | Risky Services | Print Spooler, Remote Registry, SNMP, Telnet, Remote Access, .NET TCP Port Sharing, Internet Connection Sharing — should be disabled where not required |

## Section 2 — Security Checks (7 checks)

| # | Check | Verifies |
|---|---|---|
| 24 | SMB Server Configuration | SMBv1 disabled, SMBv1 auditing, SMBv2/v3 state, server signing, encryption, reject unencrypted |
| 25 | Anonymous Enumeration | `HKLM\System\CurrentControlSet\Control\Lsa` — `RestrictAnonymous` and `RestrictAnonymousSAM` |
| 26 | Untrusted Fonts | `HKLM\...\Session Manager\Kernel!MitigationOptions` — Windows 10+ untrusted font blocking |
| 27 | ASR Rules | Attack Surface Reduction rules via `Get-MpPreference` (CMD: info-only) |
| 28 | SMB Client Signing | `HKLM\...\LanmanWorkstation\Parameters!RequireSecuritySignature` and `EnableSecuritySignature` |
| 29 | TLS/SSL Protocol Configuration | `HKLM\SYSTEM\...\SCHANNEL\Protocols\<proto>\Server!Enabled` — SSL 2.0/3.0/TLS 1.0/1.1 disabled, TLS 1.2/1.3 enabled |
| 30 | Audit Policy | `auditpol /get /category:*` — key subcategories (Logon, Account Management, Process Creation, Security System Extension, etc.) |

## Section 3 — Authentication Checks (9 checks)

| # | Check | Verifies |
|---|---|---|
| 31 | RDP Deny | `AllowRemoteRPC` and `fDenyTSConnections` under `HKLM\System\CurrentControlSet\Control\Terminal Server` |
| 32 | Local Administrators | Membership of the local `Administrators` group |
| 33 | NTLM Session Security | `NtlmMinServerSec` and `NtlmMinClientSec` — should be `0x20080030` (NTLMv2 + 128-bit) |
| 34 | LAN Manager Authentication | `LmCompatibilityLevel` (should be 5) and `NoLmHash` (should be 1) |
| 35 | Cached Logons | `CachedLogonsCount` under `Winlogon` — should be 0 or 1 |
| 36 | Interactive Login | `LocalAccountTokenFilterPolicy` in `policies\system` (and `Wow6432Node` mirror) — should not be 1 |
| 37 | WDigest | `HKLM\SYSTEM\...\SecurityProviders\WDigest!UseLogonCredential` — should be 0 |
| 38 | Restrict RPC Clients | `HKLM\Software\Policies\Microsoft\Windows NT\Rpc!RestrictRemoteClients` — should be 1 |
| 39 | RDP Network Level Authentication | `HKLM\...\RDP-Tcp!UserAuthentication` (NLA required) and `MinEncryptionLevel` (should be 3 or 4) |

## Section 4 — Network Checks (10 checks)

| # | Check | Verifies |
|---|---|---|
| 40 | IPv4 Interfaces | Active IPv4 addresses on all network adapters |
| 41 | IPv6 Interfaces | Active IPv6 addresses (flags non-link-local; link-local `fe80::` is reported as informational) |
| 42 | WPAD | `hosts` file entry, `WpadOverride` registry, `WinHttpAutoProxySvc` service, KB3165191 hotfix |
| 43 | WINS Configuration | `Win32_NetworkAdapterConfiguration.DNSEnabledForWINSResolution` and `WINSEnableLMHostsLookup` |
| 44 | LLMNR | `HKLM\Software\policies\Microsoft\Windows NT\DNSClient!EnableMulticast` — should be 0 |
| 45 | Computer Browser Service | `Browser` service — should be stopped/disabled |
| 46 | NetBIOS over TCP/IP | Per-adapter `TcpipNetbiosOptions` — should be 2 (disabled) |
| 47 | Network Connections | Listening ports and established connections (with process names where available) |
| 48 | Firewall Profiles | Domain / Private / Public profile enabled state and default inbound/outbound actions |
| 49 | TCP/IP Stack Hardening | `DisableIPSourceRouting`, `EnableICMPRedirect`, `PerformRouterDiscovery` |

## Section 5 — PowerShell Checks (7 checks)

| # | Check | Verifies |
|---|---|---|
| 50 | PowerShell Versions | Current PS major version, PS v2 feature state, .NET versions that permit v2 (CMD: info-only) |
| 51 | PowerShell Language Mode | `$ExecutionContext.SessionState.LanguageMode` — should be `ConstrainedLanguage` (CMD: info-only) |
| 52 | PS Module Logging | `HKLM\SOFTWARE\Policies\...\ModuleLogging!EnableModuleLogging` and `ModuleNames\*` |
| 53 | PS Script Block Logging | `EnableScriptBlockLogging` and `EnableScriptBlockInvocationLogging` |
| 54 | PS Transcription | `EnableTranscripting`, `EnableInvocationHeader`, `OutputDirectory` |
| 55 | PS Protected Event Logging | `EnableProtectedEventLogging` |
| 56 | WinRM | Service state via `Test-WSMan` or `Get-Service`; firewall rule for `Windows Remote Management (HTTP-In)` |

## Section 6 — Logging Checks (3 checks)

| # | Check | Verifies |
|---|---|---|
| 57 | Event Log Sizes | Maximum size of 11 critical logs (Application, System, Security, Windows PowerShell, PowerShell/Operational, TerminalServices-LocalSessionManager/Operational, TaskScheduler/Operational, SMBServer/Audit, Security-Netlogon/Operational, WinRM/Operational, WMI-Activity/Operational) |
| 58 | Command-line Auditing | `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit!ProcessCreationIncludeCmdLine_Enabled` |
| 59 | Windows Script Host | `HKLM\Software\Microsoft\Windows Script Host\Settings!Enabled` — should be 0 |

## Script Capability Matrix

| Check Range | PSv3 | PSv2 | CMD |
|---|:---:|:---:|:---:|
| Checks 1–23 (System Info) | Full | Full | Full except #12 AppLocker (info-only) |
| Checks 24–30 (Security) | Full | Full | Full except #27 ASR Rules (info-only) |
| Checks 31–39 (Authentication) | Full | Full | Full |
| Checks 40–49 (Network) | Full | Full | Full |
| Checks 50–56 (PowerShell) | Full | Full | #50 and #51 info-only (require PowerShell runtime); #52–#56 implemented via registry |
| Checks 57–59 (Logging) | Full | Full | Full (`wevtutil gl` used for log sizes) |

CMD emits `[*] <check name>: Not available in CMD. <reason>.` for the four info-only checks, ensuring every report from every script covers all 59 checks.

## Disabling Individual Checks

Each script has boolean toggles at the top (e.g., `$getBitLockerCheck = $true`). Set any to `$false` to skip that check for the current run. Useful when a check is known to hang on a specific platform or is irrelevant to the assessment scope.

Running the script with the `-Config` switch prints the current toggle state and exits (PowerShell scripts only).
