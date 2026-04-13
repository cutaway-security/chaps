# CANONICAL_CHECKS.md

Canonical check order for all three CHAPS scripts. PSv3 is the reference implementation. PSv2 and CMD must implement every check in this exact order. Checks that cannot be performed by a given script must output an info line with the reason.

## System Info Checks

| # | Check | PSv3 Function | Method | CMD Possible |
|---|-------|---------------|--------|:---:|
| 1 | System information | Get-SystemInfo | systeminfo / Get-ComputerInfo | Yes (wmic/systeminfo) |
| 2 | Windows version | Get-WinVersion | Environment.OSVersion | Yes (ver/wmic) |
| 3 | User PATH | Get-UserPath | $env:Path | Yes (%PATH%) |
| 4 | Auto update config | Get-AutoUpdateConfig | COM object | Yes (registry) |
| 5 | Missing patches | Get-WinPatch | COM object | Partial (wmic qfe) |
| 6 | BitLocker | Get-BitLocker | Get-BitLockerVolume / manage-bde | Yes (manage-bde) |
| 7 | AlwaysInstallElevated | Get-InstallElevated | Registry | Yes (reg query) |
| 8 | EMET / Exploit Protection | Get-EMET | Get-ProcessMitigation / Get-Service | Partial (registry) |
| 9 | LAPS | Get-LAPS | Registry + file check | Yes (reg query + if exist) |
| 10 | GPO reprocessing | Get-GPO | Registry | Yes (reg query) |
| 11 | Net Session Enumeration | Get-NetSessionEnum | Registry | Yes (reg query) |
| 12 | AppLocker | Get-AppLocker | Get-AppLockerPolicy | No (PS cmdlet only) -- info msg |
| 13 | Credential/Device Guard | Get-CredDeviceGuard | CIM Win32_DeviceGuard | Partial (wmic) |
| 14 | MS Office macros | Get-MSOffice | Registry | Yes (reg query) |
| 15 | Sysmon | Get-Sysmon | Get-Service | Yes (sc query) |
| 16 | USB devices | Get-USBDevices | Get-PnpDevice / WMI | Yes (wmic) |
| 17 | Antivirus/EDR | Get-AntiVirus | CIM SecurityCenter2 / Get-MpComputerStatus | Partial (wmic) |
| 18 | Software inventory | Get-SoftwareInventory | Registry Uninstall keys | Yes (reg query) |
| 19 | UAC configuration | Get-UACConfig | Registry | Yes (reg query) |
| 20 | Account policies | Get-AccountPolicy | net accounts / Get-LocalUser | Yes (net accounts) |
| 21 | Secure Boot | Get-SecureBoot | Confirm-SecureBootUEFI / Registry | Yes (reg query) |
| 22 | LSA Protection | Get-LSAProtection | Registry | Yes (reg query) |
| 23 | Risky services | Get-ServiceHardening | Get-Service | Yes (sc query) |

## Security Checks

| # | Check | PSv3 Function | Method | CMD Possible |
|---|-------|---------------|--------|:---:|
| 24 | SMB server config | Get-SMBv1 | Get-SmbServerConfiguration | Partial (registry) |
| 25 | Anonymous enumeration | Get-AnonEnum | Registry | Yes (reg query) |
| 26 | Untrusted fonts | Get-UntrustedFonts | Registry | Yes (reg query) |
| 27 | ASR rules | Get-ASRRules | Get-MpPreference | No (PS cmdlet only) -- info msg |
| 28 | SMB client signing | Get-SMBClientConfig | Registry | Yes (reg query) |
| 29 | TLS/SSL protocols | Get-TLSConfig | Registry | Yes (reg query) |
| 30 | Audit policy | Get-AuditPolicy | auditpol | Yes (auditpol) |

## Authentication Checks

| # | Check | PSv3 Function | Method | CMD Possible |
|---|-------|---------------|--------|:---:|
| 31 | RDP deny | Get-RDPDeny | Registry | Yes (reg query) |
| 32 | Local administrators | Get-LocalAdmin | Get-LocalGroupMember / net localgroup | Yes (net localgroup) |
| 33 | NTLM session security | Get-NTLMSession | Registry | Yes (reg query) |
| 34 | LAN Manager auth | Get-LANMAN | Registry | Yes (reg query) |
| 35 | Cached logons | Get-CachedLogons | Registry | Yes (reg query) |
| 36 | Interactive login | Get-InteractiveLogin | Registry | Yes (reg query) |
| 37 | WDigest | Get-WDigest | Registry | Yes (reg query) |
| 38 | Restrict RPC clients | Get-RestrictRDPClients | Registry | Yes (reg query) |
| 39 | RDP NLA | Get-RDPNLAConfig | Registry | Yes (reg query) |

## Network Checks

| # | Check | PSv3 Function | Method | CMD Possible |
|---|-------|---------------|--------|:---:|
| 40 | IPv4 interfaces | Get-NetworkSettingsIPv4 | Get-NetIPAddress / WMI | Yes (ipconfig) |
| 41 | IPv6 interfaces | Get-NetworkSettingsIPv6 | WMI | Yes (ipconfig) |
| 42 | WPAD | Get-WPAD | hosts file + Registry + Get-Service | Yes (findstr + reg query + sc query) |
| 43 | WINS | Get-WINSConfig | WMI | Yes (wmic) |
| 44 | LLMNR | Get-LLMNRConfig | Registry | Yes (reg query) |
| 45 | Computer Browser | Get-CompBrowser | Get-Service | Yes (sc query) |
| 46 | NetBIOS | Get-NetBIOS | WMI | Yes (wmic) |
| 47 | Network connections | Get-NetConnections | Get-NetTCPConnection / netstat | Yes (netstat) |
| 48 | Firewall profiles | Get-FirewallProfile | Get-NetFirewallProfile / netsh | Yes (netsh) |
| 49 | TCP/IP hardening | Get-TCPIPHardening | Registry | Yes (reg query) |

## PowerShell Checks

| # | Check | PSv3 Function | Method | CMD Possible |
|---|-------|---------------|--------|:---:|
| 50 | PS versions | Get-PSVersions | $PSVersionTable / Get-WindowsOptionalFeature | N/A -- requires PowerShell runtime |
| 51 | PS language mode | Get-PSLanguage | $ExecutionContext.SessionState | N/A -- requires PowerShell runtime |
| 52 | PS module logging | Get-PSModule | Registry | Yes (reg query) |
| 53 | PS script block logging | Get-PSScript | Registry | Yes (reg query) |
| 54 | PS transcription | Get-PSTranscript | Registry | Yes (reg query) |
| 55 | PS protected events | Get-PSProtectedEvent | Registry | Yes (reg query) |
| 56 | WinRM | Get-WinRM | Test-WSMan / Get-Service / netsh | Partial (sc query + netsh) |

## Logging Checks

| # | Check | PSv3 Function | Method | CMD Possible |
|---|-------|---------------|--------|:---:|
| 57 | Event log sizes | Get-PSEventLog | Get-WinEvent -ListLog | Partial (wevtutil) |
| 58 | Command-line auditing | Get-CmdAuditing | Registry | Yes (reg query) |
| 59 | Windows Script Host | Get-WinScripting | Registry + Get-HotFix | Yes (reg query) |

## Summary

- **Total checks**: 59
- **CMD fully possible**: 44
- **CMD partially possible**: 8 (can check some aspects but not all)
- **CMD N/A**: 2 (PSVersions, PSLanguage -- require PowerShell runtime)
- **CMD info-only**: 5 (AppLocker, ASR -- require PS-only cmdlets with no CMD equivalent)

For N/A and info-only checks, CMD outputs: `[*] <Check Name>: Not available in CMD. <Reason>.`
