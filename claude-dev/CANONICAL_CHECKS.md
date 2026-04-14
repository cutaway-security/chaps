# CANONICAL_CHECKS.md

Canonical check order for all three CHAPS scripts. PSv3 is the reference implementation. PSv2 and CMD must implement every check in this exact order. Checks that cannot be performed by a given script must output an info line with the reason.

Total checks: 63.

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
| 24 | Unquoted service paths | Get-UnquotedServicePaths | Registry walk + path parsing | Yes (wmic + findstr; manual review) |
| 25 | Weak program directory permissions | Get-WeakProgramPermissions | Get-Acl | Yes (icacls + findstr) |
| 26 | Installed compilers | Get-InstalledCompilers | Get-Command + filesystem search | Yes (where + dir) |

## Security Checks

| # | Check | PSv3 Function | Method | CMD Possible |
|---|-------|---------------|--------|:---:|
| 27 | SMB server config | Get-SMBv1 | Get-SmbServerConfiguration | Partial (registry) |
| 28 | Anonymous enumeration | Get-AnonEnum | Registry | Yes (reg query) |
| 29 | Untrusted fonts | Get-UntrustedFonts | Registry | Yes (reg query) |
| 30 | ASR rules | Get-ASRRules | Get-MpPreference | No (PS cmdlet only) -- info msg |
| 31 | SMB client signing | Get-SMBClientConfig | Registry | Yes (reg query) |
| 32 | TLS/SSL protocols | Get-TLSConfig | Registry | Yes (reg query) |
| 33 | Audit policy | Get-AuditPolicy | auditpol | Yes (auditpol) |

## Authentication Checks

| # | Check | PSv3 Function | Method | CMD Possible |
|---|-------|---------------|--------|:---:|
| 34 | RDP deny | Get-RDPDeny | Registry | Yes (reg query) |
| 35 | Local administrators | Get-LocalAdmin | Get-LocalGroupMember / net localgroup | Yes (net localgroup) |
| 36 | NTLM session security | Get-NTLMSession | Registry | Yes (reg query) |
| 37 | LAN Manager auth | Get-LANMAN | Registry | Yes (reg query) |
| 38 | Cached logons | Get-CachedLogons | Registry | Yes (reg query) |
| 39 | Interactive login | Get-InteractiveLogin | Registry | Yes (reg query) |
| 40 | WDigest | Get-WDigest | Registry | Yes (reg query) |
| 41 | Restrict RPC clients | Get-RestrictRDPClients | Registry | Yes (reg query) |
| 42 | RDP NLA | Get-RDPNLAConfig | Registry | Yes (reg query) |

## Network Checks

| # | Check | PSv3 Function | Method | CMD Possible |
|---|-------|---------------|--------|:---:|
| 43 | IPv4 interfaces | Get-NetworkSettingsIPv4 | Get-NetIPAddress / WMI | Yes (ipconfig) |
| 44 | IPv6 interfaces | Get-NetworkSettingsIPv6 | WMI | Yes (ipconfig) |
| 45 | WPAD | Get-WPAD | hosts file + Registry + Get-Service | Yes (findstr + reg query + sc query) |
| 46 | WINS | Get-WINSConfig | WMI | Yes (wmic) |
| 47 | LLMNR | Get-LLMNRConfig | Registry | Yes (reg query) |
| 48 | Computer Browser | Get-CompBrowser | Get-Service | Yes (sc query) |
| 49 | NetBIOS | Get-NetBIOS | WMI | Yes (wmic) |
| 50 | Network connections | Get-NetConnections | Get-NetTCPConnection / netstat | Yes (netstat) |
| 51 | Firewall profiles | Get-FirewallProfile | Get-NetFirewallProfile / netsh | Yes (netsh) |
| 52 | TCP/IP hardening | Get-TCPIPHardening | Registry | Yes (reg query) |
| 53 | Network shares | Get-NetworkShares | Get-SmbShare / Win32_Share | Yes (net share) |

## PowerShell Checks

| # | Check | PSv3 Function | Method | CMD Possible |
|---|-------|---------------|--------|:---:|
| 54 | PS versions | Get-PSVersions | $PSVersionTable / Get-WindowsOptionalFeature | N/A -- requires PowerShell runtime |
| 55 | PS language mode | Get-PSLanguage | $ExecutionContext.SessionState | N/A -- requires PowerShell runtime |
| 56 | PS module logging | Get-PSModule | Registry | Yes (reg query) |
| 57 | PS script block logging | Get-PSScript | Registry | Yes (reg query) |
| 58 | PS transcription | Get-PSTranscript | Registry | Yes (reg query) |
| 59 | PS protected events | Get-PSProtectedEvent | Registry | Yes (reg query) |
| 60 | WinRM | Get-WinRM | Test-WSMan / Get-Service / netsh | Partial (sc query + netsh) |

## Logging Checks

| # | Check | PSv3 Function | Method | CMD Possible |
|---|-------|---------------|--------|:---:|
| 61 | Event log sizes | Get-PSEventLog | Get-WinEvent -ListLog | Partial (wevtutil) |
| 62 | Command-line auditing | Get-CmdAuditing | Registry | Yes (reg query) |
| 63 | Windows Script Host | Get-WinScripting | Registry + Get-HotFix | Yes (reg query) |

## Summary

- **Total checks**: 63
- **CMD fully possible**: 47
- **CMD partially possible / manual review**: 9 (BitLocker, EMET, CredDeviceGuard, AntiVirus, SMBv1 server, WinRM, EventLog sizes, plus #24 unquoted service paths is dump-and-review)
- **CMD N/A**: 2 (PSVersions, PSLanguage -- require PowerShell runtime)
- **CMD info-only**: 5 (AppLocker, ASR -- require PS-only cmdlets with no CMD equivalent; PSVersions, PSLanguage; Unquoted service paths reports raw data)

For N/A and info-only checks, CMD outputs: `[*] <Check Name>: Not available in CMD. <Reason>.`
