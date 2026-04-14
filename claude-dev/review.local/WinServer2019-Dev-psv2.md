# CHAPS Report: chaps_PSv2 2.0.0

| Field | Value |
|-------|-------|
| Hostname | WIN-0SUVHVBQL4O |
| Start Time | Monday 04/13/2026 22:04:33 -07:00 |
| PS Version | 5 |
| OS Version | Microsoft Windows NT 10.0.17763.0 |
| Auditing Company | Cutaway Security, LLC |
| Site/Plant | plant1 |
| Admin Status | Administrator |

## System Info Checks

[*] Microsoft Windows Server 2019 Standard, 10.0.17763, 17763, 64-bit, WORKGROUP
[*] Windows Version: Microsoft Windows NT 10.0.17763.0
[*] Windows Default Path for administrator : C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Windows\System32\OpenSSH\;C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps;
[-] Windows AutoUpdate is not configured to automatically install updates:  : System.Collections.Hashtable.
[x] Check for Critical and Important Windows patches test failed: no internet connection.
[*] BitLocker check skipped: neither Get-BitLockerVolume nor manage-bde.exe available. BitLocker feature is likely not installed.
[+] Users cannot install software as NT AUTHORITY\SYSTEM.
[*] EMET is deprecated. Windows Exploit Protection is the replacement.
[-] System-wide DEP (Data Execution Prevention) is not enabled: NOTSET
[-] System-wide mandatory ASLR is not enabled: NOTSET
[-] System-wide Control Flow Guard (CFG) is not enabled: NOTSET
[-] Local Administrator Password Solution (LAPS) is not installed (checked Windows LAPS and legacy LAPS).
[*] System may not be assigned GPOs.
[+] SrvsvcSessionInfo registry key is configured (Net Session Enumeration is restricted).
[-] RestrictRemoteSAM registry key is not configured.
[-] AppLocker not configured (SrpV2 registry path not found).
[-] Credential Guard or HVCI service is not running.
[-] Device Guard: no properties exist and therefore is not configured.
[*] No Microsoft Office installations detected in registry.
[+] Sysmon service is running: Sysmon64 (Sysmon64)
[+] Sysmon driver (SysmonDrv) is present: Status: Running
[*] USB Plug and Play devices detected: 2
[*] USB Device: Intel(R) 82371SB PCI to USB Universal Host Controller (Status: OK, ID: PCI\VEN_8086&DEV_7020&SUBSYS_11001AF4&REV_01\3&267A616A&1&0A)
[*] USB Device: USB Root Hub (Status: OK, ID: USB\ROOT_HUB\4&1ED6D481&0)
[*] SecurityCenter2 not available (expected on Server editions).
[+] Windows Defender Antivirus is enabled.
[+] Windows Defender Real-Time Protection is enabled.
[+] Windows Defender signatures are 0 day(s) old.
[*] Installed software count: 5
[*] Software: QEMU guest agent (Version: 110.0.2, Publisher: RedHat)
[*] Software: Red Hat QXL controller (Version: 0.21.2.0, Publisher: Red Hat, Inc.)
[*] Software: Spice Agent 0.10.0-5 (64-bit) (Version: 0.10.5, Publisher: Red Hat, Inc.)
[*] Software: Virtio-win-driver-installer (Version: 0.1.285, Publisher: Red Hat, Inc.)
[*] Software: Virtio-win-guest-tools (Version: 0.1.285, Publisher: Red Hat, Inc.)
[+] UAC is enabled (EnableLUA: 1)
[-] UAC admin prompt may not be secure (ConsentPromptBehaviorAdmin: 5)
[+] UAC prompts on secure desktop (PromptOnSecureDesktop: 1)
[*] Maximum password age: 42
[-] Minimum password length is too short: 0
[-] Account lockout threshold is not configured: Never
[*] Account lockout duration: 30
[+] Guest account is disabled.
[-] Built-in Administrator account has not been renamed.
[*] Built-in Administrator account disabled: False
[*] Secure Boot check not supported on this system (may be BIOS/legacy boot).
[-] LSA Protection (RunAsPPL) registry key not found.
[+] Routing and Remote Access service is disabled.
[+] .NET TCP Port Sharing service is disabled.
[*] Remote Registry service status: Stopped, start type: Automatic
[-] Print Spooler (PrintNightmare risk) service is running.
[+] Internet Connection Sharing service is disabled.

## Security Checks

[-] SMBv1 registry key not set (SMBv1 may be enabled by default).
[-] SMBv1 Auditing is not configured.
[+] SMBv2/SMBv3 registry key not set (enabled by default on modern Windows).
[-] SMB Server Require Security Signature is Disabled: 0
[-] RestrictAnonymous registry key is not configured: 0
[+] RestrictAnonymoussam registry key is configured: 1
[-] Kernel MitigationOptions key does not exist.
[-] No Attack Surface Reduction rules configured.
[-] SMB Client Require Security Signature is Disabled: 0
[+] SMB Client Enable Security Signature is Enabled.
[*] SSL 2.0 Server not explicitly configured (OS default behavior).
[*] SSL 3.0 Server not explicitly configured (OS default behavior).
[*] TLS 1.0 Server not explicitly configured (OS default behavior).
[*] TLS 1.1 Server not explicitly configured (OS default behavior).
[*] Audit policy for Security group changes: Success only
[*] Audit policy for User account changes: Success only
[-] Audit policy for Process creation events: No Auditing
[-] Audit policy for Security system changes: No Auditing

## Authentication Checks

[-] AllowRemoteRPC should be disabled to deny RDP: 1
[+] fDenyTSConnections is set to deny remote connections: 1
[+] One account in local Administrators group.
[*] Account in local Administrator group: WIN-0SUVHVBQL4O\Administrator
[-] NTLM Session Server Security settings is not configured to require NTLMv2 and 128-bit encryption: 536870912
[-] NTLM Session Client Security settings is not configured to require NTLMv2 and 128-bit encryption: 536870912
[+] NoLmHash registry key is configured: 1
[-] LM Compatability Level registry key is not configured.
[-] CachedLogonsCount Is Not Set to 0 or 1: 10
[+] LocalAccountTokenFilterPolicy Is Not Set
[+] LocalAccountTokenFilterPolicy in Wow6432Node Is Not Set
[-] WDigest UseLogonCredential key does not exist.
[-] RestrictRemoteClients registry key is not configured: 
[+] RDP Network Level Authentication (NLA) is required.
[-] RDP minimum encryption level is below High: 2

## Network Checks

[*] Host network interface assigned: 192.168.100.15
[-] Host IPv6 network interface assigned (gwmi): fe80::90fa:157b:e3f1:1df0
[-] No WPAD entry detected. Should contain: wpad 255.255.255.255
[*] System not configured with the WpadOverride registry key.
[-] KB3165191 to harden WPAD is not installed.
[-] WinHttpAutoProxySvc service is: Running
[+] DNSEnabledForWINSResolution is disabled
[-] WINSEnableLMHostsLookup is enabled
[-] DNSClient.EnableMulticast does not exist or is enabled: 
[-] Computer Browser service is: Running
[-] NetBios is Enabled: 0
[*] Listening TCP ports:
[*]   :::22 (PID: 2560, Process: sshd)
[*]   :::80 (PID: 4, Process: System)
[*]   :::135 (PID: 848, Process: svchost)
[*]   192.168.100.15:139 (PID: 4, Process: System)
[*]   :::445 (PID: 4, Process: System)
[*]   :::5357 (PID: 4, Process: System)
[*]   :::5985 (PID: 4, Process: System)
[*]   :::47001 (PID: 4, Process: System)
[*]   0.0.0.0:49664 (PID: 448, Process: wininit)
[*]   0.0.0.0:49665 (PID: 1028, Process: svchost)
[*]   0.0.0.0:49666 (PID: 1404, Process: svchost)
[*]   :::49667 (PID: 2132, Process: spoolsv)
[*]   :::49668 (PID: 588, Process: services)
[*]   :::49673 (PID: 596, Process: lsass)
[*] Established TCP connections:
[*]   192.168.100.15:22 -> 192.168.1.24:49998 (PID: 2560, Process: sshd)
[+] Windows Firewall Domain profile is Enabled.
[*]   Domain DefaultInboundAction: NotConfigured
[*]   Domain DefaultOutboundAction: NotConfigured
[+] Windows Firewall Private profile is Enabled.
[*]   Private DefaultInboundAction: NotConfigured
[*]   Private DefaultOutboundAction: NotConfigured
[+] Windows Firewall Public profile is Enabled.
[*]   Public DefaultInboundAction: NotConfigured
[*]   Public DefaultOutboundAction: NotConfigured
[*] DisableIPSourceRouting not configured (default behavior).
[-] ICMP redirects are enabled: 1

## PowerShell Checks

[+] Current PowerShell Version: 5.1.17763.8510
[*] PowerShell Engine Version: 2.0
[*] PowerShell 3+ Engine Version: 5.1.17763.1
[+] .NET Framework greater than 3.0 installed: 4.7.03190
[+] .NET Framework greater than 3.0 installed: 4.7.03190
[+] .NET Framework greater than 3.0 installed: 4.7.03190
[+] .NET Framework greater than 3.0 installed: 4.7.03190
[+] .NET Framework greater than 3.0 installed: 4.0.0.0
[-] Execution Langugage Mode Is Not ConstrainedLanguage: FullLanguage
[-] EnableModuleLogging Is Not Set
[*] No specific modules configured for Module Logging.
[-] EnableScriptBlockLogging Is Not Set
[-] EnableScriptBlockInvocationLogging Is Not Set
[-] EnableTranscripting Is Not Set
[-] EnableInvocationHeader Is Not Set
[-] EnableProtectedEventLogging Is Not Set
[-] WinRM Services is running and may be accepting connections: Test-WSMan check.
[-] WinRM Firewall Rule WINRM-HTTP-In-TCP is enabled.
[-] WinRM Firewall Rule WINRM-HTTP-In-TCP-PUBLIC is enabled.

## Logging Checks

[-] Microsoft-Windows-SMBServer/Audit max log size is smaller than 1 GB: 0.008 GB
[-] Security max log size is smaller than 4 GB: 0.02 GB
[-] Microsoft-Windows-PowerShell/Operational max log size is smaller than 1 GB: 0.015 GB
[-] Microsoft-Windows-TaskScheduler/Operational max log size is smaller than 1 GB: 0.01 GB
[-] Microsoft-Windows-WinRM/Operational max log size is smaller than 1 GB: 0.001 GB
[-] Microsoft-Windows-Security-Netlogon/Operational max log size is smaller than 1 GB: 0.001 GB
[-] Microsoft-Windows-WMI-Activity/Operational max log size is smaller than 1 GB: 0.001 GB
[-] Windows PowerShell max log size is smaller than 4 GB: 0.015 GB
[-] System max log size is smaller than 4 GB: 0.02 GB
[-] Application max log size is smaller than 4 GB: 0.02 GB
[-] Microsoft-Windows-TerminalServices-LocalSessionManager/Operational max log size is smaller than 1 GB: 0.001 GB
[-] ProcessCreationIncludeCmdLine_Enabled Is Not Set
[-] WSH Setting Enabled key does not exist.
[-] KB2871997 is not installed.

---

**chaps_PSv2 completed** -- Stop Time: Monday 04/13/2026 22:04:43 -07:00

---

*CHAPS chaps_PSv2 2.0.0 -- Cutaway Security, LLC*
*Assessment and auditing: info [@] cutawaysecurity.com -- Script help: dev [@] cutawaysecurity.com*
