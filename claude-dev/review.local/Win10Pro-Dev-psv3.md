# CHAPS Report: chaps_PSv3+ 2.0.0

| Field | Value |
|-------|-------|
| Hostname | DESKTOP-582JB74 |
| Start Time | Monday 04/13/2026 22:03:07 -07:00 |
| PS Version | 5 |
| OS Version | Microsoft Windows NT 10.0.17763.0 |
| Auditing Company | Cutaway Security, LLC |
| Site/Plant | plant1 |
| Admin Status | Administrator |

## System Info Checks

[*] Microsoft Windows 10 Pro, 10.0.17763, 17763, 64-bit, WORKGROUP
[*] Windows Version: Microsoft Windows NT 10.0.17763.0
[*] Windows Default Path for devadm : C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Windows\System32\OpenSSH\;C:\Windows\system32\config\systemprofile\AppData\Local\Microsoft\WindowsApps;C:\Users\devadm\AppData\Local\Microsoft\WindowsApps;
[-] Windows AutoUpdate is not configured to automatically install updates:  : System.Collections.Hashtable.
[x] Check for Critical and Important Windows patches test failed: no internet connection.
[-] BitLocker not detected on Operating System Volume or encryption is not complete. Check for other encryption methods: FullyDecrypted
[+] Users cannot install software as NT AUTHORITY\SYSTEM.
[*] EMET is deprecated. Windows Exploit Protection is the replacement.
[-] System-wide DEP (Data Execution Prevention) is not enabled: NOTSET
[-] System-wide mandatory ASLR is not enabled: NOTSET
[-] System-wide Control Flow Guard (CFG) is not enabled: NOTSET
[-] Local Administrator Password Solution (LAPS) is not installed (checked Windows LAPS and legacy LAPS).
[*] System may not be assigned GPOs.
[+] SrvsvcSessionInfo registry key is configured (Net Session Enumeration is restricted).
[-] RestrictRemoteSAM registry key is not configured.
[-] AppLocker not configured
[-] Credential Guard or HVCI service is not running.
[-] Device Guard: no properties exist and therefore is not configured.
[*] No Microsoft Office installations detected in registry.
[+] Sysmon service is running: Sysmon64 (Sysmon64)
[+] Sysmon driver (SysmonDrv) is present: Status: Running
[*] USB Plug and Play devices detected: 2
[*] USB Device: USB Root Hub (Status: OK, ID: USB\ROOT_HUB\4&F9A5D10&0)
[*] USB Device: Intel(R) 82371SB PCI to USB Universal Host Controller (Status: OK, ID: PCI\VEN_8086&DEV_7020&SUBSYS_11001AF4&REV_01\3&267A616A&2&0A)
[*] Antivirus detected: Windows Defender
[+] Windows Defender is enabled.
[+] Windows Defender definitions appear up to date.
[*] Installed software count: 2
[*] Software: Microsoft Update Health Tools (Version: 2.85.0.0, Publisher: Microsoft Corporation)
[*] Software: Virtio-win-driver-installer (Version: 0.1.285, Publisher: Red Hat, Inc.)
[+] UAC is enabled (EnableLUA: 1)
[-] UAC admin prompt may not be secure (ConsentPromptBehaviorAdmin: 5)
[+] UAC prompts on secure desktop (PromptOnSecureDesktop: 1)
[*] Maximum password age: 42
[-] Minimum password length is too short: 0
[-] Account lockout threshold is not configured: Never
[*] Account lockout duration: 30
[+] Guest account is disabled: Guest
[-] Built-in Administrator account has not been renamed.
[*] Built-in Administrator account enabled: False
[*] Secure Boot check not supported on this system (may be BIOS/legacy boot).
[-] LSA Protection (RunAsPPL) registry key not found.
[+] Routing and Remote Access service is disabled.
[+] .NET TCP Port Sharing service is disabled.
[+] Remote Registry service is disabled.
[-] Print Spooler (PrintNightmare risk) service is running.
[*] Internet Connection Sharing service status: Stopped, start type: Manual

## Security Checks

[+] SMBv1 is Disabled
[-] SMBv1 Auditing is Disabled
[+] SMBv2/SMBv3 is Enabled
[-] SMB Server Require Security Signature is Disabled
[-] SMB Server Encryption (EncryptData) is Disabled
[+] SMB Server RejectUnencryptedAccess is Enabled
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

[+] AllowRemoteRPC is set to deny RDP: 0
[+] fDenyTSConnections is set to deny remote connections: 1
[-] More than one account is in local Administrators group: 3
[*] Account in local Administrator group: DESKTOP-582JB74\Administrator
[*] Account in local Administrator group: DESKTOP-582JB74\devadm
[*] Account in local Administrator group: DESKTOP-582JB74\setup
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

[*] Host network interface assigned: 192.168.100.11
[-] Host IPv6 network interface assigned (gwmi): fe80::b8ea:d8ae:e878:6941
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
[*]   0.0.0.0:22 (PID: 2636, Process: sshd)
[*]   :::135 (PID: 852, Process: svchost)
[*]   192.168.100.11:139 (PID: 4, Process: System)
[*]   :::445 (PID: 4, Process: System)
[*]   0.0.0.0:5040 (PID: 4324, Process: svchost)
[*]   :::5357 (PID: 4, Process: System)
[*]   :::7680 (PID: 1952, Process: svchost)
[*]   0.0.0.0:49664 (PID: 468, Process: wininit)
[*]   0.0.0.0:49665 (PID: 1160, Process: svchost)
[*]   0.0.0.0:49666 (PID: 1100, Process: svchost)
[*]   :::49667 (PID: 2200, Process: spoolsv)
[*]   :::49668 (PID: 580, Process: services)
[*]   :::49690 (PID: 612, Process: lsass)
[*] Established TCP connections:
[*]   192.168.100.11:49819 -> 104.208.203.90:443 (PID: 2764, Process: svchost)
[*]   192.168.100.11:22 -> 192.168.1.24:54840 (PID: 2636, Process: sshd)
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

[+] Current PowerShell Version: 5.1.17763.1
[-] PowerShell Version 2 should be disabled: Enabled
[+] .NET Framework greater than 3.0 installed: 4.8.03761
[+] .NET Framework greater than 3.0 installed: 4.8.03761
[+] .NET Framework greater than 3.0 installed: 4.8.03761
[+] .NET Framework greater than 3.0 installed: 4.8.03761
[+] .NET Framework greater than 3.0 installed: 4.0.0.0
[-] Execution Langugage Mode Is Not ConstrainedLanguage: FullLanguage
[-] EnableModuleLogging Is Not Set
[*] No specific modules configured for Module Logging.
[-] EnableScriptBlockLogging Is Not Set
[-] EnableScriptBlockInvocationLogging Is Not Set
[-] EnableTranscripting Is Not Set
[-] EnableInvocationHeader Is Not Set
[-] EnableProtectedEventLogging Is Not Set
[+] WinRM Services is not running: Get-Service check.
[+] WinRM Firewall Rule WINRM-HTTP-In-TCP-NoScope is disabled.
[+] WinRM Firewall Rule WINRM-HTTP-In-TCP is disabled.

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

**chaps_PSv3+ completed** -- Stop Time: Monday 04/13/2026 22:03:18 -07:00

---

*CHAPS chaps_PSv3+ 2.0.0 -- Cutaway Security, LLC*
*Assessment and auditing: info [@] cutawaysecurity.com -- Script help: dev [@] cutawaysecurity.com*
