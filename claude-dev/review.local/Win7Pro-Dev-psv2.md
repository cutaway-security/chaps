# CHAPS Report: chaps_PSv2 2.0.0

| Field | Value |
|-------|-------|
| Hostname | DEVADM-WIN7PRO |
| Start Time | Tuesday 04/14/2026 00:06:08 -05:00 |
| PS Version | 2 |
| OS Version | Microsoft Windows NT 6.1.7601 Service Pack 1 |
| Auditing Company | Cutaway Security, LLC |
| Site/Plant | plant1 |
| Admin Status | Administrator |

## System Info Checks

[*] Microsoft Windows 7 Professional , 6.1.7601, 7601, 64-bit, WORKGROUP
[*] Windows Version: Microsoft Windows NT 6.1.7601 Service Pack 1
[*] Windows Default Path for devadm : C:\Program Files\OpenSSH\;C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\
[-] Windows AutoUpdate is not configured to automatically install updates:  : System.Collections.Hashtable.
[-] Missing Critical or Important Update KB: 2912390
[-] Missing Critical or Important Update KB: 3035126
[-] Missing Critical or Important Update KB: 3110329
[-] Missing Critical or Important Update KB: 3156016
[-] Missing Critical or Important Update KB: 4054518
[-] Missing Critical or Important Update KB: 4490628
[-] Missing Critical or Important Update KB: 4516065
[-] Missing Critical or Important Update KB: 4535102
[-] Missing Critical or Important Update KB: 4536952
[-] BitLocker not detected or encryption is not complete (manage-bde):     Conversion Status:    Fully Decrypted
[+] Users cannot install software as NT AUTHORITY\SYSTEM.
[-] EMET Service not found. EMET may not be installed.
[-] Local Administrator Password Solution (LAPS) is not installed (checked Windows LAPS and legacy LAPS).
[*] System may not be assigned GPOs.
[+] SrvsvcSessionInfo registry key is configured (Net Session Enumeration is restricted).
[-] RestrictRemoteSAM registry key is not configured.
[-] AppLocker not configured (SrpV2 registry path not found).
[*] Windows Version is older than 10. Cannot test for Credential or Device Guard.
[*] No Microsoft Office installations detected in registry.
[+] Sysmon service is running: Sysmon64 (Sysmon64)
[+] Sysmon driver (SysmonDrv) is present: Status: Running
[*] USB devices detected via WMI: 3
[-] No antivirus products detected via SecurityCenter2.
[*] Installed software count: 2
[*] Software: OpenSSH (Version: 10.0.0.0, Publisher: Microsoft Corporation)
[*] Software: QEMU guest agent (Version: 100.0.0, Publisher: RedHat)
[+] UAC is enabled (EnableLUA: 1)
[-] UAC admin prompt may not be secure (ConsentPromptBehaviorAdmin: 5)
[+] UAC prompts on secure desktop (PromptOnSecureDesktop: 1)
[-] UAC does not filter built-in Administrator token (FilterAdministratorToken: 0)
[*] Maximum password age: 42
[-] Minimum password length is too short: 0
[-] Account lockout threshold is not configured: Never
[*] Account lockout duration: 30
[+] Guest account is disabled.
[-] Built-in Administrator account has not been renamed.
[*] Built-in Administrator account disabled: True
[*] Secure Boot status could not be determined (BIOS/legacy boot may be in use).
[-] LSA Protection (RunAsPPL) registry key not found.
[*] Remote Registry service status: Stopped, start type: 
[*] .NET TCP Port Sharing service status: Stopped, start type: 
[-] Print Spooler (PrintNightmare risk) service is running.
[*] Internet Connection Sharing service status: Stopped, start type: 
[*] Routing and Remote Access service status: Stopped, start type: 

## Security Checks

[-] SMBv1 registry key not set (SMBv1 may be enabled by default).
[-] SMBv1 Auditing is not configured.
[+] SMBv2/SMBv3 registry key not set (enabled by default on modern Windows).
[-] SMB Server Require Security Signature is Disabled: 0
[-] RestrictAnonymous registry key is not configured: 0
[+] RestrictAnonymoussam registry key is configured: 1
[*] Windows Version is older than 10. Cannot test for Untrusted Fonts.
[*] Get-MpPreference not available. Cannot check ASR rules.
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
[x] Testing local Administrator Accounts failed.
[-] NTLM Session Server Security settings is not configured to require NTLMv2 and 128-bit encryption: 536870912
[-] NTLM Session Client Security settings is not configured to require NTLMv2 and 128-bit encryption: 536870912
[+] NoLmHash registry key is configured: 1
[-] LM Compatability Level registry key is not configured.
[-] CachedLogonsCount Is Not Set to 0 or 1: 10
[+] LocalAccountTokenFilterPolicy Is Not Set
[+] LocalAccountTokenFilterPolicy in Wow6432Node Is Not Set
[-] WDigest UseLogonCredential key does not exist.
[-] RestrictRemoteClients registry key is not configured: 
[-] RDP Network Level Authentication (NLA) is not required: 0
[-] RDP minimum encryption level is below High: 2

## Network Checks

[*] Host network interface assigned: 192.168.100.10
[-] Host IPv6 network interface assigned (gwmi): fe80::b1ca:1a4f:d3f9:e073
[-] No WPAD entry detected. Should contain: wpad 255.255.255.255
[*] System not configured with the WpadOverride registry key.
[-] KB3165191 to harden WPAD is not installed.
[-] WinHttpAutoProxySvc service is: Running
[+] DNSEnabledForWINSResolution is disabled
[-] WINSEnableLMHostsLookup is enabled
[-] DNSClient.EnableMulticast does not exist or is enabled: 
[+] Computer Browser service is: Stopped
[-] NetBios is Enabled: 0
[*] Network connections (netstat -ano):
[*]   
[*]   Active Connections
[*]   
[*]     Proto  Local Address          Foreign Address        State           PID
[*]     TCP    0.0.0.0:22             0.0.0.0:0              LISTENING       1396
[*]     TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       708
[*]     TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
[*]     TCP    0.0.0.0:49152          0.0.0.0:0              LISTENING       384
[*]     TCP    0.0.0.0:49153          0.0.0.0:0              LISTENING       784
[*]     TCP    0.0.0.0:49154          0.0.0.0:0              LISTENING       948
[*]     TCP    0.0.0.0:49155          0.0.0.0:0              LISTENING       488
[*]     TCP    0.0.0.0:49157          0.0.0.0:0              LISTENING       504
[*]     TCP    192.168.100.10:22      192.168.1.24:53978     ESTABLISHED     1396
[*]     TCP    192.168.100.10:22      192.168.1.24:53994     ESTABLISHED     1396
[*]     TCP    192.168.100.10:139     0.0.0.0:0              LISTENING       4
[*]     TCP    192.168.100.10:49177   199.232.210.172:80     ESTABLISHED     948
[*]     TCP    192.168.100.10:49178   128.85.113.135:443     ESTABLISHED     948
[*]     TCP    192.168.100.10:49179   199.232.210.172:80     ESTABLISHED     564
[*]     TCP    [::]:22                [::]:0                 LISTENING       1396
[*]     TCP    [::]:135               [::]:0                 LISTENING       708
[*]     TCP    [::]:445               [::]:0                 LISTENING       4
[*]     TCP    [::]:49152             [::]:0                 LISTENING       384
[*]     TCP    [::]:49153             [::]:0                 LISTENING       784
[*]     TCP    [::]:49154             [::]:0                 LISTENING       948
[*]     TCP    [::]:49155             [::]:0                 LISTENING       488
[*]     TCP    [::]:49157             [::]:0                 LISTENING       504
[*]     UDP    0.0.0.0:5355           *:*                                    564
[*]     UDP    192.168.100.10:137     *:*                                    4
[*]     UDP    192.168.100.10:138     *:*                                    4
[*]     UDP    [::]:5355              *:*                                    564
[*] Windows Firewall profile status (netsh):
[*] Domain Profile Settings:
[*] ----------------------------------------------------------------------
[+] State                                 ON
[*] Private Profile Settings:
[*] ----------------------------------------------------------------------
[+] State                                 ON
[*] Public Profile Settings:
[*] ----------------------------------------------------------------------
[+] State                                 ON
[*] Ok.
[*] DisableIPSourceRouting not configured (default behavior).
[-] ICMP redirects are enabled: 1

## PowerShell Checks

[-] Current PowerShell Version is less than Version 5: 2.0
[*] PowerShell Engine Version: 2.0
[*] Only PowerShell v2 engine detected.
[-] .NET Framework less than 3.0 installed which could allow PSv2 execution: 
[-] Execution Langugage Mode Is Not ConstrainedLanguage: FullLanguage
[-] EnableModuleLogging Is Not Set
[*] No specific modules configured for Module Logging.
[-] EnableScriptBlockLogging Is Not Set
[-] EnableScriptBlockInvocationLogging Is Not Set
[-] EnableTranscripting Is Not Set
[-] EnableInvocationHeader Is Not Set
[-] EnableProtectedEventLogging Is Not Set
[+] WinRM Services is not running: Get-Service check.
[+] WinRM Firewall Rule is disabled (netsh).

## Logging Checks

[-] Security max log size is smaller than 4 GB: 0.02 GB
[x] Could not determine Microsoft-Windows-Security-Netlogon/Operational log size.
[-] Microsoft-Windows-TaskScheduler/Operational max log size is smaller than 1 GB: 0.01 GB
[-] Microsoft-Windows-WinRM/Operational max log size is smaller than 1 GB: 0.001 GB
[-] Microsoft-Windows-TerminalServices-LocalSessionManager/Operational max log size is smaller than 1 GB: 0.001 GB
[-] Microsoft-Windows-PowerShell/Operational max log size is smaller than 1 GB: 0.015 GB
[-] Windows PowerShell max log size is smaller than 4 GB: 0.015 GB
[-] Microsoft-Windows-SMBServer/Audit max log size is smaller than 1 GB: 0.008 GB
[-] System max log size is smaller than 4 GB: 0.02 GB
[x] Could not determine Microsoft-Windows-WMI-Activity/Operational log size.
[-] Application max log size is smaller than 4 GB: 0.02 GB
[-] ProcessCreationIncludeCmdLine_Enabled Is Not Set
[-] WSH Setting Enabled key does not exist.
[-] KB2871997 is not installed.

---

**chaps_PSv2 completed** -- Stop Time: Tuesday 04/14/2026 00:07:06 -05:00

---

*CHAPS chaps_PSv2 2.0.0 -- Cutaway Security, LLC*
*Assessment and auditing: info [@] cutawaysecurity.com -- Script help: dev [@] cutawaysecurity.com*
