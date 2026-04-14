# CHAPS Report

| Field | Value |
| ----- | ----- |
| Script | chaps.bat 1.0.0 |
| Computer | DESKTOP-PSI6556 |
| Date | 04/13/2026 22:05:02 |
| Admin | true |

## System Info Checks

### Check 1: System Information

[*] OS: Microsoft Windows 11 Pro
[*] Version: 10.0.22621
[*] Architecture: 64-bit

### Check 2: Windows Version

[*] Microsoft Windows [Version 10.0.22621.4317]

### Check 3: User PATH

[*] PATH: C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Windows\System32\OpenSSH\;C:\Users\devadm\AppData\Local\Microsoft\WindowsApps;

### Check 4: Auto Update Configuration

[*] AUOptions registry value not found. Auto Update may be managed by other means.

### Check 5: Installed Hotfixes

[*] Installed hotfixes (review for missing patches):
[*]   HotFixID   InstalledOn  
[*]   KB5022497  5/5/2023     
[*]   KB5044285  4/10/2026    
[*]   KB5025351  5/5/2023     
[*]   KB5046247  4/10/2026    

### Check 6: BitLocker

[-] BitLocker service (BDESVC) is installed but stopped.

### Check 7: AlwaysInstallElevated

[+] HKLM AlwaysInstallElevated is not enabled: 
[+] HKCU AlwaysInstallElevated is not enabled: 
[+] AlwaysInstallElevated is not configured (good).

### Check 8: EMET / Exploit Protection

[*] EMET service not found. On Windows 10+, Exploit Protection is built in.
[*] Use PowerShell Get-ProcessMitigation to check Exploit Protection settings.

### Check 9: LAPS

[-] LAPS does not appear to be configured on this system.

### Check 10: GPO Reprocessing

[*] NoGPOListChanges not configured. Default behavior applies.

### Check 11: Net Session Enumeration

[-] RestrictRemoteSAM is not configured. Remote SAM enumeration may be possible.
[*] SrvsvcSessionInfo default security descriptor is present.

### Check 12: AppLocker

[*] AppLocker: Not available in CMD. Requires PowerShell Get-AppLockerPolicy cmdlet.

### Check 13: Credential Guard / Device Guard

[*] SecurityServicesConfigured: {0}
[*] SecurityServicesRunning: {0}

### Check 14: MS Office Macro Security

[*] No Office VBAWarnings registry keys found. Office may not be installed or macros are at default.

### Check 15: Sysmon

[+] Sysmon64 service is running.
[+] SysmonDrv service is running.

### Check 16: USB Devices

[*] USB controller devices:
[*]   Dependent                                                                                           
[*]   \\DESKTOP-PSI6556\root\cimv2:Win32_PnPEntity.DeviceID="USB\ROOT_HUB20\4&4DBE681&0"                  
[*]   \\DESKTOP-PSI6556\root\cimv2:Win32_PnPEntity.DeviceID="USB\ROOT_HUB\4&1985EEFF&0"                   
[*]   \\DESKTOP-PSI6556\root\cimv2:Win32_PnPEntity.DeviceID="USB\ROOT_HUB\4&34EFF09C&0"                   
[*]   \\DESKTOP-PSI6556\root\cimv2:Win32_PnPEntity.DeviceID="USB\ROOT_HUB\4&1E3A6A79&0"                   
[*]   \\DESKTOP-PSI6556\root\cimv2:Win32_PnPEntity.DeviceID="USB\ROOT_HUB\4&1C1A21DE&0"                   
[*]   \\DESKTOP-PSI6556\root\cimv2:Win32_PnPEntity.DeviceID="USB\ROOT_HUB\4&416A68C&0"                    
[*]   \\DESKTOP-PSI6556\root\cimv2:Win32_PnPEntity.DeviceID="USB\ROOT_HUB20\4&1150E251&0"                 
[*]   \\DESKTOP-PSI6556\root\cimv2:Win32_PnPEntity.DeviceID="USB\VID_0627&PID_0001\28754-0000:00:1D.7-1"  
[*]   \\DESKTOP-PSI6556\root\cimv2:Win32_PnPEntity.DeviceID="HID\VID_0627&PID_0001\6&38621D22&1&0000"     
[*]   \\DESKTOP-PSI6556\root\cimv2:Win32_PnPEntity.DeviceID="USB\ROOT_HUB\4&2E62E93&0"                    

### Check 17: Antivirus / EDR

[+] Antivirus detected: Windows Defender

### Check 18: Software Inventory

[*] Installed software (HKLM Uninstall):
[*]   @C:\Windows\System32\mstsc.exe,-4000
[*]   Red Hat QXL controller
[*]   Virtio-win-driver-installer
[*]   Microsoft Update Health Tools
[*]   Spice Agent 0.10.0-5 (64-bit)
[*]   QEMU guest agent

### Check 19: UAC Configuration

[+] EnableLUA: Enabled (UAC is on)
[*] ConsentPromptBehaviorAdmin: 0x5 (5=prompt for consent for non-Windows binaries, 2=prompt for credentials)
[+] PromptOnSecureDesktop: Enabled
[*] FilterAdministratorToken:  (0=default, consider enabling on sensitive systems)

### Check 20: Account Policies

[*] Net accounts output:
[*]   Force user logoff how long after time expires?:       Never
[*]   Minimum password age (days):                          0
[*]   Maximum password age (days):                          42
[*]   Minimum password length:                              0
[*]   Length of password history maintained:                None
[*]   Lockout threshold:                                    10
[*]   Lockout duration (minutes):                           10
[*]   Lockout observation window (minutes):                 10
[*]   Computer role:                                        WORKSTATION
[*]   The command completed successfully.

[*] Guest account status:
[*]   Comment                      Built-in account for guest access to the computer/domain
[*]   Account active               No
[*]   Account expires              Never

[*] Built-in Administrator account (SID -500):

### Check 21: Secure Boot

[+] UEFI Secure Boot is enabled.

### Check 22: LSA Protection

[*] RunAsPPL not configured:  (Default: not protected)

### Check 23: Risky Services

[-] Spooler service is RUNNING. Evaluate whether this service is needed.
[*] RemoteRegistry service is installed but stopped.
[+] SNMP service is not installed.
[+] TlntSvr service is not installed.
[*] RemoteAccess service is installed but stopped.
[*] NetTcpPortSharing service is installed but stopped.
[*] SharedAccess service is installed but stopped.

## Security Checks

### Check 24: SMB Server Configuration

[*] SMB1 registry value not found. SMBv1 may be enabled by default on older systems.
[*] SMB2 registry value not set (enabled by default on modern systems).
[*] AuditSmb1Access:  (Recommend enabling)
[-] SMB server RequireSecuritySignature: 0x0 (Recommend 1)
[*] SMB server EncryptData:  (Recommend enabling for SMB 3.0+)
[*] RejectUnencryptedAccess: 

### Check 25: Anonymous Enumeration

[-] RestrictAnonymous: 0 (anonymous access allowed). Recommend setting to 1 or 2.
[+] RestrictAnonymousSAM: 1 (anonymous SAM enumeration restricted)

### Check 26: Untrusted Font Blocking

[*] MitigationOptions not configured. Untrusted font blocking is at default.

### Check 27: ASR Rules

[*] ASR Rules: Not available in CMD. Requires PowerShell Get-MpPreference cmdlet.

### Check 28: SMB Client Signing

[-] SMB client RequireSecuritySignature: 0x0 (Recommend 1)
[+] SMB client signing is enabled.

### Check 29: TLS/SSL Protocol Configuration

[*] SSL 2.0 Server: Not explicitly configured (OS default applies)
[*] SSL 3.0 Server: Not explicitly configured (OS default applies)
[*] TLS 1.0 Server: Not explicitly configured (OS default applies)
[*] TLS 1.1 Server: Not explicitly configured (OS default applies)
[*] TLS 1.2 Server: Not explicitly configured (OS default applies)
[*] TLS 1.3 Server: Not explicitly configured (OS default applies)

### Check 30: Audit Policy

[*] Audit policy settings:
[*]   System audit policy
[*]   Category/Subcategory                      Setting
[*]   System
[*]   Security System Extension               No Auditing
[*]   System Integrity                        Success and Failure
[*]   IPsec Driver                            No Auditing
[*]   Other System Events                     Success and Failure
[*]   Security State Change                   Success
[*]   Logon/Logoff
[*]   Logon                                   Success and Failure
[*]   Logoff                                  Success
[*]   Account Lockout                         Success
[*]   IPsec Main Mode                         No Auditing
[*]   IPsec Quick Mode                        No Auditing
[*]   IPsec Extended Mode                     No Auditing
[*]   Special Logon                           Success
[*]   Other Logon/Logoff Events               No Auditing
[*]   Network Policy Server                   Success and Failure
[*]   User / Device Claims                    No Auditing
[*]   Group Membership                        No Auditing
[*]   Object Access
[*]   File System                             No Auditing
[*]   Registry                                No Auditing
[*]   Kernel Object                           No Auditing
[*]   SAM                                     No Auditing
[*]   Certification Services                  No Auditing
[*]   Application Generated                   No Auditing
[*]   Handle Manipulation                     No Auditing
[*]   File Share                              No Auditing
[*]   Filtering Platform Packet Drop          No Auditing
[*]   Filtering Platform Connection           No Auditing
[*]   Other Object Access Events              No Auditing
[*]   Detailed File Share                     No Auditing
[*]   Removable Storage                       No Auditing
[*]   Central Policy Staging                  No Auditing
[*]   Privilege Use
[*]   Non Sensitive Privilege Use             No Auditing
[*]   Other Privilege Use Events              No Auditing
[*]   Sensitive Privilege Use                 No Auditing
[*]   Detailed Tracking
[*]   Process Creation                        No Auditing
[*]   Process Termination                     No Auditing
[*]   DPAPI Activity                          No Auditing
[*]   RPC Events                              No Auditing
[*]   Plug and Play Events                    No Auditing
[*]   Token Right Adjusted Events             No Auditing
[*]   Policy Change
[*]   Audit Policy Change                     Success
[*]   Authentication Policy Change            Success
[*]   Authorization Policy Change             No Auditing
[*]   MPSSVC Rule-Level Policy Change         No Auditing
[*]   Filtering Platform Policy Change        No Auditing
[*]   Other Policy Change Events              No Auditing
[*]   Account Management
[*]   Computer Account Management             No Auditing
[*]   Security Group Management               Success
[*]   Distribution Group Management           No Auditing
[*]   Application Group Management            No Auditing
[*]   Other Account Management Events         No Auditing
[*]   User Account Management                 Success
[*]   DS Access
[*]   Directory Service Access                No Auditing
[*]   Directory Service Changes               No Auditing
[*]   Directory Service Replication           No Auditing
[*]   Detailed Directory Service Replication  No Auditing
[*]   Account Logon
[*]   Kerberos Service Ticket Operations      No Auditing
[*]   Other Account Logon Events              No Auditing
[*]   Kerberos Authentication Service         No Auditing
[*]   Credential Validation                   No Auditing

## Authentication Checks

### Check 31: RDP Configuration

[+] AllowRemoteRPC is disabled: 0x0
[+] fDenyTSConnections: 1 (RDP connections denied)

### Check 32: Local Administrators

[-] 3 accounts in local Administrators group. Review membership.
[*] Members: Administrator, devadm, setup

### Check 33: NTLM Session Security

[*] NtlmMinServerSec: 0x20000000 (Recommend 0x20080030 for NTLMv2 + 128-bit)
[*] NtlmMinClientSec: 0x20000000 (Recommend 0x20080030 for NTLMv2 + 128-bit)

### Check 34: LAN Manager Authentication

[-] LmCompatibilityLevel not configured. Default may allow LM/NTLM.
[+] NoLmHash: 1 (LM hash storage disabled)

### Check 35: Cached Logons

[*] CachedLogonsCount: 10 (Recommend 4 or fewer for sensitive systems, 0-1 for high security)

### Check 36: Interactive Login (LocalAccountTokenFilterPolicy)

[+] LocalAccountTokenFilterPolicy not set (default: filtered).
[+] LocalAccountTokenFilterPolicy (Wow6432Node):  (OK)

### Check 37: WDigest Credential Caching

[*] WDigest UseLogonCredential not configured. Default depends on OS version (disabled on Win 8.1+).

### Check 38: Restrict RPC Clients

[*] RestrictRemoteClients:  (not configured, default applies)

### Check 39: RDP Network Level Authentication

[+] RDP NLA (UserAuthentication) is enabled.
[*] RDP MinEncryptionLevel: 2 (Client Compatible)

## Network Checks

### Check 40: IPv4 Interfaces

[*] IPv4: 192.168.100.12

### Check 41: IPv6 Interfaces

[*] IPv6 link-local: fe80
[+] No non-link-local IPv6 addresses detected.

### Check 42: WPAD Configuration

[*] No WPAD entry in hosts file.
[*] WinHTTP Auto-Proxy Service is running.

### Check 43: WINS Configuration

[+] DNSEnabledForWINSResolution: FALSE
[-] WINSEnableLMHostsLookup: TRUE. Consider disabling LMHOSTS lookup.

### Check 44: LLMNR

[-] EnableMulticast not configured. LLMNR is likely enabled by default.

### Check 45: Computer Browser Service

[+] Computer Browser service is not installed.

### Check 46: NetBIOS over TCP/IP

[*] TcpipNetbiosOptions: 0 (Default - DHCP controlled)

### Check 47: Network Connections

[*] Active network connections (netstat -ano):
[*]   Active Connections
[*]   Proto  Local Address          Foreign Address        State           PID
[*]   TCP    0.0.0.0:22             0.0.0.0:0              LISTENING       3416
[*]   TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       528
[*]   TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
[*]   TCP    0.0.0.0:5040           0.0.0.0:0              LISTENING       5192
[*]   TCP    0.0.0.0:5357           0.0.0.0:0              LISTENING       4
[*]   TCP    0.0.0.0:7680           0.0.0.0:0              LISTENING       2744
[*]   TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING       836
[*]   TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING       684
[*]   TCP    0.0.0.0:49666          0.0.0.0:0              LISTENING       1480
[*]   TCP    0.0.0.0:49667          0.0.0.0:0              LISTENING       2084
[*]   TCP    0.0.0.0:49669          0.0.0.0:0              LISTENING       2936
[*]   TCP    0.0.0.0:49670          0.0.0.0:0              LISTENING       824
[*]   TCP    192.168.100.12:22      192.168.1.24:42102     ESTABLISHED     3416
[*]   TCP    192.168.100.12:139     0.0.0.0:0              LISTENING       4
[*]   TCP    192.168.100.12:50099   104.208.203.90:443     ESTABLISHED     3512
[*]   TCP    [::]:22                [::]:0                 LISTENING       3416
[*]   TCP    [::]:135               [::]:0                 LISTENING       528
[*]   TCP    [::]:445               [::]:0                 LISTENING       4
[*]   TCP    [::]:5357              [::]:0                 LISTENING       4
[*]   TCP    [::]:7680              [::]:0                 LISTENING       2744
[*]   TCP    [::]:49664             [::]:0                 LISTENING       836
[*]   TCP    [::]:49665             [::]:0                 LISTENING       684
[*]   TCP    [::]:49666             [::]:0                 LISTENING       1480
[*]   TCP    [::]:49667             [::]:0                 LISTENING       2084
[*]   TCP    [::]:49669             [::]:0                 LISTENING       2936
[*]   TCP    [::]:49670             [::]:0                 LISTENING       824
[*]   UDP    0.0.0.0:3702           *:*                                    4312
[*]   UDP    0.0.0.0:3702           *:*                                    3768
[*]   UDP    0.0.0.0:3702           *:*                                    4312
[*]   UDP    0.0.0.0:3702           *:*                                    3768
[*]   UDP    0.0.0.0:5050           *:*                                    5192
[*]   UDP    0.0.0.0:5353           *:*                                    1964
[*]   UDP    0.0.0.0:5355           *:*                                    1964
[*]   UDP    0.0.0.0:51392          *:*                                    3768
[*]   UDP    0.0.0.0:58350          *:*                                    4312
[*]   UDP    127.0.0.1:1900         *:*                                    4280
[*]   UDP    127.0.0.1:51391        *:*                                    4280
[*]   UDP    127.0.0.1:56915        127.0.0.1:56915                        3252
[*]   UDP    192.168.100.12:137     *:*                                    4
[*]   UDP    192.168.100.12:138     *:*                                    4
[*]   UDP    192.168.100.12:1900    *:*                                    4280
[*]   UDP    192.168.100.12:51390   *:*                                    4280
[*]   UDP    [::]:3702              *:*                                    4312
[*]   UDP    [::]:3702              *:*                                    4312
[*]   UDP    [::]:3702              *:*                                    3768
[*]   UDP    [::]:3702              *:*                                    3768
[*]   UDP    [::]:5353              *:*                                    1964
[*]   UDP    [::]:5355              *:*                                    1964
[*]   UDP    [::]:51393             *:*                                    3768
[*]   UDP    [::]:58351             *:*                                    4312
[*]   UDP    [::1]:1900             *:*                                    4280
[*]   UDP    [::1]:51389            *:*                                    4280
[*]   UDP    [fe80::6c54:1978:1995:37b7%14]:1900  *:*                                    4280
[*]   UDP    [fe80::6c54:1978:1995:37b7%14]:51388  *:*                                    4280

### Check 48: Firewall Profiles

[*] Firewall profile status:
[*]   Domain Profile Settings: 
[*]   ----------------------------------------------------------------------
[*]   State                                 ON
[*]   Firewall Policy                       BlockInbound,AllowOutbound
[*]   LocalFirewallRules                    N/A (GPO-store only)
[*]   LocalConSecRules                      N/A (GPO-store only)
[*]   InboundUserNotification               Enable
[*]   RemoteManagement                      Disable
[*]   UnicastResponseToMulticast            Enable
[*]   Logging:
[*]   LogAllowedConnections                 Disable
[*]   LogDroppedConnections                 Disable
[*]   FileName                              %systemroot%\system32\LogFiles\Firewall\pfirewall.log
[*]   MaxFileSize                           4096
[*]   Private Profile Settings: 
[*]   ----------------------------------------------------------------------
[*]   State                                 ON
[*]   Firewall Policy                       BlockInbound,AllowOutbound
[*]   LocalFirewallRules                    N/A (GPO-store only)
[*]   LocalConSecRules                      N/A (GPO-store only)
[*]   InboundUserNotification               Enable
[*]   RemoteManagement                      Disable
[*]   UnicastResponseToMulticast            Enable
[*]   Logging:
[*]   LogAllowedConnections                 Disable
[*]   LogDroppedConnections                 Disable
[*]   FileName                              %systemroot%\system32\LogFiles\Firewall\pfirewall.log
[*]   MaxFileSize                           4096
[*]   Public Profile Settings: 
[*]   ----------------------------------------------------------------------
[*]   State                                 ON
[*]   Firewall Policy                       BlockInbound,AllowOutbound
[*]   LocalFirewallRules                    N/A (GPO-store only)
[*]   LocalConSecRules                      N/A (GPO-store only)
[*]   InboundUserNotification               Enable
[*]   RemoteManagement                      Disable
[*]   UnicastResponseToMulticast            Enable
[*]   Logging:
[*]   LogAllowedConnections                 Disable
[*]   LogDroppedConnections                 Disable
[*]   FileName                              %systemroot%\system32\LogFiles\Firewall\pfirewall.log
[*]   MaxFileSize                           4096
[*]   Ok.

### Check 49: TCP/IP Stack Hardening

[*] DisableIPSourceRouting not configured.
[*] EnableICMPRedirect not configured (default: enabled).
[*] PerformRouterDiscovery not configured.

## PowerShell Checks

### Check 50: PowerShell Versions

[*] PowerShell Versions: Not available in CMD. Requires PowerShell runtime.

### Check 51: PowerShell Language Mode

[*] PowerShell Language Mode: Not available in CMD. Requires PowerShell runtime.

### Check 52: PowerShell Module Logging

[-] PowerShell Module Logging is not enabled. Recommend enabling for audit visibility.

### Check 53: PowerShell Script Block Logging

[-] Script Block Logging is not enabled. Recommend enabling for threat detection.
[*] Script Block Invocation Logging:  (optional, can be noisy)

### Check 54: PowerShell Transcription

[-] PowerShell Transcription is not enabled. Recommend enabling.
[*] Transcription EnableInvocationHeader: 
[*] Transcription OutputDirectory not configured (default location).

### Check 55: PowerShell Protected Event Logging

[*] Protected Event Logging is not enabled: 

### Check 56: WinRM Service

[+] WinRM service is installed but stopped.
[*] WinRM HTTP-In firewall rule:
[*]   Rule Name:                            Windows Remote Management (HTTP-In)
[*]   ----------------------------------------------------------------------
[*]   Enabled:                              No
[*]   Direction:                            In
[*]   Profiles:                             Domain,Private
[*]   Grouping:                             Windows Remote Management
[*]   LocalIP:                              Any
[*]   RemoteIP:                             Any
[*]   Protocol:                             TCP
[*]   LocalPort:                            5985
[*]   RemotePort:                           Any
[*]   Edge traversal:                       No
[*]   Action:                               Allow
[*]   Rule Name:                            Windows Remote Management (HTTP-In)
[*]   ----------------------------------------------------------------------
[*]   Enabled:                              No
[*]   Direction:                            In
[*]   Profiles:                             Public
[*]   Grouping:                             Windows Remote Management
[*]   LocalIP:                              Any
[*]   RemoteIP:                             LocalSubnet
[*]   Protocol:                             TCP
[*]   LocalPort:                            5985
[*]   RemotePort:                           Any
[*]   Edge traversal:                       No
[*]   Action:                               Allow
[*]   Ok.

## Logging Checks

### Check 57: Event Log Sizes

[*] Application maxSize: 20971520 bytes
[*] Security maxSize: 20971520 bytes
[*] System maxSize: 20971520 bytes
[*] Windows PowerShell: log not found or not accessible.
[*] Microsoft-Windows-PowerShell/Operational maxSize: 15728640 bytes
[*] Microsoft-Windows-Sysmon/Operational maxSize: 67108864 bytes
[*] Microsoft-Windows-TaskScheduler/Operational maxSize: 10485760 bytes
[*] Microsoft-Windows-Windows Firewall With Advanced Security/Firewall: log not found or not accessible.
[*] Microsoft-Windows-TerminalServices-LocalSessionManager/Operational maxSize: 1052672 bytes
[*] Microsoft-Windows-WMI-Activity/Operational maxSize: 1052672 bytes
[*] Microsoft-Windows-DNS-Client/Operational maxSize: 1052672 bytes

### Check 58: Command-Line Process Auditing

[-] Command-line process auditing is not enabled. Recommend enabling for forensic visibility.

### Check 59: Windows Script Host

[*] Windows Script Host Enabled value:  (default: enabled)

---

## Report Footer

| Field | Value |
| ----- | ----- |
| Script | chaps.bat 1.0.0 |
| Computer | DESKTOP-PSI6556 |
| Completed | Mon 04/13/2026 22:05:08.51 |

---

*CHAPS Audit Script: chaps.bat 1.0.0*
*Brought to you by Cutaway Security, LLC*
*For assessment and auditing help, contact info [@] cutawaysecurity.com*
*For script help, contact dev [@] cutawaysecurity.com*

