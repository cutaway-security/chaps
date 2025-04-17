# Configuration Hardening Assessment PowerShell Script (CHAPS)
CHAPS is a PowerShell script for checking system security settings where additional software and assessment tools, such as Microsoft Policy Analyzer, cannot be installed. The purpose of this script is to run it on a server or workstation to collect configuration information about that system. The information collected can then be used to provide recommendations (and references) to improve the security of the individual system and systemic issues within the organization's Windows environment. Examples of environments where this script is useful include Industrial Control System (ICS) environments where systems cannot be modified. These systems include Engineer / Operator workstations, Human Machine Interface (HMI) systems, and management servers that are deployed in production environments.

This script is NOT intended to be a replacement for Microsoft's Policy Analyzer. The best way to audit a system's configuration is to use the [Microsoft Security Compliance Toolkit](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-compliance-toolkit-10) and Policy Analyzer with a [Windows Workstation Security Baseline GPO](https://adsecurity.org/?p=3299). The Policy Analyzer's output can be exported an MS Excel file, but it requires the Microsoft Excel is installed on the system. Cut and pasting this information does work, but might not be an option on a physical system. Also, using the Policy Analyzer requires installation of the Windows software, which may not be permitted.

This script runs in PowerShell and should be PowerShell-version independent. Some checks may fail depending on the Windows version, system configurations, and whether or not it is run with Administrator privileges. Instances where commands did not run successfully are noted and should be manually investigated where possible.

This script was developed using information from several sources \(noted in Useful Resources section\) to identify recommended security configurations to reduce the likelihood of a compromised system and to log user events conducted on the system. It pulls heavily from the [Securing Windows Workstations](https://adsecurity.org/?p=3299) baseline outlined by [Sean Metcalf](https://adsecurity.org/?author=2). 

## How To Use
The best way to run this script within an ICS environment is to not write any programs or scripts to the system being reviewed. Do this by serving these scripts from a webserver running on another system on the network. Download CHAPS and PowerSploit into the same directory and open a terminal and change into that directory. Using Python3 run the command ```python3 -m http.server 8181```. This will start a webserver listening on all of the systems IP addresses. 

On the target system open a CMD.exe window, preferably as an Administrator. Run the command ```powershell.exe -exec bypass``` to being a PowerShell prompt. If you started a PowerShell terminal, as administrator, run the ```Set-ExecutionPolicy Bypass -scope Process``` to allow scripts to execute. From this prompt, run the following command to execute the ```chaps.ps1``` script.

```
IEX (New-Object Net.WebClient).DownloadString('http://<webserver>:8181/chaps/chaps.ps1')
```

To run the ```chaps-powershell.ps1``` script be sure to turn off the system's Anti-virus to include real-time protection. Running the following commands will import the appropriate PowerSploit scripts and then run them.

```
IEX (New-Object Net.WebClient).DownloadString('http://<webserver>:8181/PowerSploit/Recon/PowerView.ps1')
IEX (New-Object Net.WebClient).DownloadString('http://<webserver>:8181/PowerSploit/Exfiltration/Get-GPPPassword.ps1')
IEX (New-Object Net.WebClient).DownloadString('http://<webserver>:8181/PowerSploit/Exfiltration/Get-GPPAutologon.ps1')
IEX (New-Object Net.WebClient).DownloadString('http://<webserver>:8181/PowerSploit/Exfiltration/Get-VaultCredential.ps1')
IEX (New-Object Net.WebClient).DownloadString('http://<webserver>:8181/PowerSploit/Privesc/PowerUp.ps1')
IEX (New-Object Net.WebClient).DownloadString('http://<webserver>:8181/chaps/chaps-powersploit.ps1')
```

Each script's outputs will be written to the user's Temp directory as defined by the $env:temp variable. Copy these files off of the system being reviewed, delete them, and, if necessary, restart the system's anti-virus.

Print out and use the [CHAPS Assessment Guide](./chaps_steps.md) to walk through this process with the system administrators or guide your team.

## System Configuration Checks
### System Info Command
* Run the systeminfo command to get system information to run the [Windows Exploit Suggester - Next Generation](https://github.com/bitsadmin/wesng) tool. 

### System Information
* Administrator rights
  * This check determines if the user running the script has administrator rights. Some checks may not work without admin rights. Most of the checks will work, unless some security controls or configurations prevent it.
  * There is an error suppression line that has been disabled. Uncomment the line to suppress all errors. The "-ErrorAction SilentlyContinue" has also been used on some of the commands within the script.
* System information
  * System Version
  * User and Path Information
  * System IPv4 addresses. 
  * System IPv6 addresses. 
  * Windows AutoUpdate configuration.
  * Check for missing Critical and Important Updates
  * Check for BitLocker Disk Encryption
  * Check AlwaysInstallElevated Registry Keys
* PowerShell Event Log Settings
  * Determine if PowerShell Commandline Auditing is Enabled.
  * Determine if PowerShell Module Logging is Enabled.
  * Determine if PowerShell Script Block and Invocation Logging is Enabled.
  * Determine if PowerShell PowerShell Invocation Header Logging is Enabled.
  * Determine if PowerShell Protected Event Logging is Enabled.
* Windows Event Log Configurations
  * Check the maximum log file settings for critical logs:
   * Application
   * System
   * Security
   * Windows PowerShell
   * Microsoft-Windows-TerminalServices-LocalSessionManager/Operational
   * Microsoft-Windows-TaskScheduler/Operational
   * Microsoft-Windows-SMBServer/Audit
   * Microsoft-Windows-Security-Netlogon/Operational
   * Microsoft-Windows-WinRM/Operational
   * Microsoft-Windows-WMI-Activity/Operational
* PowerShell Configuration Settings
  * Version of default PowerShell
  * Check if PowerShell version 2 is permitted.
  * Determine installed versions of .NET to determine if they support PowerShell version 2.
  * Determine if PowerShell Language Mode is "ConstratinedLanguage".
* Cached Credentials
  * Check how many Cached Credentials the system is configured to maintain.
* Remote Access Configurations
  * Determine if RDP is configured to permit remote connections.
    * Check the setting of AllowRemoteRPC.
    * Check the setting of fDenyTSConnections.
 * Understand WinRM configuration.
   * Test if the WinRM Service is running using two different methods.
   * Check the Windows Firewall configuration to see if the rules to permit WinRM are enabled.
* Local Administrator Accounts
  * Determine if more than one user is a member of the Local Administrator group.

### CHAPS PowerSploit Security Checks
The PowerSploit project (dev branch) can be used to gather additional information about the system. The ```chaps-powersploit.ps1``` script has been developed to gather this information. Of course, most anti-malware programs will prevent, protect, and alert on the use of PowerSploit. Therefore, the anti-malware should be disabled or the chaps-powersploit.ps1 script should not be used, **NOTE**: anti-malware programs should be re-enabled immediately upon verification that the script ran correctly.

#### chaps-powersploit.ps1 TODO:
Here are a list of things that aren't working, need to be addressed, or are possible function requests.
* Needs to be tested in a Domain environment.
* Handle errors gracefully.
* Identify new cmdlets to run, such as ```Find-InterestingFiles``` with a list of specific files related to ICS project files.

### Secure Baseline Checks - Securing Windows Workstations

* Check AppLocker
  * Determine if AppLocker is configured to monitor scripts, at a minimum.
* Check EMET
  * If version is less than Windows 10, check that EMET service is running.
* Deploy LAPS
  * Determine if LAPS is installed. **NOTE**: not checking if it is configured or used.
* Force Group Policy to reapply settings during “refresh”
  * Determine how NoGPOListChanges is configured to see if GPOs are allied every time they are checked.
* Disable Net Session Enumeration
  * **NOTE**: For now, extra actions are required to test this. See: [TechNet script NetSessEnumPerm.ps1](https://gallery.technet.microsoft.com/scriptcenter/View-Net-Session-Enum-dfced139)
* Disable WPAD
  * Check for a WPAD entry in the Windows "etc\hosts" file.
  * Check for the WpadOverride registry key.
  * Determine if the WinHTTPAutoProxySvc is running.
  * Check if the Windows Hotfix KB3165191 is installed.
  * Check WINS configuration.
  * Determine network adapter configurations for: 
    * DNSEnabledForWINSResolution
    * WINSEnableLMHostsLookup
* Disable LLMNR
  * Determine if DNSClient.EnableMulticast is disabled.
* Disable Windows Browser Protocol
  * Determine if the Computer Browser service is running.
* Disable NetBIOS
  * Check the setting of TcpipNetbiosOptions to determine if it is disabled.
* Disable Windows Scripting
  * Check if Windows Scripting Host registry key is enabled.
  * Check if Windows Hotfix KB2871997 is installed.
  * **NOTE**: not sure how to check "Control Scripting File Extensions"
* Prevent Interactive Login
  * Check the configuration of registry key LocalAccountTokenFilterPolicy to see if it is disabled.
* Disable WDigest
  * Check the configuration of registry key WDigest.UseLogonCredential to determine if it is disabled.
* Disable SMBv1
  * Use Get-SmbServerConfiguration to check:
    * If SMBv1 is disabled.
    * If SMBv1 auditing is enabled.
* Block Untrusted Fonts on Windows 10
  * Check the registry key Kernel.MitigationOptions to determine if it is configured to block untrusted fonts.
* Enable Credential / Device Guard on Windows 10
  * Check if the Credential Guard or HVCI service is running. **NOTE**: not checking configuration settings.
  * Check if Device Guard is configured. **NOTE**: not checking configuration settings.
* Secure LanMan Authentication
  * Check if the registry key Lsa.NoLmHash is enabled.
  * Check if the registry key Lsa.LmCompatibilityLevel is configured to "Send NTLMv2 response only. Refuse LM & NTLM."
  * Check if Anonymous Enumeration of domain is restricted.
  * Check if Anonymous Enumeration of local system is restricted.
* Secure Microsoft Office
  * Not implemented at this time.
* Restrict RPC Clients
  * Determine if remote RPC client access is restricted.
* Configure NTLM session security
  * Check NTLM Session Server Security settings to determine if it requires NTLMv2 and 128-bit encryption.
  * Check NTLM Session Client Security settings to determine if it requires NTLMv2 and 128-bit encryption.

## CHAPS TODO:
Here are a list of things that aren't working, need to be addressed, or are possible function requests.
* Issues
  * WMI remoting and firewall rules may be required by Vulnerability scanning tools. Thus, if enabled, test for limiting to users and specific systems.
  * Fix PowerShell version 2 check
  * Fix .NET version check.
    * (Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -Recurse -Error Action 0| Get-ItemProperty -Name Version -ErrorAction 0) | Select-Object Version
* Useful
  * Generate lines for reporting.
    * Marked so another script can scan the result and build finding and recommendation sections for a report.
  * Check for SYSMON Program.
  * Update checks so that they are Windows version specific. E.G. Windows 10, Windows 7, Windows 2018.
  * List Installed Programs (to include x86) and programs installed directly to C: drive
  * Detect and acquire version information for JAVA, flash, and Adobe.
* Nice-To-Haves
  * Update with Domain tests, as a user specified option.
  * CMD-only (non-PowerShell) version.
  * Add checks from Carlos Perez's HoneyBadger plugin. Must be converted from Ruby to PowerShell.

## Useful Resources:
* [Securing Windows Workstations: Developing a Secure Baseline]( https://adsecurity.org/?p=3299)
* [Windows Privilege Escalation Fundamentals](http://www.fuzzysecurity.com/tutorials/16.html)
* [New tool: Policy Analyzer]( https://blogs.technet.microsoft.com/secguide/2016/01/22/new-tool-policy-analyzer/)
* [Use PowerShell to Explore Active Directory Security](https://blogs.technet.microsoft.com/heyscriptingguy/2012/03/12/use-powershell-to-explore-active-directory-security/)
* [Trimarc: Securing Active Directory: Performing an Active Directory Security Review](https://www.hub.trimarcsecurity.com/post/securing-active-directory-performing-an-active-directory-security-review)
* [Otorio: Siemens Simatic PCS 7 Hardening Tool](https://github.com/otoriocyber/PCS7-Hardening-Tool)
* [Penetration Testers’ Guide to Windows 10 Privacy & Security](https://hackernoon.com/the-2017-pentester-guide-to-windows-10-privacy-security-cf734c510b8d)
* [15 Ways to Bypass the PowerShell Execution Policy](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
* **NOTE**: Additional resources are outline throughout the script as references to resources that helped outline what to check for the associated subject.

## Collaborators
I would like to thank those individuals who have helped troubleshoot and add features to this project.

* Mike Saunders [@hardwaterhacker](https://twitter.com/hardwaterhacker) - [RedSiege, LLC.](https://www.redsiege.com/)
* Brandon Workentin - [Enaxy, LLC](https://www.enaxy.com)
