<#
chaps.ps1 - a PowerShell script for checking system security
            when conducting an assessment of systems where
            the Microsoft Policy Analyzer and other assessment
            tools cannot be installed.
#>

<#
License: 
Copyright (c) 2019, Cutaway Security, Inc. <don@cutawaysecurity.com>
 
chaps.ps1 is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
 
chaps.ps1 is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

Point Of Contact:    Don C. Weber <don@cutawaysecurity.com>
#>

<#
There are lots of ways to run this script. For instance "15 Ways to Bypass the PowerShell Execution Policy": https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/
Obviously, these actions should be logged and generate alerts. If not, that is a finding.
    Get-Content C:\Users\<user>\Documents\chaps.ps1 | PowerShell.exe -noprofile -
    PowerShell.exe -ExecutionPolicy Bypass -File .\chaps.ps1
    "In PS. May need to be run as Administrator if this fails."
        Set-ExecutionPolicy bypass
    

The best way to audit a system's configuration is to use the Microsoft Security Compliance Manager and the Microsoft Policy Analyzer. The MS Policy Analyzer's output can be exported an MS Excel file, but it requires the MS Excel is installed on the system. Cut and pasting this information does work. However, this all requires installation of this software. This script is to help when software cannot / should not be installed.

Useful Resources:
    New tool: Policy Analyzer: https://blogs.technet.microsoft.com/secguide/2016/01/22/new-tool-policy-analyzer/
    Use PowerShell to Explore Active Directory Security: https://blogs.technet.microsoft.com/heyscriptingguy/2012/03/12/use-powershell-to-explore-active-directory-security/
    Penetration Testers’ Guide to Windows 10 Privacy & Security: https://hackernoon.com/the-2017-pentester-guide-to-windows-10-privacy-security-cf734c510b8d
    15 Ways to Bypass the PowerShell Execution Policy: https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/
#>

########### User Parameters ###################
# https://stackoverflow.com/questions/2157554/how-to-handle-command-line-arguments-in-powershell
param (
    [switch]$report = $false
)

if ($report){
    Write-Info; Write-Host "Reporting not implemented at this time."
}
###############################

########## Output Header Write-Host Functions ##############
# Postive Outcomes - configurations / settings that are, at a minimum, expected.
Function Write-Pos{
    Write-Host "[+] " -ForegroundColor Green -NoNewline;
}
# Negative Outcomes - configurations / settings that are not expected, dangerous, or unnecessarily increase risk.
Function Write-Neg{
    Write-Host "[-] " -ForegroundColor Red -NoNewline;
}
# Information Statements - general statements about the system or a test.
Function Write-Info{
    Write-Host "[*] " -ForegroundColor Blue -NoNewline;
}
# Reporting Marks - markers that can be used to automate reporting.
Function Write-Rep{
    Write-Host "[$] " -ForegroundColor Magenta -NoNewline;
}
# Error Outcomes - tests that resulted in errors. Could be, but are not necessarily,  a finding. Each should be manually reviewed.
Function Write-Err{
    Write-Host "[x] " -ForegroundColor Yellow -NoNewline;
}
###############################

########## Check for Administrator Role ##############

if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")){ 
    Write-Neg; Write-Host "You do not have Administrator rights. Some checks will not succeed. Note warnings."
} else {
    Write-Info; Write-Host "Script running with Administrator rights."
}

# Suppress All Errors? Uncomment this line
# Don't use this, we need to manually handle each error to produce Write-Err
#$ErrorActionPreference = "SilentlyContinue"

###############################

########## Check for Windows Information ##############
Write-Info; Write-Host "Start Date/Time:" $(get-date -format yyyyMMddTHHmmssffzz)
Write-Info; Write-Host "Windows Version:" ([Environment]::OSVersion).VersionString
Write-Info; Write-Host "Windows Default Path for" $env:Username ":" $env:Path

Write-Info; Write-Host "Checking IPv4 Network Settings"
Try{
    $ips = (Get-NetIPAddress | Where AddressFamily -eq 'IPv4' | Where IPAddress -ne '127.0.0.1').IPAddress
    if ($ips -ne $null){
        foreach ($ip in $ips){
            if ($ip -ne $null){
                Write-Info; Write-Host "Host network interface assigned:" $ip
            }
        }
    }else{
        # Use Throw function to call the Catch function
        Throw('Get-NetIPAddress error')
    }
}
Catch{
    Try{
        $ips = (gwmi win32_networkadapterconfiguration -filter 'ipenabled=true')
        if ($ips -ne $null){
            foreach ($ip in $ips){
                if ($ip -ne $null){
                    foreach ($i in $ip.IPAddress){
                        if ($i -notmatch ":"){
                            Write-Info; Write-Host "Host network interface assigned (gwmi):" $i
                        }
                    }
                }
            }
        } else {
            # Use Throw function to call the Catch function
            Throw('gwmi win32_networkadapterconfiguration error')
        }
    }
    Catch{
        Write-Err; Write-Host "Check IPv4 Network Settings failed."
    }
}

Write-Info; Write-Host "Checking IPv6 Network Settings"
Try{
    # Checking using gwmi tells us if IPv6 is enabled on an interface because
    # it returns an IPv6 address. Get-NetIPAddress does to, but this is easier.
    $noipv6 = $true
    $ips = (gwmi win32_networkadapterconfiguration -filter 'ipenabled=true')
    if ($ips -ne $null){
        foreach ($ip in $ips){
            if ($ip -ne $null){
                foreach ($i in $ip.IPAddress){
                    if ($i -match ":"){
                        Write-Neg; Write-Host "Host IPv6 network interface assigned (gwmi):" $i
                        $noipv6 = $false
                    }
                }
            }
        }
        if ($noipv6){
            Write-Pos; Write-Host "No interfaces with IPv6 network interface assigned (gwmi)."
        }
    } else {
        # Use Throw function to call the Catch function
        Throw('gwmi win32_networkadapterconfiguration error')
    }
}
Catch{
    Write-Err; Write-Host "Check IPv6 Network Settings failed (gwmi)."
}

<#
Resources:
    Managing Windows Update with PowerShell: https://blogs.technet.microsoft.com/jamesone/2009/01/27/managing-windows-update-with-powershell/
#>

Write-Info; Write-Host "Checking Windows AutoUpdate Configuration"
# Check Auto Update Configuration
$AutoUpdateNotificationLevels= @{0="Not configured"; 1="Disabled" ; 2="Notify before download"; 3="Notify before installation"; 4="Scheduled installation"}
Try{
    $resa = ((New-Object -com "Microsoft.Update.AutoUpdate").Settings).NotificationLevel
    if ( $resa -eq 4){
        Write-Pos; Write-Host "Windows AutoUpdate is set to" $resa ":" $AutoUpdateNotificationLevels.$resa
    } else {
        Write-Neg; Write-Host "Windows AutoUpdate is not configuration to automatically install updates:" $resa ":" $AutoUpdateNotificationLevels.$resa
    }
}
Catch{
    Write-Err; Write-Host "Windows AutoUpdate test failed."
}

# List KB IDs of critical and important updates that have not been applied.
<#
Gist Grimthorr/pending-updates.ps1: https://gist.github.com/Grimthorr/44727ea8cf5d3df11cf7
#>
Write-Info; Write-Host "Checking for missing Windows patches with Critical or Important MsrcSeverity values. NOTE: This make take a few minutes."
Try{
    $UpdateSession = New-Object -ComObject Microsoft.Update.Session
    $UpdateSearcher = $UpdateSession.CreateupdateSearcher()
    $Updates = @($UpdateSearcher.Search("IsHidden=0 and IsInstalled=0").Updates)
    #$Updates | Select-Object Title
    $missing_updates = $Updates | Where-Object {$_.MsrcSeverity -gt 2} | Select-Object @{Name="KB"; Expression={$_.KBArticleIDs}} |Select-Object -ExpandProperty KB | Sort-Object -Unique 

    if ($missing_updates) {
        foreach ($m in $missing_updates){
            Write-Neg; Write-Host "Missing Critical or Important Update KB: " $m
        }
    } else {
        Write-Pos; Write-Host "Windows system appears to be up-to-date for Critical and Important patches."
    }
}
Catch{
    Write-Err; Write-Host "Check for Critical and Important Windows patches test failed. Review Internet or patch server connectivity."
}

# Check for BitLocker Disk Encryption
Write-Info; Write-Host "Checking BitLocker Encryption"

Try{
    $vs = Get-BitLockerVolume -ErrorAction Stop | Where-Object {$_.VolumeType -eq 'OperatingSystem'} | Select VolumeStatus -ErrorAction Stop
	$resvs = $vs.VolumeStatus 
    if ($resvs -eq 'FullyEncrypted'){
        Write-Pos; Write-Host "BitLocker detected and Operating System Volume is:" $resvs
    } else {
        Write-Neg; Write-Host "BitLocker not detected on Operating System Volume or encryption is not complete. Please check for other encryption methods:" $resvs
    }
}
Catch{
	$vsm = manage-bde -status | Select-String -Pattern 'Conversion Status'
	if ($vsm -ne $null){
	    $resvsm = Select-String -Pattern 'Fully Encrypted'
		if ($resvsm -ne $null){
			Write-Pos; Write-Host "Operating System Volume is Fully Encrypted (manage-bde): " $resvsm
		} else {
	    	Write-Pos; Write-Host "BitLocker not detected or encryption is not complete. Please check for other encryption methods (manage-bde): " $resvsm
	    }
	} else {
		Write-Info; Write-Host "BitLocker not detected. Please check for other encryption methods."
	}
}

# Check AlwaysInstallElevated Registry Keys
<#
Resources:
Windows Privilege Escalation Fundamentals: http://www.fuzzysecurity.com/tutorials/16.html
#>
Write-Info; Write-Host "Checking if users can install software as NT AUTHORITY\SYSTEM"
Try{
    $ressysele = Get-ItemProperty -path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated' -ErrorAction stop
    $resusrele = Get-ItemProperty -path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated' -ErrorAction stop

    if ($ressysele -ne $null -and $resusrele -ne $null){
        $resvs = $vs.VolumeStatus
        if ($ressysele -and $resusrele){
            Write-Neg; Write-Host "Users can install software as NT AUTHORITY\SYSTEM."
        } else {
            Write-Pos; Write-Host "Users cannot install software as NT AUTHORITY\SYSTEM."
        }
    } else {
        Write-Pos; Write-Host "Users cannot install software as NT AUTHORITY\SYSTEM."
    }
}
Catch{
    Write-Err; Write-Host "Check if users can install software as NT AUTHORITY\SYSTEM failed"
}

###############################

########## PowerShell Log Settings ##############
<#
Resources:
    From PowerShell to P0W3rH3LL – Auditing PowerShell: https://www.eventsentry.com/blog/2018/01/powershell-p0wrh11-securing-powershell.html
    Practical PowerShell Security: Enable Auditing and Logging with DSC: https://blogs.technet.microsoft.com/ashleymcglone/2017/03/29/practical-powershell-security-enable-auditing-and-logging-with-dsc/
    PowerShell ♥ the Blue Team: https://blogs.msdn.microsoft.com/powershell/2015/06/09/powershell-the-blue-team/
    PowerShell Security Best Practices: https://www.digitalshadows.com/blog-and-research/powershell-security-best-practices/
    Detecting Offensive PowerShell Attack Tools: https://adsecurity.org/?p=2604
    Windows 10 Protected Event Logging: https://www.petri.com/windows-10-protected-event-logging
    WINDOWS POWERSHELL LOGGING CHEAT SHEET - Win 7/Win 2008 or later: https://static1.squarespace.com/static/552092d5e4b0661088167e5c/t/5760096ecf80a129e0b17634/1465911664070/Windows+PowerShell+Logging+Cheat+Sheet+ver+June+2016+v2.pdf0
#>

Write-Info; Write-Host "Testing if PowerShell Commandline Audting is Enabled"
Try{
    if ([bool](Get-ItemProperty -path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -ErrorAction SilentlyContinue).ProcessCreationIncludeCmdLine_Enabled){
        Write-Pos; Write-Host "ProcessCreationIncludeCmdLine_Enabled Is Set"
    } else {
        Write-Neg; Write-Host "ProcessCreationIncludeCmdLine_Enabled Is Not Set"
    }
}
Catch{
    Write-Err; Write-Host "Testing PowerShell Commandline Audting failed"
}

Write-Info; Write-Host "Testing if PowerShell Moduling is Enabled"
Try{
    if ([bool](Get-ItemProperty -path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -ErrorAction SilentlyContinue).EnableModuleLogging){
        Write-Pos; Write-Host "EnableModuleLogging Is Set"
    } else {
        Write-Neg; Write-Host "EnableModuleLogging Is Not Set"
    }
}
Catch{
    Try{
        if ([bool](Get-ItemProperty -path 'HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -ErrorAction SilentlyContinue).EnableModuleLogging){
            Write-Pos; Write-Host "EnableModuleLogging Is Set"
        } else {
            Write-Neg; Write-Host "EnableModuleLogging Is Not Set"
        }
    }
    Catch{
        Write-Err; Write-Host "Testing PowerShell Moduling failed"
    }
}

Write-Info; Write-Host "Testing if PowerShell EnableScriptBlockLogging is Enabled"
Try{
    if ([bool](Get-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ErrorAction SilentlyContinue).EnableScriptBlockLogging){
        Write-Pos; Write-Host "EnableScriptBlockLogging Is Set"
    } else {
        Write-Neg; Write-Host "EnableScriptBlockLogging Is Not Set"
    }
}
Catch{
    Try{
        if ([bool](Get-ItemProperty -path 'HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ErrorAction SilentlyContinue).EnableScriptBlockLogging){
            Write-Pos; Write-Host "EnableScriptBlockLogging Is Set"
        } else {
            Write-Neg; Write-Host "EnableScriptBlockLogging Is Not Set"
        }
    }
    Catch{
        Write-Err; Write-Host "Testing PowerShell EnableScriptBlockLogging failed"
    }
}

Write-Info; Write-Host "Testing if PowerShell EnableScriptBlockInvocationLogging is Enabled"
Try{
    if ([bool](Get-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ErrorAction SilentlyContinue).EnableScriptBlockInvocationLogging){
        Write-Pos; Write-Host "EnableScriptBlockInvocationLogging Is Set"
    } else {
        Write-Neg; Write-Host "EnableScriptBlockInvocationLogging Is Not Set"
    }
}
Catch{
    Try{
        if ([bool](Get-ItemProperty -path 'HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ErrorAction SilentlyContinue).EnableScriptBlockInvocationLogging){
            Write-Pos; Write-Host "EnableScriptBlockInvocationLogging Is Set"
        } else {
            Write-Neg; Write-Host "EnableScriptBlockInvocationLogging Is Not Set"
        }
    }
    Catch{
        Write-Err; Write-Host "Testing PowerShell EnableScriptBlockInvocationLogging failed"
    }
}

Write-Info; Write-Host "Testing if PowerShell EnableTranscripting is Enabled"
Try{
    if ([bool](Get-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription' -ErrorAction SilentlyContinue).EnableTranscripting){
        Write-Pos; Write-Host "EnableTranscripting Is Set"
    } else {
        Write-Neg; Write-Host "EnableTranscripting Is Not Set"
    }
}
Catch{
    Try{
        if ([bool](Get-ItemProperty -path 'HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription' -ErrorAction SilentlyContinue).EnableTranscripting){
            Write-Pos; Write-Host "EnableTranscripting Is Set"
        } else {
            Write-Neg; Write-Host "EnableTranscripting Is Not Set"
        }
    }
    Catch{
        Write-Err; Write-Host "Testing PowerShell EnableTranscripting failed"
    }
}

Write-Info; Write-Host "Testing if PowerShell EnableInvocationHeader is Enabled"
Try{
    if ([bool](Get-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription' -ErrorAction SilentlyContinue).EnableInvocationHeader){
        Write-Pos; Write-Host "EnableInvocationHeader Is Set"
    } else {
        Write-Neg; Write-Host "EnableInvocationHeader Is Not Set"
    }
}
Catch{
    Try{
        if ([bool](Get-ItemProperty -path 'HKLM:\Software\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription' -ErrorAction SilentlyContinue).EnableInvocationHeader){
            Write-Pos; Write-Host "EnableInvocationHeader Is Set"
        } else {
            Write-Neg; Write-Host "EnableInvocationHeader Is Not Set"
        }
    }
    Catch{
        Write-Err; Write-Host "Testing PowerShell EnableInvocationHeader failed"
    }
}

Write-Info; Write-Host "Testing if PowerShell ProtectedEventLogging is Enabled"
Try{
    if ([bool](Get-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\ProtectedEventLogging' -ErrorAction SilentlyContinue).EnableProtectedEventLogging){
        Write-Pos; Write-Host "EnableProtectedEventLogging Is Set"
    } else {
        Write-Neg; Write-Host "EnableProtectedEventLogging Is Not Set"
    }
}
Catch{
    Try{
        if ([bool](Get-ItemProperty -path 'HKLM:\Software\Wow6432Node\Policies\Microsoft\Windows\EventLog\ProtectedEventLogging' -ErrorAction SilentlyContinue).EnableProtectedEventLogging){
            Write-Pos; Write-Host "EnableProtectedEventLogging Is Set"
        } else {
            Write-Neg; Write-Host "EnableProtectedEventLogging Is Not Set"
        }
    }
    Catch{
        Write-Err; Write-Host "Testing PowerShell ProtectedEventLogging failed"
    }
}


########## Event Log Settings ##############
<#
Resources:
    Get-EventLog: https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-eventlog?view=powershell-5.1
    Recommended settings for event log sizes in Windows: https://support.microsoft.com/en-us/help/957662/recommended-settings-for-event-log-sizes-in-windows
    Hey, Scripting Guy! How Can I Check the Size of My Event Log and Then Backup and Archive It If It Is More Than Half Full?: https://blogs.technet.microsoft.com/heyscriptingguy/2009/04/08/hey-scripting-guy-how-can-i-check-the-size-of-my-event-log-and-then-backup-and-archive-it-if-it-is-more-than-half-full/
    Is there a log file for RDP connections?: https://social.technet.microsoft.com/Forums/en-US/cb1c904f-b542-4102-a8cb-e0c464249280/is-there-a-log-file-for-rdp-connections?forum=winserverTS
    WINDOWS POWERSHELL LOGGING CHEAT SHEET - Win 7/Win 2008 or later: https://static1.squarespace.com/static/552092d5e4b0661088167e5c/t/5760096ecf80a129e0b17634/1465911664070/Windows+PowerShell+Logging+Cheat+Sheet+ver+June+2016+v2.pdf0
#>

Write-Info; Write-Host "Event logs settings defaults are too small. Test that max sizes have been increased."

$logs = @{
'Application' = 4
'System' = 4
'Security' = 4
'Windows PowerShell' = 4
'Microsoft-Windows-PowerShell/Operational' = 1
'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'= 1
'Microsoft-Windows-TaskScheduler/Operational' = 1
'Microsoft-Windows-SMBServer/Audit' = 1
'Microsoft-Windows-Security-Netlogon/Operational' = 1
'Microsoft-Windows-WinRM/Operational' = 1
'Microsoft-Windows-WMI-Activity/Operational' = 1
}

foreach ($l in $logs.keys){
    Try{
        $lsize = [math]::Round((Get-WinEvent -ListLog $l -ErrorAction Stop).MaximumSizeInBytes / (1024*1024*1024),3)
        if ($lsize -lt $logs[$l]){
            Write-Neg; Write-Host $l "max log size is smaller than" $logs[$l] "GB:" $lsize "GB"
        } else {
            Write-Pos; Write-Host $l "max log size is okay:" $lsize "GB"   
        }
    }
    Catch{
        Write-Err; Write-Host "Testing" $l "log size failed."
    }
}

###############################

########## PowerShell Settings ##############

# Check PowerShell Version. Should be > 5. Powershell 2 should not be installed.
<#
Resources:
    Detecting Offensive PowerShell Attack Tools: https://adsecurity.org/?p=2604
    How to Enable or Disable Windows PowerShell 2.0 in Windows 10: https://www.tenforums.com/tutorials/111654-enable-disable-windows-powershell-2-0-windows-10-a.html
    Check Installed .NET Versions Using PowerShell: https://www.syspanda.com/index.php/2018/09/25/check-installed-net-versions-using-powershell/
    PowerShell Security Best Practices: https://www.digitalshadows.com/blog-and-research/powershell-security-best-practices/
#>

Write-Info; Write-Host "Testing if PowerShell Version is at least version 5"
Try{
    $psver = $PSVersionTable.PSVersion.Major
    $fpsver = $PSVersionTable.PSVersion
    if ([int]$psver -lt 5) { 
        Write-Neg; Write-Host "Current PowerShell Version is less than Version 5:" $fpsver 
    } else { 
        Write-Pos; Write-Host "Current PowerShell Version:" $fpsver
    }
}
Catch{
    Write-Err; Write-Host "Testing PowerShell Version failed."
}

Write-Info; Write-Host "Testing if PowerShell Version 2 is permitted"
Try{
    # NOTE: Workstation test. Servers would need to test "Get-WindowsFeature PowerShell-V2"
    $psver2 = (Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2).state
    if ($psver2 -ne $null){
        if ($psver2 -eq 'Enabled') { 
            Write-Neg; Write-Host "PowerShell Version 2 should be disabled:" $psver2 
        } else { 
            Write-Pos; Write-Host "PowerShell Version 2 is:" $psver2 
        }
    }else{
        Write-Info; Write-Host "Get-WindowsOptionalFeature is not available to test if PowerShell Version 2 is permitted."
    }
}
Catch{
    Write-Err; Write-Host "Testing for PowerShell Version 2 failed."
}

Write-Info; Write-Host "Testing if .NET Framework version supports PowerShell Version 2"
Try{
    $netv=(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -Recurse -ErrorAction SilentlyContinue| Get-ItemProperty -Name Version -ErrorAction SilentlyContinue).Version
    foreach ($e in $netv){
        if ($e -lt 3.0) {
            Write-Neg; Write-Host ".NET Framework less than 3.0 installed which could allow PS2 execution:" $e
        } else {
            Write-Pos; Write-Host ".NET Framework greater than 3.0 installed:" $e
        }
    }
}
Catch{
    Write-Err; Write-Host "Testing for .NET vesions that support PowerShell Version 2 failed."
}

# Check PowerShell Language Mode. It should be "ConstrainedLanguage"
<#
Resources:
    Detecting Offensive PowerShell Attack Tools: https://adsecurity.org/?p=2604
#>
Write-Info; Write-Host "Testing if PowerShell is configured to use Constrained Language."
Try{
    $ps_lang = $ExecutionContext.SessionState.LanguageMode
    if ($ps_lang -eq 'ConstrainedLanguage') { 
        Write-Pos; Write-Host "Execution Langugage Mode Is:" $ps_lang 
    } else  { 
        Write-Neg; Write-Host "Execution Langugage Mode Is Not ConstrainedLanguage:" $ps_lang 
    }
}
Catch{
    Write-Err; Write-Host "Testing for PowerShell Constrained Language failed."
}
###############################

########## Cached Creds ##############
<#
Resources:
    Cached logons and CachedLogonsCount: https://blogs.technet.microsoft.com/instan/2011/12/06/cached-logons-and-cachedlogonscount/
    Cached domain logon information: https://support.microsoft.com/en-us/help/172931/cached-domain-logon-information
#>

# Cached Logons should be set to 0 or 1.
Write-Info; Write-Host "Testing if system is configured to limit the number of stored credentials."
Try{
    $regv = (Get-ItemProperty -path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" -ErrorAction SilentlyContinue).CachedLogonsCount
    if ([int]$regv -lt 2) {
        Write-Pos; Write-Host "CachedLogonsCount Is Set to:" $regv
    } else {
        Write-Neg; Write-Host "CachedLogonsCount Is Not Set to 0 or 1:" $regv
    }
}
Catch{
    Write-Err; Write-Host "Testing for stored credential settings failed."
}

###############################
########## Remote Access ##############

<#
Resources:
    How to disable RDP access for Administrator: https://serverfault.com/questions/598278/how-to-disable-rdp-access-for-administrator/598279
    How to Remotely Enable and Disable (RDP) Remote Desktop: https://www.interfacett.com/blogs/how-to-remotely-enable-and-disable-rdp-remote-desktop/
#>

# Deny RDP Connections
Write-Info; Write-Host "Testing if system is configured to prevent RDP service."
Try{
    if ([bool](Get-ItemProperty -path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -ErrorAction SilentlyContinue).AllowRemoteRPC){
        Write-Neg; Write-Host "AllowRemoteRPC is should be set to disable RDP: 1"
    } else {
        Write-Pos; Write-Host "AllowRemoteRPC is set to deny RDP: 0"
    }
}
Catch{
    Write-Err; Write-Host "Testing if system prevents RDP service failed."
}

Write-Info; Write-Host "Testing if system is configured to deny remote access via Terminal Services."
Try{
    if ([bool](Get-ItemProperty -path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -ErrorAction SilentlyContinue).fDenyTSConnections){
        Write-Pos; Write-Host "fDenyTSConnections is set to deny remote connections: 1"
    } else {
        Write-Neg; Write-Host "fDenyTSConnections should be set to not allow remote connections: 0"
    }
}
Catch{
    Write-Err; Write-Host "Testing if system denies remote access via Terminal Services failed."
}

# Check if the WinRM Service is running
<#
Resources:
    NEED TO TEST IF WINRM IS LISTENING?: https://stevenmurawski.com/2015/06/need-to-test-if-winrm-is-listening/
    Enable PowerShell Remoting and check if it’s enabled: https://www.dtonias.com/enable-powershell-remoting-check-enabled/
#>

Write-Info; Write-Host "Testing if WinFW Service is running."
Try{
    if (Test-WSMan -ErrorAction Stop) { 
        Write-Neg; Write-Host "WinRM Services is running and may be accepting connections: Test-WSMan check." 
    } else { 
        Write-Pos; Write-Host "WinRM Services is not running: Test-WSMan check." 
    }   
}
Catch{
    Try{
        $ress = (Get-Service WinRM).status
        if ($ress -eq 'Stopped') { 
            Write-Pos; Write-Host "WinRM Services is not running: Get-Service check." 
        } else { 
            Write-Neg; Write-Host "WinRM Services is running and may be accepting connections: Get-Service check." 
        }
    }
    Catch{
        Write-Err; Write-Host "Testing if WimRM Service is running failed."
    }
}

Write-Info; Write-Host "Testing if Windows Network Firewall rules allow remote connections."
Try{
    $resfw = Get-NetFirewallRule -DisplayName 'Windows Remote Management (HTTP-In)'
    foreach ($r in $resfw){
        if ($r.Enabled -eq 'False'){
            Write-Pos; Write-Host "WinRM Firewall Rule" $r.Name "is disabled."
        } else {
            Write-Neg; Write-Host "WinRM Firewall Rule" $r.Name "is enabled."
        }
    }
}
Catch{
    Write-Err; Write-Host "Testing if Windows Network Firewall rules failed."
}

###############################
########## Local Administrator Accounts ##############
<#
Resources:
    Get-LocalGroupMember: https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.localaccounts/get-localgroupmember?view=powershell-5.1
#>
Write-Info; Write-Host "Testing Local Administrator Accounts."
Try{
    $numadmin = (Get-LocalGroupMember -Group "Administrators").Name.count
    if ([int]$numadmin -gt 1){
        Write-Neg; Write-Host "More than one account is in local Administrators group:" $numadmin
    } else {
        Write-Pos; Write-Host "One account in local Administrators group."
    }

    foreach ($n in (Get-LocalGroupMember -Group "Administrators").Name) {
        Write-Info; Write-Host "Account in local Administrator group:" $n
    }
}
Catch{
    Write-Err; Write-Host "Testing local Administrator Accounts failed."
}

###############################
###### Secure Baseline ##############
###############################
<#
Resources:
    Securing Windows Workstations: Developing a Secure Baseline: https://adsecurity.org/?p=3299
    Microsoft Local Administrator Password Solution (LAPS): https://adsecurity.org/?p=1790
    How to Disable LLMNR & Why You Want To: https://www.blackhillsinfosec.com/how-to-disable-llmnr-why-you-want-to/
#>

###############################
# Check AppLocker
###############################

# Deploy Microsoft AppLocker to lock down what can run on the system.

Write-Info; Write-Host "Testing if AppLocker is configured."
Try{
    $resapp = (Get-AppLockerPolicy -local -ErrorAction Stop).RuleCollectionTypes
    if ($resapp){
        $resapp_names = $resapp -join ','
        if ($resapp.Contains('Script')){
            Write-Pos; Write-Host "AppLocker configured to manage PowerShell scripts:" $resapp_names
        } else {

            Write-Neg; Write-Host "AppLocker not configured to manage PowerShell scripts:" $resapp_names
        }
    } else {
        Write-Neg; Write-Host "AppLocker not configured"
    }
}
Catch{
    Write-Err; Write-Host "Testing for Microsoft AppLocker failed."
}

###############################
# Check EMET.
###############################
# Deploy current version of EMET with recommended software settings.

Try{
    if ([System.Environment]::OSVersion.Version.Major -lt 10){
        $resemet = (get-service EMET_Service).status
        if ($resemet -eq 'Running'){
            Write-Pos; Write-Host "EMET Service is running."
        } else {
            Write-Neg; Write-Host "EMET Service is not running:" $resemet
        }
    } else {
        Write-Info; Write-Host "EMET Service components are built into Windows 10."
    }
}
Catch{
    Write-Err; Write-Host "Testing for Microsoft EMET service failed."
}

###############################
# Deploy LAPS to manage the local Administrator (RID 500) password.
###############################
Write-Info; Write-Host "Testing if Local Administrator Password Solution (LAPS) is installed."
Try{
    if (Get-ChildItem ‘C:\program files\LAPS\CSE\Admpwd.dll’ -ErrorAction Stop){
        Write-Pos; Write-Host "Local Administrator Password Solution (LAPS) is installed."
    } else {
        Write-Neg; Write-Host "Local Administrator Password Solution (LAPS) is not installed."
    }
}
Catch{
    Write-Err; Write-Host "Testing for Microsoft LAPS failed."
}

###############################
# GPOs configured to apply when processed, not change.
###############################
# Force Group Policy to reapply settings during “refresh”

<#
Resources:
    Group Policy objects must be reprocessed even if they have not changed.: https://www.stigviewer.com/stig/windows_server_2012_member_server/2014-01-07/finding/V-4448
#>

Write-Info; Write-Host "Testing if Group Policy Objects."
Try{
    $ressess = (Get-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\' -ErrorAction SilentlyContinue).NoGPOListChanges
    if ($ressess -ne $null){
        if ($ressess){
            Write-Neg; Write-Host "GPO settings are configured to only be applied after change:" $ressess
        } else {
            Write-Pos; Write-Host "GPO settings are configured to be applied when GPOs are processed:" $ressess
        }
    } else {
        Write-Info; Write-Host "System may not be assigned GPOs."
    }
}
Catch{
    Write-Err; Write-Host "Testing for Microsoft GPO failed."
}

###############################
# Disable Net Session Enumeration (NetCease)
###############################
# NetCease is run on a DC, not local system.
<#
Resources:
View Net Session Enum Permissions: https://gallery.technet.microsoft.com/scriptcenter/View-Net-Session-Enum-dfced139
Net Cease - Hardening Net Session Enumeration: https://gallery.technet.microsoft.com/Net-Cease-Blocking-Net-1e8dcb5b
#>

Write-Info; Write-Host "Testing Net Session Enumeration configuration using the TechNet script NetSessEnumPerm.ps1"

###############################
# Disable WPAD
###############################
# Disable WPAD
<#
Resources:
    Microsoft Security Bulletin MS16-063 - Critical: https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2016/ms16-063
#>

Write-Info; Write-Host "Testing for WPAD entry in" $env:systemdrive\Windows\System32\Drivers\etc\hosts
Try{
    $reswpad = Select-String -path $env:systemdrive\Windows\System32\Drivers\etc\hosts -pattern wpad
    if ($resllmnr -ne $null){
        Write-Pos; Write-Host "WPAD entry detected:" $reswpad
    } else {
        Write-Neg; Write-Host "No WPAD entry detected. Should contain: wpad 255.255.255.255"
    }
}
Catch{
    Write-Err; Write-Host "Testing for WPAD in /etc/hosts failed."
}

Write-Info; Write-Host "Testing for WPADOverride registry key."
Try{
    $reswpad2 = (Get-ItemProperty -path 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad' -ErrorAction SilentlyContinue).WpadOverride
    if ($reswpad2 -ne $null){
        if ($reswpad2){
            Write-Pos; Write-Host "WpadOverride registry key is configured to disable WPAD:" $reswpad2
        } else {
            Write-Neg; Write-Host "WpadOverride registry key is configured to allow WPAD:" $reswpad2
        }
    } else {
        Write-Info; Write-Host "System not configured with the WpadOverride registry key."
    }
}
Catch{
    Write-Err; Write-Host "Testing for WpadOverride registry key failed."
}

Write-Info; Write-Host "Testing WinHttpAutoProxySvc configuration."
Try{
    $reswpads = (Get-Service -name WinHttpAutoProxySvc).Status
    if ($reswpads -ne $null){
        if ($reswpads -eq 'Running'){
            Write-Neg; Write-Host "WinHttpAutoProxySvc service is:" $reswpads
        } else {
            Write-Pos; Write-Host "WinHttpAutoProxySvc service is:" $reswpads
        }
    } else {
        Write-Info; Write-Host "WinHttpAutoProxySvc service was not found:" $reswpads
    }
}
Catch{
    Write-Err; Write-Host "Testing for WinHttpAutoProxySvc failed."
}

# Deploy security back-port patch (KB3165191).
Write-Info; Write-Host "Testing if KB3165191 is installed to harden WPAD by check installation date."
Try{
    $reswphf = (Get-HotFix -id KB3165191 -ErrorAction SilentlyContinue).InstalledOn
    if ($reswphf -ne $null){
        Write-Pos; Write-Host "KB3165191 to harden WPAD is installed:" $reswphf
    } else {
        Write-Neg; Write-Host "KB3165191 to harden WPAD is not installed."
    }
}
Catch{
    Write-Err; Write-Host "Testing for WPAD KB3165191 failed."
}

# NetBIOS configuration tested later.

# Check WINS configuration.
Write-Info; Write-Host "Testing if Network Adapters are configured to enable WINS Resolution: DNSEnabledForWINSResolution"
Try{
    if ([bool](Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=TRUE").DNSEnabledForWINSResolution){
        Write-Neg; Write-Host "DNSEnabledForWINSResolution is enabled"
    } else {
        Write-Pos; Write-Host "DNSEnabledForWINSResolution is disabled"
    }
}
Catch{
    Write-Err; Write-Host "Testing for WINS Resolution: DNSEnabledForWINSResolution failed."
}

Write-Info; Write-Host "Testing if Network Adapters are configured to enable WINS Resolution: WINSEnableLMHostsLookup"
Try{
    if ([bool](Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=TRUE").WINSEnableLMHostsLookup){
        Write-Neg; Write-Host "WINSEnableLMHostsLookup is enabled"
    } else {
        Write-Pos; Write-Host "WINSEnableLMHostsLookup is disabled"
    }
}
Catch{
    Write-Err; Write-Host "Testing for WINS Resolution: WINSEnableLMHostsLookup failed."
}

###############################
# Disable LLMNR
###############################
Write-Info; Write-Host "Testing if LLMNR is disabled."
Try{
    $resllmnr = (Get-ItemProperty -path 'HKLM:\Software\policies\Microsoft\Windows NT\DNSClient' -ErrorAction SilentlyContinue).EnableMulticast
    if ($resllmnr -ne $null){
        Write-Pos; Write-Host "DNSClient.EnableMulticast is disabled:" $resllmnr
    } else {
        Write-Neg; Write-Host "DNSClient.EnableMulticast does not exist or is enabled:" $resllmnr
    }
}
Catch{
    Write-Err; Write-Host "Testing for LLMNR failed."
}

###############################
# Disable Windows Browser Protocol
###############################

Write-Info; Write-Host "Testing if Computer Browser service is disabled."
Try{
    $resbr = (Get-Service -name Browser).Status
    if ($resbr -ne $null){
        if ($resbr -eq 'Running'){
            Write-Neg; Write-Host "Computer Browser service is:" $resbr
        } else {
            Write-Pos; Write-Host "Computer Browser service is:" $resbr
        }
    } else {
        Write-Info; Write-Host "Computer Browser service was not found:" $resbr
    }
}
Catch{
    Write-Err; Write-Host "Testing for Computer Browser service failed."
}

###############################
# Disable NetBIOS
###############################
<#
Resources:
    Getting TCP/IP Netbios information: https://powershell.org/forums/topic/getting-tcpip-netbios-information/
#>

Write-Info; Write-Host "Testing if NetBios is disabled."
Try{
    $resnetb = (Get-WmiObject -Class Win32_NetWorkAdapterConfiguration -Filter "IPEnabled=$true").TcpipNetbiosOptions
    if ($resnetb -eq $null){
        Write-Neg; Write-Host "NetBios TcpipNetbiosOptions key does not exist."
    } else {
        if ([int]$resnetb -eq 2){
            Write-Pos; Write-Host "NetBios is Disabled:" $resnetb
        } else {
            Write-Neg; Write-Host "NetBios is Enabled:" $resnetb
        }
    }
}
Catch{
    Write-Err; Write-Host "Testing for NetBios failed."
}

###############################
# Disable Windows Scripting
###############################
# Disable Windows Scripting Host (WSH) & Control Scripting File Extensions
Write-Info; Write-Host "Testing if Windows Scripting Host (WSH) is disabled."
Try{
    $ressh = (Get-ItemProperty -path 'HKLM:\Software\Microsoft\Windows Script Host\Settings').Enabled
    if ($ressh -eq $null){
        Write-Neg; Write-Host "WSH Setting Enabled key does not exist."
    } else {
        if ($ressh){
            Write-Neg; Write-Host "WSH Setting Enabled key is Enabled:" $ressh
        } else {
            Write-Pos; Write-Host "WSH Setting Enabled key is Disabled:" $ressh
        }
    }
}
Catch{
    Write-Err; Write-Host "Testing for Windows Scripting Host (WSH) failed."
}

# Deploy security back-port patch (KB2871997).
Write-Info; Write-Host  "Testing if security back-port patch KB2871997 is installed by check installation date."
Try{
    $reshf = (Get-HotFix -id KB2871997 -ErrorAction SilentlyContinue).InstalledOn
    if ($reshf -ne $null){
        Write-Pos; Write-Host "KB2871997 is installed:" $reshf
    } else {
        Write-Neg; Write-Host "KB2871997 is not installed."
    }
}
Catch{
    Write-Err; Write-Host "Testing for security back-port patch KB2871997 failed."
}

# Not sure how to test Control Scripting File Extensions

###############################
# Prevent Interactive Login
###############################
# Prevent local Administrator (RID 500) accounts from authenticating over the network
<#
Resources:
    Disable PowerShell remoting: Disable-PSRemoting, WinRM, listener, firewall, LocalAccountTokenFilterPolicy: https://4sysops.com/wiki/disable-powershell-remoting-disable-psremoting-winrm-listener-firewall-and-localaccounttokenfilterpolicy/
    Pass-the-Hash Is Dead: Long Live LocalAccountTokenFilterPolicy: https://www.harmj0y.net/blog/redteaming/pass-the-hash-is-dead-long-live-localaccounttokenfilterpolicy/
#>

Write-Info; Write-Host "Testing if PowerShell LocalAccountTokenFilterPolicy in Policies is Disabled"
Try{
    if ([bool](Get-ItemProperty -path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\system' -ErrorAction SilentlyContinue).LocalAccountTokenFilterPolicy){
        Write-Neg; Write-Host "LocalAccountTokenFilterPolicy Is Set"
    } else {
        Write-Pos; Write-Host "LocalAccountTokenFilterPolicy Is Not Set"
    }
}
Catch{
    Write-Err; Write-Host "Testing for LocalAccountTokenFilterPolicy in Policies failed."
}

Write-Info; Write-Host "Testing if PowerShell LocalAccountTokenFilterPolicy in Wow6432Node Policies is Disabled"
Try{
    if ([bool](Get-ItemProperty -path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\policies\system' -ErrorAction SilentlyContinue).LocalAccountTokenFilterPolicy){
        Write-Neg; Write-Host "LocalAccountTokenFilterPolicy in Wow6432Node Is Set"
    } else {
        Write-Pos; Write-Host "LocalAccountTokenFilterPolicy in Wow6432Node Is Not Set"
    }
}
Catch{
    Write-Err; Write-Host "Testing for LocalAccountTokenFilterPolicy in Wow6432Node failed."
}

###############################
# Disable WDigest
###############################
# Ensure WDigest is disabled

Write-Info; Write-Host "Testing if WDigest is disabled."
Try{
    $reswd = (Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest').UseLogonCredential
    if ($reswd -eq $null){
        Write-Neg; Write-Host "WDigest UseLogonCredential key does not exist."
    } else {
        if ($reswd){
            Write-Neg; Write-Host "WDigest UseLogonCredential key is Enabled:" $reswd
        } else {
            Write-Pos; Write-Host "WDigest UseLogonCredential key is Disabled:" $reswd
        }
    }
}
Catch{
    Write-Err; Write-Host "Testing for WDigest failed."
}

###############################
# Disable SMBV1
###############################
# Check if SMBv1 is available and if signing is turned on.
<#
Resources:
    Stop using SMB1: https://blogs.technet.microsoft.com/filecab/2016/09/16/stop-using-smb1/
    How to detect, enable and disable SMBv1, SMBv2, and SMBv3 in Windows and Windows Server: https://support.microsoft.com/en-us/help/2696547/how-to-detect-enable-and-disable-smbv1-smbv2-and-smbv3-in-windows-and
    Detecting and remediating SMBv1: https://blogs.technet.microsoft.com/leesteve/2017/05/11/detecting-and-remediating-smbv1/
#>

# Remove SMB v1 support
Write-Info; Write-Host "Testing if SMBv1 is disabled."
Try{
    $ressmb = Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol 
    Write-Info; Write-Host "Testing if SMBv1 is disabled."
    if ([bool] $ressmb) { 
        Write-Neg; Write-Host "SMBv1 is Enabled" 
    } else { 
        Write-Pos; Write-Host "SMBv1 is Disabled" 
    }
    Write-Info; Write-Host "Testing if system is configured to audit SMBv1 activity."
    if ([bool](Get-SmbServerConfiguration | Select-Object AuditSmb1Access)) { 
        Write-Pos; Write-Host "SMBv1 Auditing should be Enabled: Enabled" 
    } else { 
        Write-Neg; Write-Host "SMBv1 Auditing is Disabled" 
    }
}
Catch{
    Write-Err; Write-Host "Testing for SMBv1 failed."
}

###############################
# Untrusted Fonts
###############################
# Block Untrusted Fonts
<#
Resources:
    Block untrusted fonts in an enterprise: https://docs.microsoft.com/en-us/windows/security/threat-protection/block-untrusted-fonts-in-enterprise
    How to Verify if Device Guard is Enabled or Disabled in Windows 10: https://www.tenforums.com/tutorials/68926-verify-if-device-guard-enabled-disabled-windows-10-a.html
#>

if ([System.Environment]::OSVersion.Version.Major -eq 10){
    Write-Info; Write-Host "Testing if Untrusted Fonts are disabled using the Kernel MitigationOptions."
    Try{
        $resuf = (Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\').MitigationOptions
        if ($resuf -eq $null){
            Write-Neg; Write-Host "Kernel MitigationOptions key does not exist."
        } else {
            if ($ressh -ge 2000000000000){
                Write-Neg; Write-Host "Kernel MitigationOptions key is configured not to block:" $resuf
            } else {
                Write-Pos; Write-Host "Kernel MitigationOptions key is set to block:" $resuf
            }
        }
    }
    Catch{
        Write-Err; Write-Host "Testing for Untrusted Fonts configuration failed."
    }
} else {
    Write-Info; Write-Host "Windows Version is not 10. Cannot test for Untrusted Fonts."
}

###############################
# Credential and Device Guard
###############################
# Enable Credential Guard
# Configure Device Guard
<#
Resources:
    Block untrusted fonts in an enterprise: https://docs.microsoft.com/en-us/windows/security/threat-protection/block-untrusted-fonts-in-enterprise
    How to Verify if Device Guard is Enabled or Disabled in Windows 10: https://www.tenforums.com/tutorials/68926-verify-if-device-guard-enabled-disabled-windows-10-a.html
    Security Focus: Check Credential Guard Status with PowerShell: https://blogs.technet.microsoft.com/poshchap/2016/09/23/security-focus-check-credential-guard-status-with-powershell/
#>

if ([System.Environment]::OSVersion.Version.Major -eq 10){
    Write-Info; Write-Host "Testing for Credential Guard."
    Try{
        if ((Get-CimInstance –ClassName Win32_DeviceGuard –Namespace root\Microsoft\Windows\DeviceGuard).SecurityServicesRunning){
            Write-Pos; Write-Host "Credential Guard or HVCI service is running."
        } else {
            Write-Neg; Write-Host "Credential Guard or HVCI service is not running."
        }
    }
    Catch{
        Write-Err; Write-Host "Testing for Credential Guard failed."
    }

    Write-Info; Write-Host "Testing for Device Guard."
    Try{
        if ((Get-CimInstance –ClassName Win32_DeviceGuard –Namespace root\Microsoft\Windows\DeviceGuard).AvailableSecurityProperties){
            Write-Pos; Write-Host "Device Guard appears to be configured."
        } else {
            Write-Neg; Write-Host "Device Guard, no properties exist and therefore is not configured."
        }
    }
    Catch{
        Write-Err; Write-Host "Testing for Device Guard failed."
    }

} else {
    Write-Info; Write-Host "Windows Version is not 10. Cannot test for Credential or Device Guard."
}

###############################
# Secure LanMan
###############################

#Configure Lanman Authentication to a secure setting

<#
Resources:
    Understanding the Anonymous Enumeration Policies:https://www.itprotoday.com/compute-engines/understanding-anonymous-enumeration-policies
    The LanMan authentication level must be set to send NTLMv2 response only, and to refuse LM and NTLM.: https://www.stigviewer.com/stig/windows_8/2014-01-07/finding/V-1153
#>

Write-Info; Write-Host "Testing Lanman Authentication for NoLmHash registry key."
Try{
    $reslm = (Get-ItemProperty -path 'HKLM:\System\CurrentControlSet\Control\Lsa\').NoLmHash
    if ($reslm -eq $null){
        Write-Neg; Write-Host "NoLmHash registry key is not configured."
    } else {
        if ($reslm){
            Write-Pos; Write-Host "NoLmHash registry key is configured:" $reslm
        } else {        
            Write-Neg; Write-Host "NoLmHash registry key is not configured:" $reslm
        }   
    }
}
Catch{
    Write-Err; Write-Host "Testing for NoLmHash registry key failed."
}

Write-Info; Write-Host "Testing Lanman Authentication for LM Compatability Level registry key."
Try{
    $reslmcl = (Get-ItemProperty -path 'HKLM:\System\CurrentControlSet\Control\Lsa\').LmCompatibilityLevel
    if ($reslmcl -eq $null){
        Write-Neg; Write-Host "LM Compatability Level registry key is not configured."
    } else {
        if ([int]$reslmcl -eq 5){
            Write-Pos; Write-Host "LM Compatability Level is configured correctly:" $reslmcl
        } else {        
            Write-Neg; Write-Host "LM Compatability Level is not configured to prevent LM and NTLM:" $reslmcl
        }   
    }
}
Catch{
    Write-Err; Write-Host "Testing for LM Compatability registry key failed."
}

# Restrict Anonymous Enumeration
Write-Info; Write-Host "Testing Domain and Local Anonymous Enumeration settings: RestrictAnonymous."
Try{
    $resra = (Get-ItemProperty -path 'HKLM:\System\CurrentControlSet\Control\Lsa\').RestrictAnonymous 
    if ($resra -eq $null){
        Write-Neg; Write-Host "RestrictAnonymous registry key is not configured."
    } else {
        if ($resra){
            Write-Pos; Write-Host "RestrictAnonymous registry key is configured:" $resra
        } else {        
            Write-Neg; Write-Host "RestrictAnonymous registry key is not configured:" $resra
        }   
    }
}
Catch{
    Write-Err; Write-Host "Testing for Anonymous Enumeration RestrictAnonymous failed."
}

Write-Info; Write-Host "Testing Domain and Local Anonymous Enumeration settings: RestrictAnonymoussam"
Try{
    $resras = (Get-ItemProperty -path 'HKLM:\System\CurrentControlSet\Control\Lsa\').RestrictAnonymoussam 
    if ($resras -eq $null){
        Write-Neg; Write-Host "RestrictAnonymoussam registry key is not configured."
    } else {
        if ($resras){
            Write-Pos; Write-Host "RestrictAnonymoussam registry key is configured:" $resras
        } else {        
            Write-Neg; Write-Host "RestrictAnonymoussam registry key is not configured:" $resras
        }   
    }
}
Catch{
    Write-Err; Write-Host "Testing for Anonymous Enumeration RestrictAnonymoussam failed."
}

###############################
# Secure MS Office
###############################
# Disable Office Macros
# Disable Office OLE

# Not implemented at this time.

###############################
# Restrict RPC Clients
###############################
# Configure restrictions for unauthenticated RPC clients
<#
Resources:
    Restrict Unauthenticated RPC clients: https://getadmx.com/?Category=Windows_10_2016&Policy=Microsoft.Policies.RemoteProcedureCalls::RpcRestrictRemoteClients
    Restrict unauthenticated RPC clients.: https://www.stigviewer.com/stig/windows_7/2017-12-01/finding/V-14253
#>

Write-Info; Write-Host "Testing Restrict RPC Clients settings."
$resrpc = (Get-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Windows NT\Rpc\' -ErrorAction SilentlyContinue).RestrictRemoteClients 
Try{
    if ($resrpc){
        Write-Pos; Write-Host "RestrictRemoteClients registry key is configured:" $resrpc
    } else {        
        Write-Neg; Write-Host "RestrictRemoteClients registry key is not configured:" $resrpc
    }   
}
Catch{
    Write-Err; Write-Host "Testing Restrict RPC Clients settings failed."
}

###############################
# NTLM Settings
###############################
# Configure NTLM session security
<#
Resource:
    Session security for NTLM SSP-based servers must be configured to require NTLMv2 session security and 128-bit encryption.: https://www.stigviewer.com/stig/windows_server_2016/2018-03-07/finding/V-73697
    The system is not configured to meet the minimum requirement for session security for NTLM SSP based clients.: https://www.stigviewer.com/stig/windows_7/2012-07-02/finding/V-3382
#>

Write-Info; Write-Host "Testing NTLM Session Server Security settings."
Try{
    $resntssec = (Get-ItemProperty -path 'HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0' -ErrorAction SilentlyContinue).NtlmMinServerSec
    if ([int]$resntssec -eq 537395200){
        Write-Pos; Write-Host "NTLM Session Server Security settings is configured to require NTLMv2 and 128-bit encryption:" $resntssec
    } else {        
        Write-Neg; Write-Host "NTLM Session Server Security settings is not configured to require NTLMv2 and 128-bit encryption:" $resntssec
    }   
}
Catch{
    Write-Err; Write-Host "Testing NTLM Session Server Security settings failed."
}

Write-Info; Write-Host "Testing NTLM Session Client Security settings."
$resntcsec = (Get-ItemProperty -path 'HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0' -ErrorAction SilentlyContinue).NtlmMinClientSec
Try{
    if ([int]$resntcsec -eq 537395200){
        Write-Pos; Write-Host "NTLM Session Client Security settings is configured to require NTLMv2 and 128-bit encryption:" $resntcsec
    } else {        
        Write-Neg; Write-Host "NTLM Session Client Security settings is not configured to require NTLMv2 and 128-bit encryption:" $resntcsec
    }   
}
Catch{
    Write-Err; Write-Host "Testing NTLM Session Client Security settings failed."
}

########## Windows Information ##############
Write-Info; Write-Host "Completed Date/Time:" $(get-date -format yyyyMMddTHHmmssffzz)
