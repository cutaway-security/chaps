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
The best way to run this script within an ICS environment is to not write any programs or scripts to the system being reviewed. Do this by serving these scripts from a webserver running on another system on the network. Download CHAPS and PowerSploit into the same directory and open a terminal and change into that directory. Using Python3 run the command 'python3 -m http.server 8181'. This will start a webserver listening on all of the systems IP addresses. 

On the target system open a CMD.exe window, preferably as an Administrator. Run the command `powershell.exe -exec bypass` to being a PowerShell prompt. From this prompt, run the following command to execute the `chaps.ps1` script.

```
IEX (New-Object Net.WebClient).DownloadString('http://<webserver>:8181/chaps/chaps.ps1')
```

To run the `chaps-powershell.ps1` script be sure to turn off the system's Anti-virus to include real-time protection. Running the following commands will import the appropriate PowerSploit scripts and then run them.

```
IEX (New-Object Net.WebClient).DownloadString('http://<webserver>:8181/PowerSploit/Recon/PowerView.ps1')
IEX (New-Object Net.WebClient).DownloadString('http://<webserver>:8181/PowerSploit/Exfiltration/Get-GPPPassword.ps1')
IEX (New-Object Net.WebClient).DownloadString('http://<webserver>:8181/PowerSploit/Exfiltration/Get-GPPAutologon.ps1')
IEX (New-Object Net.WebClient).DownloadString('http://<webserver>:8181/PowerSploit/Exfiltration/Get-VaultCredential.ps1')
IEX (New-Object Net.WebClient).DownloadString('http://<webserver>:8181/PowerSploit/Privesc/PowerUp.ps1')
IEX (New-Object Net.WebClient).DownloadString('http://<webserver>:8181/chaps/chaps-powersploit.ps1')
```

Script outputs will be written to the user's Temp directory as defined by the $env:emp variable.

Useful Resources:
    New tool: Policy Analyzer: https://blogs.technet.microsoft.com/secguide/2016/01/22/new-tool-policy-analyzer/
    Use PowerShell to Explore Active Directory Security: https://blogs.technet.microsoft.com/heyscriptingguy/2012/03/12/use-powershell-to-explore-active-directory-security/
    Penetration Testers’ Guide to Windows 10 Privacy & Security: https://hackernoon.com/the-2017-pentester-guide-to-windows-10-privacy-security-cf734c510b8d
    15 Ways to Bypass the PowerShell Execution Policy: https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/
#>

########## Create storage directory for files in users Temp directory at $env:temp ##############
$chaps_dest = "chaps-$(get-date -f yyyyMMdd-hhmmss)"
New-Item -ItemType directory -Path $env:temp\$chaps_dest
$out_file = "$env:temp\$chaps_dest\$Env:ComputerName-chaps.txt"
$sysinfo_file = "$env:temp\$chaps_dest\$Env:Computername-sysinfo.txt"
###############################

########## Output Header Write-Host Functions ##############
# Postive Outcomes - configurations / settings that are, at a minimum, expected.
$pos_str = "[+] "
$neg_str = "[-] "
$inf_str = "[*] "
$rep_str = "[$] "
$err_str = "[x] "
###############################

########## Check for Administrator Role ##############
$inf_str + "Start Date/Time: $(get-date -format yyyyMMddTHHmmssffzz)" | Tee-Object -FilePath $out_file -Append
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")){ 
    $neg_str + "You do not have Administrator rights. Some checks will not succeed. Note warnings." | Tee-Object -FilePath $out_file -Append
} else {
    $inf_str +  "Script running with Administrator rights." | Tee-Object -FilePath $out_file -Append
}

# Suppress All Errors? Uncomment this line
# Don't use this, we need to manually handle each error to produce Write-Err
#$ErrorActionPreference = "SilentlyContinue"
###############################

########### Gather System Info #############
$inf_str +  "Dumping System Info to seperate file\n" | Tee-Object -FilePath $out_file -Append
systeminfo  | Tee-Object -FilePath $sysinfo_file -Append
###############################

########## Check for Windows Information ##############
$inf_str + "Windows Version: $(([Environment]::OSVersion).VersionString)" | Tee-Object -FilePath $out_file -Append
$inf_str + "Windows Default Path for $env:Username : $env:Path" | Tee-Object -FilePath $out_file -Append

$inf_str + "Checking IPv4 Network Settings"
Try{
    $ips = (Get-NetIPAddress | Where AddressFamily -eq 'IPv4' | Where IPAddress -ne '127.0.0.1').IPAddress
    if ($ips -ne $null){
        foreach ($ip in $ips){
            if ($ip -ne $null){
                #$inf_str + "Host network interface assigned:" $ip
                $inf_str + "Host network interface assigned: $ip" | Tee-Object -FilePath $out_file -Append
            }
        }
    }else{
        # Use Throw function to call the Catch function
        Throw('Get-NetIPAddress error') | Tee-Object -FilePath $out_file -Append
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
                            $inf_str + "Host network interface assigned (gwmi): $i" | Tee-Object -FilePath $out_file -Append
                        }
                    }
                }
            }
        } else {
            # Use Throw function to call the Catch function
            Throw('gwmi win32_networkadapterconfiguration error') | Tee-Object -FilePath $out_file -Append
        }
    }
    Catch{
        $err_str + "Check IPv4 Network Settings failed." | Tee-Object -FilePath $out_file -Append
    }
}

$inf_str + "Checking IPv6 Network Settings" | Tee-Object -FilePath $out_file -Append
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
                        $neg_str + "Host IPv6 network interface assigned (gwmi): $i" | Tee-Object -FilePath $out_file -Append
                        $noipv6 = $false
                    }
                }
            }
        }
        if ($noipv6){
            $pos_str + "No interfaces with IPv6 network interface assigned (gwmi)." | Tee-Object -FilePath $out_file -Append
        }
    } else {
        # Use Throw function to call the Catch function
        Throw('gwmi win32_networkadapterconfiguration error') | Tee-Object -FilePath $out_file -Append
    }
}
Catch{
    $err_str + "Check IPv6 Network Settings failed (gwmi)." | Tee-Object -FilePath $out_file -Append
}

<#
Resources:
    Managing Windows Update with PowerShell: https://blogs.technet.microsoft.com/jamesone/2009/01/27/managing-windows-update-with-powershell/
#>

$inf_str + "Checking Windows AutoUpdate Configuration" | Tee-Object -FilePath $out_file -Append
# Check Auto Update Configuration
$AutoUpdateNotificationLevels= @{0="Not configured"; 1="Disabled" ; 2="Notify before download"; 3="Notify before installation"; 4="Scheduled installation"}
Try{
    $resa = ((New-Object -com "Microsoft.Update.AutoUpdate").Settings).NotificationLevel
    if ( $resa -eq 4){
        $pos_str + "Windows AutoUpdate is set to $resa : $AutoUpdateNotificationLevels.$resa" | Tee-Object -FilePath $out_file -Append
    } else {
        $neg_str + "Windows AutoUpdate is not configuration to automatically install updates: $resa : $AutoUpdateNotificationLevels.$resa" | Tee-Object -FilePath $out_file -Append
    }
}
Catch{
    $err_str + "Windows AutoUpdate test failed." | Tee-Object -FilePath $out_file -Append
}

# List KB IDs of critical and important updates that have not been applied.
<#
Gist Grimthorr/pending-updates.ps1: https://gist.github.com/Grimthorr/44727ea8cf5d3df11cf7
#>
$inf_str + "Checking for missing Windows patches with Critical or Important MsrcSeverity values. NOTE: This may take a while." | Tee-Object -FilePath $out_file -Append
Try{
    $UpdateSession = New-Object -ComObject Microsoft.Update.Session
    $UpdateSearcher = $UpdateSession.CreateupdateSearcher()
    $Updates = @($UpdateSearcher.Search("IsHidden=0 and IsInstalled=0").Updates)
    #$Updates | Select-Object Title
    $missing_updates = $Updates | Where-Object {$_.MsrcSeverity -gt 2} | Select-Object @{Name="KB"; Expression={$_.KBArticleIDs}} |Select-Object -ExpandProperty KB | Sort-Object -Unique 

    if ($missing_updates) {
        foreach ($m in $missing_updates){
            $neg_str + "Missing Critical or Important Update KB: $m" | Tee-Object -FilePath $out_file -Append
        }
    } else {
        $pos_str + "Windows system appears to be up-to-date for Critical and Important patches." | Tee-Object -FilePath $out_file -Append
    }
}
Catch{
    $err_str + "Check for Critical and Important Windows patches test failed. Review Internet or patch server connectivity." | Tee-Object -FilePath $out_file -Append
}

# Check for BitLocker Disk Encryption
$inf_str + "Checking BitLocker Encryption" | Tee-Object -FilePath $out_file -Append

Try{
    $vs = Get-BitLockerVolume -ErrorAction Stop | Where-Object {$_.VolumeType -eq 'OperatingSystem'} | Select VolumeStatus -ErrorAction Stop
	$resvs = $vs.VolumeStatus 
    if ($resvs -eq 'FullyEncrypted'){
        $pos_str + "BitLocker detected and Operating System Volume is: $resvs" | Tee-Object -FilePath $out_file -Append
    } else {
        $neg_str + "BitLocker not detected on Operating System Volume or encryption is not complete. Please check for other encryption methods: $resvs" | Tee-Object -FilePath $out_file -Append
    }
}
Catch{
	$vsm = manage-bde -status | Select-String -Pattern 'Conversion Status'
	if ($vsm -ne $null){
	    $resvsm = Select-String -Pattern 'Fully Encrypted'
		if ($resvsm -ne $null){
			$pos_str + "Operating System Volume is Fully Encrypted (manage-bde): $resvsm" | Tee-Object -FilePath $out_file -Append
		} else {
	    	$pos_str + "BitLocker not detected or encryption is not complete. Please check for other encryption methods (manage-bde): $resvsm" | Tee-Object -FilePath $out_file -Append
	    }
	} else {
		$inf_str + "BitLocker not detected. Please check for other encryption methods." | Tee-Object -FilePath $out_file -Append
	}
}

# Check AlwaysInstallElevated Registry Keys
# BugFix 20190523: Mike Saunders - RedSiege, LLC
<#
Resources:
Windows Privilege Escalation Fundamentals: http://www.fuzzysecurity.com/tutorials/16.html
Abusing MSI's Elevated Privileges: https://www.greyhathacker.net/?p=185
#>
$inf_str + "Checking if users can install software as NT AUTHORITY\SYSTEM" | Tee-Object -FilePath $out_file -Append
Try{
    Try{
        $ressysele = Get-ItemProperty -path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated' -ErrorAction stop
    }
    Catch{
        $ressysele = $null;
    }
    Try{
        $resusrele = Get-ItemProperty -path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated' -ErrorAction stop
    }
    Catch{
        $resusrele = $null;
    }

    if ($ressysele -and $resusrele){
            $neg_str + "Users can install software as NT AUTHORITY\SYSTEM." | Tee-Object -FilePath $out_file -Append
    } else {
            $pos_str + "Users cannot install software as NT AUTHORITY\SYSTEM." | Tee-Object -FilePath $out_file -Append
    }
}
Catch{
    $err_str + "Check if users can install software as NT AUTHORITY\SYSTEM failed" | Tee-Object -FilePath $out_file -Append
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

$inf_str + "Testing if PowerShell Commandline Audting is Enabled" | Tee-Object -FilePath $out_file -Append
Try{
    if ([bool](Get-ItemProperty -path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -ErrorAction SilentlyContinue).ProcessCreationIncludeCmdLine_Enabled){
        $pos_str + "ProcessCreationIncludeCmdLine_Enabled Is Set" | Tee-Object -FilePath $out_file -Append
    } else {
        $neg_str + "ProcessCreationIncludeCmdLine_Enabled Is Not Set" | Tee-Object -FilePath $out_file -Append
    }
}
Catch{
    $err_str + "Testing PowerShell Commandline Audting failed" | Tee-Object -FilePath $out_file -Append
}

$inf_str + "Testing if PowerShell Moduling is Enabled" | Tee-Object -FilePath $out_file -Append
Try{
    if ([bool](Get-ItemProperty -path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -ErrorAction SilentlyContinue).EnableModuleLogging){
        $pos_str + "EnableModuleLogging Is Set" | Tee-Object -FilePath $out_file -Append
    } else {
        $neg_str + "EnableModuleLogging Is Not Set" | Tee-Object -FilePath $out_file -Append
    }
}
Catch{
    Try{
        if ([bool](Get-ItemProperty -path 'HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -ErrorAction SilentlyContinue).EnableModuleLogging){
            $pos_str + "EnableModuleLogging Is Set" | Tee-Object -FilePath $out_file -Append
        } else {
            $neg_str + "EnableModuleLogging Is Not Set" | Tee-Object -FilePath $out_file -Append
        }
    }
    Catch{
        $err_str + "Testing PowerShell Moduling failed" | Tee-Object -FilePath $out_file -Append
    }
}

$inf_str + "Testing if PowerShell EnableScriptBlockLogging is Enabled" | Tee-Object -FilePath $out_file -Append
Try{
    if ([bool](Get-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ErrorAction SilentlyContinue).EnableScriptBlockLogging){
        $pos_str + "EnableScriptBlockLogging Is Set" | Tee-Object -FilePath $out_file -Append
    } else {
        $neg_str + "EnableScriptBlockLogging Is Not Set" | Tee-Object -FilePath $out_file -Append
    }
}
Catch{
    Try{
        if ([bool](Get-ItemProperty -path 'HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ErrorAction SilentlyContinue).EnableScriptBlockLogging){
            $pos_str + "EnableScriptBlockLogging Is Set" | Tee-Object -FilePath $out_file -Append
        } else {
            $neg_str + "EnableScriptBlockLogging Is Not Set" | Tee-Object -FilePath $out_file -Append
        }
    }
    Catch{
        $err_str + "Testing PowerShell EnableScriptBlockLogging failed" | Tee-Object -FilePath $out_file -Append
    }
}

$inf_str + "Testing if PowerShell EnableScriptBlockInvocationLogging is Enabled" | Tee-Object -FilePath $out_file -Append
Try{
    if ([bool](Get-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ErrorAction SilentlyContinue).EnableScriptBlockInvocationLogging){
        $pos_str + "EnableScriptBlockInvocationLogging Is Set" | Tee-Object -FilePath $out_file -Append
    } else {
        $neg_str + "EnableScriptBlockInvocationLogging Is Not Set" | Tee-Object -FilePath $out_file -Append
    }
}
Catch{
    Try{
        if ([bool](Get-ItemProperty -path 'HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ErrorAction SilentlyContinue).EnableScriptBlockInvocationLogging){
            $pos_str + "EnableScriptBlockInvocationLogging Is Set" | Tee-Object -FilePath $out_file -Append
        } else {
            $neg_str + "EnableScriptBlockInvocationLogging Is Not Set" | Tee-Object -FilePath $out_file -Append
        }
    }
    Catch{
        $err_str + "Testing PowerShell EnableScriptBlockInvocationLogging failed" | Tee-Object -FilePath $out_file -Append
    }
}

$inf_str + "Testing if PowerShell EnableTranscripting is Enabled" | Tee-Object -FilePath $out_file -Append
Try{
    if ([bool](Get-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription' -ErrorAction SilentlyContinue).EnableTranscripting){
        $pos_str + "EnableTranscripting Is Set" | Tee-Object -FilePath $out_file -Append
    } else {
        $neg_str + "EnableTranscripting Is Not Set" | Tee-Object -FilePath $out_file -Append
    }
}
Catch{
    Try{
        if ([bool](Get-ItemProperty -path 'HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription' -ErrorAction SilentlyContinue).EnableTranscripting){
            $pos_str + "EnableTranscripting Is Set" | Tee-Object -FilePath $out_file -Append
        } else {
            $neg_str + "EnableTranscripting Is Not Set" | Tee-Object -FilePath $out_file -Append
        }
    }
    Catch{
        $err_str + "Testing PowerShell EnableTranscripting failed" | Tee-Object -FilePath $out_file -Append
    }
}

$inf_str + "Testing if PowerShell EnableInvocationHeader is Enabled" | Tee-Object -FilePath $out_file -Append
Try{
    if ([bool](Get-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription' -ErrorAction SilentlyContinue).EnableInvocationHeader){
        $pos_str + "EnableInvocationHeader Is Set" | Tee-Object -FilePath $out_file -Append
    } else {
        $neg_str + "EnableInvocationHeader Is Not Set" | Tee-Object -FilePath $out_file -Append
    }
}
Catch{
    Try{
        if ([bool](Get-ItemProperty -path 'HKLM:\Software\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription' -ErrorAction SilentlyContinue).EnableInvocationHeader){
            $pos_str + "EnableInvocationHeader Is Set" | Tee-Object -FilePath $out_file -Append
        } else {
            $neg_str + "EnableInvocationHeader Is Not Set" | Tee-Object -FilePath $out_file -Append
        }
    }
    Catch{
        $err_str + "Testing PowerShell EnableInvocationHeader failed" | Tee-Object -FilePath $out_file -Append
    }
}

$inf_str + "Testing if PowerShell ProtectedEventLogging is Enabled" | Tee-Object -FilePath $out_file -Append
Try{
    if ([bool](Get-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\ProtectedEventLogging' -ErrorAction SilentlyContinue).EnableProtectedEventLogging){
        $pos_str + "EnableProtectedEventLogging Is Set" | Tee-Object -FilePath $out_file -Append
    } else {
        $neg_str + "EnableProtectedEventLogging Is Not Set" | Tee-Object -FilePath $out_file -Append
    }
}
Catch{
    Try{
        if ([bool](Get-ItemProperty -path 'HKLM:\Software\Wow6432Node\Policies\Microsoft\Windows\EventLog\ProtectedEventLogging' -ErrorAction SilentlyContinue).EnableProtectedEventLogging){
            $pos_str + "EnableProtectedEventLogging Is Set" | Tee-Object -FilePath $out_file -Append
        } else {
            $neg_str + "EnableProtectedEventLogging Is Not Set" | Tee-Object -FilePath $out_file -Append
        }
    }
    Catch{
        $err_str + "Testing PowerShell ProtectedEventLogging failed" | Tee-Object -FilePath $out_file -Append
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

$inf_str + "Event logs settings defaults are too small. Test that max sizes have been increased." | Tee-Object -FilePath $out_file -Append

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
            #$neg_str + $l "max log size is smaller than $logs[$l] GB: $lsize GB" | Tee-Object -FilePath $out_file -Append
            $neg_str + "$l max log size is smaller than $logs[$l] GB: $lsize GB" | Tee-Object -FilePath $out_file -Append
        } else {
            #$pos_str + $l "max log size is okay: $lsize GB" | Tee-Object -FilePath $out_file -Append
            $pos_str + "$l max log size is okay: $lsize GB" | Tee-Object -FilePath $out_file -Append
        }
    }
    Catch{
        $err_str + "Testing $l log size failed." | Tee-Object -FilePath $out_file -Append
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

$inf_str + "Testing if PowerShell Version is at least version 5" | Tee-Object -FilePath $out_file -Append
Try{
    $psver = $PSVersionTable.PSVersion.Major
    $fpsver = $PSVersionTable.PSVersion
    if ([int]$psver -lt 5) { 
        $neg_str + "Current PowerShell Version is less than Version 5: $fpsver"  | Tee-Object -FilePath $out_file -Append
    } else { 
        $pos_str + "Current PowerShell Version: $fpsver" | Tee-Object -FilePath $out_file -Append
    }
}
Catch{
    $err_str + "Testing PowerShell Version failed." | Tee-Object -FilePath $out_file -Append
}

$inf_str + "Testing if PowerShell Version 2 is permitted" | Tee-Object -FilePath $out_file -Append
Try{
    # NOTE: Workstation test. Servers would need to test "Get-WindowsFeature PowerShell-V2"
    $psver2 = (Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2).state
    if ($psver2 -ne $null){
        if ($psver2 -eq 'Enabled') { 
            $neg_str + "PowerShell Version 2 should be disabled: $psver2" | Tee-Object -FilePath $out_file -Append
        } else { 
            $pos_str + "PowerShell Version 2 is: $psver2" | Tee-Object -FilePath $out_file -Append
        }
    }else{
        $inf_str + "Get-WindowsOptionalFeature is not available to test if PowerShell Version 2 is permitted." | Tee-Object -FilePath $out_file -Append
    }
}
Catch{
    $err_str + "Testing for PowerShell Version 2 failed." | Tee-Object -FilePath $out_file -Append
}

$inf_str + "Testing if .NET Framework version supports PowerShell Version 2" | Tee-Object -FilePath $out_file -Append
Try{
    $netv=(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -Recurse -ErrorAction SilentlyContinue| Get-ItemProperty -Name Version -ErrorAction SilentlyContinue).Version
    foreach ($e in $netv){
        if ($e -lt 3.0) {
            $neg_str + ".NET Framework less than 3.0 installed which could allow PS2 execution: $e" | Tee-Object -FilePath $out_file -Append
        } else {
            $pos_str + ".NET Framework greater than 3.0 installed: $e" | Tee-Object -FilePath $out_file -Append
        }
    }
}
Catch{
    $err_str + "Testing for .NET vesions that support PowerShell Version 2 failed." | Tee-Object -FilePath $out_file -Append
}

# Check PowerShell Language Mode. It should be "ConstrainedLanguage"
<#
Resources:
    Detecting Offensive PowerShell Attack Tools: https://adsecurity.org/?p=2604
#>
$inf_str + "Testing if PowerShell is configured to use Constrained Language." | Tee-Object -FilePath $out_file -Append
Try{
    $ps_lang = $ExecutionContext.SessionState.LanguageMode
    if ($ps_lang -eq 'ConstrainedLanguage') { 
        $pos_str + "Execution Langugage Mode Is: $ps_lang" | Tee-Object -FilePath $out_file -Append
    } else  { 
        $neg_str + "Execution Langugage Mode Is Not ConstrainedLanguage: $ps_lang" | Tee-Object -FilePath $out_file -Append
    }
}
Catch{
    $err_str + "Testing for PowerShell Constrained Language failed." | Tee-Object -FilePath $out_file -Append
}
###############################

########## Cached Creds ##############
<#
Resources:
    Cached logons and CachedLogonsCount: https://blogs.technet.microsoft.com/instan/2011/12/06/cached-logons-and-cachedlogonscount/
    Cached domain logon information: https://support.microsoft.com/en-us/help/172931/cached-domain-logon-information
#>

# Cached Logons should be set to 0 or 1.
$inf_str + "Testing if system is configured to limit the number of stored credentials." | Tee-Object -FilePath $out_file -Append
Try{
    $regv = (Get-ItemProperty -path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" -ErrorAction SilentlyContinue).CachedLogonsCount
    if ([int]$regv -lt 2) {
        $pos_str + "CachedLogonsCount Is Set to: $regv" | Tee-Object -FilePath $out_file -Append
    } else {
        $neg_str + "CachedLogonsCount Is Not Set to 0 or 1: $regv" | Tee-Object -FilePath $out_file -Append
    }
}
Catch{
    $err_str + "Testing for stored credential settings failed." | Tee-Object -FilePath $out_file -Append
}

###############################
########## Remote Access ##############

<#
Resources:
    How to disable RDP access for Administrator: https://serverfault.com/questions/598278/how-to-disable-rdp-access-for-administrator/598279
    How to Remotely Enable and Disable (RDP) Remote Desktop: https://www.interfacett.com/blogs/how-to-remotely-enable-and-disable-rdp-remote-desktop/
#>

# Deny RDP Connections
$inf_str + "Testing if system is configured to prevent RDP service." | Tee-Object -FilePath $out_file -Append
Try{
    if ([bool](Get-ItemProperty -path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -ErrorAction SilentlyContinue).AllowRemoteRPC){
        $neg_str + "AllowRemoteRPC is should be set to disable RDP: 1" | Tee-Object -FilePath $out_file -Append
    } else {
        $pos_str + "AllowRemoteRPC is set to deny RDP: 0" | Tee-Object -FilePath $out_file -Append
    }
}
Catch{
    $err_str + "Testing if system prevents RDP service failed." | Tee-Object -FilePath $out_file -Append
}

$inf_str + "Testing if system is configured to deny remote access via Terminal Services." | Tee-Object -FilePath $out_file -Append
Try{
    if ([bool](Get-ItemProperty -path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -ErrorAction SilentlyContinue).fDenyTSConnections){
        $pos_str + "fDenyTSConnections is set to deny remote connections: 1" | Tee-Object -FilePath $out_file -Append
    } else {
        $neg_str + "fDenyTSConnections should be set to not allow remote connections: 0" | Tee-Object -FilePath $out_file -Append
    }
}
Catch{
    $err_str + "Testing if system denies remote access via Terminal Services failed." | Tee-Object -FilePath $out_file -Append
}

# Check if the WinRM Service is running
<#
Resources:
    NEED TO TEST IF WINRM IS LISTENING?: https://stevenmurawski.com/2015/06/need-to-test-if-winrm-is-listening/
    Enable PowerShell Remoting and check if it’s enabled: https://www.dtonias.com/enable-powershell-remoting-check-enabled/
#>

$inf_str + "Testing if WinFW Service is running." | Tee-Object -FilePath $out_file -Append
Try{
    if (Test-WSMan -ErrorAction Stop) { 
        $neg_str + "WinRM Services is running and may be accepting connections: Test-WSMan check."  | Tee-Object -FilePath $out_file -Append
    } else { 
        $pos_str + "WinRM Services is not running: Test-WSMan check."  | Tee-Object -FilePath $out_file -Append
    }   
}
Catch{
    Try{
        $ress = (Get-Service WinRM).status
        if ($ress -eq 'Stopped') { 
            $pos_str + "WinRM Services is not running: Get-Service check."  | Tee-Object -FilePath $out_file -Append
        } else { 
            $neg_str + "WinRM Services is running and may be accepting connections: Get-Service check."  | Tee-Object -FilePath $out_file -Append
        }
    }
    Catch{
        $err_str + "Testing if WimRM Service is running failed." | Tee-Object -FilePath $out_file -Append
    }
}

$inf_str + "Testing if Windows Network Firewall rules allow remote connections." | Tee-Object -FilePath $out_file -Append
Try{
    $resfw = Get-NetFirewallRule -DisplayName 'Windows Remote Management (HTTP-In)'
    foreach ($r in $resfw){
        if ($r.Enabled -eq 'False'){
            $pos_str + "WinRM Firewall Rule $r.Name is disabled." | Tee-Object -FilePath $out_file -Append
        } else {
            $neg_str + "WinRM Firewall Rule $r.Name is enabled." | Tee-Object -FilePath $out_file -Append
        }
    }
}
Catch{
    $err_str + "Testing if Windows Network Firewall rules failed." | Tee-Object -FilePath $out_file -Append
}

###############################
########## Local Administrator Accounts ##############
###############################
# BugFix 20190523: Mike Saunders - RedSiege, LLC
<#
Resources:
    Get-LocalGroupMember: https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.localaccounts/get-localgroupmember?view=powershell-5.1
#>
$inf_str + "Testing Local Administrator Accounts." | Tee-Object -FilePath $out_file -Append
Try{
    $numadmin = (Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop).Name.count
    if ([int]$numadmin -gt 1){
        $neg_str + "More than one account is in local Administrators group: $numadmin" | Tee-Object -FilePath $out_file -Append
    } else {
        $pos_str + "One account in local Administrators group." | Tee-Object -FilePath $out_file -Append
    }

    foreach ($n in (Get-LocalGroupMember -Group "Administrators").Name) {
        $inf_str + "Account in local Administrator group: $n" | Tee-Object -FilePath $out_file -Append
    }
}
# No PS Cmdlet, use net command
Catch [System.InvalidOperationException]{
    $netout = (net localgroup Administrators)
    foreach ($item in $netout){
        if ($item -match '----') {
            $index = $netout.IndexOf($item)
        }
    }

    $numadmin = $netout[($index + 1)..($netout.Length - 3)]
    if ($content.length -gt 1){
        $neg_str + "More than one account is in local Administrators group: $numadmin.length" | Tee-Object -FilePath $out_file -Append
    } else {
        $pos_str + "One account in local Administrators group." | Tee-Object -FilePath $out_file -Append
    }
}
Catch{
    $err_str + "Testing local Administrator Accounts failed." | Tee-Object -FilePath $out_file -Append
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

$inf_str + "Testing if AppLocker is configured." | Tee-Object -FilePath $out_file -Append
Try{
    $resapp = (Get-AppLockerPolicy -local -ErrorAction Stop).RuleCollectionTypes
    if ($resapp){
        $resapp_names = $resapp -join ','
        if ($resapp.Contains('Script')){
            $pos_str + "AppLocker configured to manage PowerShell scripts: $resapp_names" | Tee-Object -FilePath $out_file -Append
        } else {

            $neg_str + "AppLocker not configured to manage PowerShell scripts: $resapp_names" | Tee-Object -FilePath $out_file -Append
        }
    } else {
        $neg_str + "AppLocker not configured" | Tee-Object -FilePath $out_file -Append
    }
}
Catch{
    $err_str + "Testing for Microsoft AppLocker failed." | Tee-Object -FilePath $out_file -Append
}

###############################
# Check EMET.
###############################
# Deploy current version of EMET with recommended software settings.

Try{
    if ([System.Environment]::OSVersion.Version.Major -lt 10){
        $resemet = (get-service EMET_Service).status
        if ($resemet -eq 'Running'){
            $pos_str + "EMET Service is running." | Tee-Object -FilePath $out_file -Append
        } else {
            $neg_str + "EMET Service is not running: $resemet" | Tee-Object -FilePath $out_file -Append
        }
    } else {
        $inf_str + "EMET Service components are built into Windows 10." | Tee-Object -FilePath $out_file -Append
    }
}
Catch{
    $err_str + "Testing for Microsoft EMET service failed." | Tee-Object -FilePath $out_file -Append
}

###############################
# Deploy LAPS to manage the local Administrator (RID 500) password.
###############################
$inf_str + "Testing if Local Administrator Password Solution (LAPS) is installed." | Tee-Object -FilePath $out_file -Append
Try{
    if (Get-ChildItem ‘C:\program files\LAPS\CSE\Admpwd.dll’ -ErrorAction Stop){
        $pos_str + "Local Administrator Password Solution (LAPS) is installed." | Tee-Object -FilePath $out_file -Append
    } else {
        $neg_str + "Local Administrator Password Solution (LAPS) is not installed." | Tee-Object -FilePath $out_file -Append
    }
}
Catch{
    $err_str + "Testing for Microsoft LAPS failed." | Tee-Object -FilePath $out_file -Append
}

###############################
# GPOs configured to apply when processed, not change.
###############################
# Force Group Policy to reapply settings during “refresh”

<#
Resources:
    Group Policy objects must be reprocessed even if they have not changed.: https://www.stigviewer.com/stig/windows_server_2012_member_server/2014-01-07/finding/V-4448
#>

$inf_str + "Testing if Group Policy Objects." | Tee-Object -FilePath $out_file -Append
Try{
    $ressess = (Get-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\' -ErrorAction SilentlyContinue).NoGPOListChanges
    if ($ressess -ne $null){
        if ($ressess){
            $neg_str + "GPO settings are configured to only be applied after change: $ressess" | Tee-Object -FilePath $out_file -Append
        } else {
            $pos_str + "GPO settings are configured to be applied when GPOs are processed: $ressess" | Tee-Object -FilePath $out_file -Append
        }
    } else {
        $inf_str + "System may not be assigned GPOs." | Tee-Object -FilePath $out_file -Append
    }
}
Catch{
    $err_str + "Testing for Microsoft GPO failed." | Tee-Object -FilePath $out_file -Append
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

$inf_str + "Testing Net Session Enumeration configuration using the TechNet script NetSessEnumPerm.ps1" | Tee-Object -FilePath $out_file -Append

###############################
# Disable WPAD
###############################
# Disable WPAD
<#
Resources:
    Microsoft Security Bulletin MS16-063 - Critical: https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2016/ms16-063
#>

$inf_str + "Testing for WPAD entry in $env:systemdrive\Windows\System32\Drivers\etc\hosts" | Tee-Object -FilePath $out_file -Append
Try{
    $reswpad = Select-String -path $env:systemdrive\Windows\System32\Drivers\etc\hosts -pattern wpad
    if ($resllmnr -ne $null){
        $pos_str + "WPAD entry detected: $reswpad" | Tee-Object -FilePath $out_file -Append
    } else {
        $neg_str + "No WPAD entry detected. Should contain: wpad 255.255.255.255" | Tee-Object -FilePath $out_file -Append
    }
}
Catch{
    $err_str + "Testing for WPAD in /etc/hosts failed." | Tee-Object -FilePath $out_file -Append
}

$inf_str + "Testing for WPADOverride registry key." | Tee-Object -FilePath $out_file -Append
Try{
    $reswpad2 = (Get-ItemProperty -path 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad' -ErrorAction SilentlyContinue).WpadOverride
    if ($reswpad2 -ne $null){
        if ($reswpad2){
            $pos_str + "WpadOverride registry key is configured to disable WPAD: $reswpad2" | Tee-Object -FilePath $out_file -Append
        } else {
            $neg_str + "WpadOverride registry key is configured to allow WPAD: $reswpad2" | Tee-Object -FilePath $out_file -Append
        }
    } else {
        $inf_str + "System not configured with the WpadOverride registry key." | Tee-Object -FilePath $out_file -Append
    }
}
Catch{
    $err_str + "Testing for WpadOverride registry key failed." | Tee-Object -FilePath $out_file -Append
}

$inf_str + "Testing WinHttpAutoProxySvc configuration." | Tee-Object -FilePath $out_file -Append
Try{
    $reswpads = (Get-Service -name WinHttpAutoProxySvc).Status
    if ($reswpads -ne $null){
        if ($reswpads -eq 'Running'){
            $neg_str + "WinHttpAutoProxySvc service is: $reswpads" | Tee-Object -FilePath $out_file -Append
        } else {
            $pos_str + "WinHttpAutoProxySvc service is: $reswpads" | Tee-Object -FilePath $out_file -Append
        }
    } else {
        $inf_str + "WinHttpAutoProxySvc service was not found: $reswpads" | Tee-Object -FilePath $out_file -Append
    }
}
Catch{
    $err_str + "Testing for WinHttpAutoProxySvc failed." | Tee-Object -FilePath $out_file -Append
}

# Deploy security back-port patch (KB3165191).
$inf_str + "Testing if KB3165191 is installed to harden WPAD by check installation date." | Tee-Object -FilePath $out_file -Append
Try{
    $reswphf = (Get-HotFix -id KB3165191 -ErrorAction SilentlyContinue).InstalledOn
    if ($reswphf -ne $null){
        $pos_str + "KB3165191 to harden WPAD is installed: $reswphf" | Tee-Object -FilePath $out_file -Append
    } else {
        $neg_str + "KB3165191 to harden WPAD is not installed." | Tee-Object -FilePath $out_file -Append
    }
}
Catch{
    $err_str + "Testing for WPAD KB3165191 failed." | Tee-Object -FilePath $out_file -Append
}

# NetBIOS configuration tested later.

# Check WINS configuration.
$inf_str + "Testing if Network Adapters are configured to enable WINS Resolution: DNSEnabledForWINSResolution" | Tee-Object -FilePath $out_file -Append
Try{
    if ([bool](Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=TRUE").DNSEnabledForWINSResolution){
        $neg_str + "DNSEnabledForWINSResolution is enabled" | Tee-Object -FilePath $out_file -Append
    } else {
        $pos_str + "DNSEnabledForWINSResolution is disabled" | Tee-Object -FilePath $out_file -Append
    }
}
Catch{
    $err_str + "Testing for WINS Resolution: DNSEnabledForWINSResolution failed." | Tee-Object -FilePath $out_file -Append
}

$inf_str + "Testing if Network Adapters are configured to enable WINS Resolution: WINSEnableLMHostsLookup" | Tee-Object -FilePath $out_file -Append
Try{
    if ([bool](Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=TRUE").WINSEnableLMHostsLookup){
        $neg_str + "WINSEnableLMHostsLookup is enabled" | Tee-Object -FilePath $out_file -Append
    } else {
        $pos_str + "WINSEnableLMHostsLookup is disabled" | Tee-Object -FilePath $out_file -Append
    }
}
Catch{
    $err_str + "Testing for WINS Resolution: WINSEnableLMHostsLookup failed." | Tee-Object -FilePath $out_file -Append
}

###############################
# Disable LLMNR
###############################
$inf_str + "Testing if LLMNR is disabled." | Tee-Object -FilePath $out_file -Append
Try{
    $resllmnr = (Get-ItemProperty -path 'HKLM:\Software\policies\Microsoft\Windows NT\DNSClient' -ErrorAction SilentlyContinue).EnableMulticast
    if ($resllmnr -ne $null){
        $pos_str + "DNSClient.EnableMulticast is disabled: $resllmnr" | Tee-Object -FilePath $out_file -Append
    } else {
        $neg_str + "DNSClient.EnableMulticast does not exist or is enabled: $resllmnr" | Tee-Object -FilePath $out_file -Append
    }
}
Catch{
    $err_str + "Testing for LLMNR failed." | Tee-Object -FilePath $out_file -Append
}

###############################
# Disable Windows Browser Protocol
###############################

$inf_str + "Testing if Computer Browser service is disabled." | Tee-Object -FilePath $out_file -Append
Try{
    $resbr = (Get-Service -name Browser).Status
    if ($resbr -ne $null){
        if ($resbr -eq 'Running'){
            $neg_str + "Computer Browser service is: $resbr" | Tee-Object -FilePath $out_file -Append
        } else {
            $pos_str + "Computer Browser service is: $resbr" | Tee-Object -FilePath $out_file -Append
        }
    } else {
        $inf_str + "Computer Browser service was not found: $resbr" | Tee-Object -FilePath $out_file -Append
    }
}
Catch{
    $err_str + "Testing for Computer Browser service failed." | Tee-Object -FilePath $out_file -Append
}

###############################
# Disable NetBIOS
###############################
<#
Resources:
    Getting TCP/IP Netbios information: https://powershell.org/forums/topic/getting-tcpip-netbios-information/
#>

$inf_str + "Testing if NetBios is disabled." | Tee-Object -FilePath $out_file -Append
Try{
    $resnetb = (Get-WmiObject -Class Win32_NetWorkAdapterConfiguration -Filter "IPEnabled=$true").TcpipNetbiosOptions
    if ($resnetb -eq $null){
        $neg_str + "NetBios TcpipNetbiosOptions key does not exist." | Tee-Object -FilePath $out_file -Append
    } else {
        if ([int]$resnetb -eq 2){
            $pos_str + "NetBios is Disabled: $resnetb" | Tee-Object -FilePath $out_file -Append
        } else {
            $neg_str + "NetBios is Enabled: $resnetb" | Tee-Object -FilePath $out_file -Append
        }
    }
}
Catch{
    $err_str + "Testing for NetBios failed." | Tee-Object -FilePath $out_file -Append
}

###############################
# Disable Windows Scripting
###############################
# Disable Windows Scripting Host (WSH) & Control Scripting File Extensions
$inf_str + "Testing if Windows Scripting Host (WSH) is disabled." | Tee-Object -FilePath $out_file -Append
Try{
    $ressh = (Get-ItemProperty -path 'HKLM:\Software\Microsoft\Windows Script Host\Settings').Enabled
    if ($ressh -eq $null){
        $neg_str + "WSH Setting Enabled key does not exist." | Tee-Object -FilePath $out_file -Append
    } else {
        if ($ressh){
            $neg_str + "WSH Setting Enabled key is Enabled: $ressh" | Tee-Object -FilePath $out_file -Append
        } else {
            $pos_str + "WSH Setting Enabled key is Disabled: $ressh" | Tee-Object -FilePath $out_file -Append
        }
    }
}
Catch{
    $err_str + "Testing for Windows Scripting Host (WSH) failed." | Tee-Object -FilePath $out_file -Append
}

# Deploy security back-port patch (KB2871997).
$inf_str +  "Testing if security back-port patch KB2871997 is installed by check installation date." | Tee-Object -FilePath $out_file -Append
Try{
    $reshf = (Get-HotFix -id KB2871997 -ErrorAction SilentlyContinue).InstalledOn
    if ($reshf -ne $null){
        $pos_str + "KB2871997 is installed: $reshf" | Tee-Object -FilePath $out_file -Append
    } else {
        $neg_str + "KB2871997 is not installed." | Tee-Object -FilePath $out_file -Append
    }
}
Catch{
    $err_str + "Testing for security back-port patch KB2871997 failed." | Tee-Object -FilePath $out_file -Append
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

$inf_str + "Testing if PowerShell LocalAccountTokenFilterPolicy in Policies is Disabled" | Tee-Object -FilePath $out_file -Append
Try{
    if ([bool](Get-ItemProperty -path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\system' -ErrorAction SilentlyContinue).LocalAccountTokenFilterPolicy){
        $neg_str + "LocalAccountTokenFilterPolicy Is Set" | Tee-Object -FilePath $out_file -Append
    } else {
        $pos_str + "LocalAccountTokenFilterPolicy Is Not Set" | Tee-Object -FilePath $out_file -Append
    }
}
Catch{
    $err_str + "Testing for LocalAccountTokenFilterPolicy in Policies failed." | Tee-Object -FilePath $out_file -Append
}

$inf_str + "Testing if PowerShell LocalAccountTokenFilterPolicy in Wow6432Node Policies is Disabled" | Tee-Object -FilePath $out_file -Append
Try{
    if ([bool](Get-ItemProperty -path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\policies\system' -ErrorAction SilentlyContinue).LocalAccountTokenFilterPolicy){
        $neg_str + "LocalAccountTokenFilterPolicy in Wow6432Node Is Set" | Tee-Object -FilePath $out_file -Append
    } else {
        $pos_str + "LocalAccountTokenFilterPolicy in Wow6432Node Is Not Set" | Tee-Object -FilePath $out_file -Append
    }
}
Catch{
    $err_str + "Testing for LocalAccountTokenFilterPolicy in Wow6432Node failed." | Tee-Object -FilePath $out_file -Append
}

###############################
# Disable WDigest
###############################
# Ensure WDigest is disabled

$inf_str + "Testing if WDigest is disabled."
Try{
    $reswd = (Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest').UseLogonCredential
    if ($reswd -eq $null){
        $neg_str + "WDigest UseLogonCredential key does not exist." | Tee-Object -FilePath $out_file -Append
    } else {
        if ($reswd){
            $neg_str + "WDigest UseLogonCredential key is Enabled: $reswd" | Tee-Object -FilePath $out_file -Append
        } else {
            $pos_str + "WDigest UseLogonCredential key is Disabled: $reswd" | Tee-Object -FilePath $out_file -Append
        }
    }
}
Catch{
    $err_str + "Testing for WDigest failed." | Tee-Object -FilePath $out_file -Append
}

###############################
# Disable SMBV1
###############################
# Check if SMBv1 is available and if auditing is turned on.
<#
Resources:
    Stop using SMB1: https://blogs.technet.microsoft.com/filecab/2016/09/16/stop-using-smb1/
    How to detect, enable and disable SMBv1, SMBv2, and SMBv3 in Windows and Windows Server: https://support.microsoft.com/en-us/help/2696547/how-to-detect-enable-and-disable-smbv1-smbv2-and-smbv3-in-windows-and
    Detecting and remediating SMBv1: https://blogs.technet.microsoft.com/leesteve/2017/05/11/detecting-and-remediating-smbv1/
#>

# Remove SMB v1 support
$inf_str + "Testing if SMBv1 is disabled." | Tee-Object -FilePath $out_file -Append
Try{
    $smbConfig = Get-SmbServerConfiguration
    if ($smbConfig.EnableSMB1Protocol) {
        $neg_str + "SMBv1 is Enabled" | Tee-Object -FilePath $out_file -Append
    } else {
        $pos_str + "SMBv1 is Disabled" | Tee-Object -FilePath $out_file -Append
    } 
    $inf_str + "Testing if system is configured to audit SMBv1 activity." | Tee-Object -FilePath $out_file -Append
    if ($smbConfig.AuditSmb1Access){
        $pos_str + "SMBv1 Auditing is Enabled"  | Tee-Object -FilePath $out_file -Append
    } else { 
        $neg_str + "SMBv1 Auditing is Disabled"  | Tee-Object -FilePath $out_file -Append
    }
}
Catch {
    $err_str + "Testing for SMBv1 failed." | Tee-Object -FilePath $out_file -Append   
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
    $inf_str + "Testing if Untrusted Fonts are disabled using the Kernel MitigationOptions." | Tee-Object -FilePath $out_file -Append
    Try{
        $resuf = (Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\').MitigationOptions
        if ($resuf -eq $null){
            $neg_str + "Kernel MitigationOptions key does not exist." | Tee-Object -FilePath $out_file -Append
        } else {
            if ($ressh -ge 2000000000000){
                $neg_str + "Kernel MitigationOptions key is configured not to block: $resuf" | Tee-Object -FilePath $out_file -Append
            } else {
                $pos_str + "Kernel MitigationOptions key is set to block: $resuf" | Tee-Object -FilePath $out_file -Append
            }
        }
    }
    Catch{
        $err_str + "Testing for Untrusted Fonts configuration failed." | Tee-Object -FilePath $out_file -Append
    }
} else {
    $inf_str + "Windows Version is not 10. Cannot test for Untrusted Fonts." | Tee-Object -FilePath $out_file -Append
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
    $inf_str + "Testing for Credential Guard." | Tee-Object -FilePath $out_file -Append
    Try{
        if ((Get-CimInstance –ClassName Win32_DeviceGuard –Namespace root\Microsoft\Windows\DeviceGuard).SecurityServicesRunning){
            $pos_str + "Credential Guard or HVCI service is running." | Tee-Object -FilePath $out_file -Append
        } else {
            $neg_str + "Credential Guard or HVCI service is not running." | Tee-Object -FilePath $out_file -Append
        }
    }
    Catch{
        $err_str + "Testing for Credential Guard failed." | Tee-Object -FilePath $out_file -Append
    }

    $inf_str + "Testing for Device Guard." | Tee-Object -FilePath $out_file -Append
    Try{
        if ((Get-CimInstance –ClassName Win32_DeviceGuard –Namespace root\Microsoft\Windows\DeviceGuard).AvailableSecurityProperties){
            $pos_str + "Device Guard appears to be configured." | Tee-Object -FilePath $out_file -Append
        } else {
            $neg_str + "Device Guard, no properties exist and therefore is not configured." | Tee-Object -FilePath $out_file -Append
        }
    }
    Catch{
        $err_str + "Testing for Device Guard failed." | Tee-Object -FilePath $out_file -Append
    }

} else {
    $inf_str + "Windows Version is not 10. Cannot test for Credential or Device Guard." | Tee-Object -FilePath $out_file -Append
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

$inf_str + "Testing Lanman Authentication for NoLmHash registry key." | Tee-Object -FilePath $out_file -Append
Try{
    $reslm = (Get-ItemProperty -path 'HKLM:\System\CurrentControlSet\Control\Lsa\').NoLmHash
    if ($reslm -eq $null){
        $neg_str + "NoLmHash registry key is not configured." | Tee-Object -FilePath $out_file -Append
    } else {
        if ($reslm){
            $pos_str + "NoLmHash registry key is configured: $reslm" | Tee-Object -FilePath $out_file -Append
        } else {        
            $neg_str + "NoLmHash registry key is not configured: $reslm" | Tee-Object -FilePath $out_file -Append
        }   
    }
}
Catch{
    $err_str + "Testing for NoLmHash registry key failed." | Tee-Object -FilePath $out_file -Append
}

$inf_str + "Testing Lanman Authentication for LM Compatability Level registry key." | Tee-Object -FilePath $out_file -Append
Try{
    $reslmcl = (Get-ItemProperty -path 'HKLM:\System\CurrentControlSet\Control\Lsa\').LmCompatibilityLevel
    if ($reslmcl -eq $null){
        $neg_str + "LM Compatability Level registry key is not configured." | Tee-Object -FilePath $out_file -Append
    } else {
        if ([int]$reslmcl -eq 5){
            $pos_str + "LM Compatability Level is configured correctly: $reslmcl" | Tee-Object -FilePath $out_file -Append
        } else {        
            $neg_str + "LM Compatability Level is not configured to prevent LM and NTLM: $reslmcl" | Tee-Object -FilePath $out_file -Append
        }   
    }
}
Catch{
    $err_str + "Testing for LM Compatability registry key failed." | Tee-Object -FilePath $out_file -Append
}

# Restrict Anonymous Enumeration
$inf_str + "Testing Domain and Local Anonymous Enumeration settings: RestrictAnonymous." | Tee-Object -FilePath $out_file -Append
Try{
    $resra = (Get-ItemProperty -path 'HKLM:\System\CurrentControlSet\Control\Lsa\').RestrictAnonymous 
    if ($resra -eq $null){
        $neg_str + "RestrictAnonymous registry key is not configured." | Tee-Object -FilePath $out_file -Append
    } else {
        if ($resra){
            $pos_str + "RestrictAnonymous registry key is configured: $resra" | Tee-Object -FilePath $out_file -Append
        } else {        
            $neg_str + "RestrictAnonymous registry key is not configured: $resra" | Tee-Object -FilePath $out_file -Append
        }   
    }
}
Catch{
    $err_str + "Testing for Anonymous Enumeration RestrictAnonymous failed." | Tee-Object -FilePath $out_file -Append
}

$inf_str + "Testing Domain and Local Anonymous Enumeration settings: RestrictAnonymoussam" | Tee-Object -FilePath $out_file -Append
Try{
    $resras = (Get-ItemProperty -path 'HKLM:\System\CurrentControlSet\Control\Lsa\').RestrictAnonymoussam 
    if ($resras -eq $null){
        $neg_str + "RestrictAnonymoussam registry key is not configured." | Tee-Object -FilePath $out_file -Append
    } else {
        if ($resras){
            $pos_str + "RestrictAnonymoussam registry key is configured: $resras" | Tee-Object -FilePath $out_file -Append
        } else {        
            $neg_str + "RestrictAnonymoussam registry key is not configured: $resras" | Tee-Object -FilePath $out_file -Append
        }   
    }
}
Catch{
    $err_str + "Testing for Anonymous Enumeration RestrictAnonymoussam failed." | Tee-Object -FilePath $out_file -Append
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

$inf_str + "Testing Restrict RPC Clients settings." | Tee-Object -FilePath $out_file -Append
$resrpc = (Get-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Windows NT\Rpc\' -ErrorAction SilentlyContinue).RestrictRemoteClients 
Try{
    if ($resrpc){
        $pos_str + "RestrictRemoteClients registry key is configured: $resrpc" | Tee-Object -FilePath $out_file -Append
    } else {        
        $neg_str + "RestrictRemoteClients registry key is not configured: $resrpc" | Tee-Object -FilePath $out_file -Append
    }   
}
Catch{
    $err_str + "Testing Restrict RPC Clients settings failed." | Tee-Object -FilePath $out_file -Append
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

$inf_str + "Testing NTLM Session Server Security settings." | Tee-Object -FilePath $out_file -Append
Try{
    $resntssec = (Get-ItemProperty -path 'HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0' -ErrorAction SilentlyContinue).NtlmMinServerSec
    if ([int]$resntssec -eq 537395200){
        $pos_str + "NTLM Session Server Security settings is configured to require NTLMv2 and 128-bit encryption: $resntssec" | Tee-Object -FilePath $out_file -Append
    } else {        
        $neg_str + "NTLM Session Server Security settings is not configured to require NTLMv2 and 128-bit encryption: $resntssec" | Tee-Object -FilePath $out_file -Append
    }   
}
Catch{
    $err_str + "Testing NTLM Session Server Security settings failed." | Tee-Object -FilePath $out_file -Append
}

$inf_str + "Testing NTLM Session Client Security settings." | Tee-Object -FilePath $out_file -Append
$resntcsec = (Get-ItemProperty -path 'HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0' -ErrorAction SilentlyContinue).NtlmMinClientSec
Try{
    if ([int]$resntcsec -eq 537395200){
        $pos_str + "NTLM Session Client Security settings is configured to require NTLMv2 and 128-bit encryption: $resntcsec" | Tee-Object -FilePath $out_file -Append
    } else {        
        $neg_str + "NTLM Session Client Security settings is not configured to require NTLMv2 and 128-bit encryption: $resntcsec" | Tee-Object -FilePath $out_file -Append
    }   
}
Catch{
    $err_str + "Testing NTLM Session Client Security settings failed." | Tee-Object -FilePath $out_file -Append
}

########## Windows Information ##############
$inf_str + "Completed Date/Time: $(get-date -format yyyyMMddTHHmmssffzz)" | Tee-Object -FilePath $out_file -Append
