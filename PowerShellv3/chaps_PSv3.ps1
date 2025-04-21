<#
    chaps_PSv3.ps1 - a PowerShell script for checking system security
    when conducting an assessment of systems where the Microsoft 
    Policy Analyzer and other assessment tools cannot be installed.

    Author: Don C. Weber (@cutaway)
    Date:   April 20, 2025
#>

<#
	License: 
	Copyright (c) 2025, Cutaway Security, Inc. <dev [@] cutawaysecurity.com>
	
	chaps_PSv3.ps1 is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.
	
	chaps_PSv3.ps1 is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.
	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.
	Point Of Contact:    Don C. Weber <dev [@] cutawaysecurity.com>
#>

param (
    # The config parameter will print the current configuration and exit
    # See Collection Parameters section to manage script behavior
    # To use `chaps_PSv3.ps1 -config`
    [switch]$Config
 )
 #############################
# Collection Parameters
# NOTE: Set these to $false to disable
#############################
## System Info Checks
$getSystemInfoCheck         = $true    
$getWinVersionCheck         = $true   
$getUserPathCheck           = $true     
$getAutoUpdateConfigCheck   = $true
$getWinPatchCheck           = $true      
$getBitLockerCheck          = $true      
$getInstallElevatedCheck    = $true
$getEMETCheck               = $true        
$getLAPSCheck               = $true       
$getGPOCheck                = $true           
$getNetSessionEnumCheck     = $false
$getAppLockerCheck          = $true   
$getCredDeviceGuardCheck    = $true
$getMSOfficeCheck           = $false     
## Security Checks
$getSMBv1Check              = $true        
$getAnonEnumCheck           = $true   
$getUntrustedFontsCheck     = $true
## Authentication Checks
$getRDPDenyCheck            = $true     
$getLocalAdminCheck         = $true  
$getNTLMSessionsCheck       = $true
$getLANMANCheck             = $true      
$getCachedLogonCheck        = $true  
$getInteractiveLoginCheck   = $true
$getWDigestCheck            = $true   
$getRestrictRDPClientsCheck = $true
## Network Checks
$getNetworkIPv4Check        = $true
$getNetworkIPv6Check        = $true
$getWPADCheck               = $true      
$getWINSConfigCheck         = $true
$getLLMNRConfigCheck        = $true
$getCompBrowserCheck        = $true  
$getNetBIOSCheck            = $true 
## PowerShell Checks
$getPSVersionCheck          = $true
$getPSLanguageCheck         = $true
$getPSModuleCheck           = $true
$getPSScriptCheck           = $true   
$getPSTranscriptCheck       = $true
$getPSProtectedCheck        = $true
$getWinRMCheck              = $true     
## Logging Checks
$getPSEventLogCheck         = $true
$getCmdAuditingCheck        = $true 
$getWinScriptingCheck       = $true


#############################
# Script behavior parameters
#############################
$cutsec_footer      = $true # change to false to disable CutSec footer
$auditor_company    = 'Cutaway Security, LLC' # make empty string to disable
$sitename           = 'plant1' # make empty string to disable
$global:admin_user  = $false # Disable some checks if not running as an Administrator
$ps_version         = $PSVersionTable.PSVersion.Major # Get major version to ensure at least PSv3

if ($ps_version -lt 3) { 
    Write-Output "ERROR: This script requires PSv3+."
    exit
}

#############################
# Set up document header information
#############################
$script_name            = 'chaps_PSv3+'
$script_version         = '1.0.1'
$filename_date	        = Get-Date -Format "yyyyddMM_HHmmss"
$start_time_readable    = Get-Date -Format "dddd MM/dd/yyyy HH:mm:ss K"
$computername           = $env:ComputerName
$sysdrive               = $env:SystemDrive
$out_dir                = $computername + "_" + $filename_date
$out_file               = "$Env:ComputerName-chaps.txt"
$sysinfo_file           = "$Env:Computername-sysinfo.txt"

############################# 
# Output Header Write-Host functions 
#############################
# Positive Outcomes - configurations / settings that are, at a minimum, expected.
$pos_str = "[+]"
$neg_str = "[-]"
$inf_str = "[*]"
$rep_str = "[$]"
$err_str = "[x]"

#############################
# Print functions
#############################
function Set-Output{
	Param(
		# Create the output directory in the local directory.
                # Change into the directory to write data.
		$indir = 'Results directory'
	)

    Write-Output "`n#############################"
    Write-Output "# Creating output directory named: $indir"
    Write-Output "#############################"
    if (-not(test-path $indir)){new-item $indir -ItemType Directory | Out-Null}
    Set-Location -Path $indir    
    if (-not(test-path $out_file)){new-item $out_file -ItemType File | Out-Null}
}

function Prt-SectionHeader{
	Param(
		# Enable means to change the setting to the default / insecure state.
		$SectionName = 'Section Name'
	)

    Write-Output "`n#############################" | Tee-Object -FilePath $out_file -Append
    Write-Output "# $SectionName" | Tee-Object -FilePath $out_file -Append
    Write-Output "#############################" | Tee-Object -FilePath $out_file -Append
}

function Prt-ReportHeader{
    Write-Output "`n#############################" | Tee-Object -FilePath $out_file -Append
    Write-Output "# CHAPS Audit Script: $script_name $script_version" | Tee-Object -FilePath $out_file -Append
    if ($auditor_company){Write-Output "# Auditing Company: $auditor_company" | Tee-Object -FilePath $out_file -Append}
    if ($sitename){Write-Output "# Site / Plant: $sitename" | Tee-Object -FilePath $out_file -Append}
    Write-Output "#############################" | Tee-Object -FilePath $out_file -Append
    Write-Output "# Hostname: $computername" | Tee-Object -FilePath $out_file -Append
    Write-Output "# Start Time: $start_time_readable" | Tee-Object -FilePath $out_file -Append
    Write-Output "# PS Version: $ps_version" | Tee-Object -FilePath $out_file -Append
    Get-AdminState
    Write-Output "#############################" | Tee-Object -FilePath $out_file -Append
}

function Prt-ReportFooter{
    $stop_time_readable = Get-Date -Format "dddd MM/dd/yyyy HH:mm:ss K"
    Write-Output "`n#############################" | Tee-Object -FilePath $out_file -Append
    Write-Output "# $script_name completed" | Tee-Object -FilePath $out_file -Append
    Write-Output "# Stop Time: $stop_time_readable" | Tee-Object -FilePath $out_file -Append
    Write-Output "#############################`n" | Tee-Object -FilePath $out_file -Append
}

function Prt-CutSec-ReportFooter{
    Write-Output "`n#############################" | Tee-Object -FilePath $out_file -Append
    Write-Output "# CHAPS Audit Script: $script_name $script_version" | Tee-Object -FilePath $out_file -Append
    Write-Output "# Brought to you by Cutaway Security, LLC" | Tee-Object -FilePath $out_file -Append
    Write-Output "# For assessment and auditing help, contact info [@] cutawaysecurity.com" | Tee-Object -FilePath $out_file -Append
    Write-Output "# For script help, contact dev [@] cutawaysecurity.com" | Tee-Object -FilePath $out_file -Append
    Write-Output "#############################`n" | Tee-Object -FilePath $out_file -Append
}

function Show-Config{
    Write-Output "$script_name $script_version Configuration:"
    ## System Info Checks
    Write-Output "    Get System Information: $getSysInfo"
    Write-Output "    Get Windows Version: $getWinVersionCheck" 
    Write-Output "    Get User Path: $getUserPathCheck"     
    Write-Output "    Get Auto Update Config: $getAutoUpdateConfigCheck"
    Write-Output "    Get Windows Patch Level: $getWinPatchCheck"      
    Write-Output "    Get BitLocker Config: $getBitLockerCheck"      
    Write-Output "    Get Install Elevated Config: $getInstallElevatedCheck"
    Write-Output "    Get EMET Config: $getEMETCheck"        
    Write-Output "    Get LAPS Config: $getLAPSCheck"       
    Write-Output "    Get GPO Config: $getGPOCheck"           
    Write-Output "    Get Net Session Enum: $getNetSessionEnumCheck"
    Write-Output "    Get AppLocker Config: $getAppLockerCheck"   
    Write-Output "    Get Cred and Device Guard: $getCredDeviceGuardCheck"
    Write-Output "    Get MS Office Config: $getMSOfficeCheck"     
    ## Security Checks
    Write-Output "    Get SMBv1 Check: $getSMBv1Check"        
    Write-Output "    Get Anonmyous Enumeration: $getAnonEnumCheck"   
    Write-Output "    Get Untrusted Fonts: $getUntrustedFontsCheck"
    ## Authentication Checks
    Write-Output "    Get RDP Deny Config: $getRDPDenyCheck"     
    Write-Output "    Get Local Administrator: $getLocalAdminCheck"  
    Write-Output "    Get NTLM Sessions: $getNTLMSessionsCheck"
    Write-Output "    Get LANMAN Config: $getLANMANCheck"      
    Write-Output "    Get Cached Logon Config: $getCachedLogonCheck"  
    Write-Output "    Get Interactive Logon Config: $getInteractiveLoginCheck"
    Write-Output "    Get WDigest Config: $getWDigestCheck"   
    Write-Output "    Get Restrict RDP Clients: $getRestrictRDPClientsCheck"
    ## Network Checks
    Write-Output "    Get IPv4 Network: $getNetworkIPv4Check"
    Write-Output "    Get IPv6 Network: $getNetworkIPv6Check"
    Write-Output "    Get WPAD Config: $getWPADCheck"      
    Write-Output "    Get WINS Config: $getWINSConfigCheck"
    Write-Output "    Get LLMNR Config: $getLLMNRConfigCheck"
    Write-Output "    Get Computer Browser: $getCompBrowserCheck"  
    Write-Output "    Get NetBIOS Config: $getNetBIOSCheck" 
    ## PowerShell Checks
    Write-Output "    Get PS Version: $getPSVersionCheck"
    Write-Output "    Get PS Language: $getPSLanguageCheck"
    Write-Output "    Get PS Module Logging: $getPSModuleCheck"
    Write-Output "    Get PS Script Block Logging: $getPSScriptCheck"   
    Write-Output "    Get PS Transcript Logging: $getPSTranscriptCheck"
    Write-Output "    Get PS Protected Config: $getPSProtectedCheck"
    Write-Output "    Get WinRM Config: $getWinRMCheck"     
    ## Logging Checks
    Write-Output "    Get Event Log Config: $getEventLogCheck"
    Write-Output "    Get CMD Auditing Config: $getCmdAuditingCheck" 
    Write-Output "    Get Win Scripting Config: $getWinScriptingCheck"

    Write-Output "`nSee the Collection Parameters section to manage script behavior.`n"
    exit
}

#############################
# Helper functions
#############################
# Check for Cmdlet, else use CimInstance
function Test-CommandExists{
    Param ($command)
    $oldPreference = $ErrorActionPreference
    $ErrorActionPreference = 'stop'
    try {if(Get-Command $command){RETURN $true}}
    Catch {RETURN $false}
    Finally {$ErrorActionPreference=$oldPreference}
} 

# Check for Administrator Role
function Get-AdminState {
	if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")){ 
		Write-Output "# Script Running As Normal User"  | Tee-Object -FilePath $out_file -Append
        $global:admin_user = $false
	} else {
		Write-Output "# Script Running As Administrator"  | Tee-Object -FilePath $out_file -Append
        $global:admin_user = $true
    }
}

#############################
# Information Collection functions
#############################

# System Info Checks
#############################
function Get-SystemInfo{    
    $sdata = systeminfo
    $sdata  | Out-file -FilePath $sysinfo_file

    if (Test-CommandExists Get-ComputerInfo){
        $comsysinfo = Get-ComputerInfo -Property WindowsProductName,OsVersion,WindowsCurrentVersion,WindowsVersion,OsArchitecture,CsWorkgroup
        $sysdata = "$($comsysinfo.WindowsProductName),$($comsysinfo.OsVersion),$($comsysinfo.WindowsCurrentVersion),$($comsysinfo.WindowsVersion),$($comsysinfo.OsArchitecture),$($comsysinfo.CsWorkgroup)"
    }else{
        if ($sdata -eq ''){$sdata = systeminfo}
        $sysdata = $sdata | Select-String -Pattern '^OS Version','^OS Name','^System Type','^Domain'  
    }
    Write-Output "$inf_str $sysdata" | Tee-Object -FilePath $out_file -Append
}

function Get-WinVersion{
    $winVersion = "Windows Version: $(([Environment]::OSVersion).VersionString)"
    Write-Output "$inf_str $winVersion" | Tee-Object -FilePath $out_file -Append
}

function Get-UserPath{
    $userPath = "Windows Default Path for $env:Username : $env:Path"
    Write-Output "$inf_str $userPath" | Tee-Object -FilePath $out_file -Append
}

function Get-AutoUpdateConfig {
    $AutoUpdateNotificationLevels= @{0="Not configured"; 1="Disabled" ; 2="Notify before download"; 3="Notify before installation"; 4="Scheduled installation"}
    Try{
        $resa = ((New-Object -com "Microsoft.Update.AutoUpdate").Settings).NotificationLevel
        if ( $resa -eq 4){
            Write-Output "$pos_str Windows AutoUpdate is set to $resa : $AutoUpdateNotificationLevels.$resa" | Tee-Object -FilePath $out_file -Append
        } else {
            Write-Output "$neg_str Windows AutoUpdate is not configuration to automatically install updates: $resa : $AutoUpdateNotificationLevels.$resa" | Tee-Object -FilePath $out_file -Append
        }
    }
    Catch{
        Write-Output "$err_str Windows AutoUpdate test failed." | Tee-Object -FilePath $out_file -Append
    }
}

function Get-WinPatch {    
    # Gist Grimthorr/pending-updates.ps1: https://gist.github.com/Grimthorr/44727ea8cf5d3df11cf7

    if (Test-CommandExists Test-NetConnection){
        $internetConn = (Test-NetConnection -ComputerName www.google.com -InformationLevel Quiet -WarningAction SilentlyContinue -ErrorAction SilentlyContinue).PingSucceeded
        if (-not $internetConn){
            Write-Output "$err_str Check for Critical and Important Windows patches test failed: no internet connection." | Tee-Object -FilePath $out_file -Append
            return
        }
    } 

    Try{
        $UpdateSession = New-Object -ComObject Microsoft.Update.Session
        $UpdateSearcher = $UpdateSession.CreateupdateSearcher()
        $Updates = @($UpdateSearcher.Search("IsHidden=0 and IsInstalled=0").Updates)
        #$Updates | Select-Object Title
        $missing_updates = $Updates | Where-Object {$_.MsrcSeverity -gt 2} | Select-Object @{Name="KB"; Expression={$_.KBArticleIDs}} | Select-Object -ExpandProperty KB | Sort-Object -Unique 

        if ($missing_updates) {
            foreach ($m in $missing_updates){
                Write-Output "$neg_str Missing Critical or Important Update KB: $m" | Tee-Object -FilePath $out_file -Append
            }
        } else {
            Write-Output "$pos_str Windows system appears to be up-to-date for Critical and Important patches." | Tee-Object -FilePath $out_file -Append
        }
    }
    Catch{
        Write-Output "$err_str Check for Critical and Important Windows patches test failed: command failed." | Tee-Object -FilePath $out_file -Append
    }
}

function Get-BitLocker {    
    if (-NOT $global:admin_user){ return }
    if (Test-CommandExists Get-BitLockerVolume){
        $vs = Get-BitLockerVolume -ErrorAction Stop | Where-Object {$_.VolumeType -eq 'OperatingSystem'} | Select VolumeStatus -ErrorAction Stop
        $resvs = $vs.VolumeStatus 
        if ($resvs -eq 'FullyEncrypted'){
            Write-Output "$pos_str BitLocker detected and Operating System Volume is: $resvs" | Tee-Object -FilePath $out_file -Append
        } else {
            Write-Output "$neg_str BitLocker not detected on Operating System Volume or encryption is not complete. Check for other encryption methods: $resvs"  | Tee-Object -FilePath $out_file -Append
        }
    } else {
        $vsm = manage-bde -status | Select-String -Pattern 'Conversion Status'
        if ($vsm -ne $null){
            $resvsm = Select-String -Pattern 'Fully Encrypted'
            if ($resvsm -ne $null){
                Write-Output "$pos_str Operating System Volume is Fully Encrypted (manage-bde): $resvsm" | Tee-Object -FilePath $out_file -Append
            } else {
                Write-Output "$pos_str BitLocker not detected or encryption is not complete. Please check for other encryption methods (manage-bde): $resvsm" | Tee-Object -FilePath $out_file -Append
            }
        } else {
            Write-Output "$inf_str BitLocker not detected. Please check for other encryption methods." | Tee-Object -FilePath $out_file -Append
        }
    }
}

function Get-InstallElevated {
    # Windows Privilege Escalation Fundamentals: http://www.fuzzysecurity.com/tutorials/16.html
    # Abusing MSI's Elevated Privileges: https://www.greyhathacker.net/?p=185

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
            Write-Output "$neg_str Users can install software as NT AUTHORITY\SYSTEM." | Tee-Object -FilePath $out_file -Append
        } else {
            Write-Output "$pos_str Users cannot install software as NT AUTHORITY\SYSTEM." | Tee-Object -FilePath $out_file -Append
        }
    }
    Catch{
        Write-Output "$err_str Check if users can install software as NT AUTHORITY\SYSTEM failed" | Tee-Object -FilePath $out_file -Append
    }
}

function Get-EMET {
    Try{
        if ([System.Environment]::OSVersion.Version.Major -lt 10){
            $resemet = (get-service EMET_Service).status
            if ($resemet -eq 'Running'){
                Write-Output "$pos_str EMET Service is running." | Tee-Object -FilePath $out_file -Append
            } else {
                Write-Output "$neg_str EMET Service is not running: $resemet" | Tee-Object -FilePath $out_file -Append
            }
        } else {
            Write-Output "$inf_str EMET Service components are built into Windows 10." | Tee-Object -FilePath $out_file -Append
        }
    }
    Catch{
        Write-Output "$err_str Testing for Microsoft EMET service failed." | Tee-Object -FilePath $out_file -Append
    }
}

function Get-LAPS {
    Try{
        if (Get-ChildItem ‘C:\program files\LAPS\CSE\Admpwd.dll’ -ErrorAction Stop){
            Write-Output "$pos_str Local Administrator Password Solution (LAPS) is installed." | Tee-Object -FilePath $out_file -Append
        } else {
            Write-Output "$neg_str Local Administrator Password Solution (LAPS) is not installed." | Tee-Object -FilePath $out_file -Append
        }
    }
    Catch{
        Write-Output "$err_str Testing for Microsoft LAPS failed." | Tee-Object -FilePath $out_file -Append
    }
}


function Get-GPO {
    # Group Policy objects must be reprocessed even if they have not changed.: https://www.stigviewer.com/stig/windows_server_2012_member_server/2014-01-07/finding/V-4448
    Try{
        $ressess = (Get-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\' -ErrorAction SilentlyContinue).NoGPOListChanges
        if ($ressess -ne $null){
            if ($ressess){
                Write-Output "$neg_str GPO settings are configured to only be applied after change: $ressess" | Tee-Object -FilePath $out_file -Append
            } else {
                Write-Output "$pos_str GPO settings are configured to be applied when GPOs are processed: $ressess" | Tee-Object -FilePath $out_file -Append
            }
        } else {
            Write-Output "$inf_str System may not be assigned GPOs." | Tee-Object -FilePath $out_file -Append
        }
    }
    Catch{
        Write-Output "$err_str Testing for Microsoft GPO failed." | Tee-Object -FilePath $out_file -Append
    }
}


function Get-NetSessionEnum {
    # View Net Session Enum Permissions: https://gallery.technet.microsoft.com/scriptcenter/View-Net-Session-Enum-dfced139
    #Net Cease - Hardening Net Session Enumeration: https://gallery.technet.microsoft.com/Net-Cease-Blocking-Net-1e8dcb5b

    # Not configured, yet
    # Write-Output "$inf_str Testing Net Session Enumeration configuration using the TechNet script NetSessEnumPerm.ps1" | Tee-Object -FilePath $out_file -Append
}

function Get-AppLocker {
    Try{
        $resapp = (Get-AppLockerPolicy -local -ErrorAction Stop).RuleCollectionTypes
        if ($resapp){
            $resapp_names = $resapp -join ','
            if ($resapp.Contains('Script')){
                Write-Output "$pos_str AppLocker configured to manage PowerShell scripts: $resapp_names" | Tee-Object -FilePath $out_file -Append
            } else {

                Write-Output "$neg_str AppLocker not configured to manage PowerShell scripts: $resapp_names" | Tee-Object -FilePath $out_file -Append
            }
        } else {
            Write-Output "$neg_str AppLocker not configured" | Tee-Object -FilePath $out_file -Append
        }
    }
    Catch{
        Write-Output "$err_str Testing for Microsoft AppLocker failed." | Tee-Object -FilePath $out_file -Append
    }
}


function Get-CredDeviceGuard {
    
    # How to Verify if Device Guard is Enabled or Disabled in Windows 10: https://www.tenforums.com/tutorials/68926-verify-if-device-guard-enabled-disabled-windows-10-a.html
    # Security Focus: Check Credential Guard Status with PowerShell: https://blogs.technet.microsoft.com/poshchap/2016/09/23/security-focus-check-credential-guard-status-with-powershell/
    
    # TODO: Add Win 11
    if ([System.Environment]::OSVersion.Version.Major -eq 10){
        Try{
            $secServConfig = (Get-CimInstance –ClassName Win32_DeviceGuard –Namespace root\Microsoft\Windows\DeviceGuard).SecurityServicesConfigured
            $secServRunning = (Get-CimInstance –ClassName Win32_DeviceGuard –Namespace root\Microsoft\Windows\DeviceGuard).SecurityServicesRunning
        }
        Catch{
            Write-Output "$err_str Testing for Credential and Device Guard failed." | Tee-Object -FilePath $out_file -Append
        }
        
        if ($secServConfig){
            Write-Output "$pos_str Credential Guard or HVCI service is running." | Tee-Object -FilePath $out_file -Append
        } else {
            Write-Output "$neg_str Credential Guard or HVCI service is not running." | Tee-Object -FilePath $out_file -Append
        }
        if ($secServRunning){
            Write-Output "$pos_str Device Guard appears to be configured." | Tee-Object -FilePath $out_file -Append
        } else {
            Write-Output "$neg_str Device Guard, no properties exist and therefore is not configured." | Tee-Object -FilePath $out_file -Append
        }

    } else {
        Write-Output "$inf_str Windows Version is not 10. Cannot test for Credential or Device Guard." | Tee-Object -FilePath $out_file -Append
    }
} 

function Get-MSOffice { 
    # Not configured, yet
}

# Security Checks
#############################
function Get-SMBv1 {
    # Stop using SMB1: https://blogs.technet.microsoft.com/filecab/2016/09/16/stop-using-smb1/
    # How to detect, enable and disable SMBv1, SMBv2, and SMBv3 in Windows and Windows Server: https://support.microsoft.com/en-us/help/2696547/how-to-detect-enable-and-disable-smbv1-smbv2-and-smbv3-in-windows-and
    # Detecting and remediating SMBv1: https://blogs.technet.microsoft.com/leesteve/2017/05/11/detecting-and-remediating-smbv1/
    # https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3?tabs=server

    # TODO: SMBv3, Encryption, Signing
    Try{
        $smbConfig = Get-SmbServerConfiguration

        if ($smbConfig.EnableSMB1Protocol) {
            Write-Output "$neg_str SMBv1 is Enabled" | Tee-Object -FilePath $out_file -Append
        } else {
            Write-Output "$pos_str SMBv1 is Disabled" | Tee-Object -FilePath $out_file -Append
        } 
        
        if ($smbConfig.AuditSmb1Access) {
            Write-Output "$pos_str SMBv1 Auditing is Enabled"  | Tee-Object -FilePath $out_file -Append
        } else { 
            Write-Output "$neg_str SMBv1 Auditing is Disabled"  | Tee-Object -FilePath $out_file -Append
        }

        if ($smbConfig.EnableSMB2Protocol) {
            Write-Output "$pos_str SMBv2 is Enabled" | Tee-Object -FilePath $out_file -Append
        } else {
            Write-Output "$neg_str SMBv2 is Disabled" | Tee-Object -FilePath $out_file -Append
        } 

        if ($smbConfig.RequireSecuritySignature) {
            Write-Output "$pos_str Require Security Signature is Enabled" | Tee-Object -FilePath $out_file -Append
        } else {
            Write-Output "$neg_str Require Security Signature is Disabled" | Tee-Object -FilePath $out_file -Append
        } 
    }
    Catch {
        Write-Output "$err_str Testing for SMBv1 failed." | Tee-Object -FilePath $out_file -Append   
    }
}

function Get-AnonEnum {

    Try{
        $resra = (Get-ItemProperty -path 'HKLM:\System\CurrentControlSet\Control\Lsa\').RestrictAnonymous 
        if ($resra -eq $null){
            Write-Output "$neg_str RestrictAnonymous registry key is not configured." | Tee-Object -FilePath $out_file -Append
        } else {
            if ($resra){
                Write-Output "$pos_str RestrictAnonymous registry key is configured: $resra" | Tee-Object -FilePath $out_file -Append
            } else {        
                Write-Output "$neg_str RestrictAnonymous registry key is not configured: $resra" | Tee-Object -FilePath $out_file -Append
            }   
        }
    }
    Catch{
        Write-Output "$err_str Testing for Anonymous Enumeration RestrictAnonymous failed." | Tee-Object -FilePath $out_file -Append
    }

    Try{
        $resras = (Get-ItemProperty -path 'HKLM:\System\CurrentControlSet\Control\Lsa\').RestrictAnonymoussam 
        if ($resras -eq $null){
            Write-Output "$neg_str RestrictAnonymoussam registry key is not configured." | Tee-Object -FilePath $out_file -Append
        } else {
            if ($resras){
                Write-Output "$pos_str RestrictAnonymoussam registry key is configured: $resras" | Tee-Object -FilePath $out_file -Append
            } else {        
                Write-Output "$neg_str RestrictAnonymoussam registry key is not configured: $resras" | Tee-Object -FilePath $out_file -Append
            }   
        }
    }
    Catch{
        Write-Output "$err_str Testing for Anonymous Enumeration RestrictAnonymoussam failed." | Tee-Object -FilePath $out_file -Append
    }
}


function Get-UntrustedFonts {
    # Block untrusted fonts in an enterprise: https://docs.microsoft.com/en-us/windows/security/threat-protection/block-untrusted-fonts-in-enterprise
    # How to Verify if Device Guard is Enabled or Disabled in Windows 10: https://www.tenforums.com/tutorials/68926-verify-if-device-guard-enabled-disabled-windows-10-a.html
    if ([System.Environment]::OSVersion.Version.Major -eq 10){
        Try{
            $resuf = (Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\').MitigationOptions
            if ($resuf -eq $null){
                Write-Output "$neg_str Kernel MitigationOptions key does not exist." | Tee-Object -FilePath $out_file -Append
            } else {
                if ($ressh -ge 2000000000000){
                    Write-Output "$neg_str Kernel MitigationOptions key is configured not to block: $resuf" | Tee-Object -FilePath $out_file -Append
                } else {
                    Write-Output "$pos_str Kernel MitigationOptions key is set to block: $resuf" | Tee-Object -FilePath $out_file -Append
                }
            }
        }
        Catch{
            Write-Output "$err_str Testing for Untrusted Fonts configuration failed." | Tee-Object -FilePath $out_file -Append
        }
    } else {
        Write-Output "$inf_str Windows Version is not 10. Cannot test for Untrusted Fonts." | Tee-Object -FilePath $out_file -Append
    }
}


# Authentication Checks
#############################
function Get-RDPDeny {
    # How to disable RDP access for Administrator: https://serverfault.com/questions/598278/how-to-disable-rdp-access-for-administrator/598279
    # How to Remotely Enable and Disable (RDP) Remote Desktop: https://www.interfacett.com/blogs/how-to-remotely-enable-and-disable-rdp-remote-desktop/
    Try{
        if ([bool](Get-ItemProperty -path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -ErrorAction SilentlyContinue).AllowRemoteRPC){
            Write-Output "$neg_str + AllowRemoteRPC is should be set to disable RDP: 1" | Tee-Object -FilePath $out_file -Append
        } else {
            Write-Output "$pos_str AllowRemoteRPC is set to deny RDP: 0" | Tee-Object -FilePath $out_file -Append
        }
    }
    Catch{
        Write-Output "$err_str Testing if system prevents RDP service failed." | Tee-Object -FilePath $out_file -Append
    }

    Try{
        if ([bool](Get-ItemProperty -path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -ErrorAction SilentlyContinue).fDenyTSConnections){
            Write-Output "$pos_str fDenyTSConnections is set to deny remote connections: 1" | Tee-Object -FilePath $out_file -Append
        } else {
            Write-Output "$neg_str fDenyTSConnections should be set to not allow remote connections: 0" | Tee-Object -FilePath $out_file -Append
        }
    }
    Catch{
        Write-Output "$err_str Testing if system denies remote access via Terminal Services failed." | Tee-Object -FilePath $out_file -Append
    }
}

function Get-LocalAdmin {

    if (Test-CommandExists Get-LocalGroupMember){
        Try{
            $numadmin = (Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop).Name.count
            if ([int]$numadmin -gt 1){
                Write-Output "$neg_str More than one account is in local Administrators group: $numadmin" | Tee-Object -FilePath $out_file -Append
            } else {
                Write-Output "$pos_str One account in local Administrators group." | Tee-Object -FilePath $out_file -Append
            }
            foreach ($n in (Get-LocalGroupMember -Group "Administrators").Name) {
                Write-Output "$inf_str Account in local Administrator group: $n" | Tee-Object -FilePath $out_file -Append
            }
        } 
        Catch{
            Write-Output "$err_str Testing local Administrator Accounts failed." | Tee-Object -FilePath $out_file -Append
        }
    } else {
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
                Write-Output "$neg_str More than one account is in local Administrators group: $numadmin.length" | Tee-Object -FilePath $out_file -Append
            } else {
                Write-Output "$pos_str One account in local Administrators group." | Tee-Object -FilePath $out_file -Append
            }
        }
    }
}

function Get-NTLMSession {
    # Session security for NTLM SSP-based servers must be configured to require NTLMv2 session security and 128-bit encryption.: https://www.stigviewer.com/stig/windows_server_2016/2018-03-07/finding/V-73697
    # The system is not configured to meet the minimum requirement for session security for NTLM SSP based clients.: https://www.stigviewer.com/stig/windows_7/2012-07-02/finding/V-3382
    Try{
        $resntssec = (Get-ItemProperty -path 'HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0' -ErrorAction SilentlyContinue).NtlmMinServerSec
        if ([int]$resntssec -eq 537395200){
            Write-Output "$pos_str NTLM Session Server Security settings is configured to require NTLMv2 and 128-bit encryption: $resntssec" | Tee-Object -FilePath $out_file -Append
        } else {        
            Write-Output "$neg_str NTLM Session Server Security settings is not configured to require NTLMv2 and 128-bit encryption: $resntssec" | Tee-Object -FilePath $out_file -Append
        }   
    }
    Catch{
        Write-Output "$err_str Testing NTLM Session Server Security settings failed." | Tee-Object -FilePath $out_file -Append
    }

    $resntcsec = (Get-ItemProperty -path 'HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0' -ErrorAction SilentlyContinue).NtlmMinClientSec
    Try{
        if ([int]$resntcsec -eq 537395200){
            Write-Output "$pos_str NTLM Session Client Security settings is configured to require NTLMv2 and 128-bit encryption: $resntcsec" | Tee-Object -FilePath $out_file -Append
        } else {        
            Write-Output "$neg_str NTLM Session Client Security settings is not configured to require NTLMv2 and 128-bit encryption: $resntcsec" | Tee-Object -FilePath $out_file -Append
        }   
    }
    Catch{
        Write-Output "$err_str Testing NTLM Session Client Security settings failed." | Tee-Object -FilePath $out_file -Append
    }
}

function Get-LANMAN {
    # Understanding the Anonymous Enumeration Policies:https://www.itprotoday.com/compute-engines/understanding-anonymous-enumeration-policies
    # The LanMan authentication level must be set to send NTLMv2 response only, and to refuse LM and NTLM.: https://www.stigviewer.com/stig/windows_8/2014-01-07/finding/V-1153
    Try{
        $reslm = (Get-ItemProperty -path 'HKLM:\System\CurrentControlSet\Control\Lsa\').NoLmHash
        if ($reslm -eq $null){
            Write-Output "$neg_str NoLmHash registry key is not configured." | Tee-Object -FilePath $out_file -Append
        } else {
            if ($reslm){
                Write-Output "$pos_str NoLmHash registry key is configured: $reslm" | Tee-Object -FilePath $out_file -Append
            } else {        
                Write-Output "$neg_str NoLmHash registry key is not configured: $reslm" | Tee-Object -FilePath $out_file -Append
            }   
        }
    }
    Catch{
        Write-Output "$err_str Testing for NoLmHash registry key failed." | Tee-Object -FilePath $out_file -Append
    }

    Try{
        $reslmcl = (Get-ItemProperty -path 'HKLM:\System\CurrentControlSet\Control\Lsa\').LmCompatibilityLevel
        if ($reslmcl -eq $null){
            Write-Output "$neg_str LM Compatability Level registry key is not configured." | Tee-Object -FilePath $out_file -Append
        } else {
            if ([int]$reslmcl -eq 5){
                Write-Output "$pos_str LM Compatability Level is configured correctly: $reslmcl" | Tee-Object -FilePath $out_file -Append
            } else {        
                Write-Output "$neg_str LM Compatability Level is not configured to prevent LM and NTLM: $reslmcl" | Tee-Object -FilePath $out_file -Append
            }   
        }
    }
    Catch{
        Write-Output "$err_str Testing for LM Compatability registry key failed." | Tee-Object -FilePath $out_file -Append
    }
}

function Get-CachedLogons {
    # Cached logons and CachedLogonsCount: https://blogs.technet.microsoft.com/instan/2011/12/06/cached-logons-and-cachedlogonscount/
    # Cached domain logon information: https://support.microsoft.com/en-us/help/172931/cached-domain-logon-information
    # Cached Logons should be set to 0 or 1.
    Try{
        $regv = (Get-ItemProperty -path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" -ErrorAction SilentlyContinue).CachedLogonsCount
        if ([int]$regv -lt 2) {
            Write-Output "$pos_str CachedLogonsCount Is Set to: $regv" | Tee-Object -FilePath $out_file -Append
        } else {
            Write-Output "$neg_str CachedLogonsCount Is Not Set to 0 or 1: $regv" | Tee-Object -FilePath $out_file -Append
        }
    }
    Catch{
        Write-Output "$err_str Testing for stored credential settings failed." | Tee-Object -FilePath $out_file -Append
    }
}

function Get-InteractiveLogin {
    # Disable PowerShell remoting: Disable-PSRemoting, WinRM, listener, firewall, LocalAccountTokenFilterPolicy: https://4sysops.com/wiki/disable-powershell-remoting-disable-psremoting-winrm-listener-firewall-and-localaccounttokenfilterpolicy/
    # Pass-the-Hash Is Dead: Long Live LocalAccountTokenFilterPolicy: https://www.harmj0y.net/blog/redteaming/pass-the-hash-is-dead-long-live-localaccounttokenfilterpolicy/
    Try{
        if ([bool](Get-ItemProperty -path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\system' -ErrorAction SilentlyContinue).LocalAccountTokenFilterPolicy){
            Write-Output "$neg_str LocalAccountTokenFilterPolicy Is Set" | Tee-Object -FilePath $out_file -Append
        } else {
            Write-Output "$pos_str LocalAccountTokenFilterPolicy Is Not Set" | Tee-Object -FilePath $out_file -Append
        }
    }
    Catch{
        Write-Output "$err_str Testing for LocalAccountTokenFilterPolicy in Policies failed." | Tee-Object -FilePath $out_file -Append
    }

    Try{
        if ([bool](Get-ItemProperty -path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\policies\system' -ErrorAction SilentlyContinue).LocalAccountTokenFilterPolicy){
            Write-Output "$neg_str LocalAccountTokenFilterPolicy in Wow6432Node Is Set" | Tee-Object -FilePath $out_file -Append
        } else {
            Write-Output "$pos_str LocalAccountTokenFilterPolicy in Wow6432Node Is Not Set" | Tee-Object -FilePath $out_file -Append
        }
    }
    Catch{
        Write-Output "$err_str Testing for LocalAccountTokenFilterPolicy in Wow6432Node failed." | Tee-Object -FilePath $out_file -Append
    }
}

function Get-WDigest {
    Try{
        $reswd = (Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest').UseLogonCredential
        if ($reswd -eq $null){
            Write-Output "$neg_str WDigest UseLogonCredential key does not exist." | Tee-Object -FilePath $out_file -Append
        } else {
            if ($reswd){
                Write-Output "$neg_str WDigest UseLogonCredential key is Enabled: $reswd" | Tee-Object -FilePath $out_file -Append
            } else {
                Write-Output "$pos_str WDigest UseLogonCredential key is Disabled: $reswd" | Tee-Object -FilePath $out_file -Append
            }
        }
    }
    Catch{
        Write-Output "$err_str Testing for WDigest failed." | Tee-Object -FilePath $out_file -Append
    }
}

function Get-RestrictRDPClients {
    # Restrict Unauthenticated RPC clients: https://getadmx.com/?Category=Windows_10_2016&Policy=Microsoft.Policies.RemoteProcedureCalls::RpcRestrictRemoteClients
    # Restrict unauthenticated RPC clients.: https://www.stigviewer.com/stig/windows_7/2017-12-01/finding/V-14253
    $resrpc = (Get-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Windows NT\Rpc\' -ErrorAction SilentlyContinue).RestrictRemoteClients 
    Try{
        if ($resrpc){
            Write-Output "$pos_str RestrictRemoteClients registry key is configured: $resrpc" | Tee-Object -FilePath $out_file -Append
        } else {        
            Write-Output "$neg_str RestrictRemoteClients registry key is not configured: $resrpc" | Tee-Object -FilePath $out_file -Append
        }   
    }
    Catch{
        Write-Output "$err_str Testing Restrict RPC Clients settings failed." | Tee-Object -FilePath $out_file -Append
    }
}

# Network Checks
#############################
function Get-NetworkSettingsIPv4 {
    Try{
        $ips = (Get-NetIPAddress | Where AddressFamily -eq 'IPv4' | Where IPAddress -ne '127.0.0.1').IPAddress
        if ($ips -ne $null){
            foreach ($ip in $ips){
                if ($ip -ne $null){
                    #$inf_str + "Host network interface assigned:" $ip
                    Write-Output "$inf_str Host network interface assigned: $ip" | Tee-Object -FilePath $out_file -Append
                }
            }
        }else{
            # Use Throw function to call the Catch function
            Write-Output "$err_str Get-NetIPAddress error" | Tee-Object -FilePath $out_file -Append
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
                                Write-Output "$inf_str Host network interface assigned (gwmi): $i" | Tee-Object -FilePath $out_file -Append
                            }
                        }
                    }
                }
            } else {
                # Use Throw function to call the Catch function
                Write-Output "$err_str gwmi win32_networkadapterconfiguration error or no network interface." | Tee-Object -FilePath $out_file -Append
            }
        }
        Catch{
            Write-Output "$err_str Check IPv4 Network Settings failed." | Tee-Object -FilePath $out_file -Append
        }
    }
}

function Get-NetworkSettingsIPv6 {
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
                            Write-Output "$neg_str Host IPv6 network interface assigned (gwmi): $i" | Tee-Object -FilePath $out_file -Append
                            $noipv6 = $false
                        }
                    }
                }
            }
            if ($noipv6){
                Write-Output "$pos_str No interfaces with IPv6 network interface assigned (gwmi)." | Tee-Object -FilePath $out_file -Append
            }
        } else {
            # Use Throw function to call the Catch function
            Write-Output "$err_str No interfaces with IPv6 network interface assigned (gwmi)." | Tee-Object -FilePath $out_file -Append
        }
    }
    Catch{
        Write-Output "$err_str Check IPv6 Network Settings failed (gwmi)." | Tee-Object -FilePath $out_file -Append
    }
}

function Get-WPAD {
    # Microsoft Security Bulletin MS16-063 - Critical: https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2016/ms16-063
    Try{
        $reswpad = Select-String -path $env:systemdrive\Windows\System32\Drivers\etc\hosts -pattern wpad
        if ($resllmnr -ne $null){
            Write-Output "$pos_str WPAD entry detected: $reswpad" | Tee-Object -FilePath $out_file -Append
        } else {
            Write-Output "$neg_str No WPAD entry detected. Should contain: wpad 255.255.255.255" | Tee-Object -FilePath $out_file -Append
        }
    }
    Catch{
        Write-Output "$err_str Testing for WPAD in /etc/hosts failed." | Tee-Object -FilePath $out_file -Append
    }

    Try{
        $reswpad2 = (Get-ItemProperty -path 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad' -ErrorAction SilentlyContinue).WpadOverride
        if ($reswpad2 -ne $null){
            if ($reswpad2){
                Write-Output "$pos_str WpadOverride registry key is configured to disable WPAD: $reswpad2" | Tee-Object -FilePath $out_file -Append
            } else {
                Write-Output "$neg_str WpadOverride registry key is configured to allow WPAD: $reswpad2" | Tee-Object -FilePath $out_file -Append
            }
        } else {
            Write-Output "$inf_str System not configured with the WpadOverride registry key." | Tee-Object -FilePath $out_file -Append
        }
    }
    Catch{
        Write-Output "$err_str Testing for WpadOverride registry key failed." | Tee-Object -FilePath $out_file -Append
    }

    # Deploy security back-port patch (KB3165191).
    Try{
        $reswphf = (Get-HotFix -id KB3165191 -ErrorAction SilentlyContinue).InstalledOn
        if ($reswphf -ne $null){
            Write-Output "$pos_str KB3165191 to harden WPAD is installed: $reswphf" | Tee-Object -FilePath $out_file -Append
        } else {
            Write-Output "$neg_str KB3165191 to harden WPAD is not installed." | Tee-Object -FilePath $out_file -Append
        }
    }
    Catch{
        Write-Output "$err_str Testing for WPAD KB3165191 failed." | Tee-Object -FilePath $out_file -Append
    }
    
    Try{
        $reswpads = (Get-Service -name WinHttpAutoProxySvc).Status
        if ($reswpads -ne $null){
            if ($reswpads -eq 'Running'){
                Write-Output "$neg_str WinHttpAutoProxySvc service is: $reswpads" | Tee-Object -FilePath $out_file -Append
            } else {
                Write-Output "$pos_str WinHttpAutoProxySvc service is: $reswpads" | Tee-Object -FilePath $out_file -Append
            }
        } else {
            Write-Output "$inf_str WinHttpAutoProxySvc service was not found: $reswpads" | Tee-Object -FilePath $out_file -Append
        }
    }
    Catch{
        Write-Output "$err_str Testing for WinHttpAutoProxySvc failed." | Tee-Object -FilePath $out_file -Append
    }
}

function Get-WINSConfig {
    Try{
        if ([bool](Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=TRUE").DNSEnabledForWINSResolution){
            Write-Output "$neg_str DNSEnabledForWINSResolution is enabled" | Tee-Object -FilePath $out_file -Append
        } else {
            Write-Output "$pos_str DNSEnabledForWINSResolution is disabled" | Tee-Object -FilePath $out_file -Append
        }
    }
    Catch{
        Write-Output "$err_str Testing for WINS Resolution: DNSEnabledForWINSResolution failed." | Tee-Object -FilePath $out_file -Append
    }

    Try{
        if ([bool](Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=TRUE").WINSEnableLMHostsLookup){
            Write-Output "$neg_str WINSEnableLMHostsLookup is enabled" | Tee-Object -FilePath $out_file -Append
        } else {
            Write-Output "$pos_str WINSEnableLMHostsLookup is disabled" | Tee-Object -FilePath $out_file -Append
        }
    }
    Catch{
        Write-Output "$err_str Testing for WINS Resolution: WINSEnableLMHostsLookup failed." | Tee-Object -FilePath $out_file -Append
    }
}

function Get-LLMNRConfig {
    Try{
        $resllmnr = (Get-ItemProperty -path 'HKLM:\Software\policies\Microsoft\Windows NT\DNSClient' -ErrorAction SilentlyContinue).EnableMulticast
        if ($resllmnr -ne $null){
            Write-Output "$pos_str DNSClient.EnableMulticast is disabled: $resllmnr" | Tee-Object -FilePath $out_file -Append
        } else {
            Write-Output "$neg_str DNSClient.EnableMulticast does not exist or is enabled: $resllmnr" | Tee-Object -FilePath $out_file -Append
        }
    }
    Catch{
        Write-Output "$err_str Testing for LLMNR failed." | Tee-Object -FilePath $out_file -Append
    }
}

function Get-CompBrowser {
    Try{
        $resbr = (Get-Service -name Browser).Status
        if ($resbr -ne $null){
            if ($resbr -eq 'Running'){
                Write-Output "$neg_str Computer Browser service is: $resbr" | Tee-Object -FilePath $out_file -Append
            } else {
                Write-Output "$pos_str Computer Browser service is: $resbr" | Tee-Object -FilePath $out_file -Append
            }
        } else {
            Write-Output "$inf_str Computer Browser service was not found: $resbr" | Tee-Object -FilePath $out_file -Append
        }
    }
    Catch{
        Write-Output "$err_str Testing for Computer Browser service failed." | Tee-Object -FilePath $out_file -Append
    }
}

function Get-NetBIOS {
    # Getting TCP/IP Netbios information: https://powershell.org/forums/topic/getting-tcpip-netbios-information/
    Try{
        $resnetb = (Get-WmiObject -Class Win32_NetWorkAdapterConfiguration -Filter "IPEnabled=$true").TcpipNetbiosOptions
        if ($resnetb -eq $null){
            Write-Output "$neg_str NetBios TcpipNetbiosOptions key does not exist." | Tee-Object -FilePath $out_file -Append
        } else {
            if ([int]$resnetb -eq 2){
                Write-Output "$pos_str NetBios is Disabled: $resnetb" | Tee-Object -FilePath $out_file -Append
            } else {
                Write-Output "$neg_str NetBios is Enabled: $resnetb" | Tee-Object -FilePath $out_file -Append
            }
        }
    }
    Catch{
        Write-Output "$err_str Testing for NetBios failed." | Tee-Object -FilePath $out_file -Append
    }
}

# PowerShell Checks
############################
<#
    From PowerShell to P0W3rH3LL – Auditing PowerShell: https://www.eventsentry.com/blog/2018/01/powershell-p0wrh11-securing-powershell.html
    Practical PowerShell Security: Enable Auditing and Logging with DSC: https://blogs.technet.microsoft.com/ashleymcglone/2017/03/29/practical-powershell-security-enable-auditing-and-logging-with-dsc/
    PowerShell ♥ the Blue Team: https://blogs.msdn.microsoft.com/powershell/2015/06/09/powershell-the-blue-team/
    PowerShell Security Best Practices: https://www.digitalshadows.com/blog-and-research/powershell-security-best-practices/
    Detecting Offensive PowerShell Attack Tools: https://adsecurity.org/?p=2604
    Windows 10 Protected Event Logging: https://www.petri.com/windows-10-protected-event-logging
    WINDOWS POWERSHELL LOGGING CHEAT SHEET - Win 7/Win 2008 or later: https://static1.squarespace.com/static/552092d5e4b0661088167e5c/t/5760096ecf80a129e0b17634/1465911664070/Windows+PowerShell+Logging+Cheat+Sheet+ver+June+2016+v2.pdf0
#>
function Get-PSVersions {
    Try{
        $psver = $PSVersionTable.PSVersion.Major
        $fpsver = $PSVersionTable.PSVersion
        if ([int]$psver -lt 5) { 
            Write-Output "$neg_str Current PowerShell Version is less than Version 5: $fpsver"  | Tee-Object -FilePath $out_file -Append
        } else { 
            Write-Output "$pos_str Current PowerShell Version: $fpsver" | Tee-Object -FilePath $out_file -Append
        }
    }
    Catch{
        Write-Output "$err_str Testing PowerShell Version failed." | Tee-Object -FilePath $out_file -Append
    }

    Try{
        # NOTE: Workstation test. Servers would need to test "Get-WindowsFeature PowerShell-V2"
        $psver2 = (Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2).state
        if ($psver2 -ne $null){
            if ($psver2 -eq 'Enabled') { 
                Write-Output "$neg_str PowerShell Version 2 should be disabled: $psver2" | Tee-Object -FilePath $out_file -Append
            } else { 
                Write-Output "$pos_str PowerShell Version 2 is: $psver2" | Tee-Object -FilePath $out_file -Append
            }
        }else{
            Write-Output "$inf_str Get-WindowsOptionalFeature is not available to test if PowerShell Version 2 is permitted." | Tee-Object -FilePath $out_file -Append
        }
    }
    Catch{
        if (-NOT $global:admin_user){ 
            Write-Output "$err_str Testing for PowerShell Version 2 requires Admin privileges." | Tee-Object -FilePath $out_file -Append 
        } else {
            Write-Output "$err_str Testing for PowerShell Version 2 failed." | Tee-Object -FilePath $out_file -Append
        }
    }
  
    Try{
        $netv=(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -Recurse -ErrorAction SilentlyContinue| Get-ItemProperty -Name Version -ErrorAction SilentlyContinue).Version
        foreach ($e in $netv){
            if ($e -lt 3.0) {
                Write-Output "$neg_str .NET Framework less than 3.0 installed which could allow PSv2 execution: $e" | Tee-Object -FilePath $out_file -Append
            } else {
                Write-Output "$pos_str .NET Framework greater than 3.0 installed: $e" | Tee-Object -FilePath $out_file -Append
            }
        }
    }
    Catch{
        Write-Output "$err_str Testing for .NET vesions that support PowerShell Version 2 failed." | Tee-Object -FilePath $out_file -Append
    }
}

function Get-PSLanguage {
    # Detecting Offensive PowerShell Attack Tools: https://adsecurity.org/?p=2604
    Try{
        $ps_lang = $ExecutionContext.SessionState.LanguageMode
        if ($ps_lang -eq 'ConstrainedLanguage') { 
            Write-Output "$pos_str Execution Langugage Mode Is: $ps_lang" | Tee-Object -FilePath $out_file -Append
        } else  { 
            Write-Output "$neg_str Execution Langugage Mode Is Not ConstrainedLanguage: $ps_lang" | Tee-Object -FilePath $out_file -Append
        }
    }
    Catch{
        Write-Output "$err_str Testing for PowerShell Constrained Language failed." | Tee-Object -FilePath $out_file -Append
    }
}

function Get-PSModule {
    # TODO: Add check for which modules, should be '*'
    Try{
        if ([bool](Get-ItemProperty -path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -ErrorAction SilentlyContinue).EnableModuleLogging){
            Write-Output "$pos_str EnableModuleLogging Is Set" | Tee-Object -FilePath $out_file -Append
        } else {
            Write-Output "$neg_str EnableModuleLogging Is Not Set" | Tee-Object -FilePath $out_file -Append
        }
    }
    Catch{
        Try{
            if ([bool](Get-ItemProperty -path 'HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -ErrorAction SilentlyContinue).EnableModuleLogging){
                Write-Output "$pos_str EnableModuleLogging Is Set" | Tee-Object -FilePath $out_file -Append
            } else {
                Write-Output "$neg_str EnableModuleLogging Is Not Set" | Tee-Object -FilePath $out_file -Append
            }
        }
        Catch{
            Write-Output "$err_str Testing PowerShell Moduling failed" | Tee-Object -FilePath $out_file -Append
        }
    }
}

function Get-PSScript {
    Try{
        if ([bool](Get-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ErrorAction SilentlyContinue).EnableScriptBlockLogging){
            Write-Output "$pos_str EnableScriptBlockLogging Is Set" | Tee-Object -FilePath $out_file -Append
        } else {
            Write-Output "$neg_str EnableScriptBlockLogging Is Not Set" | Tee-Object -FilePath $out_file -Append
        }
    }
    Catch{
        Try{
            if ([bool](Get-ItemProperty -path 'HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ErrorAction SilentlyContinue).EnableScriptBlockLogging){
                Write-Output "$pos_str EnableScriptBlockLogging Is Set" | Tee-Object -FilePath $out_file -Append
            } else {
                Write-Output "$neg_str EnableScriptBlockLogging Is Not Set" | Tee-Object -FilePath $out_file -Append
            }
        }
        Catch{
            Write-Output "$err_str Testing PowerShell EnableScriptBlockLogging failed" | Tee-Object -FilePath $out_file -Append
        }
    }

    Try{
        if ([bool](Get-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ErrorAction SilentlyContinue).EnableScriptBlockInvocationLogging){
            Write-Output "$pos_str EnableScriptBlockInvocationLogging Is Set" | Tee-Object -FilePath $out_file -Append
        } else {
            Write-Output "$neg_str EnableScriptBlockInvocationLogging Is Not Set" | Tee-Object -FilePath $out_file -Append
        }
    }
    Catch{
        Try{
            if ([bool](Get-ItemProperty -path 'HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ErrorAction SilentlyContinue).EnableScriptBlockInvocationLogging){
                Write-Output "$pos_str EnableScriptBlockInvocationLogging Is Set" | Tee-Object -FilePath $out_file -Append
            } else {
                Write-Output "$neg_str EnableScriptBlockInvocationLogging Is Not Set" | Tee-Object -FilePath $out_file -Append
            }
        }
        Catch{
            Write-Output "$err_str Testing PowerShell EnableScriptBlockInvocationLogging failed" | Tee-Object -FilePath $out_file -Append
        }
    }
}

function Get-PSTranscript {
    # TODO: Add check to find Transcript log location
    Try{
        if ([bool](Get-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription' -ErrorAction SilentlyContinue).EnableTranscripting){
            Write-Output "$pos_str EnableTranscripting Is Set" | Tee-Object -FilePath $out_file -Append
        } else {
            Write-Output "$neg_str EnableTranscripting Is Not Set" | Tee-Object -FilePath $out_file -Append
        }
    }
    Catch{
        Try{
            if ([bool](Get-ItemProperty -path 'HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription' -ErrorAction SilentlyContinue).EnableTranscripting){
                Write-Output "$pos_str EnableTranscripting Is Set" | Tee-Object -FilePath $out_file -Append
            } else {
                Write-Output "$neg_str EnableTranscripting Is Not Set" | Tee-Object -FilePath $out_file -Append
            }
        }
        Catch{
            Write-Output "$err_str Testing PowerShell EnableTranscripting failed" | Tee-Object -FilePath $out_file -Append
        }
    }

    Try{
        if ([bool](Get-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription' -ErrorAction SilentlyContinue).EnableInvocationHeader){
            Write-Output "$pos_str EnableInvocationHeader Is Set" | Tee-Object -FilePath $out_file -Append
        } else {
            Write-Output "$neg_str EnableInvocationHeader Is Not Set" | Tee-Object -FilePath $out_file -Append
        }
    }
    Catch{
        Try{
            if ([bool](Get-ItemProperty -path 'HKLM:\Software\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription' -ErrorAction SilentlyContinue).EnableInvocationHeader){
                Write-Output "$pos_str EnableInvocationHeader Is Set" | Tee-Object -FilePath $out_file -Append
            } else {
                Write-Output "$neg_str EnableInvocationHeader Is Not Set" | Tee-Object -FilePath $out_file -Append
            }
        }
        Catch{
            Write-Output "$err_str Testing PowerShell EnableInvocationHeader failed" | Tee-Object -FilePath $out_file -Append
        }
    }
}

function Get-PSProtectedEvent {
    Try{
        if ([bool](Get-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\ProtectedEventLogging' -ErrorAction SilentlyContinue).EnableProtectedEventLogging){
            Write-Output "$pos_str EnableProtectedEventLogging Is Set" | Tee-Object -FilePath $out_file -Append
        } else {
            Write-Output "$neg_str EnableProtectedEventLogging Is Not Set" | Tee-Object -FilePath $out_file -Append
        }
    }
    Catch{
        Try{
            if ([bool](Get-ItemProperty -path 'HKLM:\Software\Wow6432Node\Policies\Microsoft\Windows\EventLog\ProtectedEventLogging' -ErrorAction SilentlyContinue).EnableProtectedEventLogging){
                Write-Output "$pos_str EnableProtectedEventLogging Is Set" | Tee-Object -FilePath $out_file -Append
            } else {
                Write-Output "$neg_str EnableProtectedEventLogging Is Not Set" | Tee-Object -FilePath $out_file -Append
            }
        }
        Catch{
            Write-Output "$err_str Testing PowerShell ProtectedEventLogging failed" | Tee-Object -FilePath $out_file -Append
        }
    }
}

function Get-WinRM {
    # NEED TO TEST IF WINRM IS LISTENING?: https://stevenmurawski.com/2015/06/need-to-test-if-winrm-is-listening/
    # Enable PowerShell Remoting and check if it’s enabled: https://www.dtonias.com/enable-powershell-remoting-check-enabled/
    if (-NOT $global:admin_user){ return }
    Try{
        if (Test-WSMan -ErrorAction Stop) { 
            Write-Output "$neg_str WinRM Services is running and may be accepting connections: Test-WSMan check."  | Tee-Object -FilePath $out_file -Append
        } else { 
            Write-Output "$pos_str WinRM Services is not running: Test-WSMan check."  | Tee-Object -FilePath $out_file -Append
        }   
    }
    Catch{
        Try{
            $ress = (Get-Service WinRM).status
            if ($ress -eq 'Stopped') { 
                Write-Output "$pos_str WinRM Services is not running: Get-Service check."  | Tee-Object -FilePath $out_file -Append
            } else { 
                Write-Output "$neg_str WinRM Services is running and may be accepting connections: Get-Service check."  | Tee-Object -FilePath $out_file -Append
            }
        }
        Catch{
            Write-Output "$err_str Testing if WimRM Service is running failed." | Tee-Object -FilePath $out_file -Append
        }
    }

    Try{
        $resfw = Get-NetFirewallRule -DisplayName 'Windows Remote Management (HTTP-In)'
        foreach ($r in $resfw){
            if ($r.Enabled -eq 'False'){
                Write-Output "$pos_str WinRM Firewall Rule $(($r).Name) is disabled." | Tee-Object -FilePath $out_file -Append
            } else {
                Write-Output "$neg_str WinRM Firewall Rule $(($r).Name) is enabled." | Tee-Object -FilePath $out_file -Append
            }
        }
    }
    Catch{
        Write-Output "$err_str Testing if Windows Network Firewall rules failed." | Tee-Object -FilePath $out_file -Append
    }
}

########## Event Log Settings ##############
<#
    Get-EventLog: https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-eventlog?view=powershell-5.1
    Recommended settings for event log sizes in Windows: https://support.microsoft.com/en-us/help/957662/recommended-settings-for-event-log-sizes-in-windows
    Hey, Scripting Guy! How Can I Check the Size of My Event Log and Then Backup and Archive It If It Is More Than Half Full?: https://blogs.technet.microsoft.com/heyscriptingguy/2009/04/08/hey-scripting-guy-how-can-i-check-the-size-of-my-event-log-and-then-backup-and-archive-it-if-it-is-more-than-half-full/
    Is there a log file for RDP connections?: https://social.technet.microsoft.com/Forums/en-US/cb1c904f-b542-4102-a8cb-e0c464249280/is-there-a-log-file-for-rdp-connections?forum=winserverTS
    WINDOWS POWERSHELL LOGGING CHEAT SHEET - Win 7/Win 2008 or later: https://static1.squarespace.com/static/552092d5e4b0661088167e5c/t/5760096ecf80a129e0b17634/1465911664070/Windows+PowerShell+Logging+Cheat+Sheet+ver+June+2016+v2.pdf0
#>
function Get-PSEventLog {
    $logs = @{
    'Application' = 4;
    'System' = 4;
    'Security' = 4;
    'Windows PowerShell' = 4;
    'Microsoft-Windows-PowerShell/Operational' = 1;
    'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'= 1;
    'Microsoft-Windows-TaskScheduler/Operational' = 1;
    'Microsoft-Windows-SMBServer/Audit' = 1;
    'Microsoft-Windows-Security-Netlogon/Operational' = 1;
    'Microsoft-Windows-WinRM/Operational' = 1;
    'Microsoft-Windows-WMI-Activity/Operational' = 1;
    }

    foreach ($l in $logs.keys){
        Try{
            $lsize = [math]::Round((Get-WinEvent -ListLog $l -ErrorAction Stop).MaximumSizeInBytes / (1024*1024*1024),3)
            if ($lsize -lt $logs[$l]){
                #$neg_str + $l "max log size is smaller than $logs[$l] GB: $lsize GB" | Tee-Object -FilePath $out_file -Append
                Write-Output "$neg_str $l max log size is smaller than $($logs[$l]) GB: $lsize GB" | Tee-Object -FilePath $out_file -Append
            } else {
                #$pos_str + $l "max log size is okay: $lsize GB" | Tee-Object -FilePath $out_file -Append
                Write-Output "$pos_str $l max log size is okay: $lsize GB" | Tee-Object -FilePath $out_file -Append
            }
        }
        Catch{
            Write-Output "$err_str Testing $l log size failed." | Tee-Object -FilePath $out_file -Append
        }
    }
}

function Get-CmdAuditing {
    Try{
        if ([bool](Get-ItemProperty -path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -ErrorAction SilentlyContinue).ProcessCreationIncludeCmdLine_Enabled){
            Write-Output "$pos_str ProcessCreationIncludeCmdLine_Enabled Is Set" | Tee-Object -FilePath $out_file -Append
        } else {
            Write-Output "$neg_str ProcessCreationIncludeCmdLine_Enabled Is Not Set" | Tee-Object -FilePath $out_file -Append
        }
    }
    Catch{
        Write-Output "$err_str Testing PowerShell Commandline Audting failed" | Tee-Object -FilePath $out_file -Append
    }
}

function Get-WinScripting {
    Try{
        $ressh = (Get-ItemProperty -path 'HKLM:\Software\Microsoft\Windows Script Host\Settings').Enabled
        if ($ressh -eq $null){
            Write-Output "$neg_str WSH Setting Enabled key does not exist." | Tee-Object -FilePath $out_file -Append
        } else {
            if ($ressh){
                Write-Output "$neg_str WSH Setting Enabled key is Enabled: $ressh" | Tee-Object -FilePath $out_file -Append
            } else {
                Write-Output "$pos_str WSH Setting Enabled key is Disabled: $ressh" | Tee-Object -FilePath $out_file -Append
            }
        }
    }
    Catch{
        Write-Output "$err_str Testing for Windows Scripting Host (WSH) failed." | Tee-Object -FilePath $out_file -Append
    }

    # Deploy security back-port patch (KB2871997).
    Try{
        $reshf = (Get-HotFix -id KB2871997 -ErrorAction SilentlyContinue).InstalledOn
        if ($reshf -ne $null){
            Write-Output "$pos_str KB2871997 is installed: $reshf" | Tee-Object -FilePath $out_file -Append
        } else {
            Write-Output "$neg_str KB2871997 is not installed." | Tee-Object -FilePath $out_file -Append
        }
    }
    Catch{
        Write-Output "$err_str Testing for security back-port patch KB2871997 failed." | Tee-Object -FilePath $out_file -Append
    }
}

#############################
# Main
#############################

# Configuration Check
#############################
if ($config){ Show-Config }

# Output Directory
#############################
Set-Output $out_dir

# Report Header
#############################
Prt-ReportHeader

# Information Collection
#############################

# CHAPS functions 
## System Info Checks
if ($getSystemInfoCheck)        { Get-SystemInfo }
if ($getWinVersionCheck)        { Get-WinVersion }
if ($getUserPathCheck)          { Get-UserPath }
if ($getAutoUpdateConfigCheck)  { Get-AutoUpdateConfig }
if ($getWinPatchCheck)          { Get-WinPatch }
if ($getBitLockerCheck)         { Get-BitLocker }
if ($getInstallElevatedCheck)   { Get-InstallElevated }
if ($getEMETCheck)              { Get-EMET }
if ($getLAPSCheck)              { Get-LAPS }
if ($getGPOCheck)               { Get-GPO }
if ($getNetSessionEnumCheck)    { Get-NetSessionEnum }
if ($getAppLockerCheck)         { Get-AppLocker }
if ($getCredDeviceGuardCheck)   { Get-CredDeviceGuard }
if ($getMSOfficeCheck)          { Get-MSOffice }
## Security Checks
if ($getSMBv1Check)             { Get-SMBv1 }
if ($getAnonEnumCheck)          { Get-AnonEnum }
if ($getUntrustedFontsCheck)    { Get-UntrustedFonts }
## Authentication Checks
if ($getRDPDenyCheck)           { Get-RDPDeny }
if ($getLocalAdminCheck)        { Get-LocalAdmin }
if ($getNTLMSessionsCheck)      { Get-NTLMSession }
if ($getLANMANCheck)            { Get-LANMAN }
if ($getCachedLogonCheck)       { Get-CachedLogons }
if ($getInteractiveLoginCheck)  { Get-InteractiveLogin }
if ($getWDigestCheck)           { Get-WDigest }
if ($getRestrictRDPClientsCheck){ Get-RestrictRDPClients }
## Network Checks
if ($getNetworkIPv4Check)       { Get-NetworkSettingsIPv4 }
if ($getNetworkIPv6Check)       { Get-NetworkSettingsIPv6 }
if ($getWPADCheck)              { Get-WPAD }
if ($getWINSConfigCheck)        { Get-WINSConfig }
if ($getLLMNRConfigCheck)       { Get-LLMNRConfig }
if ($getCompBrowserCheck)       { Get-CompBrowser }
if ($getNetBIOSCheck)           { Get-NetBIOS }
## PowerShell Checks
if ($getPSVersionCheck)         { Get-PSVersions }
if ($getPSLanguageCheck)        { Get-PSLanguage }
if ($getPSModuleCheck)          { Get-PSModule }
if ($getPSScriptCheck)          { Get-PSScript }
if ($getPSTranscriptCheck)      { Get-PSTranscript }
if ($getPSProtectedCheck)       { Get-PSProtectedEvent }
if ($getWinRMCheck)             { Get-WinRM }
## Logging Checks
if ($getPSEventLogCheck)        { Get-PSEventLog }
if ($getCmdAuditingCheck)       { Get-CmdAuditing }
if ($getWinScriptingCheck)      { Get-WinScripting }

# Report Footer
#############################
Prt-ReportFooter
if($cutsec_footer){ Prt-CutSec-ReportFooter }
Set-Location -Path ..