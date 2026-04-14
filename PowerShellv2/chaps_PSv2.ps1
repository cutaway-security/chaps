<#
    chaps_PSv2.ps1 - a PowerShell script for checking system security
    when conducting an assessment of systems where the Microsoft 
    Policy Analyzer and other assessment tools cannot be installed.

    Author: Don C. Weber (@cutaway)
    Date:   April 20, 2025
#>

<#
	License: 
	Copyright (c) 2025, Cutaway Security, Inc. <dev [@] cutawaysecurity.com>
	
	chaps_PSv2.ps1 is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.
	
	chaps_PSv2.ps1 is distributed in the hope that it will be useful,
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
    # To use `chaps_PSv2.ps1 -config`
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
$getNetSessionEnumCheck     = $true
$getAppLockerCheck          = $true   
$getCredDeviceGuardCheck    = $true
$getMSOfficeCheck           = $true
$getSysmonCheck             = $true
$getUSBDevicesCheck         = $true
$getAntiVirusCheck          = $true
$getSoftwareInventoryCheck  = $true
$getUACConfigCheck          = $true
$getAccountPolicyCheck      = $true
$getSecureBootCheck         = $true
$getLSAProtectionCheck      = $true
$getServiceHardeningCheck   = $true
## Security Checks
$getSMBv1Check              = $true        
$getAnonEnumCheck           = $true   
$getUntrustedFontsCheck     = $true
$getASRCheck                = $true
$getSMBClientConfigCheck    = $true
$getTLSConfigCheck          = $true
$getAuditPolicyCheck        = $true
## Authentication Checks
$getRDPDenyCheck            = $true     
$getLocalAdminCheck         = $true  
$getNTLMSessionsCheck       = $true
$getLANMANCheck             = $true      
$getCachedLogonCheck        = $true  
$getInteractiveLoginCheck   = $true
$getWDigestCheck            = $true   
$getRestrictRDPClientsCheck = $true
$getRDPNLAConfigCheck       = $true
## Network Checks
$getNetworkIPv4Check        = $true
$getNetworkIPv6Check        = $true
$getWPADCheck               = $true      
$getWINSConfigCheck         = $true
$getLLMNRConfigCheck        = $true
$getCompBrowserCheck        = $true  
$getNetBIOSCheck            = $true
$getNetConnectionsCheck     = $true
$getFirewallProfileCheck    = $true
$getTCPIPHardeningCheck     = $true
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

if ($ps_version -lt 2) {
    Write-Output "ERROR: This script requires PSv2+."
    exit
}

#############################
# Set up document header information
#############################
$script_name            = 'chaps_PSv2'
$script_version         = '2.0.0'
$start_time_readable    = Get-Date -Format "dddd MM/dd/yyyy HH:mm:ss K"
$computername           = $env:ComputerName
$sysdrive               = $env:SystemDrive

############################# 
# Output Header Write-Host functions 
#############################
$pos_str = "[+]" # Positive Findings: System is configured to recommendation
$neg_str = "[-]" # Negative Findings: System is configured against security/audit recommmendation
$inf_str = "[*]" # Informational Text: Information about the script and/or checks being performed
$rep_str = "[$]" # Report Information: Information about the report generation
$err_str = "[x]" # Error Reports: A check failed and so the configuration is unknown

#############################
# Print functions
#############################
function Prt-ReportHeader{
    Write-Output "# CHAPS Report: $script_name $script_version"
    Write-Output ""
    Write-Output "| Field | Value |"
    Write-Output "|-------|-------|"
    Write-Output "| Hostname | $computername |"
    Write-Output "| Start Time | $start_time_readable |"
    Write-Output "| PS Version | $ps_version |"
    Write-Output "| OS Version | $(([Environment]::OSVersion).VersionString) |"
    if ($auditor_company){ Write-Output "| Auditing Company | $auditor_company |" }
    if ($sitename){ Write-Output "| Site/Plant | $sitename |" }
    Get-AdminState
    Write-Output ""
}

function Prt-ReportFooter{
    $stop_time_readable = Get-Date -Format "dddd MM/dd/yyyy HH:mm:ss K"
    Write-Output ""
    Write-Output "---"
    Write-Output ""
    Write-Output "**$script_name completed** -- Stop Time: $stop_time_readable"
}

function Prt-CutSec-ReportFooter{
    Write-Output ""
    Write-Output "---"
    Write-Output ""
    Write-Output "*CHAPS $script_name $script_version -- Cutaway Security, LLC*"
    Write-Output "*Assessment and auditing: info [@] cutawaysecurity.com -- Script help: dev [@] cutawaysecurity.com*"
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
    Write-Output "    Get Sysmon Config: $getSysmonCheck"
Write-Output "    Get USB Devices: $getUSBDevicesCheck"
    Write-Output "    Get AntiVirus Config: $getAntiVirusCheck"
Write-Output "    Get Software Inventory: $getSoftwareInventoryCheck"
    Write-Output "    Get UAC Config: $getUACConfigCheck"
Write-Output "    Get Account Policy: $getAccountPolicyCheck"
    Write-Output "    Get Secure Boot: $getSecureBootCheck"
Write-Output "    Get LSA Protection: $getLSAProtectionCheck"
    Write-Output "    Get Service Hardening: $getServiceHardeningCheck"
    ## Security Checks
    Write-Output "    Get SMBv1 Check: $getSMBv1Check"
Write-Output "    Get Anonmyous Enumeration: $getAnonEnumCheck"   
    Write-Output "    Get Untrusted Fonts: $getUntrustedFontsCheck"
Write-Output "    Get ASR Rules: $getASRCheck"
    Write-Output "    Get SMB Client Signing: $getSMBClientConfigCheck"
Write-Output "    Get TLS Config: $getTLSConfigCheck"
    Write-Output "    Get Audit Policy: $getAuditPolicyCheck"
    ## Authentication Checks
    Write-Output "    Get RDP Deny Config: $getRDPDenyCheck"
Write-Output "    Get Local Administrator: $getLocalAdminCheck"  
    Write-Output "    Get NTLM Sessions: $getNTLMSessionsCheck"
Write-Output "    Get LANMAN Config: $getLANMANCheck"      
    Write-Output "    Get Cached Logon Config: $getCachedLogonCheck"
Write-Output "    Get Interactive Logon Config: $getInteractiveLoginCheck"
    Write-Output "    Get WDigest Config: $getWDigestCheck"
Write-Output "    Get Restrict RDP Clients: $getRestrictRDPClientsCheck"
    Write-Output "    Get RDP NLA Config: $getRDPNLAConfigCheck"
    ## Network Checks
    Write-Output "    Get IPv4 Network: $getNetworkIPv4Check"
Write-Output "    Get IPv6 Network: $getNetworkIPv6Check"
    Write-Output "    Get WPAD Config: $getWPADCheck"
Write-Output "    Get WINS Config: $getWINSConfigCheck"
    Write-Output "    Get LLMNR Config: $getLLMNRConfigCheck"
Write-Output "    Get Computer Browser: $getCompBrowserCheck"  
    Write-Output "    Get NetBIOS Config: $getNetBIOSCheck"
Write-Output "    Get Network Connections: $getNetConnectionsCheck"
    Write-Output "    Get Firewall Profile: $getFirewallProfileCheck"
Write-Output "    Get TCP/IP Hardening: $getTCPIPHardeningCheck"
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
		Write-Output "| Admin Status | Normal User |"
        $global:admin_user = $false
	} else {
		Write-Output "| Admin Status | Administrator |"
        $global:admin_user = $true
    }
}

#############################
# Information Collection functions
#############################

# System Info Checks
#############################
function Get-SystemInfo {
    # PSv2: Prefer Win32_OperatingSystem WMI, fall back to 'systeminfo'.
    # Get-ComputerInfo is PSv5.1+ and may also fail under non-interactive SSH,
    # so we skip it entirely here.
    $sysdata = $null

    Try {
        $os = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction Stop
        $cs = Get-WmiObject -Class Win32_ComputerSystem -ErrorAction SilentlyContinue
        $workgroup = ''
        if ($cs -ne $null -and $cs.Workgroup) { $workgroup = $cs.Workgroup }
        $sysdata = "$($os.Caption), $($os.Version), $($os.BuildNumber), $($os.OSArchitecture), $workgroup"
    }
    Catch {
        $sysdata = $null
    }

    if (-not $sysdata) {
        Try {
            $sdata = systeminfo 2>$null
            $parts = $sdata | Select-String -Pattern '^OS Name','^OS Version','^System Type','^Domain'
            if ($parts -ne $null) {
                $sysdata = ($parts | ForEach-Object { $_.Line.Trim() }) -join ' | '
            }
        }
        Catch {
            $sysdata = $null
        }
    }

    if (-not $sysdata) {
        Write-Output "$err_str System info collection failed: Win32_OperatingSystem WMI and systeminfo both unavailable or failed."
    } else {
        Write-Output "$inf_str $sysdata"
    }
}

function Get-WinVersion{
    $winVersion = "Windows Version: $(([Environment]::OSVersion).VersionString)"
    Write-Output "$inf_str $winVersion"
}

function Get-UserPath{
    $userPath = "Windows Default Path for $env:Username : $env:Path"
    Write-Output "$inf_str $userPath"
}

function Get-AutoUpdateConfig {
    $AutoUpdateNotificationLevels= @{0="Not configured"; 1="Disabled" ; 2="Notify before download"; 3="Notify before installation"; 4="Scheduled installation"}
    Try{
        $resa = ((New-Object -com "Microsoft.Update.AutoUpdate").Settings).NotificationLevel
        if ( $resa -eq 4){
            Write-Output "$pos_str Windows AutoUpdate is set to $resa : $AutoUpdateNotificationLevels.$resa"
} else {
            Write-Output "$neg_str Windows AutoUpdate is not configured to automatically install updates: $resa : $AutoUpdateNotificationLevels.$resa"
}
    }
    Catch{
        Write-Output "$err_str Windows AutoUpdate test failed."
}
}

function Get-WinPatch {    
    # Gist Grimthorr/pending-updates.ps1: https://gist.github.com/Grimthorr/44727ea8cf5d3df11cf7

    if (Test-CommandExists Test-NetConnection){
        $internetConn = (Test-NetConnection -ComputerName www.google.com -InformationLevel Quiet -WarningAction SilentlyContinue -ErrorAction SilentlyContinue).PingSucceeded
        if (-not $internetConn){
            Write-Output "$err_str Check for Critical and Important Windows patches test failed: no internet connection."
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
                Write-Output "$neg_str Missing Critical or Important Update KB: $m"
}
        } else {
            Write-Output "$pos_str Windows system appears to be up-to-date for Critical and Important patches."
}
    }
    Catch{
        Write-Output "$err_str Check for Critical and Important Windows patches test failed: command failed."
}
}

function Get-BitLocker {    
    if (-NOT $global:admin_user){ return }
    if (Test-CommandExists Get-BitLockerVolume){
        Try {
            $vs = Get-BitLockerVolume -ErrorAction Stop | Where-Object {$_.VolumeType -eq 'OperatingSystem'} | Select VolumeStatus -ErrorAction Stop
            $resvs = $vs.VolumeStatus
            if ($resvs -eq 'FullyEncrypted'){
                Write-Output "$pos_str BitLocker detected and Operating System Volume is: $resvs"
            } else {
                Write-Output "$neg_str BitLocker not detected on Operating System Volume or encryption is not complete. Check for other encryption methods: $resvs"
            }
        }
        Catch {
            Write-Output "$inf_str Get-BitLockerVolume available but failed: $($_.Exception.Message)"
        }
        return
    }

    # Fallback: manage-bde.exe (may not exist on Server editions without BitLocker feature installed)
    Try {
        $mbde = Get-Command manage-bde.exe -ErrorAction Stop
    }
    Catch {
        Write-Output "$inf_str BitLocker check skipped: neither Get-BitLockerVolume nor manage-bde.exe available. BitLocker feature is likely not installed."
        return
    }

    Try {
        $vsm = manage-bde -status 2>$null | Select-String -Pattern 'Conversion Status'
        if ($vsm -ne $null){
            if ($vsm -match 'Fully Encrypted'){
                Write-Output "$pos_str Operating System Volume is Fully Encrypted (manage-bde): $vsm"
            } else {
                Write-Output "$neg_str BitLocker not detected or encryption is not complete (manage-bde): $vsm"
            }
        } else {
            Write-Output "$neg_str BitLocker not detected (manage-bde returned no Conversion Status)."
        }
    }
    Catch {
        Write-Output "$err_str manage-bde fallback failed: $($_.Exception.Message)"
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
            Write-Output "$neg_str Users can install software as NT AUTHORITY\SYSTEM."
} else {
            Write-Output "$pos_str Users cannot install software as NT AUTHORITY\SYSTEM."
}
    }
    Catch{
        Write-Output "$err_str Check if users can install software as NT AUTHORITY\SYSTEM failed"
}
}

function Get-EMET {
    # EMET is deprecated as of Windows 10. Its mitigations are built into Windows Defender Exploit Protection.
    # Ref: https://support.microsoft.com/en-us/topic/emet-mitigations-guidelines
    if ([System.Environment]::OSVersion.Version.Major -ge 10){
        Try{
            if (Test-CommandExists Get-ProcessMitigation){
                $sysmit = Get-ProcessMitigation -System
                Write-Output "$inf_str EMET is deprecated. Windows Exploit Protection is the replacement."
if ($sysmit.DEP.Enable -eq 'ON'){
                    Write-Output "$pos_str System-wide DEP (Data Execution Prevention) is enabled."
} else {
                    Write-Output "$neg_str System-wide DEP (Data Execution Prevention) is not enabled: $($sysmit.DEP.Enable)"
}
                if ($sysmit.ASLR.ForceRelocateImages -eq 'ON'){
                    Write-Output "$pos_str System-wide mandatory ASLR is enabled."
} else {
                    Write-Output "$neg_str System-wide mandatory ASLR is not enabled: $($sysmit.ASLR.ForceRelocateImages)"
}
                if ($sysmit.CFG.Enable -eq 'ON'){
                    Write-Output "$pos_str System-wide Control Flow Guard (CFG) is enabled."
} else {
                    Write-Output "$neg_str System-wide Control Flow Guard (CFG) is not enabled: $($sysmit.CFG.Enable)"
}
            } else {
                Write-Output "$inf_str Get-ProcessMitigation not available. Cannot check Exploit Protection settings."
}
        }
        Catch{
            Write-Output "$err_str Testing for Windows Exploit Protection settings failed."
}
    } else {
        Try{
            $resemet = (Get-Service EMET_Service -ErrorAction Stop).Status
            if ($resemet -eq 'Running'){
                Write-Output "$pos_str EMET Service is running."
} else {
                Write-Output "$neg_str EMET Service is not running: $resemet"
}
        }
        Catch{
            Write-Output "$neg_str EMET Service not found. EMET may not be installed."
}
    }
}

function Get-LAPS {
    # Check for Windows LAPS (built-in on Win10 21H2+ / Server 2019+) and legacy LAPS
    # Ref: https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview
    $laps_found = $false

    # Check for Windows LAPS (modern) via registry policy
    Try{
        $winlaps = Get-ItemProperty -path ‘HKLM:\Software\Microsoft\Policies\LAPS’ -ErrorAction Stop
        if ($winlaps -ne $null){
            Write-Output "$pos_str Windows LAPS policy is configured."
        $laps_found = $true
        }
    }
    Catch{
        # Key doesn’t exist, continue checking
    }

    # Check for Windows LAPS via CSE registry (modern)
    Try{
        $winlapscse = Get-ItemProperty -path ‘HKLM:\Software\Microsoft\Windows\CurrentVersion\LAPS\State’ -ErrorAction Stop
        if ($winlapscse -ne $null){
            Write-Output "$pos_str Windows LAPS client state found in registry."
        $laps_found = $true
        }
    }
    Catch{
        # Key doesn’t exist, continue checking
    }

    # Check for legacy LAPS (AdmPwd.dll)
    Try{
        if (Test-Path ‘C:\Program Files\LAPS\CSE\Admpwd.dll’){
            Write-Output "$pos_str Legacy LAPS (AdmPwd.dll) is installed."
        $laps_found = $true
        }
    }
    Catch{
        # File doesn’t exist, continue
    }

    if (-not $laps_found){
        Write-Output "$neg_str Local Administrator Password Solution (LAPS) is not installed (checked Windows LAPS and legacy LAPS)."
}
}


function Get-GPO {
    # Group Policy objects must be reprocessed even if they have not changed.: https://www.stigviewer.com/stig/windows_server_2012_member_server/2014-01-07/finding/V-4448
    Try{
        $ressess = (Get-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\' -ErrorAction SilentlyContinue).NoGPOListChanges
        if ($ressess -ne $null){
            if ($ressess){
                Write-Output "$neg_str GPO settings are configured to only be applied after change: $ressess"
} else {
                Write-Output "$pos_str GPO settings are configured to be applied when GPOs are processed: $ressess"
}
        } else {
            Write-Output "$inf_str System may not be assigned GPOs."
}
    }
    Catch{
        Write-Output "$err_str Testing for Microsoft GPO failed."
}
}


function Get-NetSessionEnum {
    # View Net Session Enum Permissions: https://gallery.technet.microsoft.com/scriptcenter/View-Net-Session-Enum-dfced139
    # Net Cease - Hardening Net Session Enumeration: https://gallery.technet.microsoft.com/Net-Cease-Blocking-Net-1e8dcb5b
    # SrvsvcSessionInfo registry key restricts who can call NetSessionEnum
    # Ref: https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-restrict-clients-allowed-to-make-remote-sam-calls

    Try{
        $regpath = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity'
        $ressess = (Get-ItemProperty -path $regpath -ErrorAction SilentlyContinue).SrvsvcSessionInfo
        if ($ressess -ne $null){
            Write-Output "$pos_str SrvsvcSessionInfo registry key is configured (Net Session Enumeration is restricted)."
} else {
            Write-Output "$neg_str SrvsvcSessionInfo registry key is not configured (Net Session Enumeration may be unrestricted)."
}
    }
    Catch{
        Write-Output "$err_str Testing Net Session Enumeration configuration failed."
}

    # Check RestrictRemoteSAM for SAM enumeration restrictions (related hardening)
    Try{
        $ressam = (Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue).RestrictRemoteSAM
        if ($ressam -ne $null){
            Write-Output "$pos_str RestrictRemoteSAM registry key is configured: $ressam"
} else {
            Write-Output "$neg_str RestrictRemoteSAM registry key is not configured."
}
    }
    Catch{
        Write-Output "$err_str Testing RestrictRemoteSAM configuration failed."
}
}

function Get-AppLocker {
    # PSv2: Get-AppLockerPolicy requires PSv3+. Check registry for AppLocker policy existence.
    Try{
        $alPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2'
        if (Test-Path $alPath){
            $rules = Get-ChildItem $alPath -ErrorAction SilentlyContinue
            if ($rules -ne $null -and $rules.Count -gt 0){
                $ruleNames = ($rules | ForEach-Object { $_.PSChildName }) -join ', '
                Write-Output "$pos_str AppLocker policies detected in registry: $ruleNames"
            } else {
                Write-Output "$neg_str AppLocker policy path exists but no rules configured."
            }
        } else {
            Write-Output "$neg_str AppLocker not configured (SrpV2 registry path not found)."
        }
    }
    Catch{
        Write-Output "$err_str Testing for Microsoft AppLocker failed."
    }
}


function Get-CredDeviceGuard {
    
    # How to Verify if Device Guard is Enabled or Disabled in Windows 10: https://www.tenforums.com/tutorials/68926-verify-if-device-guard-enabled-disabled-windows-10-a.html
    # Security Focus: Check Credential Guard Status with PowerShell: https://blogs.technet.microsoft.com/poshchap/2016/09/23/security-focus-check-credential-guard-status-with-powershell/
    
    if ([System.Environment]::OSVersion.Version.Major -ge 10){
        Try{
            $secServConfig = (Get-WmiObject -Class Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop).SecurityServicesConfigured
            $secServRunning = (Get-WmiObject -Class Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop).SecurityServicesRunning
        }
        Catch{
            Write-Output "$err_str Testing for Credential and Device Guard failed."
}
        
        if ($secServConfig){
            Write-Output "$pos_str Credential Guard or HVCI service is running."
} else {
            Write-Output "$neg_str Credential Guard or HVCI service is not running."
}
        if ($secServRunning){
            Write-Output "$pos_str Device Guard appears to be configured."
} else {
            Write-Output "$neg_str Device Guard: no properties exist and therefore is not configured."
}

    } else {
        Write-Output "$inf_str Windows Version is older than 10. Cannot test for Credential or Device Guard."
}
} 

function Get-MSOffice {
    # Check Microsoft Office macro security settings
    # Ref: https://learn.microsoft.com/en-us/deployoffice/security/internet-macros-blocked
    # VBAWarnings: 1=Enable all, 2=Disable with notification, 3=Disable except digitally signed, 4=Disable all
    # BlockContentExecutionFromInternet: 1=Block macros from internet files

    $office_apps = @('Word', 'Excel', 'PowerPoint', 'Access', 'Outlook')
    # Common Office version registry paths (16.0=2016/2019/365, 15.0=2013, 14.0=2010)
    $office_versions = @('16.0', '15.0', '14.0')
    $office_found = $false

    foreach ($ver in $office_versions){
        foreach ($app in $office_apps){
            Try{
                $regpath = "HKCU:\Software\Microsoft\Office\$ver\$app\Security"
                $props = Get-ItemProperty -path $regpath -ErrorAction SilentlyContinue
                if ($props -ne $null){
                    $office_found = $true
                    $vba = $props.VBAWarnings
                    if ($vba -ne $null){
                        if ([int]$vba -ge 3){
                            Write-Output "$pos_str Office $ver $app VBAWarnings is set to restrict macros: $vba"
} else {
                            Write-Output "$neg_str Office $ver $app VBAWarnings is not set to restrict macros: $vba"
}
                    } else {
                        Write-Output "$neg_str Office $ver $app VBAWarnings is not configured."
}

                    $blockinet = $props.BlockContentExecutionFromInternet
                    if ($blockinet -ne $null){
                        if ([int]$blockinet -eq 1){
                            Write-Output "$pos_str Office $ver $app blocks macros from internet files."
} else {
                            Write-Output "$neg_str Office $ver $app does not block macros from internet files: $blockinet"
}
                    }
                }
            }
            Catch{
                # Registry path doesn't exist for this version/app, skip
            }
        }

        # Check policy-level macro settings (GPO-deployed)
        Try{
            $polpath = "HKCU:\Software\Policies\Microsoft\Office\$ver"
            if (Test-Path $polpath){
                Write-Output "$inf_str Office $ver group policy settings detected at: $polpath"
}
        }
        Catch{
            # Policy path doesn't exist, skip
        }
    }

    if (-not $office_found){
        Write-Output "$inf_str No Microsoft Office installations detected in registry."
}
}

function Get-Sysmon {
    # Check if Sysmon is installed and running
    # Ref: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
    Try{
        $sysmonSvc = Get-Service -Name Sysmon* -ErrorAction SilentlyContinue
        if ($sysmonSvc -ne $null){
            foreach ($svc in $sysmonSvc){
                if ($svc.Status -eq 'Running'){
                    Write-Output "$pos_str Sysmon service is running: $($svc.Name) ($($svc.DisplayName))"
} else {
                    Write-Output "$neg_str Sysmon service found but not running: $($svc.Name) Status: $($svc.Status)"
}
            }
        } else {
            Write-Output "$neg_str Sysmon service not found."
}
    }
    Catch{
        Write-Output "$err_str Testing for Sysmon service failed."
}

    # Check for Sysmon driver
    Try{
        $sysmonDrv = Get-Service -Name SysmonDrv -ErrorAction SilentlyContinue
        if ($sysmonDrv -ne $null){
            Write-Output "$pos_str Sysmon driver (SysmonDrv) is present: Status: $($sysmonDrv.Status)"
} else {
            # Also check for 64-bit variant
            $sysmonDrv64 = Get-Service -Name Sysmon*Drv* -ErrorAction SilentlyContinue
            if ($sysmonDrv64 -ne $null){
                foreach ($drv in $sysmonDrv64){
                    Write-Output "$pos_str Sysmon driver found: $($drv.Name) Status: $($drv.Status)"
}
            } else {
                Write-Output "$neg_str Sysmon driver not found."
}
        }
    }
    Catch{
        Write-Output "$err_str Testing for Sysmon driver failed."
}
}

function Get-USBDevices {
    # Enumerate USB Plug and Play devices
    # Ref: Issue #2 feature request
    if (Test-CommandExists Get-PnpDevice){
        Try{
            $usbDevices = Get-PnpDevice -Class 'USB' -ErrorAction Stop
            if ($usbDevices -ne $null){
                Write-Output "$inf_str USB Plug and Play devices detected: $($usbDevices.Count)"
foreach ($dev in $usbDevices){
                    $status = $dev.Status
                    $name = $dev.FriendlyName
                    $id = $dev.InstanceId
                    if ($status -eq 'OK'){
                        Write-Output "$inf_str USB Device: $name (Status: $status, ID: $id)"
} else {
                        Write-Output "$inf_str USB Device: $name (Status: $status, ID: $id)"
}
                }
            } else {
                Write-Output "$inf_str No USB Plug and Play devices detected."
}
        }
        Catch{
            Write-Output "$err_str Enumerating USB Plug and Play devices failed."
}
    } else {
        # Fallback to WMI
        Try{
            $usbWmi = Get-WmiObject -Class Win32_USBControllerDevice -ErrorAction Stop
            if ($usbWmi -ne $null){
                Write-Output "$inf_str USB devices detected via WMI: $($usbWmi.Count)"
} else {
                Write-Output "$inf_str No USB devices detected via WMI."
}
        }
        Catch{
            Write-Output "$err_str Enumerating USB devices failed (WMI fallback)."
}
    }
}

function Get-AntiVirus {
    # Detect installed antivirus/EDR software
    # Ref: Issue #2 feature request
    # SecurityCenter2 namespace is available on workstation editions, not Server
    Try{
        $avProducts = Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiVirusProduct -ErrorAction Stop
        if ($avProducts -ne $null){
            foreach ($av in $avProducts){
                Write-Output "$inf_str Antivirus detected: $($av.displayName)"
        # productState is a bitmask: bits 12-8 = provider, bits 7-4 = scanner enabled, bits 3-0 = definitions up to date
                $state = $av.productState
                $enabled = ($state -band 0x1000) -ne 0
                $uptodate = ($state -band 0x10) -eq 0
                if ($enabled){
                    Write-Output "$pos_str $($av.displayName) is enabled."
} else {
                    Write-Output "$neg_str $($av.displayName) is not enabled."
}
                if ($uptodate){
                    Write-Output "$pos_str $($av.displayName) definitions appear up to date."
} else {
                    Write-Output "$neg_str $($av.displayName) definitions may be out of date."
}
            }
        } else {
            Write-Output "$neg_str No antivirus products detected via SecurityCenter2."
}
    }
    Catch{
        # SecurityCenter2 not available (likely Server edition)
        Write-Output "$inf_str SecurityCenter2 not available (expected on Server editions)."
        # Try checking Windows Defender via Get-MpComputerStatus
        Try{
            if (Test-CommandExists Get-MpComputerStatus){
                $mpStatus = Get-MpComputerStatus -ErrorAction Stop
                if ($mpStatus.AntivirusEnabled){
                    Write-Output "$pos_str Windows Defender Antivirus is enabled."
} else {
                    Write-Output "$neg_str Windows Defender Antivirus is not enabled."
}
                if ($mpStatus.RealTimeProtectionEnabled){
                    Write-Output "$pos_str Windows Defender Real-Time Protection is enabled."
} else {
                    Write-Output "$neg_str Windows Defender Real-Time Protection is not enabled."
}
                if ($mpStatus.AntivirusSignatureAge -le 7){
                    Write-Output "$pos_str Windows Defender signatures are $($mpStatus.AntivirusSignatureAge) day(s) old."
} else {
                    Write-Output "$neg_str Windows Defender signatures are $($mpStatus.AntivirusSignatureAge) day(s) old."
}
            } else {
                Write-Output "$inf_str Cannot determine antivirus status (no SecurityCenter2 or Get-MpComputerStatus)."
}
        }
        Catch{
            Write-Output "$err_str Testing for antivirus software failed."
}
    }
}

function Get-SoftwareInventory {
    # List installed software via registry (avoiding slow Win32_Product which triggers MSI reconfiguration)
    # Ref: Issue #2 feature request
    $regPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

    Try{
        $software = @()
        foreach ($path in $regPaths){
            $items = Get-ItemProperty $path -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -ne $null } | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
            if ($items -ne $null){
                $software += $items
            }
        }

        if ($software.Count -gt 0){
            # Deduplicate by DisplayName
            $unique = $software | Sort-Object DisplayName -Unique
            Write-Output "$inf_str Installed software count: $($unique.Count)"
foreach ($s in $unique){
                $name = $s.DisplayName
                $ver = $s.DisplayVersion
                $pub = $s.Publisher
                Write-Output "$inf_str Software: $name (Version: $ver, Publisher: $pub)"
}
        } else {
            Write-Output "$inf_str No installed software found in registry."
}
    }
    Catch{
        Write-Output "$err_str Enumerating installed software failed."
}
}

function Get-UACConfig {
    # Check User Account Control configuration
    # Ref: CIS Benchmark 2.3.17.x, https://learn.microsoft.com/en-us/windows/security/identity-protection/user-account-control
    Try{
        $uacPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        $uac = Get-ItemProperty -path $uacPath -ErrorAction SilentlyContinue

        # EnableLUA: UAC enabled (should be 1)
        if ($uac.EnableLUA -ne $null){
            if ($uac.EnableLUA -eq 1){
                Write-Output "$pos_str UAC is enabled (EnableLUA: $($uac.EnableLUA))"
} else {
                Write-Output "$neg_str UAC is disabled (EnableLUA: $($uac.EnableLUA))"
}
        } else {
            Write-Output "$neg_str EnableLUA registry key not found."
}

        # ConsentPromptBehaviorAdmin: 0=Elevate without prompting, 1=Prompt on secure desktop, 2=Prompt for consent on secure desktop
        # CIS recommends 1 or 2
        if ($uac.ConsentPromptBehaviorAdmin -ne $null){
            $val = $uac.ConsentPromptBehaviorAdmin
            if ([int]$val -ge 1 -and [int]$val -le 2){
                Write-Output "$pos_str UAC admin prompt is configured securely (ConsentPromptBehaviorAdmin: $val)"
} else {
                Write-Output "$neg_str UAC admin prompt may not be secure (ConsentPromptBehaviorAdmin: $val)"
}
        }

        # PromptOnSecureDesktop: should be 1
        if ($uac.PromptOnSecureDesktop -ne $null){
            if ($uac.PromptOnSecureDesktop -eq 1){
                Write-Output "$pos_str UAC prompts on secure desktop (PromptOnSecureDesktop: 1)"
} else {
                Write-Output "$neg_str UAC does not prompt on secure desktop (PromptOnSecureDesktop: $($uac.PromptOnSecureDesktop))"
}
        }

        # FilterAdministratorToken: should be 1 to filter built-in admin
        if ($uac.FilterAdministratorToken -ne $null){
            if ($uac.FilterAdministratorToken -eq 1){
                Write-Output "$pos_str UAC filters built-in Administrator token (FilterAdministratorToken: 1)"
} else {
                Write-Output "$neg_str UAC does not filter built-in Administrator token (FilterAdministratorToken: $($uac.FilterAdministratorToken))"
}
        }
    }
    Catch{
        Write-Output "$err_str Testing UAC configuration failed."
}
}

function Get-AccountPolicy {
    # Check password policy, account lockout, and special account status
    # Ref: CIS Benchmark 1.1.x, 1.2.x
    Try{
        $netAccounts = net accounts 2>&1
        if ($netAccounts -ne $null){
            foreach ($line in $netAccounts){
                $trimmed = "$line".Trim()
                if ($trimmed -match 'Lockout threshold:\s+(.+)'){
                    $threshold = $Matches[1].Trim()
                    if ($threshold -eq 'Never'){
                        Write-Output "$neg_str Account lockout threshold is not configured: $threshold"
} else {
                        Write-Output "$pos_str Account lockout threshold is set: $threshold"
}
                }
                if ($trimmed -match 'Lockout duration.*:\s+(.+)'){
                    Write-Output "$inf_str Account lockout duration: $($Matches[1].Trim())"
}
                if ($trimmed -match 'Minimum password length:\s+(.+)'){
                    $minLen = $Matches[1].Trim()
                    if ([int]$minLen -ge 14){
                        Write-Output "$pos_str Minimum password length meets recommendation (14+): $minLen"
} elseif ([int]$minLen -ge 8) {
                        Write-Output "$inf_str Minimum password length: $minLen (14+ recommended)"
} else {
                        Write-Output "$neg_str Minimum password length is too short: $minLen"
}
                }
                if ($trimmed -match 'Maximum password age.*:\s+(.+)'){
                    Write-Output "$inf_str Maximum password age: $($Matches[1].Trim())"
}
                if ($trimmed -match 'Password history length:\s+(.+)'){
                    Write-Output "$inf_str Password history length: $($Matches[1].Trim())"
}
            }
        }
    }
    Catch{
        Write-Output "$err_str Checking account policies via net accounts failed."
}

    # Check Guest account status (PSv2: use net user instead of Get-LocalUser)
    Try{
        $guestOut = net user Guest 2>&1
        if ($guestOut -ne $null){
            $activeMatch = $guestOut | Select-String -Pattern 'Account active\s+(Yes|No)'
            if ($activeMatch -ne $null){
                if ("$activeMatch" -match 'No'){
                    Write-Output "$pos_str Guest account is disabled."
                } else {
                    Write-Output "$neg_str Guest account is enabled."
                }
            }
        }
    }
    Catch{
        Write-Output "$err_str Checking Guest account status failed."
    }

    # Check if built-in Administrator is renamed (PSv2: use WMI)
    Try{
        $adminAcct = Get-WmiObject -Class Win32_UserAccount -Filter "SID LIKE '%-500'" -ErrorAction SilentlyContinue
        if ($adminAcct -ne $null){
            if ($adminAcct.Name -eq 'Administrator'){
                Write-Output "$neg_str Built-in Administrator account has not been renamed."
            } else {
                Write-Output "$pos_str Built-in Administrator account has been renamed to: $($adminAcct.Name)"
            }
            Write-Output "$inf_str Built-in Administrator account disabled: $($adminAcct.Disabled)"
        }
    }
    Catch{
        Write-Output "$err_str Checking Administrator account status failed."
    }
}

function Get-SecureBoot {
    # Check Secure Boot / UEFI status
    # Ref: CIS Benchmark, STIG V-63329
    Try{
        if (Test-CommandExists Confirm-SecureBootUEFI){
            $sb = Confirm-SecureBootUEFI -ErrorAction Stop
            if ($sb){
                Write-Output "$pos_str Secure Boot is enabled."
} else {
                Write-Output "$neg_str Secure Boot is not enabled."
}
        } else {
            # Fallback to registry
            $sbReg = (Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' -ErrorAction SilentlyContinue).UEFISecureBootEnabled
            if ($sbReg -ne $null){
                if ($sbReg -eq 1){
                    Write-Output "$pos_str Secure Boot is enabled (registry)."
} else {
                    Write-Output "$neg_str Secure Boot is not enabled (registry): $sbReg"
}
            } else {
                Write-Output "$inf_str Secure Boot status could not be determined (BIOS/legacy boot may be in use)."
}
        }
    }
    Catch{
        Write-Output "$inf_str Secure Boot check not supported on this system (may be BIOS/legacy boot)."
}
}

function Get-LSAProtection {
    # Check LSA Protection (RunAsPPL) - prevents credential dumping tools
    # Ref: https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection
    Try{
        $runasppl = (Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue).RunAsPPL
        if ($runasppl -ne $null){
            if ([int]$runasppl -eq 1){
                Write-Output "$pos_str LSA Protection (RunAsPPL) is enabled."
} else {
                Write-Output "$neg_str LSA Protection (RunAsPPL) is not enabled: $runasppl"
}
        } else {
            Write-Output "$neg_str LSA Protection (RunAsPPL) registry key not found."
}
    }
    Catch{
        Write-Output "$err_str Testing LSA Protection (RunAsPPL) failed."
}
}

function Get-ServiceHardening {
    # Check that risky services are disabled
    # Ref: CIS Benchmark 5.x, PrintNightmare, attack surface reduction
    $riskyServices = @{
        'Spooler'         = 'Print Spooler (PrintNightmare risk)'
        'RemoteRegistry'  = 'Remote Registry'
        'SNMP'            = 'SNMP Service'
        'TlntSvr'         = 'Telnet Server'
        'RemoteAccess'    = 'Routing and Remote Access'
        'NetTcpPortSharing' = '.NET TCP Port Sharing'
        'SharedAccess'    = 'Internet Connection Sharing'
    }

    foreach ($svcName in $riskyServices.Keys){
        Try{
            $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
            if ($svc -ne $null){
                if ($svc.Status -eq 'Running'){
                    Write-Output "$neg_str $($riskyServices[$svcName]) service is running."
} elseif ($svc.StartType -eq 'Disabled') {
                    Write-Output "$pos_str $($riskyServices[$svcName]) service is disabled."
} else {
                    Write-Output "$inf_str $($riskyServices[$svcName]) service status: $($svc.Status), start type: $($svc.StartType)"
}
            }
        }
        Catch{
            # Service doesn't exist on this system, skip
        }
    }
}

function Get-RDPNLAConfig {
    # Check RDP Network Level Authentication requirement
    # Ref: CIS Benchmark 18.9.65.3.9.2, STIG V-63597
    Try{
        $nla = (Get-ItemProperty -path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -ErrorAction SilentlyContinue).UserAuthentication
        if ($nla -ne $null){
            if ([int]$nla -eq 1){
                Write-Output "$pos_str RDP Network Level Authentication (NLA) is required."
} else {
                Write-Output "$neg_str RDP Network Level Authentication (NLA) is not required: $nla"
}
        } else {
            Write-Output "$inf_str RDP NLA registry key not found (RDP may not be configured)."
}
    }
    Catch{
        Write-Output "$err_str Testing RDP NLA configuration failed."
}

    # Check RDP encryption level
    Try{
        $rdpEnc = (Get-ItemProperty -path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -ErrorAction SilentlyContinue).MinEncryptionLevel
        if ($rdpEnc -ne $null){
            # 1=Low, 2=Client Compatible, 3=High, 4=FIPS
            if ([int]$rdpEnc -ge 3){
                Write-Output "$pos_str RDP minimum encryption level is High or FIPS: $rdpEnc"
} else {
                Write-Output "$neg_str RDP minimum encryption level is below High: $rdpEnc"
}
        }
    }
    Catch{
        Write-Output "$err_str Testing RDP encryption level failed."
}
}

function Get-TCPIPHardening {
    # Check TCP/IP stack hardening settings
    # Ref: CIS Benchmark 18.4.x, STIG V-63493
    $tcpPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
    Try{
        $tcp = Get-ItemProperty -path $tcpPath -ErrorAction SilentlyContinue

        # DisableIPSourceRouting: should be 2 (disabled)
        if ($tcp.DisableIPSourceRouting -ne $null){
            if ([int]$tcp.DisableIPSourceRouting -eq 2){
                Write-Output "$pos_str IP source routing is disabled: $($tcp.DisableIPSourceRouting)"
} else {
                Write-Output "$neg_str IP source routing is not fully disabled: $($tcp.DisableIPSourceRouting)"
}
        } else {
            Write-Output "$inf_str DisableIPSourceRouting not configured (default behavior)."
}

        # EnableICMPRedirect: should be 0 (disabled)
        if ($tcp.EnableICMPRedirect -ne $null){
            if ([int]$tcp.EnableICMPRedirect -eq 0){
                Write-Output "$pos_str ICMP redirects are disabled."
} else {
                Write-Output "$neg_str ICMP redirects are enabled: $($tcp.EnableICMPRedirect)"
}
        } else {
            Write-Output "$neg_str EnableICMPRedirect not configured (ICMP redirects may be accepted)."
}

        # PerformRouterDiscovery: should be 0 (disabled)
        if ($tcp.PerformRouterDiscovery -ne $null){
            if ([int]$tcp.PerformRouterDiscovery -eq 0){
                Write-Output "$pos_str IRDP router discovery is disabled."
} else {
                Write-Output "$neg_str IRDP router discovery is enabled: $($tcp.PerformRouterDiscovery)"
}
        }
    }
    Catch{
        Write-Output "$err_str Testing TCP/IP hardening settings failed."
}
}

function Get-TLSConfig {
    # Check TLS/SSL protocol versions enabled
    # Ref: CIS Benchmark 18.4.x, NIST SP 800-52
    $protocols = @('SSL 2.0', 'SSL 3.0', 'TLS 1.0', 'TLS 1.1', 'TLS 1.2', 'TLS 1.3')
    $badProtocols = @('SSL 2.0', 'SSL 3.0', 'TLS 1.0', 'TLS 1.1')
    $goodProtocols = @('TLS 1.2', 'TLS 1.3')

    foreach ($proto in $protocols){
        $serverPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$proto\Server"
        $clientPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$proto\Client"
        $isBad = $badProtocols -contains $proto

        Try{
            $serverEnabled = (Get-ItemProperty -path $serverPath -ErrorAction SilentlyContinue).Enabled
            $serverDisabledByDefault = (Get-ItemProperty -path $serverPath -ErrorAction SilentlyContinue).DisabledByDefault

            if ($serverEnabled -ne $null){
                if ([int]$serverEnabled -eq 0){
                    if ($isBad){
                        Write-Output "$pos_str $proto Server is explicitly disabled."
} else {
                        Write-Output "$neg_str $proto Server is explicitly disabled."
}
                } else {
                    if ($isBad){
                        Write-Output "$neg_str $proto Server is enabled (should be disabled)."
} else {
                        Write-Output "$pos_str $proto Server is enabled."
}
                }
            } else {
                if ($isBad){
                    Write-Output "$inf_str $proto Server not explicitly configured (OS default behavior)."
}
            }
        }
        Catch{
            # Registry path doesn't exist, protocol not configured
        }
    }
}

function Get-AuditPolicy {
    # Check basic audit policy configuration
    # Ref: CIS Benchmark 17.x, STIG audit requirements
    Try{
        $auditOut = auditpol /get /category:* 2>&1
        if ($auditOut -ne $null){
            $noAudit = $true
            $categories = @('Logon/Logoff', 'Account Logon', 'Object Access', 'Privilege Use', 'Policy Change', 'Account Management', 'System')
            foreach ($cat in $categories){
                $catLines = $auditOut | Select-String -Pattern $cat
                $successFailure = $auditOut | Select-String -Pattern "Success and Failure|Success|Failure" | Where-Object { $_.LineNumber -gt ($catLines.LineNumber | Select-Object -First 1) }
                # Simple approach: check if any auditing is configured
            }
            # Check for common critical subcategories
            $criticalChecks = @(
                @('Logon', 'Account Logon events'),
                @('Logoff', 'Account Logoff events'),
                @('Security Group Management', 'Security group changes'),
                @('User Account Management', 'User account changes'),
                @('Process Creation', 'Process creation events'),
                @('Security System Extension', 'Security system changes')
            )
            foreach ($check in $criticalChecks){
                $match = $auditOut | Select-String -Pattern $check[0] | Select-Object -First 1
                if ($match -ne $null){
                    $line = "$match".Trim()
                    if ($line -match 'No Auditing'){
                        Write-Output "$neg_str Audit policy for $($check[1]): No Auditing"
} elseif ($line -match 'Success and Failure') {
                        Write-Output "$pos_str Audit policy for $($check[1]): Success and Failure"
} elseif ($line -match 'Success') {
                        Write-Output "$inf_str Audit policy for $($check[1]): Success only"
} elseif ($line -match 'Failure') {
                        Write-Output "$inf_str Audit policy for $($check[1]): Failure only"
}
                }
            }
        }
    }
    Catch{
        Write-Output "$err_str Checking audit policy failed (may require admin privileges)."
}
}

function Get-SMBClientConfig {
    # Check SMB client-side signing configuration
    # Ref: CIS Benchmark 2.3.8.x
    Try{
        $smbClientPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
        $smbClient = Get-ItemProperty -path $smbClientPath -ErrorAction SilentlyContinue

        if ($smbClient.RequireSecuritySignature -ne $null){
            if ([int]$smbClient.RequireSecuritySignature -eq 1){
                Write-Output "$pos_str SMB Client Require Security Signature is Enabled."
} else {
                Write-Output "$neg_str SMB Client Require Security Signature is Disabled: $($smbClient.RequireSecuritySignature)"
}
        } else {
            Write-Output "$neg_str SMB Client RequireSecuritySignature not configured."
}

        if ($smbClient.EnableSecuritySignature -ne $null){
            if ([int]$smbClient.EnableSecuritySignature -eq 1){
                Write-Output "$pos_str SMB Client Enable Security Signature is Enabled."
} else {
                Write-Output "$neg_str SMB Client Enable Security Signature is Disabled: $($smbClient.EnableSecuritySignature)"
}
        }
    }
    Catch{
        Write-Output "$err_str Testing SMB Client signing configuration failed."
}
}

# Security Checks
#############################
function Get-SMBv1 {
    # Stop using SMB1: https://blogs.technet.microsoft.com/filecab/2016/09/16/stop-using-smb1/
    # How to detect, enable and disable SMBv1, SMBv2, and SMBv3 in Windows and Windows Server: https://support.microsoft.com/en-us/help/2696547/how-to-detect-enable-and-disable-smbv1-smbv2-and-smbv3-in-windows-and
    # Detecting and remediating SMBv1: https://blogs.technet.microsoft.com/leesteve/2017/05/11/detecting-and-remediating-smbv1/
    # https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3?tabs=server

    # PSv2: Use registry-based SMB checks since Get-SmbServerConfiguration is not available
    $smbSrvPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
    Try{
        $smbSrv = Get-ItemProperty -path $smbSrvPath -ErrorAction SilentlyContinue

        # SMBv1
        $smb1 = $smbSrv.SMB1
        if ($smb1 -ne $null){
            if ([int]$smb1 -eq 0){
                Write-Output "$pos_str SMBv1 is Disabled (registry SMB1: 0)"
            } else {
                Write-Output "$neg_str SMBv1 is Enabled (registry SMB1: $smb1)"
            }
        } else {
            Write-Output "$neg_str SMBv1 registry key not set (SMBv1 may be enabled by default)."
        }

        # SMBv1 Auditing
        $smb1audit = $smbSrv.AuditSmb1Access
        if ($smb1audit -ne $null){
            if ([int]$smb1audit -eq 1){
                Write-Output "$pos_str SMBv1 Auditing is Enabled"
            } else {
                Write-Output "$neg_str SMBv1 Auditing is Disabled: $smb1audit"
            }
        } else {
            Write-Output "$neg_str SMBv1 Auditing is not configured."
        }

        # SMBv2
        $smb2 = $smbSrv.SMB2
        if ($smb2 -ne $null){
            if ([int]$smb2 -eq 0){
                Write-Output "$neg_str SMBv2/SMBv3 is Disabled (registry SMB2: 0)"
            } else {
                Write-Output "$pos_str SMBv2/SMBv3 is Enabled (registry SMB2: $smb2)"
            }
        } else {
            Write-Output "$pos_str SMBv2/SMBv3 registry key not set (enabled by default on modern Windows)."
        }

        # Server signing
        $reqSign = $smbSrv.RequireSecuritySignature
        if ($reqSign -ne $null){
            if ([int]$reqSign -eq 1){
                Write-Output "$pos_str SMB Server Require Security Signature is Enabled"
            } else {
                Write-Output "$neg_str SMB Server Require Security Signature is Disabled: $reqSign"
            }
        } else {
            Write-Output "$neg_str SMB Server RequireSecuritySignature not configured."
        }

        # Encryption
        $encData = $smbSrv.EncryptData
        if ($encData -ne $null){
            if ([int]$encData -eq 1){
                Write-Output "$pos_str SMB Server Encryption (EncryptData) is Enabled"
            } else {
                Write-Output "$neg_str SMB Server Encryption (EncryptData) is Disabled: $encData"
            }
        }

        $rejectUnenc = $smbSrv.RejectUnencryptedAccess
        if ($rejectUnenc -ne $null){
            if ([int]$rejectUnenc -eq 1){
                Write-Output "$pos_str SMB Server RejectUnencryptedAccess is Enabled"
            } else {
                Write-Output "$neg_str SMB Server RejectUnencryptedAccess is Disabled: $rejectUnenc"
            }
        }
    }
    Catch {
        Write-Output "$err_str Testing for SMB configuration failed."
    }
}

function Get-AnonEnum {

    Try{
        $resra = (Get-ItemProperty -path 'HKLM:\System\CurrentControlSet\Control\Lsa\').RestrictAnonymous 
        if ($resra -eq $null){
            Write-Output "$neg_str RestrictAnonymous registry key is not configured."
} else {
            if ($resra){
                Write-Output "$pos_str RestrictAnonymous registry key is configured: $resra"
} else {        
                Write-Output "$neg_str RestrictAnonymous registry key is not configured: $resra"
}   
        }
    }
    Catch{
        Write-Output "$err_str Testing for Anonymous Enumeration RestrictAnonymous failed."
}

    Try{
        $resras = (Get-ItemProperty -path 'HKLM:\System\CurrentControlSet\Control\Lsa\').RestrictAnonymoussam 
        if ($resras -eq $null){
            Write-Output "$neg_str RestrictAnonymoussam registry key is not configured."
} else {
            if ($resras){
                Write-Output "$pos_str RestrictAnonymoussam registry key is configured: $resras"
} else {        
                Write-Output "$neg_str RestrictAnonymoussam registry key is not configured: $resras"
}   
        }
    }
    Catch{
        Write-Output "$err_str Testing for Anonymous Enumeration RestrictAnonymoussam failed."
}
}


function Get-UntrustedFonts {
    # Block untrusted fonts in an enterprise: https://docs.microsoft.com/en-us/windows/security/threat-protection/block-untrusted-fonts-in-enterprise
    # How to Verify if Device Guard is Enabled or Disabled in Windows 10: https://www.tenforums.com/tutorials/68926-verify-if-device-guard-enabled-disabled-windows-10-a.html
    if ([System.Environment]::OSVersion.Version.Major -ge 10){
        Try{
            $resuf = (Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\').MitigationOptions
            if ($resuf -eq $null){
                Write-Output "$neg_str Kernel MitigationOptions key does not exist."
} else {
                if ($resuf -ge 2000000000000){
                    Write-Output "$neg_str Kernel MitigationOptions key is configured not to block: $resuf"
} else {
                    Write-Output "$pos_str Kernel MitigationOptions key is set to block: $resuf"
}
            }
        }
        Catch{
            Write-Output "$err_str Testing for Untrusted Fonts configuration failed."
}
    } else {
        Write-Output "$inf_str Windows Version is older than 10. Cannot test for Untrusted Fonts."
}
}

function Get-ASRRules {
    # Check Attack Surface Reduction (ASR) rules status
    # Ref: https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference
    # ASR is available on Windows 10 1709+ and Windows Server 2016+
    if (Test-CommandExists Get-MpPreference){
        Try{
            $mpPref = Get-MpPreference -ErrorAction Stop
            $asrIds = $mpPref.AttackSurfaceReductionRules_Ids
            $asrActions = $mpPref.AttackSurfaceReductionRules_Actions

            if ($asrIds -ne $null -and $asrIds.Count -gt 0){
                # Action values: 0=Disabled, 1=Block, 2=Audit, 6=Warn
                $actionNames = @{0='Disabled'; 1='Block'; 2='Audit'; 6='Warn'}
                Write-Output "$pos_str Attack Surface Reduction rules configured: $($asrIds.Count) rule(s)"
                for ($i = 0; $i -lt $asrIds.Count; $i++){
                    if ($asrActions -ne $null -and $i -lt $asrActions.Count) { $action = $asrActions[$i] } else { $action = 'Unknown' }
                    if ($actionNames.ContainsKey([int]$action)) { $actionName = $actionNames[[int]$action] } else { $actionName = "Unknown ($action)" }
                    if ([int]$action -eq 1) { $prefix = $pos_str } elseif ([int]$action -eq 0) { $prefix = $neg_str } else { $prefix = $inf_str }
                    Write-Output "$prefix ASR Rule $($asrIds[$i]): $actionName"
                }
            } else {
                Write-Output "$neg_str No Attack Surface Reduction rules configured."
}
        }
        Catch{
            Write-Output "$err_str Testing for ASR rules failed."
}
    } else {
        Write-Output "$inf_str Get-MpPreference not available. Cannot check ASR rules."
}
}


# Authentication Checks
#############################
function Get-RDPDeny {
    # How to disable RDP access for Administrator: https://serverfault.com/questions/598278/how-to-disable-rdp-access-for-administrator/598279
    # How to Remotely Enable and Disable (RDP) Remote Desktop: https://www.interfacett.com/blogs/how-to-remotely-enable-and-disable-rdp-remote-desktop/
    Try{
        if ([bool](Get-ItemProperty -path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -ErrorAction SilentlyContinue).AllowRemoteRPC){
            Write-Output "$neg_str + AllowRemoteRPC is should be set to disable RDP: 1"
} else {
            Write-Output "$pos_str AllowRemoteRPC is set to deny RDP: 0"
}
    }
    Catch{
        Write-Output "$err_str Testing if system prevents RDP service failed."
}

    Try{
        if ([bool](Get-ItemProperty -path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -ErrorAction SilentlyContinue).fDenyTSConnections){
            Write-Output "$pos_str fDenyTSConnections is set to deny remote connections: 1"
} else {
            Write-Output "$neg_str fDenyTSConnections should be set to not allow remote connections: 0"
}
    }
    Catch{
        Write-Output "$err_str Testing if system denies remote access via Terminal Services failed."
}
}

function Get-LocalAdmin {

    if (Test-CommandExists Get-LocalGroupMember){
        Try{
            $numadmin = (Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop).Name.count
            if ([int]$numadmin -gt 1){
                Write-Output "$neg_str More than one account is in local Administrators group: $numadmin"
} else {
                Write-Output "$pos_str One account in local Administrators group."
}
            foreach ($n in (Get-LocalGroupMember -Group "Administrators").Name) {
                Write-Output "$inf_str Account in local Administrator group: $n"
}
        } 
        Catch{
            Write-Output "$err_str Testing local Administrator Accounts failed."
}
    } else {
        # No PS Cmdlet, use net command
        Try{
            $netout = (net localgroup Administrators)
            foreach ($item in $netout){
                if ($item -match '----') {
                    $index = $netout.IndexOf($item)
                }
            }

            $numadmin = $netout[($index + 1)..($netout.Length - 3)]
            if ($numadmin.length -gt 1){
                Write-Output "$neg_str More than one account is in local Administrators group: $($numadmin.length)"
} else {
                Write-Output "$pos_str One account in local Administrators group."
}
            foreach ($n in $numadmin) {
                Write-Output "$inf_str Account in local Administrator group: $n"
}
        }
        Catch{
            Write-Output "$err_str Testing local Administrator Accounts failed."
}
    }
}

function Get-NTLMSession {
    # Session security for NTLM SSP-based servers must be configured to require NTLMv2 session security and 128-bit encryption.: https://www.stigviewer.com/stig/windows_server_2016/2018-03-07/finding/V-73697
    # The system is not configured to meet the minimum requirement for session security for NTLM SSP based clients.: https://www.stigviewer.com/stig/windows_7/2012-07-02/finding/V-3382
    Try{
        $resntssec = (Get-ItemProperty -path 'HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0' -ErrorAction SilentlyContinue).NtlmMinServerSec
        if ([int]$resntssec -eq 537395200){
            Write-Output "$pos_str NTLM Session Server Security settings is configured to require NTLMv2 and 128-bit encryption: $resntssec"
} else {        
            Write-Output "$neg_str NTLM Session Server Security settings is not configured to require NTLMv2 and 128-bit encryption: $resntssec"
}   
    }
    Catch{
        Write-Output "$err_str Testing NTLM Session Server Security settings failed."
}

    $resntcsec = (Get-ItemProperty -path 'HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0' -ErrorAction SilentlyContinue).NtlmMinClientSec
    Try{
        if ([int]$resntcsec -eq 537395200){
            Write-Output "$pos_str NTLM Session Client Security settings is configured to require NTLMv2 and 128-bit encryption: $resntcsec"
} else {        
            Write-Output "$neg_str NTLM Session Client Security settings is not configured to require NTLMv2 and 128-bit encryption: $resntcsec"
}   
    }
    Catch{
        Write-Output "$err_str Testing NTLM Session Client Security settings failed."
}
}

function Get-LANMAN {
    # Understanding the Anonymous Enumeration Policies:https://www.itprotoday.com/compute-engines/understanding-anonymous-enumeration-policies
    # The LanMan authentication level must be set to send NTLMv2 response only, and to refuse LM and NTLM.: https://www.stigviewer.com/stig/windows_8/2014-01-07/finding/V-1153
    Try{
        $reslm = (Get-ItemProperty -path 'HKLM:\System\CurrentControlSet\Control\Lsa\').NoLmHash
        if ($reslm -eq $null){
            Write-Output "$neg_str NoLmHash registry key is not configured."
} else {
            if ($reslm){
                Write-Output "$pos_str NoLmHash registry key is configured: $reslm"
} else {        
                Write-Output "$neg_str NoLmHash registry key is not configured: $reslm"
}   
        }
    }
    Catch{
        Write-Output "$err_str Testing for NoLmHash registry key failed."
}

    Try{
        $reslmcl = (Get-ItemProperty -path 'HKLM:\System\CurrentControlSet\Control\Lsa\').LmCompatibilityLevel
        if ($reslmcl -eq $null){
            Write-Output "$neg_str LM Compatability Level registry key is not configured."
} else {
            if ([int]$reslmcl -eq 5){
                Write-Output "$pos_str LM Compatability Level is configured correctly: $reslmcl"
} else {        
                Write-Output "$neg_str LM Compatability Level is not configured to prevent LM and NTLM: $reslmcl"
}   
        }
    }
    Catch{
        Write-Output "$err_str Testing for LM Compatability registry key failed."
}
}

function Get-CachedLogons {
    # Cached logons and CachedLogonsCount: https://blogs.technet.microsoft.com/instan/2011/12/06/cached-logons-and-cachedlogonscount/
    # Cached domain logon information: https://support.microsoft.com/en-us/help/172931/cached-domain-logon-information
    # Cached Logons should be set to 0 or 1.
    Try{
        $regv = (Get-ItemProperty -path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" -ErrorAction SilentlyContinue).CachedLogonsCount
        if ([int]$regv -lt 2) {
            Write-Output "$pos_str CachedLogonsCount Is Set to: $regv"
} else {
            Write-Output "$neg_str CachedLogonsCount Is Not Set to 0 or 1: $regv"
}
    }
    Catch{
        Write-Output "$err_str Testing for stored credential settings failed."
}
}

function Get-InteractiveLogin {
    # Disable PowerShell remoting: Disable-PSRemoting, WinRM, listener, firewall, LocalAccountTokenFilterPolicy: https://4sysops.com/wiki/disable-powershell-remoting-disable-psremoting-winrm-listener-firewall-and-localaccounttokenfilterpolicy/
    # Pass-the-Hash Is Dead: Long Live LocalAccountTokenFilterPolicy: https://www.harmj0y.net/blog/redteaming/pass-the-hash-is-dead-long-live-localaccounttokenfilterpolicy/
    Try{
        if ([bool](Get-ItemProperty -path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\system' -ErrorAction SilentlyContinue).LocalAccountTokenFilterPolicy){
            Write-Output "$neg_str LocalAccountTokenFilterPolicy Is Set"
} else {
            Write-Output "$pos_str LocalAccountTokenFilterPolicy Is Not Set"
}
    }
    Catch{
        Write-Output "$err_str Testing for LocalAccountTokenFilterPolicy in Policies failed."
}

    Try{
        if ([bool](Get-ItemProperty -path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\policies\system' -ErrorAction SilentlyContinue).LocalAccountTokenFilterPolicy){
            Write-Output "$neg_str LocalAccountTokenFilterPolicy in Wow6432Node Is Set"
} else {
            Write-Output "$pos_str LocalAccountTokenFilterPolicy in Wow6432Node Is Not Set"
}
    }
    Catch{
        Write-Output "$err_str Testing for LocalAccountTokenFilterPolicy in Wow6432Node failed."
}
}

function Get-WDigest {
    Try{
        $reswd = (Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest').UseLogonCredential
        if ($reswd -eq $null){
            Write-Output "$neg_str WDigest UseLogonCredential key does not exist."
} else {
            if ($reswd){
                Write-Output "$neg_str WDigest UseLogonCredential key is Enabled: $reswd"
} else {
                Write-Output "$pos_str WDigest UseLogonCredential key is Disabled: $reswd"
}
        }
    }
    Catch{
        Write-Output "$err_str Testing for WDigest failed."
}
}

function Get-RestrictRDPClients {
    # Restrict Unauthenticated RPC clients: https://getadmx.com/?Category=Windows_10_2016&Policy=Microsoft.Policies.RemoteProcedureCalls::RpcRestrictRemoteClients
    # Restrict unauthenticated RPC clients.: https://www.stigviewer.com/stig/windows_7/2017-12-01/finding/V-14253
    $resrpc = (Get-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Windows NT\Rpc\' -ErrorAction SilentlyContinue).RestrictRemoteClients 
    Try{
        if ($resrpc){
            Write-Output "$pos_str RestrictRemoteClients registry key is configured: $resrpc"
} else {        
            Write-Output "$neg_str RestrictRemoteClients registry key is not configured: $resrpc"
}   
    }
    Catch{
        Write-Output "$err_str Testing Restrict RPC Clients settings failed."
}
}

# Network Checks
#############################
function Get-NetworkSettingsIPv4 {
    # PSv2: Use WMI directly since Get-NetIPAddress requires PSv3+
    Try{
        $ips = (gwmi win32_networkadapterconfiguration -filter 'ipenabled=true')
        if ($ips -ne $null){
            foreach ($ip in $ips){
                if ($ip -ne $null){
                    foreach ($i in $ip.IPAddress){
                        if ($i -notmatch ":"){
                            Write-Output "$inf_str Host network interface assigned: $i"
                        }
                    }
                }
            }
        } else {
            Write-Output "$err_str No network interfaces found via WMI."
        }
    }
    Catch{
        Write-Output "$err_str Check IPv4 Network Settings failed."
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
                            Write-Output "$neg_str Host IPv6 network interface assigned (gwmi): $i"
        $noipv6 = $false
                        }
                    }
                }
            }
            if ($noipv6){
                Write-Output "$pos_str No interfaces with IPv6 network interface assigned (gwmi)."
}
        } else {
            # Use Throw function to call the Catch function
            Write-Output "$err_str No interfaces with IPv6 network interface assigned (gwmi)."
}
    }
    Catch{
        Write-Output "$err_str Check IPv6 Network Settings failed (gwmi)."
}
}

function Get-WPAD {
    # Microsoft Security Bulletin MS16-063 - Critical: https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2016/ms16-063
    Try{
        $reswpad = Select-String -path $env:systemdrive\Windows\System32\Drivers\etc\hosts -pattern wpad
        if ($reswpad -ne $null){
            Write-Output "$pos_str WPAD entry detected: $reswpad"
} else {
            Write-Output "$neg_str No WPAD entry detected. Should contain: wpad 255.255.255.255"
}
    }
    Catch{
        Write-Output "$err_str Testing for WPAD in /etc/hosts failed."
}

    Try{
        $reswpad2 = (Get-ItemProperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad' -ErrorAction SilentlyContinue).WpadOverride
        if ($reswpad2 -ne $null){
            if ($reswpad2){
                Write-Output "$pos_str WpadOverride registry key is configured to disable WPAD: $reswpad2"
} else {
                Write-Output "$neg_str WpadOverride registry key is configured to allow WPAD: $reswpad2"
}
        } else {
            Write-Output "$inf_str System not configured with the WpadOverride registry key."
}
    }
    Catch{
        Write-Output "$err_str Testing for WpadOverride registry key failed."
}

    # Deploy security back-port patch (KB3165191).
    Try{
        $reswphf = (Get-HotFix -id KB3165191 -ErrorAction SilentlyContinue).InstalledOn
        if ($reswphf -ne $null){
            Write-Output "$pos_str KB3165191 to harden WPAD is installed: $reswphf"
} else {
            Write-Output "$neg_str KB3165191 to harden WPAD is not installed."
}
    }
    Catch{
        Write-Output "$err_str Testing for WPAD KB3165191 failed."
}
    
    Try{
        $reswpads = (Get-Service -name WinHttpAutoProxySvc).Status
        if ($reswpads -ne $null){
            if ($reswpads -eq 'Running'){
                Write-Output "$neg_str WinHttpAutoProxySvc service is: $reswpads"
} else {
                Write-Output "$pos_str WinHttpAutoProxySvc service is: $reswpads"
}
        } else {
            Write-Output "$inf_str WinHttpAutoProxySvc service was not found: $reswpads"
}
    }
    Catch{
        Write-Output "$err_str Testing for WinHttpAutoProxySvc failed."
}
}

function Get-WINSConfig {
    Try{
        if ([bool](Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=TRUE").DNSEnabledForWINSResolution){
            Write-Output "$neg_str DNSEnabledForWINSResolution is enabled"
} else {
            Write-Output "$pos_str DNSEnabledForWINSResolution is disabled"
}
    }
    Catch{
        Write-Output "$err_str Testing for WINS Resolution: DNSEnabledForWINSResolution failed."
}

    Try{
        if ([bool](Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=TRUE").WINSEnableLMHostsLookup){
            Write-Output "$neg_str WINSEnableLMHostsLookup is enabled"
} else {
            Write-Output "$pos_str WINSEnableLMHostsLookup is disabled"
}
    }
    Catch{
        Write-Output "$err_str Testing for WINS Resolution: WINSEnableLMHostsLookup failed."
}
}

function Get-LLMNRConfig {
    Try{
        $resllmnr = (Get-ItemProperty -path 'HKLM:\Software\policies\Microsoft\Windows NT\DNSClient' -ErrorAction SilentlyContinue).EnableMulticast
        if ($resllmnr -ne $null){
            Write-Output "$pos_str DNSClient.EnableMulticast is disabled: $resllmnr"
} else {
            Write-Output "$neg_str DNSClient.EnableMulticast does not exist or is enabled: $resllmnr"
}
    }
    Catch{
        Write-Output "$err_str Testing for LLMNR failed."
}
}

function Get-CompBrowser {
    Try{
        $resbr = (Get-Service -name Browser).Status
        if ($resbr -ne $null){
            if ($resbr -eq 'Running'){
                Write-Output "$neg_str Computer Browser service is: $resbr"
} else {
                Write-Output "$pos_str Computer Browser service is: $resbr"
}
        } else {
            Write-Output "$inf_str Computer Browser service was not found: $resbr"
}
    }
    Catch{
        Write-Output "$err_str Testing for Computer Browser service failed."
}
}

function Get-NetBIOS {
    # Getting TCP/IP Netbios information: https://powershell.org/forums/topic/getting-tcpip-netbios-information/
    Try{
        $resnetb = (Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=$true").TcpipNetbiosOptions
        if ($resnetb -eq $null){
            Write-Output "$neg_str NetBios TcpipNetbiosOptions key does not exist."
} else {
            if ([int]$resnetb -eq 2){
                Write-Output "$pos_str NetBios is Disabled: $resnetb"
} else {
                Write-Output "$neg_str NetBios is Enabled: $resnetb"
}
        }
    }
    Catch{
        Write-Output "$err_str Testing for NetBios failed."
}
}

function Get-NetConnections {
    # List active network connections
    # Ref: Issue #2 feature request
    if (Test-CommandExists Get-NetTCPConnection){
        Try{
            $conns = Get-NetTCPConnection -State Listen,Established -ErrorAction Stop | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess
            if ($conns -ne $null){
                # Listening ports
                $listening = $conns | Where-Object { $_.State -eq 'Listen' } | Sort-Object LocalPort -Unique
                if ($listening -ne $null){
                    Write-Output "$inf_str Listening TCP ports:"
foreach ($l in $listening){
                        Try{
                            $procName = (Get-Process -Id $l.OwningProcess -ErrorAction SilentlyContinue).ProcessName
                        }
                        Catch{ $procName = 'Unknown' }
                        Write-Output "$inf_str   $($l.LocalAddress):$($l.LocalPort) (PID: $($l.OwningProcess), Process: $procName)"
}
                }
                # Established connections
                $established = $conns | Where-Object { $_.State -eq 'Established' }
                if ($established -ne $null){
                    Write-Output "$inf_str Established TCP connections:"
foreach ($e in $established){
                        Try{
                            $procName = (Get-Process -Id $e.OwningProcess -ErrorAction SilentlyContinue).ProcessName
                        }
                        Catch{ $procName = 'Unknown' }
                        Write-Output "$inf_str   $($e.LocalAddress):$($e.LocalPort) -> $($e.RemoteAddress):$($e.RemotePort) (PID: $($e.OwningProcess), Process: $procName)"
}
                }
            } else {
                Write-Output "$inf_str No active TCP connections found."
}
        }
        Catch{
            Write-Output "$err_str Enumerating network connections via Get-NetTCPConnection failed."
}
    } else {
        # Fallback to netstat
        Try{
            $netstatOut = netstat -ano 2>&1
            if ($netstatOut -ne $null){
                Write-Output "$inf_str Network connections (netstat -ano):"
foreach ($line in $netstatOut){
                    Write-Output "$inf_str   $line"
}
            }
        }
        Catch{
            Write-Output "$err_str Enumerating network connections failed (netstat fallback)."
}
    }
}

function Get-FirewallProfile {
    # Check Windows Firewall profile status (enabled/disabled per network profile)
    # No individual rule enumeration per project decision
    if (Test-CommandExists Get-NetFirewallProfile){
        Try{
            $profiles = Get-NetFirewallProfile -ErrorAction Stop
            foreach ($p in $profiles){
                if ($p.Enabled){
                    Write-Output "$pos_str Windows Firewall $($p.Name) profile is Enabled."
} else {
                    Write-Output "$neg_str Windows Firewall $($p.Name) profile is Disabled."
}
                Write-Output "$inf_str   $($p.Name) DefaultInboundAction: $($p.DefaultInboundAction)"
Write-Output "$inf_str   $($p.Name) DefaultOutboundAction: $($p.DefaultOutboundAction)"
}
        }
        Catch{
            Write-Output "$err_str Testing Windows Firewall profiles failed."
}
    } else {
        # Fallback to netsh
        Try{
            $fwState = netsh advfirewall show allprofiles state 2>&1
            if ($fwState -ne $null){
                Write-Output "$inf_str Windows Firewall profile status (netsh):"
foreach ($line in $fwState){
                    $trimmed = "$line".Trim()
                    if ($trimmed -ne ''){
                        if ($trimmed -match 'ON'){
                            Write-Output "$pos_str $trimmed"
} elseif ($trimmed -match 'OFF') {
                            Write-Output "$neg_str $trimmed"
} else {
                            Write-Output "$inf_str $trimmed"
}
                    }
                }
            }
        }
        Catch{
            Write-Output "$err_str Testing Windows Firewall profiles failed (netsh fallback)."
}
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
            Write-Output "$neg_str Current PowerShell Version is less than Version 5: $fpsver"
} else { 
            Write-Output "$pos_str Current PowerShell Version: $fpsver"
}
    }
    Catch{
        Write-Output "$err_str Testing PowerShell Version failed."
}

    # PSv2: Check PS engine version via registry since Get-WindowsOptionalFeature is PSv3+
    Try{
        $psEngPath = 'HKLM:\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine'
        $psEng = Get-ItemProperty -path $psEngPath -ErrorAction SilentlyContinue
        if ($psEng -ne $null){
            Write-Output "$inf_str PowerShell Engine Version: $($psEng.PowerShellVersion)"
        }
        $psEngPath3 = 'HKLM:\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine'
        $psEng3 = Get-ItemProperty -path $psEngPath3 -ErrorAction SilentlyContinue
        if ($psEng3 -ne $null){
            Write-Output "$inf_str PowerShell 3+ Engine Version: $($psEng3.PowerShellVersion)"
        }
        if ($psEng3 -eq $null -and $psEng -ne $null){
            Write-Output "$inf_str Only PowerShell v2 engine detected."
        }
    }
    Catch{
        Write-Output "$err_str Testing for PowerShell engine versions failed."
    }
  
    Try{
        $netv=(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -Recurse -ErrorAction SilentlyContinue| Get-ItemProperty -Name Version -ErrorAction SilentlyContinue).Version
        foreach ($e in $netv){
            if ($e -lt 3.0) {
                Write-Output "$neg_str .NET Framework less than 3.0 installed which could allow PSv2 execution: $e"
} else {
                Write-Output "$pos_str .NET Framework greater than 3.0 installed: $e"
}
        }
    }
    Catch{
        Write-Output "$err_str Testing for .NET vesions that support PowerShell Version 2 failed."
}
}

function Get-PSLanguage {
    # Detecting Offensive PowerShell Attack Tools: https://adsecurity.org/?p=2604
    Try{
        $ps_lang = $ExecutionContext.SessionState.LanguageMode
        if ($ps_lang -eq 'ConstrainedLanguage') { 
            Write-Output "$pos_str Execution Langugage Mode Is: $ps_lang"
} else  { 
            Write-Output "$neg_str Execution Langugage Mode Is Not ConstrainedLanguage: $ps_lang"
}
    }
    Catch{
        Write-Output "$err_str Testing for PowerShell Constrained Language failed."
}
}

function Get-PSModule {
    Try{
        if ([bool](Get-ItemProperty -path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -ErrorAction SilentlyContinue).EnableModuleLogging){
            Write-Output "$pos_str EnableModuleLogging Is Set"
} else {
            Write-Output "$neg_str EnableModuleLogging Is Not Set"
}
    }
    Catch{
        Try{
            if ([bool](Get-ItemProperty -path 'HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -ErrorAction SilentlyContinue).EnableModuleLogging){
                Write-Output "$pos_str EnableModuleLogging Is Set"
} else {
                Write-Output "$neg_str EnableModuleLogging Is Not Set"
}
        }
        Catch{
            Write-Output "$err_str Testing PowerShell Module Logging failed"
}
    }

    # Check which modules are being logged (should be '*' for all modules)
    Try{
        $modnames = Get-ItemProperty -path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames' -ErrorAction SilentlyContinue
        if ($modnames -ne $null){
            if ($modnames.'*' -ne $null){
                Write-Output "$pos_str Module Logging is configured to log all modules (*)"
} else {
                $logged = ($modnames.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' }).Name -join ', '
                Write-Output "$neg_str Module Logging is not configured to log all modules. Logged modules: $logged"
}
        } else {
            Write-Output "$inf_str No specific modules configured for Module Logging."
}
    }
    Catch{
        # Module names key doesn't exist, skip
    }
}

function Get-PSScript {
    Try{
        if ([bool](Get-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ErrorAction SilentlyContinue).EnableScriptBlockLogging){
            Write-Output "$pos_str EnableScriptBlockLogging Is Set"
} else {
            Write-Output "$neg_str EnableScriptBlockLogging Is Not Set"
}
    }
    Catch{
        Try{
            if ([bool](Get-ItemProperty -path 'HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ErrorAction SilentlyContinue).EnableScriptBlockLogging){
                Write-Output "$pos_str EnableScriptBlockLogging Is Set"
} else {
                Write-Output "$neg_str EnableScriptBlockLogging Is Not Set"
}
        }
        Catch{
            Write-Output "$err_str Testing PowerShell EnableScriptBlockLogging failed"
}
    }

    Try{
        if ([bool](Get-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ErrorAction SilentlyContinue).EnableScriptBlockInvocationLogging){
            Write-Output "$pos_str EnableScriptBlockInvocationLogging Is Set"
} else {
            Write-Output "$neg_str EnableScriptBlockInvocationLogging Is Not Set"
}
    }
    Catch{
        Try{
            if ([bool](Get-ItemProperty -path 'HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ErrorAction SilentlyContinue).EnableScriptBlockInvocationLogging){
                Write-Output "$pos_str EnableScriptBlockInvocationLogging Is Set"
} else {
                Write-Output "$neg_str EnableScriptBlockInvocationLogging Is Not Set"
}
        }
        Catch{
            Write-Output "$err_str Testing PowerShell EnableScriptBlockInvocationLogging failed"
}
    }
}

function Get-PSTranscript {
    # Check transcript log output directory
    Try{
        $transcriptDir = (Get-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription' -ErrorAction SilentlyContinue).OutputDirectory
        if ($transcriptDir -ne $null -and $transcriptDir -ne ''){
            Write-Output "$inf_str PowerShell Transcript log location: $transcriptDir"
}
    }
    Catch{
        # Key doesn't exist, skip
    }

    Try{
        if ([bool](Get-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription' -ErrorAction SilentlyContinue).EnableTranscripting){
            Write-Output "$pos_str EnableTranscripting Is Set"
} else {
            Write-Output "$neg_str EnableTranscripting Is Not Set"
}
    }
    Catch{
        Try{
            if ([bool](Get-ItemProperty -path 'HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription' -ErrorAction SilentlyContinue).EnableTranscripting){
                Write-Output "$pos_str EnableTranscripting Is Set"
} else {
                Write-Output "$neg_str EnableTranscripting Is Not Set"
}
        }
        Catch{
            Write-Output "$err_str Testing PowerShell EnableTranscripting failed"
}
    }

    Try{
        if ([bool](Get-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription' -ErrorAction SilentlyContinue).EnableInvocationHeader){
            Write-Output "$pos_str EnableInvocationHeader Is Set"
} else {
            Write-Output "$neg_str EnableInvocationHeader Is Not Set"
}
    }
    Catch{
        Try{
            if ([bool](Get-ItemProperty -path 'HKLM:\Software\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription' -ErrorAction SilentlyContinue).EnableInvocationHeader){
                Write-Output "$pos_str EnableInvocationHeader Is Set"
} else {
                Write-Output "$neg_str EnableInvocationHeader Is Not Set"
}
        }
        Catch{
            Write-Output "$err_str Testing PowerShell EnableInvocationHeader failed"
}
    }
}

function Get-PSProtectedEvent {
    Try{
        if ([bool](Get-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Windows\EventLog\ProtectedEventLogging' -ErrorAction SilentlyContinue).EnableProtectedEventLogging){
            Write-Output "$pos_str EnableProtectedEventLogging Is Set"
} else {
            Write-Output "$neg_str EnableProtectedEventLogging Is Not Set"
}
    }
    Catch{
        Try{
            if ([bool](Get-ItemProperty -path 'HKLM:\Software\Wow6432Node\Policies\Microsoft\Windows\EventLog\ProtectedEventLogging' -ErrorAction SilentlyContinue).EnableProtectedEventLogging){
                Write-Output "$pos_str EnableProtectedEventLogging Is Set"
} else {
                Write-Output "$neg_str EnableProtectedEventLogging Is Not Set"
}
        }
        Catch{
            Write-Output "$err_str Testing PowerShell ProtectedEventLogging failed"
}
    }
}

function Get-WinRM {
    # NEED TO TEST IF WINRM IS LISTENING?: https://stevenmurawski.com/2015/06/need-to-test-if-winrm-is-listening/
    # Enable PowerShell Remoting and check if it’s enabled: https://www.dtonias.com/enable-powershell-remoting-check-enabled/
    if (-NOT $global:admin_user){ return }
    Try{
        if (Test-WSMan -ErrorAction Stop) { 
            Write-Output "$neg_str WinRM Services is running and may be accepting connections: Test-WSMan check."
} else { 
            Write-Output "$pos_str WinRM Services is not running: Test-WSMan check."
}   
    }
    Catch{
        Try{
            $ress = (Get-Service WinRM).status
            if ($ress -eq 'Stopped') { 
                Write-Output "$pos_str WinRM Services is not running: Get-Service check."
} else { 
                Write-Output "$neg_str WinRM Services is running and may be accepting connections: Get-Service check."
}
        }
        Catch{
            Write-Output "$err_str Testing if WinRM Service is running failed."
}
    }

    if (Test-CommandExists Get-NetFirewallRule){
        Try{
            $resfw = Get-NetFirewallRule -DisplayName 'Windows Remote Management (HTTP-In)' -ErrorAction Stop
            foreach ($r in $resfw){
                if ($r.Enabled -eq 'False'){
                    Write-Output "$pos_str WinRM Firewall Rule $(($r).Name) is disabled."
} else {
                    Write-Output "$neg_str WinRM Firewall Rule $(($r).Name) is enabled."
}
            }
        }
        Catch{
            Write-Output "$err_str Testing WinRM firewall rules failed."
}
    } else {
        Try{
            $fwout = netsh advfirewall firewall show rule name="Windows Remote Management (HTTP-In)" 2>&1
            if ($fwout -match 'Enabled:\s+Yes'){
                Write-Output "$neg_str WinRM Firewall Rule is enabled (netsh)."
} elseif ($fwout -match 'Enabled:\s+No') {
                Write-Output "$pos_str WinRM Firewall Rule is disabled (netsh)."
} else {
                Write-Output "$inf_str WinRM Firewall Rule not found (netsh)."
}
        }
        Catch{
            Write-Output "$err_str Testing WinRM firewall rules failed (netsh fallback)."
}
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
    # PSv2: Use wevtutil instead of Get-WinEvent -ListLog
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
            $wevtOut = wevtutil gl $l 2>&1
            $maxSizeLine = $wevtOut | Select-String -Pattern 'maxSize:'
            if ($maxSizeLine -ne $null){
                $maxBytes = [long]("$maxSizeLine" -replace '.*maxSize:\s*', '').Trim()
                $lsize = [math]::Round($maxBytes / (1024*1024*1024), 3)
                if ($lsize -lt $logs[$l]){
                    Write-Output "$neg_str $l max log size is smaller than $($logs[$l]) GB: $lsize GB"
                } else {
                    Write-Output "$pos_str $l max log size is okay: $lsize GB"
                }
            } else {
                Write-Output "$err_str Could not determine $l log size."
            }
        }
        Catch{
            Write-Output "$err_str Testing $l log size failed."
        }
    }
}

function Get-CmdAuditing {
    Try{
        if ([bool](Get-ItemProperty -path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -ErrorAction SilentlyContinue).ProcessCreationIncludeCmdLine_Enabled){
            Write-Output "$pos_str ProcessCreationIncludeCmdLine_Enabled Is Set"
} else {
            Write-Output "$neg_str ProcessCreationIncludeCmdLine_Enabled Is Not Set"
}
    }
    Catch{
        Write-Output "$err_str Testing PowerShell Commandline Audting failed"
}
}

function Get-WinScripting {
    Try{
        $ressh = (Get-ItemProperty -path 'HKLM:\Software\Microsoft\Windows Script Host\Settings').Enabled
        if ($ressh -eq $null){
            Write-Output "$neg_str WSH Setting Enabled key does not exist."
} else {
            if ($ressh){
                Write-Output "$neg_str WSH Setting Enabled key is Enabled: $ressh"
} else {
                Write-Output "$pos_str WSH Setting Enabled key is Disabled: $ressh"
}
        }
    }
    Catch{
        Write-Output "$err_str Testing for Windows Scripting Host (WSH) failed."
}

    # Deploy security back-port patch (KB2871997).
    Try{
        $reshf = (Get-HotFix -id KB2871997 -ErrorAction SilentlyContinue).InstalledOn
        if ($reshf -ne $null){
            Write-Output "$pos_str KB2871997 is installed: $reshf"
} else {
            Write-Output "$neg_str KB2871997 is not installed."
}
    }
    Catch{
        Write-Output "$err_str Testing for security back-port patch KB2871997 failed."
}
}

#############################
# Main
#############################

# Configuration Check
#############################
if ($config){ Show-Config }

# Report Header
Prt-ReportHeader

# Information Collection
Write-Output "## System Info Checks"
Write-Output ""
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
if ($getSysmonCheck)            { Get-Sysmon }
if ($getUSBDevicesCheck)        { Get-USBDevices }
if ($getAntiVirusCheck)         { Get-AntiVirus }
if ($getSoftwareInventoryCheck) { Get-SoftwareInventory }
if ($getUACConfigCheck)         { Get-UACConfig }
if ($getAccountPolicyCheck)     { Get-AccountPolicy }
if ($getSecureBootCheck)        { Get-SecureBoot }
if ($getLSAProtectionCheck)     { Get-LSAProtection }
if ($getServiceHardeningCheck)  { Get-ServiceHardening }
Write-Output ""
Write-Output "## Security Checks"
Write-Output ""
if ($getSMBv1Check)             { Get-SMBv1 }
if ($getAnonEnumCheck)          { Get-AnonEnum }
if ($getUntrustedFontsCheck)    { Get-UntrustedFonts }
if ($getASRCheck)               { Get-ASRRules }
if ($getSMBClientConfigCheck)   { Get-SMBClientConfig }
if ($getTLSConfigCheck)         { Get-TLSConfig }
if ($getAuditPolicyCheck)       { Get-AuditPolicy }
Write-Output ""
Write-Output "## Authentication Checks"
Write-Output ""
if ($getRDPDenyCheck)           { Get-RDPDeny }
if ($getLocalAdminCheck)        { Get-LocalAdmin }
if ($getNTLMSessionsCheck)      { Get-NTLMSession }
if ($getLANMANCheck)            { Get-LANMAN }
if ($getCachedLogonCheck)       { Get-CachedLogons }
if ($getInteractiveLoginCheck)  { Get-InteractiveLogin }
if ($getWDigestCheck)           { Get-WDigest }
if ($getRestrictRDPClientsCheck){ Get-RestrictRDPClients }
if ($getRDPNLAConfigCheck)      { Get-RDPNLAConfig }
Write-Output ""
Write-Output "## Network Checks"
Write-Output ""
if ($getNetworkIPv4Check)       { Get-NetworkSettingsIPv4 }
if ($getNetworkIPv6Check)       { Get-NetworkSettingsIPv6 }
if ($getWPADCheck)              { Get-WPAD }
if ($getWINSConfigCheck)        { Get-WINSConfig }
if ($getLLMNRConfigCheck)       { Get-LLMNRConfig }
if ($getCompBrowserCheck)       { Get-CompBrowser }
if ($getNetBIOSCheck)           { Get-NetBIOS }
if ($getNetConnectionsCheck)    { Get-NetConnections }
if ($getFirewallProfileCheck)   { Get-FirewallProfile }
if ($getTCPIPHardeningCheck)    { Get-TCPIPHardening }
Write-Output ""
Write-Output "## PowerShell Checks"
Write-Output ""
if ($getPSVersionCheck)         { Get-PSVersions }
if ($getPSLanguageCheck)        { Get-PSLanguage }
if ($getPSModuleCheck)          { Get-PSModule }
if ($getPSScriptCheck)          { Get-PSScript }
if ($getPSTranscriptCheck)      { Get-PSTranscript }
if ($getPSProtectedCheck)       { Get-PSProtectedEvent }
if ($getWinRMCheck)             { Get-WinRM }
Write-Output ""
Write-Output "## Logging Checks"
Write-Output ""
if ($getPSEventLogCheck)        { Get-PSEventLog }
if ($getCmdAuditingCheck)       { Get-CmdAuditing }
if ($getWinScriptingCheck)      { Get-WinScripting }

# Report Footer
Prt-ReportFooter
if($cutsec_footer){ Prt-CutSec-ReportFooter }