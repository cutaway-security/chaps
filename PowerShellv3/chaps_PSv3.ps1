<#
chaps_PSv3.ps1 - a PowerShell script for checking system security when conducting an assessment of systems where the Microsoft Policy Analyzer and other assessment tools cannot be installed.
#>

<#
License: 
Copyright (c) 2019, Cutaway Security, Inc. <don@cutawaysecurity.com>
 
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

Point Of Contact:    Don C. Weber <don@cutawaysecurity.com>
#>

<#
The best way to run this script within an ICS environment is to not write any programs or scripts to the system being reviewed. Do this by serving these scripts from a webserver running on another system on the network. Download CHAPS to the host which will serve the script files. Open a terminal and change into the directory containing the `chaps.ps1` script. Using Python3 run the command 'python3 -m http.server 8181'. This will start a webserver listening on all of the system's IP addresses. 

On the target system open a CMD.exe window, preferably as an Administrator. Run the command `powershell.exe -exec bypass` to begin a PowerShell prompt. From this prompt, run the following command to execute the `chaps_PSv3.ps1` script.

```
IEX (New-Object Net.WebClient).DownloadString('http://<webserver>:8181/chaps.ps1')
```

Script outputs will be written to the user's Temp directory as defined by the $env:temp variable by default.

Useful Resources:
    New tool: Policy Analyzer: https://blogs.technet.microsoft.com/secguide/2016/01/22/new-tool-policy-analyzer/
    Use PowerShell to Explore Active Directory Security: https://blogs.technet.microsoft.com/heyscriptingguy/2012/03/12/use-powershell-to-explore-active-directory-security/
    Penetration Testers’ Guide to Windows 10 Privacy & Security: https://hackernoon.com/the-2017-pentester-guide-to-windows-10-privacy-security-cf734c510b8d
    15 Ways to Bypass the PowerShell Execution Policy: https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/
#>
param (
    # The config parameter will print the current configuration and exit
    # See Collection Parameters section to manage script behavior
    # To use `chaps_PSv3.ps1 -config`
    [switch]$config = $false
 )

 ##############################
# Script Behavior Parameters
##############################
$cutsec_footer = $true # change to false to disable CutSec footer
$assessor_company = 'Cutaway Security, LLC' # make empty string to disable
$sitename = 'plant1' # make empty string to disable
$timestamp = Get-Timestamp
$out_dir = "$env:TEMP\chaps-$(Get-Timestamp)" # Default directory is user's TEMP directory with a timestamped subdirectory
$out_file = "$env:ComputerName-chaps.txt" # Default filename is <Computer Name>-chaps.txt
$global:admin_user = $false # Disable some checks if not running as an Administrator
$global:ps_version = $PSVersionTable.PSVersion.Major # Get major version to ensure at least PSv3

#############################
# Set up document header information
#############################
$script_name = 'chaps_PSv3.ps1'
$script_version = '1.0'
$computer_name = $env:ComputerName 

##############################
# Configuration Parameters
# Note: Set these to $false to disable
##############################
$getSysInfo = $true

##############################
# Output Label Flags 
##############################

$pos_str = "[+] " # Positive Findings: System is configured to recommendation
$neg_str = "[-] " # Negative Findings: System is configured against security/audit recommmendation
$inf_str = "[*] " # Informational Text: Information about the script and/or checks being performed
$rep_str = "[$] " # Report Information: Information about the report generation (e.g. time it was run)
$err_str = "[x] " # Error Reports: A check failed and so the configuration is unknown

##############################
# Print Functions
##############################

Function Set-Output {
    [CmdletBinding()]
    # Create the ouptut directory: defaults to subdirectory in user's TEMP directory
    # Change into the directory to write data
    # Create the main report output file: defaults to <Computer Name>-chaps.txt
    param(
        [string]$output_dir = $out_dir,
        [string]$output_file = $out_file
    )
    # Ensure the directory exists
    $msg = $inf_str + "Creating output directory: $output_dir"
    Write-Host $msg
    if (-not (Test-Path $output_dir)) {
        New-Item $output_dir -ItemType Directory | Out-Null
    }

    # Change into the directory
    Set-Location -Path $output_dir

    # Create the file if it doesn't exist
    if (-not (Test-Path $output_file)) {
        New-Item $output_file -ItemType File | Out-Null
        $msg = $inf_str + "Creating output file: $output_file"
        Write-Host $msg
    } else {
        $msg = $err_str + "File already exists: $output_file"
        Write-Host $msg
        exit
    }
}

Function Show-Config{
    Write-Log -Message "$script_name $script_version Configuration:" -rep 
    Write-Log -Message + "Get System Information: $getSysInfo" -info
    exit
}

Function Print-ReportHeader {
    Write-Log -Message "# Configuration Hardening Assessment PowerShell Script (CHAPS): $script_name $script_version"
    if ($assessor_company) { Write-Log -Message "## Assessor Company: $assessor_company" }
    if ($sitename) { Write-Log -Message "## $sitename" }
    Write-Log -Message "Hostname: $computer_name" -rep 
    Write-Log -Message "Start Time: $(Get-Timestamp -readable)" -rep 
    Write-Log -Message "PowerShell Version: $ps_version" -rep 
    Write-Log -Message "Output File: $out_dir\$out_file" -NoConsole -rep
    Get-AdminState
}

Function Print-SectionHeader {
    param (
        $section_name = "Section Name"
    )
    Write-Log -Message "`n##############################"
    Write-Log -Message "# $section_name"
    Write-Log -Message "##############################"
}

Function Print-ReportFooter {
    Write-Log -Message "`n##############################"
    Write-Log -Message "# $script_name $script_version completed"
    Write-Log -Message "Stop Time: $(Get-Timestamp -readable)"
}

Function Print-CutSec-Footer {
    Write-Log -Message "Configuration Hardening Assessment PowerShell Script (CHAPS)"
    Write-Log -Message "Brought to you by Cutaway Security, LLC"
    Write-Log -Message "For assessment and auditing help, contact info[@]cutawaysecurity.com"
    Write-Log -Message "For script help or feedback, contact dev[@]cutawaysecurity.com"
}

##############################
# Helper Functions
##############################

# Check for Administrator Role
Function Get-AdminState {
	if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")){ 
        Write-Log -Message "Script is running as normal user" -err 
        $global:admin_user = $false
	} else {
		Write-Log -Message "Script is running as Administrator" -pos 
        $global:admin_user = $true
    }
}

# Get formatted timestamp
Function Get-Timestamp {
    param(
        [switch]$readable
    )

    $now = Get-Date

    if ($readable) {
        return $now.ToString("dddd MM/dd/yyyy HH:mm:ss K")
    } else {
        return $now.ToString("yyyy-MM-ddTHHmm")
    }
}

# Check for Cmdlet, else use CimInstance
Function Test-CommandExists{
    Param ($command)
    $oldPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Stop'
    try {
        if (Get-Command $command) {
            return $true
        }
    }
    catch {
        return $false
    }
    finally {
        $ErrorActionPreference = $oldPreference
    }
} 

Function Write-Log {
    param (
        [string]$Message,
        [string]$LogFile = "$out_dir\$out_file",
        [switch]$NoConsole,
        [switch]$err,
        [switch]$pos,
        [switch]$neg,
        [switch]$info,
        [switch]$rep
    )

    # Ensure the directory exists
    $log_dir = Split-Path -Parent $LogFile
    if (-not (Test-Path $log_dir)) {
        New-Item -ItemType Directory -Path $log_dir | Out-Null
    }

    # Prepend the correct label
    if ($err) {
        $Message = $err_str + $Message
    } elseif ($pos) {
        $Message = $pos_str + $Message
    } elseif ($neg) {
        $Message = $neg_str + $Message
    } elseif ($info) {
        $Message = $inf_str + $Message
    } elseif ($rep) {
        $Message = $rep_str + $Message
    }

    # Always write to log file
    $Message | Out-File -FilePath $LogFile -Append -Encoding UTF8

    # Optionally write to console, too
    if (-not $NoConsole) {
        Write-Output $Message
    }
}

##############################
# Information Collection Functions
##############################

Function Get-SystemInfo {
    Print-SectionHeader "System Information"
    
    # Ensure output path exists
    if (-not (Test-Path $out_dir)) {
        New-Item -ItemType Directory -Path $out_dir | Out-Null
    }

    # Create a timestamped filename
    $sysinfo_file = Join-Path $out_dir "systeminfo-$(Get-Timestamp).txt"
    
    # Run systeminfo and save output to the file
    systeminfo | Out-File -FilePath $sysinfo_file -Encoding UTF8

    # Notify user
    Write-Log -Message "System information saved to: $sysinfo_file" -rep 
}

##############################
# Main
##############################
Set-Output

# Report Header
Print-ReportHeader

if ($getSysInfo) {
    Get-SystemInfo
}

# Report Footer
Print-ReportFooter
if ($cutsec_footer) {
    Print-CutSec-Footer
}