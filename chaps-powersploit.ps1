<#
chaps_powersploit.ps1 - a PowerShell script to gather system information
                        using the PowerSploit PowerShell cmdlets.
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

# Check to be sure script is being executed from the PowerSploit directory.
# Write-Host "[*] Testing current working directory.\n"
if(-NOT ((Get-Location).path.split("\")[-1] -eq "PowerSploit")){
	Write-Error "This script requires that it is executed from the PowerSpoit directory." -ErrorAction Stop
}

# Suppress All Errors until we handle errors
$ErrorActionPreference = "SilentlyContinue"

# Record PowerSploit Results
Start-Transcript -Path "..\$Env:ComputerName-powersploit.txt" -NoClobber

########## Check for Administrator Role ##############

if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")){ 
    Write-Neg; Write-Host "You do not have Administrator rights. Some checks will not succeed. Note warnings."
} else {
    Write-Info; Write-Host "Script running with Administrator rights."
}

###############################
# Gather System Info
Write-Host "\n[*] Dumping System Info to seperate file\n"
systeminfo > "..\$Env:Computername-sysinfo.txt"

# Check Environment
Write-Host "\n[*] Dumping Environment Variables\n"
Get-ChildItem Env:

# Import PowerSploit Modules
Write-Host "\n[*] Importing PowerSploit Modules\n"
Import-module .\Privesc\Privesc
Import-module .\Recon\Recon
Import-module .\Exfiltration\Exfiltration

# Run checks
## Exfiltration Checks
Write-Host "\n[*] Exfiltration Checks\n"
Write-Host "[*] Dump GPP Autologon Creds\n"
Get-GPPAutologon
Write-Host "[*] Dump GPP Password\n"
Get-GPPPassword
Write-Host "[*] Dump Windows Vault Creds\n"
Get-VaultCredential

## Recon Checks
Write-Host "\n[*] Recon Checks\n"
Write-Host "[*] Dump GPOs\n"
Get-NetGPO
Write-Host "[*] Dump Domain Trusts\n"
Invoke-MapDomainTrust
Write-Host "[*] Dump Domain Shares\n"
Invoke-ShareFinder

## Privesc Checks
Write-Host "\n[*] Privesc Checks\n"
Write-Host "[*] Run all Privesc Checks\n"
Invoke-AllChecks -Format List

# Stop recording
Stop-Transcript

