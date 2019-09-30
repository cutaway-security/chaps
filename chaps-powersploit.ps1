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


# Suppress All Errors until we handle errors
$ErrorActionPreference = "SilentlyContinue"

########### Record PowerSploit Results ############
# Create storage directory for files in users Temp directory at $env:temp
$chaps_dest = "chaps-PS-$(get-date -f yyyyMMdd-hhmmss)"
New-Item -ItemType directory -Path $env:temp\$chaps_dest
$out_file = "$env:temp\$chaps_dest\$Env:ComputerName-chaps-PS.txt"
$trans_file = "$env:temp\$chaps_dest\$Env:ComputerName-chaps-PS-transcript.txt"
#Start-Transcript -Path $trans_file -NoClobber
###############################

########## Check for Administrator Role ##############
$inf_str + "Start Date/Time: $(get-date -format yyyyMMddTHHmmssffzz)" | Tee-Object -FilePath $out_file -Append
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")){ 
    "You do not have Administrator rights. Some checks will not succeed. Note warnings." | Tee-Object -FilePath $out_file -Append
} else {
    "Script running with Administrator rights." | Tee-Object -FilePath $out_file -Append
}
###############################

###############################
# Check Environment
"[*] Dumping Environment Variables" | Tee-Object -FilePath $out_file -Append
Get-ChildItem Env: | Tee-Object -FilePath $out_file -Append

# Import PowerSploit Modules
"[*] Importing PowerSploit Modules" | Tee-Object -FilePath $out_file -Append
Import-module .\Privesc\Privesc
Import-module .\Recon\Recon
Import-module .\Exfiltration\Exfiltration

# Run checks
## Exfiltration Checks
"[*] Exfiltration Checks" | Tee-Object -FilePath $out_file -Append
"[*] Dump GPP Autologon Creds" | Tee-Object -FilePath $out_file -Append
Get-GPPAutologon | Tee-Object -FilePath $out_file -Append
"[*] Dump GPP Password" | Tee-Object -FilePath $out_file -Append
Get-GPPPassword | Tee-Object -FilePath $out_file -Append
"[*] Dump Windows Vault Creds" | Tee-Object -FilePath $out_file -Append
Get-VaultCredential | Tee-Object -FilePath $out_file -Append

## Recon Checks
### The following checks will not return anything, and may error, if a Domain account isn't used.
"[*] Recon Checks" | Tee-Object -FilePath $out_file -Append
"[*] Dump GPOs" | Tee-Object -FilePath $out_file -Append
Get-NetGPO | Tee-Object -FilePath $out_file -Append
"[*] Dump Domain Trusts" | Tee-Object -FilePath $out_file -Append
Invoke-MapDomainTrust | Tee-Object -FilePath $out_file -Append
"[*] Dump Domain Shares" | Tee-Object -FilePath $out_file -Append
Invoke-ShareFinder | Tee-Object -FilePath $out_file -Append
"[*] Dump SPN and Kerberos Tickets details" | Tee-Object -FilePath $out_file -Append
Invoke-Kerberoast | fl | Tee-Object -FilePath $out_file -Append

## Privesc Checks
"[*] Privesc Checks" | Tee-Object -FilePath $out_file -Append
"[*] Run all Privesc Checks" | Tee-Object -FilePath $out_file -Append
Invoke-AllChecks -Format List | Tee-Object -FilePath $out_file -Append

# Stop recording
#Stop-Transcript
