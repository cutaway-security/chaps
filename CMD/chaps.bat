:: chaps.bat - a Windows batch script for checking system security
:: when conducting an assessment of systems where the Microsoft
:: Policy Analyzer and other assessment tools cannot be installed.
:: All output goes to stdout in markdown format. Redirect to file:
::   chaps.bat > report.md
::
:: Author: Don C. Weber (@cutaway)
:: Date:   April 22, 2025
::
:: License:
:: Copyright (c) 2025, Cutaway Security, Inc. <dev [@] cutawaysecurity.com>
::
:: chaps.bat is free software: you can redistribute it and/or modify
:: it under the terms of the GNU General Public License as published by
:: the Free Software Foundation, either version 3 of the License, or
:: (at your option) any later version.
::
:: chaps.bat is distributed in the hope that it will be useful,
:: but WITHOUT ANY WARRANTY; without even the implied warranty of
:: MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
:: GNU General Public License for more details.
:: You should have received a copy of the GNU General Public License
:: along with this program.  If not, see <http://www.gnu.org/licenses/>.
:: Point Of Contact:    Don C. Weber <dev [@] cutawaysecurity.com>

@echo off
SETLOCAL ENABLEDELAYEDEXPANSION

:: #############################
:: Configuration
:: #############################
set "SCRIPTNAME=chaps.bat"
set "SCRIPTVERSION=1.0.0"
set "COMPANY="
set "SITENAME="
set "CUTSEC_FOOTER=true"

:: Skip helper functions, jump to main
goto :main

:: #############################
:: Helper Functions
:: #############################

:GetRegVal
:: %1 = registry path, %2 = value name, %3 = output variable
setlocal enabledelayedexpansion
set "outval="
for /f "tokens=2,*" %%A in ('reg query "%~1" /v "%~2" 2^>nul ^| findstr /i "%~2"') do set "outval=%%B"
endlocal & set "%~3=%outval%"
goto :eof

:GetRegValTokens3
:: %1 = registry path, %2 = value name, %3 = output variable
:: Uses tokens=3 for standard REG_DWORD / REG_SZ output
setlocal enabledelayedexpansion
set "outval="
for /f "tokens=3" %%A in ('reg query "%~1" /v "%~2" 2^>nul ^| findstr /i "%~2"') do set "outval=%%A"
endlocal & set "%~3=%outval%"
goto :eof

:CheckSvcState
:: %1 = service name, %2 = output variable (Running, Stopped, NotFound)
setlocal enabledelayedexpansion
set "svcstate=NotFound"
for /f "tokens=4" %%A in ('sc query "%~1" 2^>nul ^| findstr /i "STATE"') do set "svcstate=%%A"
endlocal & set "%~2=%svcstate%"
goto :eof

:PrintRegCheck
:: %1 = path, %2 = value name, %3 = good value, %4 = good msg, %5 = bad msg
setlocal enabledelayedexpansion
set "_rv="
for /f "tokens=3" %%A in ('reg query "%~1" /v "%~2" 2^>nul ^| findstr /i "%~2"') do set "_rv=%%A"
if "!_rv!"=="%~3" (
    echo [+] %~4
) else if "!_rv!"=="" (
    echo [*] %~2: not configured ^(registry value not found^)
) else (
    echo [-] %~5: !_rv!
)
endlocal
goto :eof

:main

:: #############################
:: Check admin rights
:: #############################
set "IS_ADMIN=false"
whoami /groups 2>nul | findstr /i "S-1-5-32-544" >nul 2>&1
if %errorlevel%==0 set "IS_ADMIN=true"

:: #############################
:: Get date/time
:: #############################
set "REPORT_DATE=%DATE% %TIME%"
where wmic >nul 2>&1
if %errorlevel%==0 (
    set "WMIC_PRESENT=true"
    for /f "tokens=2 delims==" %%i in ('"wmic os get localdatetime /value 2>nul"') do set "dt=%%i"
    if defined dt (
        set "REPORT_DATE=!dt:~4,2!/!dt:~6,2!/!dt:~0,4! !dt:~8,2!:!dt:~10,2!:!dt:~12,2!"
    )
) else (
    set "WMIC_PRESENT=false"
)

:: #############################
:: Markdown Header
:: #############################
echo # CHAPS Report
echo.
echo ^| Field ^| Value ^|
echo ^| ----- ^| ----- ^|
echo ^| Script ^| %SCRIPTNAME% %SCRIPTVERSION% ^|
echo ^| Computer ^| %COMPUTERNAME% ^|
echo ^| Date ^| !REPORT_DATE! ^|
echo ^| Admin ^| !IS_ADMIN! ^|
if defined COMPANY echo ^| Company ^| %COMPANY% ^|
if defined SITENAME echo ^| Site ^| %SITENAME% ^|
echo.

:: =============================================================
:: SYSTEM INFO CHECKS (1-23)
:: =============================================================
echo ## System Info Checks
echo.

:: -------------------------------------------------------
:: CHECK 1: System Information
:: -------------------------------------------------------
echo ### Check 1: System Information
echo.
if "!WMIC_PRESENT!"=="true" (
    set "OS_NAME="
    set "OS_VER="
    set "OS_ARCH="
    for /f "tokens=2 delims==" %%A in ('"wmic os get Caption /value 2>nul"') do (
        for /f "tokens=* delims= " %%B in ("%%A") do set "OS_NAME=%%B"
    )
    for /f "tokens=2 delims==" %%A in ('"wmic os get Version /value 2>nul"') do (
        for /f "tokens=* delims= " %%B in ("%%A") do set "OS_VER=%%B"
    )
    for /f "tokens=2 delims==" %%A in ('"wmic os get OSArchitecture /value 2>nul"') do (
        for /f "tokens=* delims= " %%B in ("%%A") do set "OS_ARCH=%%B"
    )
    echo [*] OS: !OS_NAME!
    echo [*] Version: !OS_VER!
    echo [*] Architecture: !OS_ARCH!
) else (
    echo [*] WMIC not available. Using ver command.
    for /f "tokens=*" %%A in ('ver') do echo [*] %%A
)
echo.

:: -------------------------------------------------------
:: CHECK 2: Windows Version
:: -------------------------------------------------------
echo ### Check 2: Windows Version
echo.
for /f "tokens=*" %%A in ('ver') do echo [*] %%A
echo.

:: -------------------------------------------------------
:: CHECK 3: User PATH
:: -------------------------------------------------------
echo ### Check 3: User PATH
echo.
echo [*] PATH: %PATH%
echo.

:: -------------------------------------------------------
:: CHECK 4: Auto Update Configuration
:: -------------------------------------------------------
echo ### Check 4: Auto Update Configuration
echo.
set "AU_VAL="
for /f "tokens=3" %%A in ('reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v AUOptions 2^>nul ^| findstr /i "AUOptions"') do set "AU_VAL=%%A"
if defined AU_VAL (
    set "AU_DESC=Unknown"
    if "!AU_VAL!"=="0x1" set "AU_DESC=Disabled"
    if "!AU_VAL!"=="0x2" set "AU_DESC=Notify before download"
    if "!AU_VAL!"=="0x3" set "AU_DESC=Notify before installation"
    if "!AU_VAL!"=="0x4" set "AU_DESC=Scheduled installation"
    if "!AU_VAL!"=="0x0" set "AU_DESC=Not configured"
    if "!AU_VAL!"=="0x4" (
        echo [+] Auto Update: !AU_VAL! - !AU_DESC!
    ) else (
        echo [-] Auto Update: !AU_VAL! - !AU_DESC!. Recommended: Scheduled installation ^(4^)
    )
) else (
    echo [*] AUOptions registry value not found. Auto Update may be managed by other means.
)
echo.

:: -------------------------------------------------------
:: CHECK 5: Missing Patches / Installed Hotfixes
:: -------------------------------------------------------
echo ### Check 5: Installed Hotfixes
echo.
echo [*] Installed hotfixes ^(review for missing patches^):
if "!WMIC_PRESENT!"=="true" (
    for /f "tokens=*" %%A in ('"wmic qfe get HotFixID,InstalledOn /format:table 2>nul"') do (
        :: Inner for /f tokens=* filters out whitespace-only lines (produces no iteration)
        for /f "tokens=*" %%B in ("%%A") do echo [*]   %%B
    )
) else (
    echo [*] WMIC not available. Use systeminfo to review installed hotfixes.
)
echo.

:: -------------------------------------------------------
:: CHECK 6: BitLocker
:: -------------------------------------------------------
echo ### Check 6: BitLocker
echo.
call :CheckSvcState BDESVC _blsvc
if /i "!_blsvc!"=="RUNNING" (
    echo [+] BitLocker service ^(BDESVC^) is running.
) else if /i "!_blsvc!"=="STOPPED" (
    echo [-] BitLocker service ^(BDESVC^) is installed but stopped.
) else (
    if exist "%windir%\System32\manage-bde.exe" (
        echo [*] BitLocker service not found but manage-bde.exe exists.
    ) else (
        echo [-] BitLocker does not appear to be available on this system.
    )
)
echo.

:: -------------------------------------------------------
:: CHECK 7: AlwaysInstallElevated
:: -------------------------------------------------------
echo ### Check 7: AlwaysInstallElevated
echo.
set "HKLM_AIE="
set "HKCU_AIE="
call :GetRegValTokens3 "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" "AlwaysInstallElevated" HKLM_AIE
call :GetRegValTokens3 "HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer" "AlwaysInstallElevated" HKCU_AIE
set "aie_bad=false"
if "!HKLM_AIE!"=="0x1" (
    echo [-] HKLM AlwaysInstallElevated is ENABLED. This is a privilege escalation risk.
    set "aie_bad=true"
) else (
    echo [+] HKLM AlwaysInstallElevated is not enabled: !HKLM_AIE!
)
if "!HKCU_AIE!"=="0x1" (
    echo [-] HKCU AlwaysInstallElevated is ENABLED. This is a privilege escalation risk.
    set "aie_bad=true"
) else (
    echo [+] HKCU AlwaysInstallElevated is not enabled: !HKCU_AIE!
)
if "!aie_bad!"=="false" if "!HKLM_AIE!"=="" if "!HKCU_AIE!"=="" (
    echo [+] AlwaysInstallElevated is not configured ^(good^).
)
echo.

:: -------------------------------------------------------
:: CHECK 8: EMET / Exploit Protection
:: -------------------------------------------------------
echo ### Check 8: EMET / Exploit Protection
echo.
call :CheckSvcState EMET_Service _emetsvc
if /i "!_emetsvc!"=="RUNNING" (
    echo [+] EMET service is running.
) else if /i "!_emetsvc!"=="STOPPED" (
    echo [*] EMET service is installed but stopped.
) else (
    echo [*] EMET service not found. On Windows 10+, Exploit Protection is built in.
    echo [*] Use PowerShell Get-ProcessMitigation to check Exploit Protection settings.
)
echo.

:: -------------------------------------------------------
:: CHECK 9: LAPS
:: -------------------------------------------------------
echo ### Check 9: LAPS
echo.
set "laps_found=false"
reg query "HKLM\Software\Microsoft\Policies\LAPS" >nul 2>&1
if %errorlevel%==0 (
    echo [+] LAPS registry key found.
    set "laps_found=true"
)
reg query "HKLM\Software\Policies\Microsoft Services\AdmPwd" >nul 2>&1
if %errorlevel%==0 (
    echo [+] Legacy LAPS ^(AdmPwd^) registry key found.
    set "laps_found=true"
)
if exist "C:\Program Files\LAPS\CSE\Admpwd.dll" (
    echo [+] LAPS CSE DLL found at C:\Program Files\LAPS\CSE\Admpwd.dll
    set "laps_found=true"
)
if "!laps_found!"=="false" (
    echo [-] LAPS does not appear to be configured on this system.
)
echo.

:: -------------------------------------------------------
:: CHECK 10: GPO Reprocessing
:: -------------------------------------------------------
echo ### Check 10: GPO Reprocessing
echo.
set "GPO_NOGLC="
call :GetRegValTokens3 "HKLM\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" "NoGPOListChanges" GPO_NOGLC
if "!GPO_NOGLC!"=="0x0" (
    echo [+] NoGPOListChanges is 0: GPOs are reapplied even when unchanged ^(good^).
) else if "!GPO_NOGLC!"=="0x1" (
    echo [-] NoGPOListChanges is 1: GPOs are NOT reapplied when unchanged. Recommend setting to 0.
) else if "!GPO_NOGLC!"=="" (
    echo [*] NoGPOListChanges not configured. Default behavior applies.
) else (
    echo [*] NoGPOListChanges: !GPO_NOGLC!
)
echo.

:: -------------------------------------------------------
:: CHECK 11: Net Session Enumeration
:: -------------------------------------------------------
echo ### Check 11: Net Session Enumeration
echo.
set "RRSAM="
call :GetRegValTokens3 "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictRemoteSAM" RRSAM
if defined RRSAM (
    echo [+] RestrictRemoteSAM is configured: !RRSAM!
) else (
    echo [-] RestrictRemoteSAM is not configured. Remote SAM enumeration may be possible.
)
reg query "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity" /v SrvsvcSessionInfo >nul 2>&1
if %errorlevel%==0 (
    echo [*] SrvsvcSessionInfo default security descriptor is present.
) else (
    echo [*] SrvsvcSessionInfo not found in registry.
)
echo.

:: -------------------------------------------------------
:: CHECK 12: AppLocker
:: -------------------------------------------------------
echo ### Check 12: AppLocker
echo.
echo [*] AppLocker: Not available in CMD. Requires PowerShell Get-AppLockerPolicy cmdlet.
echo.

:: -------------------------------------------------------
:: CHECK 13: Credential Guard / Device Guard
:: -------------------------------------------------------
echo ### Check 13: Credential Guard / Device Guard
echo.
if "!WMIC_PRESENT!"=="true" (
    set "dg_found=false"
    for /f "tokens=2 delims==" %%A in ('"wmic /namespace:\\root\Microsoft\Windows\DeviceGuard path Win32_DeviceGuard get SecurityServicesConfigured /value 2>nul"') do (
        for /f "tokens=* delims= " %%B in ("%%A") do (
            if not "%%B"=="" (
                echo [*] SecurityServicesConfigured: %%B
                set "dg_found=true"
            )
        )
    )
    for /f "tokens=2 delims==" %%A in ('"wmic /namespace:\\root\Microsoft\Windows\DeviceGuard path Win32_DeviceGuard get SecurityServicesRunning /value 2>nul"') do (
        for /f "tokens=* delims= " %%B in ("%%A") do (
            if not "%%B"=="" (
                echo [*] SecurityServicesRunning: %%B
                set "dg_found=true"
            )
        )
    )
    if "!dg_found!"=="false" (
        echo [*] Device Guard WMI class not available or returned no data.
    )
) else (
    echo [*] WMIC not available. Cannot query Device Guard status.
)
echo.

:: -------------------------------------------------------
:: CHECK 14: MS Office Macros
:: -------------------------------------------------------
echo ### Check 14: MS Office Macro Security
echo.
set "macro_checked=false"
for %%V in (16.0 15.0 14.0 12.0) do (
    for %%A in (Word Excel PowerPoint) do (
        set "_vba="
        for /f "tokens=3" %%X in ('reg query "HKCU\Software\Microsoft\Office\%%V\%%A\Security" /v VBAWarnings 2^>nul ^| findstr /i "VBAWarnings"') do set "_vba=%%X"
        if defined _vba (
            set "macro_checked=true"
            if "!_vba!"=="0x4" (
                echo [+] Office %%V %%A VBAWarnings: !_vba! ^(macros disabled^)
            ) else if "!_vba!"=="0x3" (
                echo [+] Office %%V %%A VBAWarnings: !_vba! ^(all macros disabled except digitally signed^)
            ) else if "!_vba!"=="0x2" (
                echo [-] Office %%V %%A VBAWarnings: !_vba! ^(macros disabled with notification^)
            ) else if "!_vba!"=="0x1" (
                echo [-] Office %%V %%A VBAWarnings: !_vba! ^(all macros enabled^)
            ) else (
                echo [*] Office %%V %%A VBAWarnings: !_vba!
            )
        )
    )
)
if "!macro_checked!"=="false" (
    echo [*] No Office VBAWarnings registry keys found. Office may not be installed or macros are at default.
)
echo.

:: -------------------------------------------------------
:: CHECK 15: Sysmon
:: -------------------------------------------------------
echo ### Check 15: Sysmon
echo.
set "sysmon_running=false"
for %%S in (Sysmon Sysmon64 SysmonDrv) do (
    call :CheckSvcState %%S _syssvc
    if /i "!_syssvc!"=="RUNNING" (
        echo [+] %%S service is running.
        set "sysmon_running=true"
    ) else if /i "!_syssvc!"=="STOPPED" (
        echo [*] %%S service is installed but stopped.
    )
)
if "!sysmon_running!"=="false" (
    echo [-] No Sysmon service detected. Consider deploying Sysmon for endpoint visibility.
)
echo.

:: -------------------------------------------------------
:: CHECK 16: USB Devices
:: -------------------------------------------------------
echo ### Check 16: USB Devices
echo.
if "!WMIC_PRESENT!"=="true" (
    echo [*] USB controller devices:
    for /f "tokens=*" %%A in ('"wmic path Win32_USBControllerDevice get Dependent 2>nul"') do (
        :: Inner for /f tokens=* filters out whitespace-only lines (produces no iteration)
        for /f "tokens=*" %%B in ("%%A") do echo [*]   %%B
    )
) else (
    echo [*] WMIC not available. Cannot enumerate USB devices.
)
echo.

:: -------------------------------------------------------
:: CHECK 17: Antivirus / EDR
:: -------------------------------------------------------
echo ### Check 17: Antivirus / EDR
echo.
if "!WMIC_PRESENT!"=="true" (
    set "av_found=false"
    for /f "tokens=2 delims==" %%A in ('"wmic /namespace:\\root\SecurityCenter2 path AntiVirusProduct get displayName /value 2>nul"') do (
        for /f "tokens=* delims= " %%B in ("%%A") do (
            if not "%%B"=="" (
                echo [+] Antivirus detected: %%B
                set "av_found=true"
            )
        )
    )
    if "!av_found!"=="false" (
        echo [*] No antivirus detected via SecurityCenter2. This WMI namespace may not exist on servers.
    )
) else (
    echo [*] WMIC not available. Cannot query antivirus status.
)
echo.

:: -------------------------------------------------------
:: CHECK 18: Software Inventory
:: -------------------------------------------------------
echo ### Check 18: Software Inventory
echo.
echo [*] Installed software ^(HKLM Uninstall^):
for /f "tokens=2,*" %%A in ('reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" /s 2^>nul ^| findstr /i "DisplayName"') do (
    for /f "tokens=*" %%C in ("%%B") do echo [*]   %%C
)
echo.

:: -------------------------------------------------------
:: CHECK 19: UAC Configuration
:: -------------------------------------------------------
echo ### Check 19: UAC Configuration
echo.
set "UAC_PATH=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
set "_elua="
call :GetRegValTokens3 "%UAC_PATH%" "EnableLUA" _elua
if "!_elua!"=="0x1" (
    echo [+] EnableLUA: Enabled ^(UAC is on^)
) else if "!_elua!"=="0x0" (
    echo [-] EnableLUA: Disabled. UAC is OFF. This is a significant security risk.
) else (
    echo [*] EnableLUA: !_elua!
)
set "_cpba="
call :GetRegValTokens3 "%UAC_PATH%" "ConsentPromptBehaviorAdmin" _cpba
echo [*] ConsentPromptBehaviorAdmin: !_cpba! ^(5=prompt for consent for non-Windows binaries, 2=prompt for credentials^)
set "_posd="
call :GetRegValTokens3 "%UAC_PATH%" "PromptOnSecureDesktop" _posd
if "!_posd!"=="0x1" (
    echo [+] PromptOnSecureDesktop: Enabled
) else (
    echo [-] PromptOnSecureDesktop: !_posd! ^(Recommend 1^)
)
set "_fat="
call :GetRegValTokens3 "%UAC_PATH%" "FilterAdministratorToken" _fat
if "!_fat!"=="0x1" (
    echo [+] FilterAdministratorToken: Enabled
) else (
    echo [*] FilterAdministratorToken: !_fat! ^(0=default, consider enabling on sensitive systems^)
)
echo.

:: -------------------------------------------------------
:: CHECK 20: Account Policies
:: -------------------------------------------------------
echo ### Check 20: Account Policies
echo.
echo [*] Net accounts output:
for /f "tokens=*" %%A in ('net accounts 2^>nul') do for /f "tokens=*" %%B in ("%%A") do echo [*]   %%B
echo.
echo [*] Guest account status:
for /f "tokens=*" %%A in ('net user Guest 2^>nul ^| findstr /i "Account active"') do for /f "tokens=*" %%B in ("%%A") do echo [*]   %%B
echo.
if "!WMIC_PRESENT!"=="true" (
    echo [*] Built-in Administrator account ^(SID -500^):
    for /f "tokens=2 delims==" %%A in ('"wmic useraccount where \"SID like '%%-500'\" get Name,Disabled /value 2>nul"') do (
        for /f "tokens=* delims= " %%B in ("%%A") do (
            if not "%%B"=="" echo [*]   %%B
        )
    )
)
echo.

:: -------------------------------------------------------
:: CHECK 21: Secure Boot
:: -------------------------------------------------------
echo ### Check 21: Secure Boot
echo.
set "_sboot="
call :GetRegValTokens3 "HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State" "UEFISecureBootEnabled" _sboot
if "!_sboot!"=="0x1" (
    echo [+] UEFI Secure Boot is enabled.
) else if "!_sboot!"=="0x0" (
    echo [-] UEFI Secure Boot is disabled. Recommend enabling if hardware supports it.
) else (
    echo [*] Secure Boot status could not be determined: !_sboot!
)
echo.

:: -------------------------------------------------------
:: CHECK 22: LSA Protection (RunAsPPL)
:: -------------------------------------------------------
echo ### Check 22: LSA Protection
echo.
set "_ppl="
call :GetRegValTokens3 "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" "RunAsPPL" _ppl
if "!_ppl!"=="0x1" (
    echo [+] LSA Protection ^(RunAsPPL^) is enabled.
) else if "!_ppl!"=="0x2" (
    echo [+] LSA Protection ^(RunAsPPL^) is enabled ^(UEFI lock^).
) else if "!_ppl!"=="0x0" (
    echo [-] LSA Protection ^(RunAsPPL^) is disabled. Recommend enabling to protect LSASS.
) else (
    echo [*] RunAsPPL not configured: !_ppl! ^(Default: not protected^)
)
echo.

:: -------------------------------------------------------
:: CHECK 23: Risky Services
:: -------------------------------------------------------
echo ### Check 23: Risky Services
echo.
for %%S in (Spooler RemoteRegistry SNMP TlntSvr RemoteAccess NetTcpPortSharing SharedAccess) do (
    call :CheckSvcState %%S _rsvc
    if /i "!_rsvc!"=="RUNNING" (
        echo [-] %%S service is RUNNING. Evaluate whether this service is needed.
    ) else if /i "!_rsvc!"=="STOPPED" (
        echo [*] %%S service is installed but stopped.
    ) else (
        echo [+] %%S service is not installed.
    )
)
echo.

:: -------------------------------------------------------
:: CHECK 24: Unquoted Service Paths
:: -------------------------------------------------------
echo ### Check 24: Unquoted Service Paths
echo.
echo [*] Services with unquoted PathName values (starting with a drive letter, not a quote).
echo [*] Review each for a space before the .exe -- those are privilege escalation risks:
if "!WMIC_PRESENT!"=="true" (
    wmic service get Name,PathName /value 2>nul | findstr /r /i /c:"^PathName=[A-Za-z]:"
) else (
    echo [*] WMIC not available. Cannot enumerate service paths.
)
echo.

:: -------------------------------------------------------
:: CHECK 25: Weak Program Directory Permissions
:: -------------------------------------------------------
echo ### Check 25: Weak Program Directory Permissions
echo.
if "!IS_ADMIN!"=="false" (
    echo [*] Weak program permission check skipped ^(requires Administrator for consistent ACL reads^).
    goto :check25_done
)
echo [*] Directories granting Modify/Write/FullControl to Users, Authenticated Users, or Everyone:
echo [*] ^(Review each -- these are privilege escalation risks^)
set "weak_found=0"
set "permtmp=%TEMP%\chaps_perm.txt"
if exist "!permtmp!" del "!permtmp!" >nul 2>&1
:: Collect directories to inspect into a temp listing. Write paths, one per line, to a secondary temp.
set "dirlist=%TEMP%\chaps_dirs.txt"
if exist "!dirlist!" del "!dirlist!" >nul 2>&1
:: Enumerate Program Files and Program Files (x86) children
dir /ad /b "%SystemDrive%\Program Files" 2>nul > "!permtmp!"
for /f "usebackq delims=" %%D in ("!permtmp!") do echo %SystemDrive%\Program Files\%%D>> "!dirlist!"
dir /ad /b "%SystemDrive%\Program Files (x86)" 2>nul > "!permtmp!"
for /f "usebackq delims=" %%D in ("!permtmp!") do echo %SystemDrive%\Program Files (x86)\%%D>> "!dirlist!"
:: Enumerate non-standard root folders
dir /ad /b "%SystemDrive%\" 2>nul > "!permtmp!"
for /f "usebackq delims=" %%D in ("!permtmp!") do (
    set "dn=%%D"
    set "skipit=0"
    if /i "!dn!"=="Program Files"       set "skipit=1"
    if /i "!dn!"=="Program Files (x86)" set "skipit=1"
    if /i "!dn!"=="Windows"             set "skipit=1"
    if /i "!dn!"=="Users"               set "skipit=1"
    if /i "!dn!"=="ProgramData"         set "skipit=1"
    if /i "!dn!"=="PerfLogs"            set "skipit=1"
    if /i "!dn!"=="Recovery"            set "skipit=1"
    if /i "!dn!"=="MSOCache"            set "skipit=1"
    if /i "!dn!"=="inetpub"             set "skipit=1"
    if "!dn:~0,1!"=="$" set "skipit=1"
    if "!skipit!"=="0" echo %SystemDrive%\!dn!>> "!dirlist!"
)
:: Process each candidate directory with icacls
if exist "!dirlist!" (
    for /f "usebackq delims=" %%P in ("!dirlist!") do (
        :: Run icacls, filter output for risky principal + rights combo
        icacls "%%P" 2>nul | findstr /i /c:"Everyone:" /c:"BUILTIN\Users:" /c:"Authenticated Users:" > "!permtmp!"
        if exist "!permtmp!" (
            findstr /i /c:"(F)" /c:"(M)" /c:"(W)" /c:"(WD)" /c:"(Modify)" /c:"(FullControl)" "!permtmp!" >nul 2>&1
            if not errorlevel 1 (
                echo [-] %%P
                for /f "usebackq delims=" %%A in ("!permtmp!") do echo [*]     %%A
                set /a weak_found+=1
            )
        )
    )
)
if exist "!permtmp!" del "!permtmp!" >nul 2>&1
if exist "!dirlist!" del "!dirlist!" >nul 2>&1
if "!weak_found!"=="0" (
    echo [+] No weak permissions detected on program/vendor directories examined.
) else (
    echo [*] !weak_found! director^(ies^) with weak permissions found ^(listed above^).
)
:check25_done
echo.

:: -------------------------------------------------------
:: CHECK 26: Installed Compilers
:: -------------------------------------------------------
echo ### Check 26: Installed Compilers
echo.
set "compiler_found=0"
:: Search PATH via 'where' for common compiler binaries
for %%C in (gcc.exe g++.exe cc.exe cc1.exe clang.exe clang++.exe clang-cl.exe cl.exe mingw32-gcc.exe x86_64-w64-mingw32-gcc.exe i686-w64-mingw32-gcc.exe nasm.exe masm.exe ml.exe ml64.exe make.exe mingw32-make.exe nmake.exe cmake.exe perl.exe python.exe) do (
    for /f "delims=" %%P in ('where %%C 2^>nul') do (
        for /f "tokens=*" %%Q in ("%%P") do (
            echo [*]   %%Q
            set /a compiler_found+=1
        )
    )
)
:: Check common install roots
for %%R in ("%SystemDrive%\Strawberry" "%SystemDrive%\Perl" "%SystemDrive%\Perl64" "%SystemDrive%\MinGW" "%SystemDrive%\msys64" "%SystemDrive%\msys" "%SystemDrive%\cygwin64" "%SystemDrive%\cygwin" "%SystemDrive%\Python27" "%SystemDrive%\Python3" "%SystemDrive%\TDM-GCC-64" "%SystemDrive%\Program Files\LLVM" "%SystemDrive%\Program Files (x86)\LLVM") do (
    if exist "%%~R" (
        for /f "delims=" %%F in ('dir /s /b "%%~R\gcc.exe" "%%~R\g++.exe" "%%~R\clang.exe" "%%~R\cl.exe" "%%~R\perl.exe" "%%~R\make.exe" "%%~R\cmake.exe" "%%~R\nasm.exe" 2^>nul') do (
            echo [*]   %%F
            set /a compiler_found+=1
        )
    )
)
if "!compiler_found!"=="0" (
    echo [+] No common compilers or build tools detected.
) else (
    echo [-] !compiler_found! compiler/build tool binary^(ies^) detected ^(living-off-the-land risk; listed above^).
)
echo.

:: =============================================================
:: SECURITY CHECKS (27-33)
:: =============================================================
echo ## Security Checks
echo.

:: -------------------------------------------------------
:: CHECK 27: SMB Server Configuration
:: -------------------------------------------------------
echo ### Check 27: SMB Server Configuration
echo.
set "SMB_PATH=HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
set "_smb1="
call :GetRegValTokens3 "%SMB_PATH%" "SMB1" _smb1
if "!_smb1!"=="0x0" (
    echo [+] SMB1 server protocol is disabled.
) else if "!_smb1!"=="0x1" (
    echo [-] SMB1 server protocol is ENABLED. Recommend disabling SMBv1.
) else (
    echo [*] SMB1 registry value not found. SMBv1 may be enabled by default on older systems.
)
set "_smb2="
call :GetRegValTokens3 "%SMB_PATH%" "SMB2" _smb2
if "!_smb2!"=="0x0" (
    echo [-] SMB2 server protocol is disabled. This is unusual.
) else if "!_smb2!"=="0x1" (
    echo [+] SMB2 server protocol is enabled.
) else (
    echo [*] SMB2 registry value not set ^(enabled by default on modern systems^).
)
set "_asmb1="
call :GetRegValTokens3 "%SMB_PATH%" "AuditSmb1Access" _asmb1
if "!_asmb1!"=="0x1" (
    echo [+] SMB1 access auditing is enabled.
) else (
    echo [*] AuditSmb1Access: !_asmb1! ^(Recommend enabling^)
)
set "_srss="
call :GetRegValTokens3 "%SMB_PATH%" "RequireSecuritySignature" _srss
if "!_srss!"=="0x1" (
    echo [+] SMB server signing is required.
) else (
    echo [-] SMB server RequireSecuritySignature: !_srss! ^(Recommend 1^)
)
set "_senc="
call :GetRegValTokens3 "%SMB_PATH%" "EncryptData" _senc
if "!_senc!"=="0x1" (
    echo [+] SMB server encryption is enabled.
) else (
    echo [*] SMB server EncryptData: !_senc! ^(Recommend enabling for SMB 3.0+^)
)
set "_srue="
call :GetRegValTokens3 "%SMB_PATH%" "RejectUnencryptedAccess" _srue
if "!_srue!"=="0x1" (
    echo [+] SMB server rejects unencrypted access.
) else (
    echo [*] RejectUnencryptedAccess: !_srue!
)
echo.

:: -------------------------------------------------------
:: CHECK 28: Anonymous Enumeration
:: -------------------------------------------------------
echo ### Check 28: Anonymous Enumeration
echo.
set "_ra="
call :GetRegValTokens3 "HKLM\System\CurrentControlSet\Control\Lsa" "RestrictAnonymous" _ra
if "!_ra!"=="0x1" (
    echo [+] RestrictAnonymous: 1 ^(anonymous enumeration of SAM accounts/shares restricted^)
) else if "!_ra!"=="0x2" (
    echo [+] RestrictAnonymous: 2 ^(no access without explicit anonymous permissions^)
) else if "!_ra!"=="0x0" (
    echo [-] RestrictAnonymous: 0 ^(anonymous access allowed^). Recommend setting to 1 or 2.
) else (
    echo [*] RestrictAnonymous: !_ra!
)
set "_ras="
call :GetRegValTokens3 "HKLM\System\CurrentControlSet\Control\Lsa" "RestrictAnonymousSAM" _ras
if "!_ras!"=="0x1" (
    echo [+] RestrictAnonymousSAM: 1 ^(anonymous SAM enumeration restricted^)
) else if "!_ras!"=="0x0" (
    echo [-] RestrictAnonymousSAM: 0. Recommend setting to 1.
) else (
    echo [*] RestrictAnonymousSAM: !_ras!
)
echo.

:: -------------------------------------------------------
:: CHECK 29: Untrusted Font Blocking
:: -------------------------------------------------------
echo ### Check 29: Untrusted Font Blocking
echo.
set "_mopt="
call :GetRegVal "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel" "MitigationOptions" _mopt
if defined _mopt (
    echo [*] MitigationOptions value: !_mopt!
    echo [*] Review this value for untrusted font blocking ^(third nibble from right^).
) else (
    echo [*] MitigationOptions not configured. Untrusted font blocking is at default.
)
echo.

:: -------------------------------------------------------
:: CHECK 30: ASR Rules
:: -------------------------------------------------------
echo ### Check 30: ASR Rules
echo.
echo [*] ASR Rules: Not available in CMD. Requires PowerShell Get-MpPreference cmdlet.
echo.

:: -------------------------------------------------------
:: CHECK 31: SMB Client Signing
:: -------------------------------------------------------
echo ### Check 31: SMB Client Signing
echo.
set "SMBC_PATH=HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
set "_crss="
call :GetRegValTokens3 "%SMBC_PATH%" "RequireSecuritySignature" _crss
if "!_crss!"=="0x1" (
    echo [+] SMB client signing is required.
) else (
    echo [-] SMB client RequireSecuritySignature: !_crss! ^(Recommend 1^)
)
set "_cess="
call :GetRegValTokens3 "%SMBC_PATH%" "EnableSecuritySignature" _cess
if "!_cess!"=="0x1" (
    echo [+] SMB client signing is enabled.
) else (
    echo [*] SMB client EnableSecuritySignature: !_cess!
)
echo.

:: -------------------------------------------------------
:: CHECK 32: TLS/SSL Protocol Configuration
:: -------------------------------------------------------
echo ### Check 32: TLS/SSL Protocol Configuration
echo.
set "SCHANNEL_BASE=HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
for %%P in ("SSL 2.0" "SSL 3.0" "TLS 1.0" "TLS 1.1" "TLS 1.2" "TLS 1.3") do (
    set "_tls_en="
    for /f "tokens=3" %%A in ('reg query "%SCHANNEL_BASE%\%%~P\Server" /v Enabled 2^>nul ^| findstr /i "Enabled"') do set "_tls_en=%%A"
    if "!_tls_en!"=="0x0" (
        echo [+] %%~P Server: Disabled
    ) else if "!_tls_en!"=="0x1" (
        set "_proto=%%~P"
        if "!_proto!"=="TLS 1.2" (
            echo [+] %%~P Server: Enabled
        ) else if "!_proto!"=="TLS 1.3" (
            echo [+] %%~P Server: Enabled
        ) else (
            echo [-] %%~P Server: Enabled. Recommend disabling legacy protocols.
        )
    ) else (
        echo [*] %%~P Server: Not explicitly configured ^(OS default applies^)
    )
)
echo.

:: -------------------------------------------------------
:: CHECK 33: Audit Policy
:: -------------------------------------------------------
echo ### Check 33: Audit Policy
echo.
echo [*] Audit policy settings:
for /f "tokens=*" %%A in ('auditpol /get /category:* 2^>nul') do for /f "tokens=*" %%B in ("%%A") do echo [*]   %%B
echo.

:: =============================================================
:: AUTHENTICATION CHECKS (34-42)
:: =============================================================
echo ## Authentication Checks
echo.

:: -------------------------------------------------------
:: CHECK 34: RDP Deny
:: -------------------------------------------------------
echo ### Check 34: RDP Configuration
echo.
set "_arrpc="
call :GetRegValTokens3 "HKLM\System\CurrentControlSet\Control\Terminal Server" "AllowRemoteRPC" _arrpc
if "!_arrpc!"=="0x0" (
    echo [+] AllowRemoteRPC is disabled: !_arrpc!
) else if "!_arrpc!"=="0x1" (
    echo [-] AllowRemoteRPC is enabled: !_arrpc! ^(Recommend disabling^)
) else (
    echo [*] AllowRemoteRPC: !_arrpc!
)
set "_fdts="
call :GetRegValTokens3 "HKLM\System\CurrentControlSet\Control\Terminal Server" "fDenyTSConnections" _fdts
if "!_fdts!"=="0x1" (
    echo [+] fDenyTSConnections: 1 ^(RDP connections denied^)
) else if "!_fdts!"=="0x0" (
    echo [-] fDenyTSConnections: 0 ^(RDP connections allowed^)
) else (
    echo [*] fDenyTSConnections: !_fdts!
)
echo.

:: -------------------------------------------------------
:: CHECK 35: Local Administrators
:: -------------------------------------------------------
echo ### Check 35: Local Administrators
echo.
set "foundSep=false"
set /a numAdmins=0
set "adminList="
for /f "tokens=* delims=" %%L in ('net localgroup Administrators 2^>nul') do (
    set "line=%%L"
    if "!foundSep!"=="true" (
        if /i not "!line!"=="The command completed successfully." (
            if not "!line!"=="" (
                set /a numAdmins+=1
                if defined adminList (
                    set "adminList=!adminList!, !line!"
                ) else (
                    set "adminList=!line!"
                )
            )
        )
    )
    if "!line:~0,4!"=="----" set "foundSep=true"
)
if !numAdmins! GTR 1 (
    echo [-] !numAdmins! accounts in local Administrators group. Review membership.
) else (
    echo [+] !numAdmins! account in local Administrators group.
)
echo [*] Members: !adminList!
echo.

:: -------------------------------------------------------
:: CHECK 36: NTLM Session Security
:: -------------------------------------------------------
echo ### Check 36: NTLM Session Security
echo.
set "_nss="
call :GetRegValTokens3 "HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0" "NtlmMinServerSec" _nss
if "!_nss!"=="0x20080030" (
    echo [+] NtlmMinServerSec: !_nss! ^(NTLMv2 + 128-bit encryption required^)
) else if defined _nss (
    echo [*] NtlmMinServerSec: !_nss! ^(Recommend 0x20080030 for NTLMv2 + 128-bit^)
) else (
    echo [-] NtlmMinServerSec not configured. Recommend 0x20080030.
)
set "_nsc="
call :GetRegValTokens3 "HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0" "NtlmMinClientSec" _nsc
if "!_nsc!"=="0x20080030" (
    echo [+] NtlmMinClientSec: !_nsc! ^(NTLMv2 + 128-bit encryption required^)
) else if defined _nsc (
    echo [*] NtlmMinClientSec: !_nsc! ^(Recommend 0x20080030 for NTLMv2 + 128-bit^)
) else (
    echo [-] NtlmMinClientSec not configured. Recommend 0x20080030.
)
echo.

:: -------------------------------------------------------
:: CHECK 37: LAN Manager Authentication
:: -------------------------------------------------------
echo ### Check 37: LAN Manager Authentication
echo.
set "_lmcl="
call :GetRegValTokens3 "HKLM\System\CurrentControlSet\Control\Lsa" "LmCompatibilityLevel" _lmcl
if "!_lmcl!"=="0x5" (
    echo [+] LmCompatibilityLevel: 5 ^(Send NTLMv2 only, refuse LM and NTLM^)
) else if "!_lmcl!"=="0x4" (
    echo [*] LmCompatibilityLevel: 4 ^(Send NTLMv2 only, refuse LM^)
) else if "!_lmcl!"=="0x3" (
    echo [*] LmCompatibilityLevel: 3 ^(Send NTLMv2 only^)
) else if defined _lmcl (
    echo [-] LmCompatibilityLevel: !_lmcl! ^(Recommend 5 to refuse LM and NTLM^)
) else (
    echo [-] LmCompatibilityLevel not configured. Default may allow LM/NTLM.
)
set "_nlmh="
call :GetRegValTokens3 "HKLM\System\CurrentControlSet\Control\Lsa" "NoLmHash" _nlmh
if "!_nlmh!"=="0x1" (
    echo [+] NoLmHash: 1 ^(LM hash storage disabled^)
) else (
    echo [-] NoLmHash: !_nlmh! ^(Recommend 1 to prevent LM hash storage^)
)
echo.

:: -------------------------------------------------------
:: CHECK 38: Cached Logons
:: -------------------------------------------------------
echo ### Check 38: Cached Logons
echo.
set "_clc="
call :GetRegValTokens3 "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" "CachedLogonsCount" _clc
if defined _clc (
    echo [*] CachedLogonsCount: !_clc! ^(Recommend 4 or fewer for sensitive systems, 0-1 for high security^)
) else (
    echo [*] CachedLogonsCount not configured ^(default is 10^). Consider reducing.
)
echo.

:: -------------------------------------------------------
:: CHECK 39: Interactive Login / LocalAccountTokenFilterPolicy
:: -------------------------------------------------------
echo ### Check 39: Interactive Login (LocalAccountTokenFilterPolicy)
echo.
set "_latfp="
call :GetRegValTokens3 "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "LocalAccountTokenFilterPolicy" _latfp
if "!_latfp!"=="0x1" (
    echo [-] LocalAccountTokenFilterPolicy is SET ^(1^). Remote local admin access enabled ^(pass-the-hash risk^).
) else if "!_latfp!"=="0x0" (
    echo [+] LocalAccountTokenFilterPolicy is 0. Remote admin tokens are filtered.
) else (
    echo [+] LocalAccountTokenFilterPolicy not set ^(default: filtered^).
)
:: Check Wow6432Node variant
set "_wlatfp="
call :GetRegValTokens3 "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\System" "LocalAccountTokenFilterPolicy" _wlatfp
if "!_wlatfp!"=="0x1" (
    echo [-] LocalAccountTokenFilterPolicy ^(Wow6432Node^) is SET ^(1^).
) else (
    echo [+] LocalAccountTokenFilterPolicy ^(Wow6432Node^): !_wlatfp! ^(OK^)
)
echo.

:: -------------------------------------------------------
:: CHECK 40: WDigest
:: -------------------------------------------------------
echo ### Check 40: WDigest Credential Caching
echo.
set "_wdig="
call :GetRegValTokens3 "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" "UseLogonCredential" _wdig
if "!_wdig!"=="0x0" (
    echo [+] WDigest UseLogonCredential is disabled ^(0^). Credentials are not cached in plaintext.
) else if "!_wdig!"=="0x1" (
    echo [-] WDigest UseLogonCredential is ENABLED ^(1^). Plaintext passwords cached in memory!
) else (
    echo [*] WDigest UseLogonCredential not configured. Default depends on OS version ^(disabled on Win 8.1+^).
)
echo.

:: -------------------------------------------------------
:: CHECK 41: Restrict RPC Clients
:: -------------------------------------------------------
echo ### Check 41: Restrict RPC Clients
echo.
set "_rrpc="
call :GetRegValTokens3 "HKLM\Software\Policies\Microsoft\Windows NT\Rpc" "RestrictRemoteClients" _rrpc
if "!_rrpc!"=="0x1" (
    echo [+] RestrictRemoteClients: 1 ^(authenticated RPC only^)
) else if "!_rrpc!"=="0x2" (
    echo [+] RestrictRemoteClients: 2 ^(no exceptions^)
) else if "!_rrpc!"=="0x0" (
    echo [-] RestrictRemoteClients: 0 ^(no restrictions^). Recommend setting to 1.
) else (
    echo [*] RestrictRemoteClients: !_rrpc! ^(not configured, default applies^)
)
echo.

:: -------------------------------------------------------
:: CHECK 42: RDP NLA
:: -------------------------------------------------------
echo ### Check 42: RDP Network Level Authentication
echo.
set "_nla="
call :GetRegValTokens3 "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" "UserAuthentication" _nla
if "!_nla!"=="0x1" (
    echo [+] RDP NLA ^(UserAuthentication^) is enabled.
) else if "!_nla!"=="0x0" (
    echo [-] RDP NLA is disabled. Recommend enabling to require NLA before connection.
) else (
    echo [*] UserAuthentication: !_nla!
)
set "_mel="
call :GetRegValTokens3 "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" "MinEncryptionLevel" _mel
if "!_mel!"=="0x3" (
    echo [+] RDP MinEncryptionLevel: 3 ^(High/FIPS^)
) else if "!_mel!"=="0x2" (
    echo [*] RDP MinEncryptionLevel: 2 ^(Client Compatible^)
) else if defined _mel (
    echo [-] RDP MinEncryptionLevel: !_mel! ^(Recommend 3 for high encryption^)
) else (
    echo [*] MinEncryptionLevel not configured.
)
echo.

:: =============================================================
:: NETWORK CHECKS (43-52)
:: =============================================================
echo ## Network Checks
echo.

:: -------------------------------------------------------
:: CHECK 43: IPv4 Interfaces
:: -------------------------------------------------------
echo ### Check 43: IPv4 Interfaces
echo.
set "ipv4_found=false"
for /f "tokens=2 delims=:" %%A in ('ipconfig 2^>nul ^| findstr /C:"IPv4 Address" /C:"IP Address"') do (
    for /f "tokens=* delims= " %%B in ("%%A") do (
        echo [*] IPv4: %%B
        set "ipv4_found=true"
    )
)
if "!ipv4_found!"=="false" echo [*] No IPv4 addresses found.
echo.

:: -------------------------------------------------------
:: CHECK 44: IPv6 Interfaces
:: -------------------------------------------------------
echo ### Check 44: IPv6 Interfaces
echo.
set "ipv6_global=false"
for /f "tokens=2 delims=:" %%A in ('ipconfig 2^>nul ^| findstr /C:"IPv6 Address"') do (
    for /f "tokens=* delims= " %%B in ("%%A") do (
        set "addr=%%B"
        echo !addr! | findstr /i "^fe80" >nul 2>&1
        if !errorlevel!==0 (
            echo [*] IPv6 link-local: !addr!
        ) else (
            echo [-] IPv6 non-link-local: !addr! ^(review if IPv6 is needed^)
            set "ipv6_global=true"
        )
    )
)
if "!ipv6_global!"=="false" echo [+] No non-link-local IPv6 addresses detected.
echo.

:: -------------------------------------------------------
:: CHECK 45: WPAD
:: -------------------------------------------------------
echo ### Check 45: WPAD Configuration
echo.
findstr /i "wpad" "%SystemRoot%\System32\drivers\etc\hosts" >nul 2>&1
if %errorlevel%==0 (
    echo [*] WPAD entry found in hosts file:
    for /f "tokens=*" %%A in ('findstr /i "wpad" "%SystemRoot%\System32\drivers\etc\hosts" 2^>nul') do for /f "tokens=*" %%B in ("%%A") do echo [*]   %%B
) else (
    echo [*] No WPAD entry in hosts file.
)
set "_wpad="
call :GetRegValTokens3 "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" "WpadOverride" _wpad
if defined _wpad echo [*] WpadOverride: !_wpad!
call :CheckSvcState WinHttpAutoProxySvc _winsvc
if /i "!_winsvc!"=="RUNNING" (
    echo [*] WinHTTP Auto-Proxy Service is running.
) else if /i "!_winsvc!"=="STOPPED" (
    echo [+] WinHTTP Auto-Proxy Service is stopped.
) else (
    echo [+] WinHTTP Auto-Proxy Service not found.
)
echo.

:: -------------------------------------------------------
:: CHECK 46: WINS
:: -------------------------------------------------------
echo ### Check 46: WINS Configuration
echo.
if "!WMIC_PRESENT!"=="true" (
    for /f "tokens=2 delims==" %%A in ('"wmic nicconfig where IPEnabled=TRUE get DNSEnabledForWINSResolution /value 2>nul"') do (
        for /f "tokens=* delims= " %%B in ("%%A") do (
            if /i "%%B"=="TRUE" (
                echo [-] DNSEnabledForWINSResolution: TRUE. Consider disabling WINS resolution.
            ) else if /i "%%B"=="FALSE" (
                echo [+] DNSEnabledForWINSResolution: FALSE
            )
        )
    )
    for /f "tokens=2 delims==" %%A in ('"wmic nicconfig where IPEnabled=TRUE get WINSEnableLMHostsLookup /value 2>nul"') do (
        for /f "tokens=* delims= " %%B in ("%%A") do (
            if /i "%%B"=="TRUE" (
                echo [-] WINSEnableLMHostsLookup: TRUE. Consider disabling LMHOSTS lookup.
            ) else if /i "%%B"=="FALSE" (
                echo [+] WINSEnableLMHostsLookup: FALSE
            )
        )
    )
) else (
    echo [*] WMIC not available. Cannot query WINS configuration.
)
echo.

:: -------------------------------------------------------
:: CHECK 47: LLMNR
:: -------------------------------------------------------
echo ### Check 47: LLMNR
echo.
set "_llmnr="
call :GetRegValTokens3 "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient" "EnableMulticast" _llmnr
if "!_llmnr!"=="0x0" (
    echo [+] LLMNR is disabled ^(EnableMulticast=0^).
) else if "!_llmnr!"=="0x1" (
    echo [-] LLMNR is enabled ^(EnableMulticast=1^). Recommend disabling to prevent name resolution poisoning.
) else (
    echo [-] EnableMulticast not configured. LLMNR is likely enabled by default.
)
echo.

:: -------------------------------------------------------
:: CHECK 48: Computer Browser Service
:: -------------------------------------------------------
echo ### Check 48: Computer Browser Service
echo.
call :CheckSvcState Browser _brsvc
if /i "!_brsvc!"=="RUNNING" (
    echo [-] Computer Browser service is RUNNING. This is a legacy protocol, consider disabling.
) else if /i "!_brsvc!"=="STOPPED" (
    echo [*] Computer Browser service is installed but stopped.
) else (
    echo [+] Computer Browser service is not installed.
)
echo.

:: -------------------------------------------------------
:: CHECK 49: NetBIOS over TCP/IP
:: -------------------------------------------------------
echo ### Check 49: NetBIOS over TCP/IP
echo.
if "!WMIC_PRESENT!"=="true" (
    for /f "tokens=2 delims==" %%A in ('"wmic nicconfig where IPEnabled=TRUE get TcpipNetbiosOptions /value 2>nul"') do (
        for /f "tokens=* delims= " %%B in ("%%A") do (
            if "%%B"=="0" echo [*] TcpipNetbiosOptions: 0 ^(Default - DHCP controlled^)
            if "%%B"=="1" echo [*] TcpipNetbiosOptions: 1 ^(NetBIOS enabled^)
            if "%%B"=="2" echo [+] TcpipNetbiosOptions: 2 ^(NetBIOS disabled^)
        )
    )
) else (
    echo [*] WMIC not available. Cannot query NetBIOS over TCP/IP status.
)
echo.

:: -------------------------------------------------------
:: CHECK 50: Network Connections
:: -------------------------------------------------------
echo ### Check 50: Network Connections
echo.
echo [*] Active network connections ^(netstat -ano^):
for /f "tokens=*" %%A in ('netstat -ano 2^>nul') do for /f "tokens=*" %%B in ("%%A") do echo [*]   %%B
echo.

:: -------------------------------------------------------
:: CHECK 51: Firewall Profiles
:: -------------------------------------------------------
echo ### Check 51: Firewall Profiles
echo.
echo [*] Firewall profile status:
for /f "tokens=*" %%A in ('netsh advfirewall show allprofiles 2^>nul') do for /f "tokens=*" %%B in ("%%A") do echo [*]   %%B
echo.

:: -------------------------------------------------------
:: CHECK 52: TCP/IP Stack Hardening
:: -------------------------------------------------------
echo ### Check 52: TCP/IP Stack Hardening
echo.
set "TCPIP_PATH=HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
set "_disr="
call :GetRegValTokens3 "%TCPIP_PATH%" "DisableIPSourceRouting" _disr
if "!_disr!"=="0x2" (
    echo [+] DisableIPSourceRouting: 2 ^(all source-routed packets dropped^)
) else if defined _disr (
    echo [-] DisableIPSourceRouting: !_disr! ^(Recommend 2^)
) else (
    echo [*] DisableIPSourceRouting not configured.
)
set "_eicmp="
call :GetRegValTokens3 "%TCPIP_PATH%" "EnableICMPRedirect" _eicmp
if "!_eicmp!"=="0x0" (
    echo [+] EnableICMPRedirect: 0 ^(ICMP redirects ignored^)
) else if defined _eicmp (
    echo [-] EnableICMPRedirect: !_eicmp! ^(Recommend 0^)
) else (
    echo [*] EnableICMPRedirect not configured ^(default: enabled^).
)
set "_prd="
call :GetRegValTokens3 "%TCPIP_PATH%" "PerformRouterDiscovery" _prd
if "!_prd!"=="0x0" (
    echo [+] PerformRouterDiscovery: 0 ^(disabled^)
) else if defined _prd (
    echo [-] PerformRouterDiscovery: !_prd! ^(Recommend 0^)
) else (
    echo [*] PerformRouterDiscovery not configured.
)
echo.

:: -------------------------------------------------------
:: CHECK 53: Network Shares
:: -------------------------------------------------------
echo ### Check 53: Network Shares
echo.
set "share_found=0"
for /f "skip=4 tokens=1,2,*" %%A in ('net share 2^>nul') do (
    set "sname=%%A"
    set "spath=%%B"
    set "sdesc=%%C"
    :: Skip the "The command completed successfully." footer line
    if /i not "!sname!"=="The" (
        :: Skip default admin shares: ADMIN$, IPC$, PRINT$, FAX$, and drive letter shares like C$, D$
        set "is_default=0"
        if /i "!sname!"=="ADMIN$" set "is_default=1"
        if /i "!sname!"=="IPC$"   set "is_default=1"
        if /i "!sname!"=="PRINT$" set "is_default=1"
        if /i "!sname!"=="FAX$"   set "is_default=1"
        :: Drive letter admin shares (single letter followed by $)
        if not "!sname:~1,1!"=="" (
            if "!sname:~1,1!"=="$" if "!sname:~2,1!"=="" set "is_default=1"
        )
        if "!is_default!"=="0" (
            if not "!sname!"=="" (
                echo [*]   !sname! -^> !spath! ^(!sdesc!^)
                set /a share_found+=1
            )
        )
    )
)
if "!share_found!"=="0" (
    echo [+] No non-default SMB shares detected.
) else (
    echo [-] !share_found! non-default SMB share^(s^) detected ^(listed above^).
)
echo.

:: =============================================================
:: POWERSHELL CHECKS (54-60)
:: =============================================================
echo ## PowerShell Checks
echo.

:: -------------------------------------------------------
:: CHECK 54: PowerShell Versions
:: -------------------------------------------------------
echo ### Check 54: PowerShell Versions
echo.
echo [*] PowerShell Versions: Not available in CMD. Requires PowerShell runtime.
echo.

:: -------------------------------------------------------
:: CHECK 55: PowerShell Language Mode
:: -------------------------------------------------------
echo ### Check 55: PowerShell Language Mode
echo.
echo [*] PowerShell Language Mode: Not available in CMD. Requires PowerShell runtime.
echo.

:: -------------------------------------------------------
:: CHECK 56: PowerShell Module Logging
:: -------------------------------------------------------
echo ### Check 56: PowerShell Module Logging
echo.
set "_pml="
call :GetRegValTokens3 "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" "EnableModuleLogging" _pml
if "!_pml!"=="0x1" (
    echo [+] PowerShell Module Logging is enabled.
    :: Check if all modules are logged
    set "_pmn="
    for /f "tokens=3" %%A in ('reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" /v "*" 2^>nul ^| findstr /i "\*"') do set "_pmn=%%A"
    if "!_pmn!"=="*" (
        echo [+] All modules ^(*^) are being logged.
    ) else (
        echo [*] Module logging is enabled but not all modules may be logged. Check ModuleNames subkey.
    )
) else (
    echo [-] PowerShell Module Logging is not enabled. Recommend enabling for audit visibility.
)
echo.

:: -------------------------------------------------------
:: CHECK 57: PowerShell Script Block Logging
:: -------------------------------------------------------
echo ### Check 57: PowerShell Script Block Logging
echo.
set "_sbl="
call :GetRegValTokens3 "HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" "EnableScriptBlockLogging" _sbl
if "!_sbl!"=="0x1" (
    echo [+] Script Block Logging is enabled.
) else (
    echo [-] Script Block Logging is not enabled. Recommend enabling for threat detection.
)
set "_sbil="
call :GetRegValTokens3 "HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" "EnableScriptBlockInvocationLogging" _sbil
if "!_sbil!"=="0x1" (
    echo [+] Script Block Invocation Logging is enabled.
) else (
    echo [*] Script Block Invocation Logging: !_sbil! ^(optional, can be noisy^)
)
echo.

:: -------------------------------------------------------
:: CHECK 58: PowerShell Transcription
:: -------------------------------------------------------
echo ### Check 58: PowerShell Transcription
echo.
set "_pst="
call :GetRegValTokens3 "HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription" "EnableTranscripting" _pst
if "!_pst!"=="0x1" (
    echo [+] PowerShell Transcription is enabled.
) else (
    echo [-] PowerShell Transcription is not enabled. Recommend enabling.
)
set "_pih="
call :GetRegValTokens3 "HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription" "EnableInvocationHeader" _pih
if "!_pih!"=="0x1" (
    echo [+] Transcription Invocation Header is enabled.
) else (
    echo [*] Transcription EnableInvocationHeader: !_pih!
)
set "_pod="
call :GetRegVal "HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription" "OutputDirectory" _pod
if defined _pod (
    echo [*] Transcription OutputDirectory: !_pod!
) else (
    echo [*] Transcription OutputDirectory not configured ^(default location^).
)
echo.

:: -------------------------------------------------------
:: CHECK 59: PowerShell Protected Event Logging
:: -------------------------------------------------------
echo ### Check 59: PowerShell Protected Event Logging
echo.
set "_pel="
call :GetRegValTokens3 "HKLM\Software\Policies\Microsoft\Windows\EventLog\ProtectedEventLogging" "EnableProtectedEventLogging" _pel
if "!_pel!"=="0x1" (
    echo [+] Protected Event Logging is enabled.
) else (
    echo [*] Protected Event Logging is not enabled: !_pel!
)
echo.

:: -------------------------------------------------------
:: CHECK 60: WinRM
:: -------------------------------------------------------
echo ### Check 60: WinRM Service
echo.
call :CheckSvcState WinRM _wrmsvc
if /i "!_wrmsvc!"=="RUNNING" (
    echo [*] WinRM service is running. Verify this is intended and properly secured.
) else if /i "!_wrmsvc!"=="STOPPED" (
    echo [+] WinRM service is installed but stopped.
) else (
    echo [+] WinRM service is not installed.
)
echo [*] WinRM HTTP-In firewall rule:
for /f "tokens=*" %%A in ('netsh advfirewall firewall show rule name^="Windows Remote Management (HTTP-In)" 2^>nul') do for /f "tokens=*" %%B in ("%%A") do echo [*]   %%B
echo.

:: =============================================================
:: LOGGING CHECKS (61-63)
:: =============================================================
echo ## Logging Checks
echo.

:: -------------------------------------------------------
:: CHECK 61: Event Log Sizes
:: -------------------------------------------------------
echo ### Check 61: Event Log Sizes
echo.
for %%L in (Application Security System "Windows PowerShell" "Microsoft-Windows-PowerShell/Operational" "Microsoft-Windows-Sysmon/Operational" "Microsoft-Windows-TaskScheduler/Operational" "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall" "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" "Microsoft-Windows-WMI-Activity/Operational" "Microsoft-Windows-DNS-Client/Operational") do (
    set "_logsize="
    for /f "tokens=2 delims=:" %%A in ('wevtutil gl %%~L 2^>nul ^| findstr /i "maxSize"') do (
        for /f "tokens=* delims= " %%B in ("%%A") do set "_logsize=%%B"
    )
    if defined _logsize (
        echo [*] %%~L maxSize: !_logsize! bytes
    ) else (
        echo [*] %%~L: log not found or not accessible.
    )
    set "_logsize="
)
echo.

:: -------------------------------------------------------
:: CHECK 62: Command-Line Process Auditing
:: -------------------------------------------------------
echo ### Check 62: Command-Line Process Auditing
echo.
set "_claud="
call :GetRegValTokens3 "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" "ProcessCreationIncludeCmdLine_Enabled" _claud
if "!_claud!"=="0x1" (
    echo [+] Command-line process auditing is enabled.
) else (
    echo [-] Command-line process auditing is not enabled. Recommend enabling for forensic visibility.
)
echo.

:: -------------------------------------------------------
:: CHECK 63: Windows Script Host
:: -------------------------------------------------------
echo ### Check 63: Windows Script Host
echo.
set "_wsh="
call :GetRegValTokens3 "HKLM\Software\Microsoft\Windows Script Host\Settings" "Enabled" _wsh
if "!_wsh!"=="0x0" (
    echo [+] Windows Script Host is disabled.
) else if "!_wsh!"=="0x1" (
    echo [-] Windows Script Host is enabled. Consider disabling if not needed.
) else (
    echo [*] Windows Script Host Enabled value: !_wsh! ^(default: enabled^)
)
echo.

:: =============================================================
:: FOOTER
:: =============================================================
echo ---
echo.
echo ## Report Footer
echo.
echo ^| Field ^| Value ^|
echo ^| ----- ^| ----- ^|
echo ^| Script ^| %SCRIPTNAME% %SCRIPTVERSION% ^|
echo ^| Computer ^| %COMPUTERNAME% ^|
echo ^| Completed ^| %DATE% %TIME% ^|
echo.

if "%CUTSEC_FOOTER%"=="true" (
    echo ---
    echo.
    echo *CHAPS Audit Script: %SCRIPTNAME% %SCRIPTVERSION%*
    echo *Brought to you by Cutaway Security, LLC*
    echo *For assessment and auditing help, contact info [@] cutawaysecurity.com*
    echo *For script help, contact dev [@] cutawaysecurity.com*
    echo.
)

ENDLOCAL
exit /b 0
