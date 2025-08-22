:: chaps.bat - a Windows batch script for checking system security
:: when conducting an assessment of systems where the Microsoft 
:: Policy Analyzer and other assessment tools cannot be installed.
:: The batch script does not perform every check included with the 
:: CHAPS PowerShell scripts, and should only be used when using a 
:: PowerShell version is not possible.

:: Author: Don C. Weber (@cutaway)
:: Date:   April 22, 2025
@echo off
setlocal enabledelayedexpansion

:: #############################
:: Set User-Configurable Variables
:: #############################

:: Set to "true" for debugging output (write to screen in addition to output file)
set "TESTING=true"

:: Set COMPANY and SITENAME to empty string to disable
set "COMPANY="
set "SITENAME="

:: Set CUTSEC_FOOTER to false to disable
set "CUTSEC_FOOTER=false"

:: Configure the output directory and filenames
set "OUTDIR=%CD%"
set "OUTFILENAME=%COMPUTERNAME%_chaps.txt"
set "SYSINFO_FILENAME=%COMPUTERNAME%_sysinfo.txt"

:: Enable/Disable Specific Checks - Set to false to disable
set "CheckAlwaysInstallElevatedEnabled=false"
set "CheckCachedLogonsEnabled=false"
set "CheckGPOProcessingEnabled=false"
set "CheckInteractiveLoginEnabled=false"
set "CheckLanmanEnabled=false"
set "CheckNTLMSessionSecEnabled=false"
set "CheckRDPDenyEnabled=false"
set "CheckRestrictAnonymousEnabled=false"
set "CheckRestrictRemoteClientsEnabled=false"
set "CheckWDigestEnabled=false"
set "CheckWindowsScriptHostEnabled=false"
set "CheckWINSConfigEnabled=false"

:: #############################
:: Perform basic checks to help with script flow
:: #############################

:: Check if WMIC is available and set flag
if "!TESTING!"=="true" ( echo [DEBUG] Calling :CheckWMICAvailable)
call :CheckWMICAvailable
if "!TESTING!"=="true" (
    echo [DEBUG] Returned from CheckWMICAvailable
    echo [DEBUG] WMIC_PRESENT: !WMIC_PRESENT!
)

if "!WMIC_PRESENT!"=="true" (
    if "!TESTING!"=="true" ( echo [DEBUG] Calling :SetWMICExe)
    call :SetWMICExe
    if "!TESTING!"=="true" (
        echo [DEBUG] Returned from :SetWMICExe
        echo [DEBUG] WMIC_EXE: !WMIC_EXE!
    )
)

:: Get the current date and time components for setting output directory
if "!TESTING!"=="true" ( echo [DEBUG] Calling :GetDate filename)
call :GetDate filename 
if "!TESTING!"=="true" ( echo [DEBUG] Returned from :GetDate with RESULT: !RESULT!)

set "FILENAME_DATE=!RESULT!"
if "!TESTING!"=="true" ( 
    echo [DEBUG] FILENAME_DATE: !FILENAME_DATE!
    echo [DEBUG] Calling :GetDate readable 
)
call :GetDate readable
if "!TESTING!"=="true" ( echo [DEBUG] Returned from :GetDate with RESULT: !RESULT!)
set "READABLE_DATE=!RESULT!"
if "!TESTING!"=="true" ( echo [DEBUG] READABLE_DATE: !READABLE_DATE!)

:: Create output directory if it doesn't exist
set "OUTDIR=!OUTDIR!\%COMPUTERNAME%_%FILENAME_DATE%"
if "!TESTING!"=="true" ( echo [DEBUG] Checking for !OUTDIR!)
if not exist "!OUTDIR!" (
    if "!TESTING!"=="true" ( echo [DEBUG] Creating OUTDIR: !OUTDIR!)
    mkdir "!OUTDIR!" >nul 2>&1
)

:: #############################
:: Set Non-Configurable Variables
:: #############################

set "SCRIPTNAME=chaps.bat"
set "SCRIPTVERSION=1.0.0"
set "OUTFILE=%OUTDIR%\%OUTFILENAME%"
set "SYSINFO_FILE=%OUTDIR%\%SYSINFO_FILENAME%"


if "!TESTING!"=="true" (
    echo [DEBUG] COMPANY: !COMPANY!
    echo [DEBUG] SITENAME: !SITENAME!
    echo [DEBUG] CUTSEC_FOOTER: !CUTSEC_FOOTER!
    echo [DEBUG] FILENAME_DATE: !FILENAME_DATE!
    echo [DEBUG] timezone: !timezone!
    echo [DEBUG] READABLE_DATE: !READABLE_DATE!
    echo [DEBUG] OUTDIR: !OUTDIR!
    echo [DEBUG] OUTFILENAME: !OUTFILENAME!
    echo [DEBUG] SYSINFO_FILENAME: !SYSINFO_FILENAME!
    echo [DEBUG] SCRIPTNAME: !SCRIPTNAME!
    echo [DEBUG] SCRIPTVERSION: !SCRIPTVERSION!
    echo [DEBUG] OUTFILE: !OUTFILE!
    echo [DEBUG] SYSINFO_FILE: !SYSINFO_FILE!
)
:: #############################
:: Print Document Header
:: #############################

:: Show where document is saved to (not written to report)
echo ##########################
echo # Saving output to: %OUTFILE%
echo ##########################

:: Create outfile and begin writing to it.
if "!TESTING!"=="true" (
    echo [DEBUG] Create outfile and begin writing to it 
    echo ##########################
    echo # CHAPS Audit Script: %SCRIPTNAME% %SCRIPTVERSION%
    if defined COMPANY ( echo # Auditing Company: %COMPANY%)
    if defined SITENAME ( echo # Site/Plant: %SITENAME%)
    echo ##########################
    echo # Computer Name: %COMPUTERNAME%
    echo # Start Time: %READABLE_DATE%
)
echo ########################## > "%OUTFILE%"
echo # CHAPS Audit Script: %SCRIPTNAME% %SCRIPTVERSION% >> "%OUTFILE%"
if defined COMPANY ( echo # Auditing Company: %COMPANY% >> "%OUTFILE%")
if defined SITENAME ( echo # Site/Plant: %SITENAME% >> "%OUTFILE%")
echo ########################## >> "%OUTFILE%"
echo # Computer Name: %COMPUTERNAME% >> "%OUTFILE%"
echo # Start Time: %READABLE_DATE% >> "%OUTFILE%"

:: Check Admin rights
if "!TESTING!"=="true" ( echo [DEBUG] Calling :CheckAdminRights)
call :CheckAdminRights
if "!TESTING!"=="true" (
    echo [DEBUG] Returned from :CheckAdminRights
)
if "!TESTING!"=="true" (
    echo ##########################
)
echo ########################## >> "%OUTFILE%"

:: ###########################
:: System Info Checks
:: ###########################
if "!TESTING!"=="true" (echo [DEBUG] Calling PrtSectionHeader System Info)
call :PrtSectionHeader System Info
if "!TESTING!"=="true" (echo [DEBUG] Returned from PrtSectionHeader)
echo [*] Collecting systeminfo to: %SYSINFO_FILE%
systeminfo > "%SYSINFO_FILE%"

set "OS_NAME=Unknown"
set "OS_VERSION_FULL=Unknown"
set "OS_ARCH=Unknown"
set "SYS_TYPE=Unknown"
set "DOMAIN=Unknown"

if "!TESTING!"=="true" (
    echo [DEBUG] OS_NAME: !OS_NAME!
    echo [DEBUG] OS_VERSION_FULL: !OS_VERSION_FULL!
    echo [DEBUG] OS_ARCH: !OS_ARCH!
    echo [DEBUG] SYS_TYPE: !SYS_TYPE!
    echo [DEBUG] DOMAIN: !DOMAIN!
)

:: Get Poduct Name
if "!TESTING!"=="true" (echo [DEBUG] Attempting to get Product Name)
if "!WMIC_PRESENT!"=="true" (
    if "!TESTING!"=="true" (echo [DEBUG] Calling :GETWMICValue os Caption value)
    call :GetWMICValue os Caption value 
    if "!TESTING!"=="true" (echo [DEBUG] Setting OS_NAME using RESULT: !RESULT!)
    set "OS_NAME=!RESULT!"
)

:: Get System Type
if "!TESTING!"=="true" (echo [DEBUG] Attempting to get System Type)
if "!WMIC_PRESENT!"=="true" (
    if "!TESTING!"=="true" (echo [DEBUG] Calling GetWMICValue computersystem SystemType value)
    call :GetWMICValue computersystem SystemType value
    if "!TESTING!"=="true" (echo [DEBUG] Setting SYS_TYPE to !RESULT!)
    set "SYS_TYPE=!RESULT!"
    if "!TESTING!"=="true" (echo [DEBUG] SYS_TYPE: !SYS_TYPE!)
) else (
    if "!TESTING!"=="true" (echo [DEBUG] Attempting to use PROCESSOR_ARCHITECTURE environment value)
    set "SYS_TYPE=%PROCESSOR_ARCHITECTURE%"
    if "!TESTING!"=="true" (echo [DEBUG] SYS_TYPE: !SYS_TYPE!)
)

:: Get OS Version
 if "!TESTING!"=="true" (echo [DEBUG] Attempting to get OS Version)
 if "!WMIC_PRESENT!"=="true" (
     if "!TESTING!"=="true" (echo [DEBUG] Calling :GETWMICValue os Version value)
     call :GetWMICValue os Version value
     if "!TESTING!"=="true" (echo [DEBUG] Setting OS_VERSION_FULL to !RESULT!)
     set "OS_VERSION_FULL=!RESULT!"
 ) else (
     if "!TESTING!"=="true" (
        echo [DEBUG] Attempting to use 'ver' command
    )
    
    :: Get the VER command output
    for /f "tokens=*" %%A in ('ver') do (
        set "VER_OUTPUT=%%A"
    )

    if "!TESTING!"=="true" (
        echo [DEBUG] VER_OUTPUT: !VER_OUTPUT!
        echo [DEBUG] Getting OS_VERSION_FULL from VER_OUTPUT
    )

    :: Extract the version and build number from inside the brackets
    for /f "tokens=2 delims=[]" %%A in ("!VER_OUTPUT!") do (
        set "OS_VERSION_FULL=%%A"
    )
)

:: Remove the word "Version" if present
if "!TESTING!"=="true" (echo [DEBUG] Removing 'Version' from OS_VERSION_FULL)
set "OS_VERSION_FULL=!OS_VERSION_FULL:Version =!"
if "!TESTING!"=="true" (echo [DEBUG] OS_VERSION_FULL: !OS_VERSION_FULL!)

:: Split OS_VERSION_FULL on .
for /f "tokens=1,2,3 delims=." %%A in ('echo !OS_VERSION_FULL!') do (
    set "OS_MAJOR=%%A"
    set "OS_MINOR=%%B"
    set "OS_BUILD_NUMBER=%%C"
)

if "!TESTING!"=="true" (
    echo [DEBUG] OS_MAJOR: !OS_MAJOR!
    echo [DEBUG] OS_MINOR: !OS_MINOR!
    echo [DEBUG] OS_BUILD_NUMBER: !OS_BUILD_NUMBER!
)

set "OS_MAJOR_MINOR=!OS_MAJOR!.!OS_MINOR!"
if "!TESTING!"=="true" (echo [DEBUG] OS_MAJOR_MINOR: !OS_MAJOR!.!OS_MINOR!)

if "!OS_NAME!"=="Unknown" (
if !TESTING!=="true" (
    echo [DEBUG] Using Version number to get OS_NAME 
    echo [DEBUG] Getting OS_MAJOR, OS_MINOR, and OS_BUILD_NUMBER
)

    :: Use Version to map to friendly name
    if "!TESTING!"=="true" echo [DEBUG] Getting WIN_OS_NAME from version 
    if "!OS_MAJOR_MINOR!"=="4.00" set "OS_NAME=Windows 95"
    if "!OS_MAJOR_MINOR!"=="5.0" set "OS_NAME=Windows NT 4.0"
    if "!OS_MAJOR_MINOR!"=="4.10" set "OS_NAME=Windows 98"
    if "!OS_MAJOR_MINOR!"=="4.90" set "OS_NAME=Windows Me"
    if "!OS_MAJOR_MINOR!"=="5.0" set "OS_NAME=Windows 2000"
    if "!OS_MAJOR_MINOR!"=="5.1" set "OS_NAME=Windows XP"
    if "!OS_MAJOR_MINOR!"=="5.2" set "OS_NAME=Windows Server 2003 or Windows XP x64"
    if "!OS_MAJOR_MINOR!"=="6.0" (
        if "!OS_BUILD_NUMBER!"=="6002" set "OS_NAME=Windows Vista"
        if "!OS_BUILD_NUMBER!"=="6003" set "OS_NAME=Windows Server 2008"
    )
    if "!OS_MAJOR_MINOR!"=="6.1" set "OS_NAME=Windows 7 or Server 2008 R2"
    if "!OS_MAJOR_MINOR!"=="6.2" set "OS_NAME=Windows 8 or Server 2012"
    if "!OS_MAJOR_MINOR!"=="6.3" set "OS_NAME=Windows 8.1 or Server 2012 R2"
    if "!OS_MAJOR_MINOR!"=="10.0" (
        if "!OS_BUILD!" geq "22000" (
            set "OS_NAME=Windows 11"
        ) else (
            set "OS_NAME=Windows 10 or Server 2016/2019/2022"
        )
    )
)

:: Get Architecture
if "!TESTING!"=="true" (echo [DEBUG] Attempting to get OS Architecture)

if "!WMIC_PRESENT!"=="true" (    
    if "!TESTING!"=="true" (echo [DEBUG] Calling :GETWMICValue os OSArchitecture value)
    call :GetWMICValue os OSArchitecture value
    if "!TESTING!"=="true" (echo [DEBUG] Setting OS_ARCH: !RESULT!)
    set "OS_ARCH=!RESULT!"
) 
if "!OS_ARCH!"=="Unknown" (
    if "!TESTING!"=="true" (echo [DEBUG] Attempting to use PROCESSOR_ARCHITEW6432 environment value)
    :: On 64-bit Windows launched under WoW64, PROCESSOR_ARCHITEW6432 is defined
    if defined PROCESSOR_ARCHITEW6432 (
        set "OS_ARCH=64-bit"
    ) else (
        :: Otherwise check %PROCESSOR_ARCHITECTURE
        if /i "%PROCESSOR_ARCHITECTURE%"=="AMD64" (
            set "OS_ARCH=64-bit"
        ) else if /i "%PROCESSOR_ARCHITECTURE%"=="IA64" (
            set "OS_ARCH=64-bit"
        ) else (
            :: Haven't found evidence of 64-bit architecture
            set "OS_ARCH=32-bit"
        ) 
    )
)

:: Get Domain / Workgroup
if "!TESTING!"=="true" (echo [DEBUG] Attempting to get Domain/Workgroup)
if "!WMIC_PRESENT!"=="true" (
    if "!TESTING!"=="true" (echo [DEBUG] Calling GetWMICValue computersystem Domain value)
    call :GetWMICValue computersystem Domain value
    if "!TESTING!"=="true" (echo [DEBUG] Setting DOMAIN: !RESULT!)
    set "DOMAIN=!RESULT!"
) else (
    if "!TESTING!"=="true" (echo [DEBUG] Setting DOMAIN: Unknown WMIC not available)
    set "DOMAIN=Unknown (WMIC not available)"
)

if "!TESTING!"=="true" (
    echo [*] Windows Product: !OS_NAME!
    echo [*] OS Version: !OS_VERSION_FULL!
    echo [*] OS Architecture: !OS_ARCH!
    echo [*] System Type: !SYS_TYPE!
    echo [*] Domain/Workgroup: !DOMAIN!
    echo [*] Effective Path: %PATH%    
)
echo [*] Windows Product: !OS_NAME! >> "%OUTFILE%"
echo [*] OS Version: !OS_VERSION_FULL! >> "%OUTFILE%"
echo [*] OS Architecture: !OS_ARCH! >> "%OUTFILE%"
echo [*] System Type: !SYS_TYPE! >> "%OUTFILE%"
echo [*] Domain/Workgroup: !DOMAIN! >> "%OUTFILE%"
echo [*] Effective Path: %PATH% >> "%OUTFILE%"

:: Check IPv4 Address
echo. >> "%OUTFILE%"
:: Clear any previous IPv4 address
if "!TESTING!"=="true" (echo [DEBUG] Setting IPv4_ADDR to empty)
set "IPv4_ADDR="

:: Look for a modern label (e.g. IPv4 or IPv6 Address)
if "!TESTING!"=="true" (echo [DEBUG] Checking for string "IPv4 Address" in ipconfig)
for /f "tokens=2 delims=:" %%A in ('
    ipconfig ^| findstr /C:"IPv4 Address"
') do (
    if "!TESTING!"=="true" (echo [DEBUG] Setting IPv4_ADDR to: "%%A")
    echo [DEBUG] Setting IPv4_ADDR to: "%%A"

    :: Trim leading spaces
    for /f "tokens=* delims= " %%B in ("%%A") do set "IPv4_ADDR=%%B"
    if "!TESTING!"=="true" (echo [DEBUG] Set IPv4_ADDR: !IPv4_ADDR!)
    echo [DEBUG] Set IPv4_ADDR: !IPv4_ADDR!
)
if "!TESTING!"=="true" (echo [DEBUG] Finished checking for "IPv4 Address" - IPv4_ADDR: !IPv4_ADDR!)
echo [DEBUG] Finished checking for "IPv4 Address" - IPv4_ADDR: !IPv4_ADDR!
:: if that failed (e.g. Windows XP), look for the old label
if not defined IPv4_ADDR (
    if "!TESTING!"=="true" (
        echo [DEBUG] IPv4_ADDR is not defined
        echo [DEBUG] Checking for string "IP Address"
    )
    for /f "tokens=2 delims=:" %%A in ('
        ipconfig ^| findstr /C:"IP Address"
    ') do (
        if "!TESTING!"=="true" (echo [DEBUG] Found String "IP Address": %%A)
        for /f "tokens=* delims= " %%B in ("%%A") do (
            if "!TESTING!"=="true" (echo [DEBUG] Setting IPv4_ADDR to: %%B)
            set "IPv4_ADDR=%%B"
            if "!TESTING!"=="true" (
                echo [DEBUG] IPv4_ADDR: !IPv4_ADDR!
                echo [DEBUG] Going to gotIPv4
            )
            goto :gotIPv4
        )
    )
)

:gotIPv4
if "!TESTING!"=="true" (echo [DEBUG] Inside gotIPv4 and IPv4_ADDR: !IPv4_ADDR!)
if defined IPv4_ADDR (
    if "!TESTING!"=="true" (
        echo [DEBUG] IPv4_ADDR is defined
        echo [*] Network Interfaces - IPv4:
        echo !IPv4_ADDR!
    )
    echo [*] Network Interfaces - IPv4: >> "%OUTFILE%"
    echo !IPv4_ADDR! >> "%OUTFILE%"
) else (
    if "!TESTING!"=="true" (echo [DEBUG] IPv4_ADDR is not defined
        echo [*] No IPv4 address found
    ) 
    echo [*] No IPv4 address found >> "%OUTFILE%"
)

:: Check IPv6 Address
echo. >> "%OUTFILE%"
echo [*] Network Interfaces - IPv6: >> %OUTFILE%
if "!TESTING!"=="true" (
    echo [*] Network Interfaces - IPv6:
    echo [DEBUG] Setting IPv6_FOUND to false
)
set "IPv6_FOUND=false"
if "!TESTING!"=="true" (echo [DEBUG] Set IPV6_FOUND: !IPv6_FOUND!)
for /f "tokens=2 delims=:" %%A in ('ipconfig ^| findstr /C:"IPv6 Address"') do (
    :: Strip leading spaces
    if "!TESTING!"=="true" (echo [DEBUG] Found IPv6 Address: %%A)
    for /f "tokens=* delims= " %%B in ("%%A%") do (
        set "addr=%%B"
        :: Skip link-local IPv6 addresses
        if /I "!addr:~0,4!"=="fe80" (
            if "!TESTING!"=="true" (echo [DEBUG] Skipping link-local address: !addr!)
        ) else (
            if "!TESTING!"=="true" (
                echo [DEBUG] Found non-link-local IPv6 address
                echo [*] !addr!
                echo [DEBUG] Setting IPv6_FOUND to true
            )
            echo [*] !addr! >> %OUTFILE%
            set "IPv6_FOUND=true"
        )
    )
)
if "!TESTING!"=="true" (
    echo [DEBUG] Done testing IPv6 addresses
    echo [DEBUG] IPv6_FOUND: !IPv6_FOUND!
)
if "!IPv6_FOUND!"=="false" (
    if "!TESTING!"=="true" (echo [*] No non-link-local IPv6 address detected)
    echo [*] No non-link-local IPv6 address detected >> "%OUTFILE%"
)

:: Anonymous Access Restrictions Check
if "!TESTING!"=="true" (echo [DEBUG] Checking LSA Restrict Anonymous configured)
echo. >> "%OUTFILE%"
:: Query LSA\restrictanonymous value from registry


:: Auto Update Registry Check
if "!TESTING!"=="true" (echo [DEBUG] Checking Auto Update Registry configuration)
echo. >> "%OUTFILE%"
:: Query AUOptions value from registry
for /f "tokens=3" %%A in ('reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v AUOptions 2^>nul') do (
    set "AU_VAL=%%A"
)
if "!TESTING!"=="true" (echo [DEBUG] Queried AUOptions value AU_VAL: !AU_VAL!)
:: Decode the value (if present)
if defined AU_VAL (
    if "!TESTING!"=="true" (echo [DEBUG] AU_VAL is defined: !AU_VAL!)
    if "!AU_VAL!"=="1" set "AU_DESC=Disabled"
    if "!AU_VAL!"=="2" set "AU_DESC=Notify before download"
    if "!AU_VAL!"=="3" set "AU_DESC=Notify before installation"
    if "!AU_VAL!"=="4" set "AU_DESC=Scheduled installation"
    if "!AU_VAL!"=="0" set "AU_DESC=Not configured"
    if "!TESTING!"=="true" (echo [DEBUG] Setting AU_DESC: !AU_DESC!)

    set /a AU_NUM=!AU_VAL! >nul 2>&1
    if !AU_NUM! EQU 4 (
        if "!TESTING!"=="true" (
            echo [+] Auto Update setting: !AU_VAL! - !AU_DESC!
        )
        echo [+] Auto Update setting: !AU_VAL! - !AU_DESC! >> "%OUTFILE%"
    ) else (
        if "!TESTING!"=="true" (
            echo [-] Auto Update setting: !AU_VAL! - !AU_DESC!
        )
        echo [-] Auto Update setting: !AU_VAL! - !AU_DESC! >> "%OUTFILE%"
    )
) else (
    if "!TESTING!"=="true" (
        echo [x] Windows AutoUpdate test failed - AUOptions registry value not found
    )
    echo [x] Windows AutoUpdate test failed - AUOptions registry value not found >> "%OUTFILE%"
)

:: BitLocker Status
if "!TESTING!"=="true" (
    echo [DEBUG] Checking for BitLocker status
    echo [DEBUG] Setting BL_STATUS to false
)
set "BL_STATUS=false"
echo. >> "%OUTFILE%"
if "!WMIC_PRESENT!"=="true" (
    if "!TESTING!"=="true" (echo [DEBUG] Checking BitLocker service with WMIC)
    for /f "skip=1 tokens=2 delims==" %%S in ('
        wmic service where "Name='BDESVC'" get State /value 2^>nul
    ') do set "raw=%%S"
    if "!TESTING!"=="true" (echo [DEBUG] WMIC svcState raw: !raw!)

    :: Strip leading/trailing spaces
    for /f "tokens=* delims= " %%T in ("!raw!") do set "svcState=%%T"
    if "!TESTING!"=="true" (echo [DEBUG] WMIC trimmed svcState: !svcState!)

    if /i "!svcState!"=="Running" (
        if "!TESTING!"=="true" (
            echo [+] BitLocker service is running
            echo [DEBUG] Setting BL_STATUS to true
        )
        set "BL_STATUS=true"
        echo [+] BitLocker service is running >> %OUTFILE%

        
    ) else if /i "!svcState!"=="Stopped" (
        if "!TESTING!"=="true" (echo [-] BitLocker service is installed but stopped)
        echo [-] BitLocker service is installed but stopped >> %OUTFILE%
    ) else (
        if "!TESTING!"=="true" (echo [-] BitLocker service not found)
        echo [-] BitLocker service not found >> %OUTFILE%
    )
) else (
    if "!TESTING!"=="true" (echo [DEBUG] WMIC not installed, testing with sc query)
    sc query BDESVC >nul 2>&1
    if "!TESTING!"=="true" (echo [DEBUG] sc query error leve: %errorlevel%)
    if %errorlevel%==0 (
        if "!TESTING!"=="true" (echo [+] BitLocker service BDESVC is installed)
        echo [+] BitLocker service BDESVC is installed >> %OUTFILE%
    ) else (
        echo [-] BitLocker service BDESVC not present >> %OUTFILE%
        if "!TESTING!"=="true" (
            echo [-] BitLocker service BDESVC not present
            echo [DEBUG] Testing if BitLocker management binary installed
        )
        set "BitLockerBinary=%windir%\System32\manage-bde.exe"
        if exist "%BLTOOL%" (
            echo [+] BitLocker tools present: %BitLockerBinary% >> %OUTFILE%
            if "!TESTING!"=="true" (echo [+] BitLocker tools present: %BitLockerBinary%)
        ) else (
            echo [-] BitLocker tools NOT found >> %OUTFILE%
            if "!TESTING!"=="true" (echo [-] BitLocker tools NOT found)
        )
    )
)

:: Enhancement - use manage-bde status to check individual drive volumes

:: #############################
:: SMB Configurations
:: #############################
echo. >> "%OUTFILE%"
if "!TESTING!"=="true" (echo [*] Checking SMB Configurations)

:: For Windows XP (OS version 5.2) and below, only SMBv1 is available
if !OS_MAJOR! LSS 5 (
    if "!TESTING!"=="true" echo [DEBUG] OS_MAJOR is less than 5; set SMBv1_ONLY to true
    set "SMBv1_ONLY=true"
) else if !OS_MAJOR! EQU 5 (
    if "!TESTING!"=="true" echo [DEBUG] OS_MAJOR equals 5
    if !OS_MINOR! LSS 3 (
        if "!TESTING!"=="true" echo [DEBUG] OS_MINOR is less than 3; set SMBv1_ONLY to true
        set "SMBv1_ONLY=true"
    ) else (
        if "!TESTING!"=="true" echo [DEBUG] OS_MAJOR is 2 or higher; set SMBv1_ONLY to false
        set "SMBv1_ONLY=false"
    )
) else (
    if "!TESTING!"=="true" echo [DEBUG] OS_MAJOR is higher than 5; set SMBv1_ONLY to false
    set "SMBv1_ONLY=false"
)

:: #############################
:: Check SMBv1 Client
if "!TESTING!"=="true" (
    echo [*] Checking if SMBv1 Client is installed and/or running
    echo [DEBUG] SMBv1_ONLY: !SMBv1_ONLY!
)

if "!SMBv1_ONLY!"=="true" (
    set "SMBv1_DRIVER_NAME=mrxsmb"
) else (
    set "SMBv1_DRIVER_NAME=mrxsmb10"
)

set "SMBv1_CLIENT=NotInstalled"
if "!WMIC_PRESENT!"=="true" (
    if "!TESTING!"=="true" (echo [DEBUG] Using wmic sysdriver where Name^="!SMBv1_DRIVER_NAME!" get State /value)
    for /f "skip=1 tokens=2 delims==" %%S in ('wmic sysdriver where Name^="!SMBv1_DRIVER_NAME!" get State /value 2^>nul') do (
        :: Trim white space
        for /f "tokens=* delims= " %%G in ("%%S") do (
            if "!TESTING!"=="true" (echo [DEBUG] Setting SMBv1_CLIENT to: %%G)
            set "SMBv1_CLIENT=%%G"
        )
    )
)

if "!SMBv1_CLIENT!"=="NotInstalled" (
    :: Use sc query to check if SMB client is installed
    if "!TESTING!"=="true" echo [DEBUG] Using sc query to check for SMBv1_CLIENT
    for /f "tokens=2 delims=:" %%A in ('sc query lanmanworkstation ^| findstr /i "STATE"') do (
        if "!TESTING!"=="true" echo [DEBUG] Found a value: %%A
        for /f "tokens=2" %%B in ("%%A") do (
            if "!TESTING!"=="true" (echo [DEBUG] Seting SMBv1_CLIENT to: %%B)
            set "SMBv1_CLIENT=%%B"
        )
    )
)

:: Report on SMBv1 Client
if "!TESTING!"=="true" (echo [DEBUG] SMBv1_CLIENT: !SMBv1_CLIENT!)

if /i "!SMBv1_CLIENT!"=="Running" (
    echo [-] SMBv1 Client driver is INSTALLED and RUNNING >> %OUTFILE%
    if "!TESTING!"=="true" (echo [-] SMBv1 Client driver is INSTALLED and RUNNING)
) else if /i "!SMBv1_CLIENT!"=="Stopped" (
    echo [-] SMBv1 Client driver is INSTALLED but STOPPED >> %OUTFILE%
    if "!TESTING!"=="true" (echo [-] SMBv1 Client driver is INSTALLED but STOPPED)
) else (
    echo [+] SMBv1 Client driver is NOT installed >> %OUTFILE%
    if "!TESTING!"=="true" (echo [+] SMBv1 Client driver is NOT installed)
)

:: #############################
:: Check SMB Server

if "!TESTING!"=="true" echo [DEBUG] Setting SMB_SERVER to NotInstalled
set "SMB_SERVER=NotInstalled"
if "!TESTING!"=="true" echo [DEBUG] SMB_SERVER: !SMB_SERVER!

if "!WMIC_PRESENT!"=="true" (
    if "!TESTING!"=="true" (echo [DEBUG] Using wmic to check for SMB_SERVER)
    for /f "skip=1 tokens=2 delims== " %%A in ('wmic service where name^="LanmanServer" get State /value 2^>nul') do (
        set "SMB_SERVER=%%A"
        if "!TESTING!"=="true" echo [DEBUG] Setting SMB server state to: %%A
    )
) else (
    if "!TESTING!"=="true" echo [DEBUG] Using sc query to check for SMB_SERVER
    for /f "tokens=2 delims=:" %%A in ('sc query lanmanserver ^| findstr /i "STATE"') do (
        if "!TESTING!"=="true" echo [DEBUG] Found a value: %%A
        for /f "tokens=2" %%B in ("%%A") do (
            if "!TESTING!"=="true" (echo [DEBUG] Setting SMB_SERVER to: %%B)
            set "SMB_SERVER=%%B"
        )
    )
)
if "!TESTING!"=="true" echo [DEBUG] SMB_SERVER: !SMB_SERVER!

if "!SMB_SERVER!"=="NotInstalled" (
    echo [+] SMB Server is NOT installed 
    if "!TESTING!"=="true" echo [+] SMB Server is NOT installed 
) else if "!SMBv1_ONLY!"=="true" (
    set "SMBv1_SERVER=!SMB_SERVER!"
    set "SMBv2_SERVER=NotInstalled"
) else if !OS_MAJOR! LSS 6 (
    if "!TESTING!"=="true" echo [DEBUG] OS Major version is 5 or less
    set "use_wmic_sysdriver=true"
) else if !OS_MAJOR! EQU 6 (
    if !OS_MINOR! LSS 2 (
        if "!TESTING!"=="true" echo [DEBUG] OS version is 6.1 or less
        set "use_wmic_sysdriver=true"
    ) else (
        if "!TESTING!"=="true" (
            echo [DEBUG] OS version is 6.2 or higher
            echo [DEBUG] Calling CheckSMBRegQuery
        )
        :: Can use reg query
        call :CheckSMBRegQuery SMB1 
        if "!TESTING!"=="true" echo [DEBUG] SMB1 Result: !RESULT!
        set "SMBv1_SERVER=!RESULT!"
        call :CheckSMBRegQuery SMB2
        if "!TESTING!"=="true" echo [DEBUG] SMB2 Result: !RESULT!
        set "SMBv2_SERVER=!RESULT!"
    )
)
if "!use_wmic_sysdriver!"=="true" (
    if "!TESTING!"=="true" echo [DEBUG] Using wmic sysdriver to check for SMB servers
    for /f "tokens=2 delims==" %%A in ('wmic sysdriver where Name^="srv" get State /value') do (
        set "SMBv1_SERVER=%%A"
    )
    for /f "tokens=2 delims==" %%A in ('wmic sysdriver where Name^="srv2" get State /value') do (
        set "SMBv2_SERVER=%%A"
    )
)

:: StartType Codes: 0 = Boot Start; 1 = System Start; 2 = Auto Start; 3 = Demand Start; 4 = Disabled
if "!SMBv1_SERVER!"=="NotInstalled" (
    echo [+] SMBv1 Server is NOT installed  >> %OUTFILE%
    if "!TESTING!"=="true" echo [+] SMBv1 Server is NOT installed
) else (
    echo [-] SMBv1 Server is INSTALLED and !SMBv1_SERVER! >> %OUTFILE%
    if "!TESTING!"=="true" echo [-] SMBv1 Server is INSTALLED and !SMBv1_SERVER!
    :: Get the start type, since it's present
    for /f "tokens=3" %%A in ('sc qc !SMBv1_DRIVER_NAME! ^| findstr /i "START_TYPE"') do set "startType=%%A"
    :: Strip any spaces
    set "startType=!startType: =!"
    if "!TESTING!"=="true" echo [DEBUG] SMBv1 startType: !startType!
    if "!startType!"=="4" (
        if "!TESTING!"=="true" (echo [+] SMBv1 server driver START_TYPE is !startType! - DISABLED)
        echo [+] SMBv1 server driver START_TYPE is !startType! - Disabled >> "%OUTFILE%"
    ) else if "!startType!"=="3" (
        if "!TESTING!"=="true" (echo [-] SMBv1 server driver START_TYPE is !startType! - Manual Start)
        echo [-] SMBv1 server driver START_TYPE is !startType! - Manual Start >> %OUTFILE%"
    ) else if "!startType!"=="2" (
        if "!TESTING!"=="true" (echo [-] SMBv1 server driver START_TYPE is !START_TYPE! - Auto Start)
        echo [-] SMBv1 server driver START_TYPE is !startType! - Auto Start >> "%OUTFILE%"
    ) else if "!startType!"=="1" (
        if "!TESTING!"=="true" (echo [-] SMBv1 server driver START_TYPE is !startType! - System Start)
        echo [-] SMBv1 server driver START_TYPE is !startType! - System Start >> "%OUTFILE%"
    )
)

if "!SMBv2_SERVER!"=="NotInstalled" (
    echo [+] SMBv2 Server is NOT installed  >> %OUTFILE%
    if "!TESTING!"=="true" echo [+] SMBv2 Server is NOT installed
) else (
    echo [-] SMBv2 Server is INSTALLED and !SMBv1_SERVER! >> %OUTFILE%
    if "!TESTING!"=="true" echo [-] SMBv2 Server is INSTALLED and !SMBv1_SERVER!
    :: Get the start type, since it's present
    for /f "tokens=3" %%A in ('sc qc !SMBv1_DRIVER_NAME! ^| findstr /i "START_TYPE"') do set "startType=%%A"
    :: Strip any spaces
    set "startType=!startType: =!"
    if "!TESTING!"=="true" echo [DEBUG] SMBv2 startType: !startType!
    if "!startType!"=="4" (
        if "!TESTING!"=="true" (echo [+] SMBv2 server driver START_TYPE is !startType! - DISABLED)
        echo [+] SMBv2 server driver START_TYPE is !startType! - Disabled >> "%OUTFILE%"
    ) else if "!startType!"=="3" (
        if "!TESTING!"=="true" (echo [-] SMBv2 server driver START_TYPE is !startType! - Manual Start)
        echo [-] SMBv2 server driver START_TYPE is !startType! - Manual Start >> %OUTFILE%"
    ) else if "!startType!"=="2" (
        if "!TESTING!"=="true" (echo [-] SMBv2 server driver START_TYPE is !startType! - Auto Start)
        echo [-] SMBv2 server driver START_TYPE is !startType! - Auto Start >> "%OUTFILE%"
    ) else if "!startType!"=="1" (
        if "!TESTING!"=="true" (echo [-] SMBv2 server driver START_TYPE is !startType! - System Start)
        echo [-] SMBv2 server driver START_TYPE is !startType! - System Start >> "%OUTFILE%"
    )
)

:: #############################
:: Local Administrator Accounts
if "!TESTING!"=="true" echo [DEBUG] Checkign Local Administrator Accounts
set "foundSeparator=false"
set /a numAdmins=0
set "adminList="
if "!TESTING!"=="true" (
    echo [DEBUG] foundSeparator: !foundSeparator!
    echo [DEBUG] numAdmins: !numAdmins!
    echo [DEBUG] adminList: !adminList!
)

:: Loop through each line of the net localgroup output
for /f "tokens=* delims=" %%L in ('net localgroup Administrators') do (
    if "!TESTING!"=="true" (
        echo [DEBUG] Checking line in net localgroup output
        echo %%L
    )
    set "line=%%L"
    if "!foundSeparator!"=="false" (
        :: Look for dashed separator line
        if "!line:~0,4!"=="----" (
            if "!TESTING!"=="true" echo [DEBUG] Found the separator line 
            set "foundSeparator=true"
            if "!TESTING!"=="true" echo [DEBUG] foundSeparator: !foundSeparator!
        )
    ) else (
        :: Stop if the success footer is seen
        if /i "!line!"=="The command completed successfully." goto :reportLocalAdmins

        :: Count any non-blank member line
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

:reportLocalAdmins
if "!TESTING!"=="true" (
    echo [DEBUG] foundSeparator: !foundSeparator!
    echo [DEBUG] numAdmins: !numAdmins!
    echo [DEBUG] adminList: !adminList!
)
if !numAdmins! GTR 1 (
    if "!TESTING!"=="true" ( echo [-] More than one account is in local Administrators group: %numAdmins%)
    echo [-] More than one account is in local Administrators group: %numAdmins% >> "%OUTFILE%"
) else (
    if "!TESTING!"=="true" ( echo [+] One account in local Administrators group )
    echo [+] One account in local Administrators group >> "%OUTFILE%"
)
if "!TESTING!"=="true" ( echo [*] Administrator Account Groups: !adminList!)
echo [*] Administrator Accounts: !adminList! >> "%OUTFILE%"

:: #############################
:: Check AlwaysInstallElevated Privileges
if "!CheckAlwaysInstallElevatedEnabled!"=="true" (
    if "!TESTING!"=="true" ( echo [DEBUG] Calling :CheckAlwaysInstallElevated)
    call :CheckAlwaysInstallElevated
    if "!TESTING!"=="true" ( echo [DEBUG] Returned from :CheckAlwaysInstallElevated)
) else (
if "!TESTING!"=="true" ( echo [DEBUG] CheckAlwaysInstallElevatedEnabled : !CheckAlwaysInstallElevatedEnabled!)
)

:: #############################
:: Check RestrictAnonymous Configuration
if "!CheckRestrictAnonymousEnabled!"=="true" (
    if "!TESTING!"=="true" ( echo [DEBUG] Calling :CheckRestrictAnonymous)
    call :CheckRestrictAnonymous
    if "!TESTING!"=="true" ( echo [DEBUG] Returned from :CheckRestrictAnonymous)
) else (
    if "!TESTING!"=="true" ( echo [DEBUG] CheckRestrictAnonymousEnabled: !CheckRestrictAnonymousEnabled!)
)

:: #############################
:: Check CachedLogonsCount Configuration
if "!CheckCachedLogonsEnabled!"=="true" (
    if "!TESTING!"=="true" ( echo [DEBUG] Calling :CheckCachedLogons)
    call :CheckCachedLogons
    if "!TESTING!"=="true" ( echo [DEBUG] Returned from :CheckCachedLogons)
) else (
    if "!TESTING!"=="true" ( echo [DEBUG] CheckCachedLogonsEnabled: !CheckCachedLogonsEnabled!)
)
:: #############################
:: Check RestrictRemoteClients Configuration
if "!CheckRestrictRemoteClientsEnabled!"=="true" (
    if "!TESTING!"=="true" ( echo [DEBUG] Calling :CheckRestrictRemoteClients)
    call :CheckRestrictRemoteClients
    if "!TESTING!"=="true" ( echo [DEBUG] Returned from :CheckRestrictRemoteClients)
) else (
    if "!TESTING!"=="true" ( echo [DEBUG] CheckRestrictRemoteClientsEnabled: !CheckRestrictRemoteClientsEnabled!)
)
:: #############################
:: Check if Windows Script Host Enabled
if "!CheckWindowsScriptHostEnabled!"=="true" (
    if "!TESTING!"=="true" ( echo [DEBUG] Calling :CheckWindowsScriptHost)
    call :CheckWindowsScriptHost
    if "!TESTING!"=="true" ( echo [DEBUG] Returned from :CheckWindowsScriptHost)
) else (
    if "!TESTING!"=="true" ( echo [DEBUG] CheckWindowsScriptHostEnabled: !CheckWindowsScriptHostEnabled!)
)
:: #############################
:: Check NTLM Session Security
if "!CheckNTLMSessionSecEnabled!"=="true" (
    if "!TESTING!"=="true" ( echo [DEBUG] Calling :CheckNTLMSessionSec)
    call :CheckNTLMSessionSec
    if "!TESTING!"=="true" ( echo [DEBUG] Returned from :CheckNTLMSessionSec)
) else (
    if "!TESTING!"=="true" ( echo [DEBUG] CheckNTLMSessionSecEnabled: !CheckNTLMSessionSecEnabled!)
)
:: #############################
:: Check LANMAN
if "!CheckLanmanEnabled!"=="true" (
    if "!TESTING!"=="true" ( echo [DEBUG] Calling :CheckLanman)
    call :CheckLanman
    if "!TESTING!"=="true" ( echo [DEBUG] Returned from :CheckLanman)
) else (
    if "!TESTING!"=="true" ( echo [DEBUG] CheckLanmanEnabled: !CheckLanmanEnabled!)
)

:: #############################
:: Check RDP Deny
if "!CheckRDPDenyEnabled!"=="true" (
    if "!TESTING!"=="true" ( echo [DEBUG] Calling :CheckRDPDeny)
    call :CheckRDPDeny
    if "!TESTING!"=="true" ( echo [DEBUG] Returned from :CheckRDPDeny)
) else (
    if "!TESTING!"=="true" ( echo [DEBUG] CheckRDPDenyEnabled: !CheckRDPDenyEnabled!)
)
:: #############################
:: Check WDigest Credential Storing
if "!CheckWDigestEnabled!"=="true" (
    if "!TESTING!"=="true" ( echo [DEBUG] Calling :CheckWDigest)
    call :CheckWDigest
    if "!TESTING!"=="true" ( echo [DEBUG] Returned from :CheckWDigest)
) else (
    if "!TESTING!"=="true" ( echo [DEBUG] CheckWDigestEnabled: !CheckWDigestEnabled!)
)
:: #############################
:: Check Interactive Login
if "!CheckInteractiveLoginEnabled!"=="true" (
    if "!TESTING!"=="true" ( echo [DEBUG] Calling :CheckInteractiveLogin)
    call :CheckInteractiveLogin
    if "!TESTING!"=="true" ( echo [DEBUG] Returned from :CheckInteractiveLogin)
) else (
    if "!TESTING!"=="true" ( echo [DEBUG] CheckInteractiveLoginEnabled: !CheckInteractiveLoginEnabled!)
)
:: #############################
:: Check GPO Re-Processing Policy
if "!CheckGPOProcessingEnabled!"=="true" (
if "!TESTING!"=="true" ( echo [DEBUG] Calling :CheckGPOProcessing)
call :CheckGPOProcessing
) else (
    if "!TESTING!"=="true" ( echo [DEBUG] CheckGPOProcessingEnabled: !CheckGPOProcessingEnabled!)
)
:: #############################
:: Check WINSConfig
:: Requires WMIC for check
if "!CheckWINSConfigEnabled!"=="true" (
    if "!TESTING!"=="true" ( echo [DEBUG] [DEBUG] WMIC_PRESENT: !WMIC_PRESENT!)
    if "!WMIC_PRESENT!"=="true" (
        if "!TESTING!"=="true" ( echo [DEBUG] Calling :CheckWINSConfig)
        call :CheckWINSConfig
        if "!TESTING!"=="true" ( echo [DEBUG] Returned from :CheckWINSConfig)
    ) else (
        if "!TESTING!"=="true" ( echo [*] WINSConfig check requires WMIC to be present)
        echo [*] WINSConfig check requires WMIC to be present >> %OUTFILE%
    )
) else (
    if "!TESTING!"=="true" ( echo [DEBUG] CheckWINSConfigEnabled: !CheckWINSConfigEnabled!)
)

:: #############################
:: Print Document Footer
:: #############################

if "!TESTING!"=="true" (echo [DEBUG] Printing document footer)
:: Get the current date and time components

for /f "tokens=2 delims==" %%i in ('"wmic os get localdatetime /value"') do set dt=%%i
if "!TESTING!"=="true" (
    echo [DEBUG] dt: !dt!
    echo [DEBUG] Setting yyyy: %dt:~0,4%
)
set "yyyy=%dt:~0,4%"
if "!TESTING!"=="true" (echo [DEBUG] Setting dd: %dt:~6,2%)
set "dd=%dt:~6,2%"
if "!TESTING!"=="true" (echo [DEBUG] Setting MONTH: %dt:~4,2%)
set "MONTH=%dt:~4,2%"
if "!TESTING!"=="true" (echo [DEBUG] Setting HH: %dt:~8,2%)
set "HH=%dt:~8,2%"
if "!TESTING!"=="true" (echo [DEBUG] Setting mm: %dt:~10,2%)
set "mm=%dt:~10,2%"
if "!TESTING!"=="true" (echo [DEBUG] Setting ss: %dt:~12,2%)
set "ss=%dt:~12,2%"
:: Format as MM/dd/yyyy HH:mm:ss K for readable date in report
if "!TESTING!"=="true" (echo [DEBUG] Setting timezone: %dt:~21,3%)
set "timezone=UTC%dt:~21,3%"
set "READABLE_DATE=%MONTH%/%dd%/%yyyy% %HH%:%mm%:%ss% %timezone%"

if "!TESTING!"=="true" (
    echo ##########################
    echo # %SCRIPTNAME% completed
    echo # Stop Time: %READABLE_DATE%
)
echo. >> "%OUTFILE%"
echo ########################## >> "%OUTFILE%"
echo # %SCRIPTNAME% completed >> "%OUTFILE%"
echo # Stop Time: %READABLE_DATE% >> "%OUTFILE%"
echo # Report saved to: %OUTFILE%
if "!TESTING!"=="true" (echo ##########################)
echo ########################## >> "%OUTFILE%"

:: Print Cutsec Footer
if "!TESTING!"=="true" (echo [DEBUG] Checking if CutSec Footer should be printed)
if "%CUTSEC_FOOTER%"=="true" (
    if "!TESTING!"=="true" (echo [DEBUG] Calling :PrintCutsecFooter)
    call :PrintCutsecFooter
    if "!TESTING!"=="true" (echo [DEBUG] Returned from :PrintCutsecFooter)
)
if "!TESTING!"=="true" (echo [DEBUG] Finished - exiting script)
:: If script started by double-clicking file, then pause so cmd window stays open
set "CMDLINE="
for /f "delims=" %%i in ('cmd /c "echo !cmdcmdline!"') do set "CMDLINE=%%i"
if "!TESTING!"=="true" (echo [DEBUG] CMDLINE: !CMDLINE!)
if "!CMDLINE:~0,3!"=="/c """ (
    if "!TESTING!"=="true" (
        echo [DEBUG] Script was launched by double-click. Pausing...
        pause
    )
)
:: End the script safely
goto :eof 


:: #############################
:: Helper Functions
:: #############################

:: Get date formatted for either report or filename
:: Call with :GetDate [readable/filename]
:GetDate
@echo off 
setlocal enabledelayedexpansion
if "!TESTING!"=="true" ( echo [DEBUG] Entered :GetDate)
set "dateFormat=%~1"
if "!TESTING!"=="true" ( echo [DEBUG] Entered :GetDate with format: !dateFormat!)

set "READABLE_DATE="
if "!WMIC_PRESENT!"=="true" (
    if "!TESTING!"=="true" ( echo [DEBUG] Calling :GetWMICValue os localdatetime value)
    call :GetWMICValue os localdatetime value
    set dt=!RESULT!
    :: for /f "tokens=2 delims==" %%i in ('"wmic os get localdatetime /value"') do set dt=%%i
    if "!TESTING!"=="true" (
        echo [DEBUG] dt: !dt!
        echo [DEBUG] Setting yyyy: !dt:~0,4!
        echo [DEBUG] Setting dd: !dt:~6,2!
        echo [DEBUG] Setting MONTH: !dt:~4,2!
        echo [DEBUG] Setting HH: !dt:~8,2!
        echo [DEBUG] Setting mm: !dt:~10,2!
        echo [DEBUG] Setting ss: !dt:~12,2!
        echo [DEBUG] Setting timezone: UTC!dt:~21,3!
    )
    set "yyyy=!dt:~0,4!"
    set "dd=!dt:~6,2!"
    set "MONTH=!dt:~4,2!"
    set "HH=!dt:~8,2!"
    set "mm=!dt:~10,2!"
    set "ss=!dt:~12,2!"
    set "timezone=UTC!dt:~21,3!"
    if "!dateFormat!"=="readable" (
        if "!TESTING!"=="true" ( echo [DEBUG] Setting DATE_OUTPUT to READABLE_DATE: !MONTH!/!dd!/!yyyy! !HH!:!mm!:!ss! !timezone!)
        set "DATE_OUTPUT=!MONTH!/!dd!/!yyyy! !HH!:!mm!:!ss! !timezone!"
        goto get_date_done
    ) else if "!dateFormat!"=="filename" (
        if "!TESTING!"=="true" ( echo [DEBUG] Setting DATE_OUTPUT to FILENAME_DATE: !yyyy!-!MONTH!-!dd!_!HH!!mm!!ss!)
        set "DATE_OUTPUT=!yyyy!-!MONTH!-!dd!_!HH!!mm!!ss!"
        goto get_date_done
    ) else (
        if "!TESTING!"=="true" ( echo [DEBUG] Setting DATE_OUTPUT to FALLBACK_DATE: !yyyy!-!mm!-!dd!)
        set "DATE_OUTPUT=!yyyy!-!mm!-!dd!"
        goto get_date_done
    )
) else (
    :: Parsing DATE and TIME depends on locale settings
    set "RAW_DATE=%DATE%"
    set "RAW_TIME=%TIME%"
    if "!TESTING!"=="true" (
        echo [DEBUG] RAW_DATE: !RAW_DATE!
        echo [DEBUG] RAW_TIME: !RAW_TIME!
    )
    if "!dateFormat!"=="readable" (
        :: We'll just use the raw output for the readable date
        if "!TESTING!"=="true" ( echo [DEBUG] Setting DATE_OUTPUT to READABLE_DATE: !RAW_DATE! !RAW_TIME!)
        set "DATE_OUTPUT=!RAW_DATE! !RAW_TIME!"
        goto get_date_done
    ) else (
        :: We'll just extract the digits from the date, it'll probably be ddmmyyyy, yyyymmdd, or mmddyyyy
        set "DATE_OUTPUT="
        for /l %%I in (0,1,31) do (
            set "char=!RAW_DATE:~%%I,1!"
            if "!char!"=="" goto get_date_done
            for %%D in (0 1 2 3 4 5 6 7 8 9) do if "!char!"=="%%D" set "DATE_OUTPUT=!DATE_OUTPUT!!char!"
        )
        if "!TESTING!"=="true" ( echo [DEBUG] Setting DATE_OUTPUT to FILENAME_DATE: !DATE_OUTPUT!)
        goto get_date_done
    )
)

:get_date_done
if "!TESTING!"=="true" (echo [DEBUG] Returning: !DATE_OUTPUT!)
endlocal & set "RESULT=!DATE_OUTPUT!"
goto :eof 

:: #############################
:: Check for Admin RIghts
:CheckAdminRights
@echo off 
setlocal enabledelayedexpansion

if "!TESTING!"=="true" (
    echo [DEBUG] Called :CheckAdminRights
    echo [DEBUG] Checking Administrator permissions using whoami
)

whoami /groups | findstr /i "S-1-5-32-544" >nul
if %errorlevel%==0 (
    if "!TESTING!"=="true" ( echo [+] Script running as Administrator)
    echo [+] Script running as Administrator >> "%OUTFILE%"
) else (
    if "!TESTING!"=="true" ( echo [x] Script NOT running as Administrator)
    echo [x] Script NOT running as Administrator >> "%OUTFILE%"
)

endlocal & goto :eof 

:: #############################
:: Sanitize Value
:SanitizeValue
setlocal enabledelayedexpansion
set "val=%~1"
if "!TESTING!"=="true" ( echo [DEBUG] Called :SanitizeValue !val!)

:: Trim leading/trailing spaces
for /f "tokens=* delims=" %%A in ("!val!") do set "val=%%A"

:: Strip outer single quotes if present
if "!val:~0,1!"=="'" if "!val:~-1!"=="'" set "val=!val:~1,-1!"

:: Remove stray CR/LF by re-tokenizing once more
for /f "tokens=* delims=" %%# in ("!val!") do set "val=%%#"

endlocal & set "CLEANED_VALUE=%val%"
if "!TESTING!"=="true" ( echo [DEBUG] Finished :SanitizedValue CLEANED_VALUE: !CLEANED_VALUE!)
goto :eof 

:: #############################
:: Helper Functions - Printing Report
:: #############################

:: Print Section Header
:PrtSectionHeader
if "!TESTING!"=="true" (
    echo ##########################
    echo # %*
    echo ##########################
)
>> "%OUTFILE%" echo.
>> "%OUTFILE%" echo ##########################
>> "%OUTFILE%" echo # %*
>> "%OUTFILE%" echo ##########################
goto :eof

:: #############################
:: Print Cutsec Footer
:PrintCutsecFooter
setlocal enabledelayedexpansion

if "!TESTING!"=="true" (
    echo [DEBUG] Called :PrintCutsecFooter
    echo ##########################
    echo # CHAPS Audit Script: !SCRIPTNAME! !SCRIPTVERSION!
    echo # Brought to you by Cutaway Security, LLC
    echo # For assessment and auditing help, contact info [@] cutawaysecurity.com
    echo # For script help, contact dev [@] cutawaysecurity.com
    echo ##########################
)
echo. >> "%OUTFILE%"
echo ########################## >> "%OUTFILE%"
echo # CHAPS Audit Script: !SCRIPTNAME! !SCRIPTVERSION! >> "!OUTFILE!"
echo # Brought to you by Cutaway Security, LLC >> "!OUTFILE!"
echo # For assessment and auditing help, contact info [@] cutawaysecurity.com >> "!OUTFILE!"
echo # For script help, contact dev [@] cutawaysecurity.com >> "!OUTFILE!"
echo ########################## >> "!OUTFILE!"
if "!TESTING!"=="true" (echo [DEBUG] Finished :PrintCutsecFooter)
goto :eof 

:: #############################
:: Helper Functions - WMIC
:: #############################
:CheckWMICAvailable
@echo off

if "!TESTING!"=="true" ( echo [DEBUG] Called :CheckWMICAvailable)
where wmic >nul 2>&1
if %errorlevel%==0 (
    if "!TESTING!"=="true" ( echo [DEBUG] Setting WMIC_PRESENT to true)
    set "WMIC_PRESENT=true"
) else (
    if "!TESTING!"=="true" ( echo [DEBUG] Setting WMIC_PRESENT to false)
    set "WMIC_PRESENT=false"
)
if "!TESTING!"=="true" (echo [DEBUG] WMIC_PRESENT: !WMIC_PRESENT!)
goto :eof

:: Set WMIC_EXE based on 32- or 64-bit Windows
:: #############################
:SetWMICExe
@echo off

if "!TESTING!"=="true" ( echo [DEBUG] Called :SetWMICExe)

if exist "%windir%\sysnative\wbem\wmic.exe" (
    if "!TESTING!"=="true" (echo [DEBUG] Setting WMIC_EXE for 32-bit)
    set "WMIC_EXE=%windir%\sysnative\wbem\wmic.exe"
) else if exist "%windir%\system32\wbem\wmic.exe" (
    if "!TESTING!"=="true" (echo [DEBUG] Setting WMIC_EXE for 64-bit)
    set "WMIC_EXE=%windir%\system32\wbem\wmic.exe"
)
if "!TESTING!"=="true" (echo [DEBUG] Set WMIC_EXE: !WMIC_EXE!)
goto :eof

:: Get WMIC Value 
:: #############################
:GetWMICValue
@echo off
setlocal enabledelayedexpansion

:: Cache parameters to local variables
set "WMIC_CLASS=%~1"
set "WMIC_PROPERTY=%~2"
set "WMIC_RESULT_TYPE=%~3"
set "WMIC_FILTER_KEY=%~4"
set "WMIC_FILTER_VALUE=%~5"
if "!TESTING!"=="true" (
    echo [DEBUG] Called GetWMICValue
    echo [DEBUG] WMIC_CLASS: !WMIC_CLASS!
    echo [DEBUG] WMIC_PROPERTY: !WMIC_PROPERTY!
    echo [DEBUG] WMIC_RESULT_TYPE: !WMIC_RESULT_TYPE!
)

: Set Result Type
if "!WMIC_RESULT_TYPE!"=="value" ( 
    if "!TESTING!"=="true" ( echo [DEBUG] Setting WMIC_TYPE_TAG: value)
    set "WMIC_TYPE_TAG=value"
) else if "!WMIC_RESULT_TYPE!"=="list" (
    set "WMIC_TYPE_TAG=format:list"
) else ( set "WMIC_TYPE_TAG=")
if "!TESTING!"=="true" ( echo [DEBUG] WMIC_TYPE_TAG: !WMIC_TYPE_TAG!)

:: Build optional WHERE statement
set "WHERE_CLAUSE="
if defined WMIC_FILTER_KEY if defined WMIC_FILTER_VALUE (
    if "!TESTING!"=="true" (
        echo [DEBUG] WMIC_FILTER_KEY: !WMIC_FILTER_KEY!
        echo [DEBUG] WMIC_FILTER_VALUE: !WMIC_FILTER_VALUE!
    )
    set "WHERE_CLAUSE=where !WMIC_FILTER_KEY!='!WMIC_FILTER_VALUE!'"
)

if "!TESTING!"=="true" ( echo [DEBUG] Attempting: wmic !WMIC_CLASS! !WHERE_CLAUSE! get !WMIC_PROPERTY! ^/!WMIC_TYPE_TAG!)
for /f "tokens=2 delims==" %%L in ('"%WMIC_EXE%" !WMIC_CLASS! !WHERE_CLAUSE! get !WMIC_PROPERTY! ^/!WMIC_TYPE_TAG! 2^>nul') do (
    if "!TESTING!"=="true" ( echo [DEBUG] WMIC Result: %%L)
    endlocal & set "RESULT=%%L"
    goto wmic_returned
)

:: If we fell through, there was nothing
if "!TESTING!"=="true" ( echo [DEBUG] WMIC returned nothing)
endlocal & set "RESULT=Unknown"
goto wmic_returned

:wmic_returned
if "!TESTING!"=="true" ( echo [DEBUG] Calling :SanitizeValue "%RESULT%")
call :SanitizeValue "%RESULT%"
if "!TESTING!"=="true" ( echo [DEBUG] Returned to :GetWMICValue)
set "RESULT=%CLEANED_VALUE%"
if "!TESTING!"=="true" ( echo [DEBUG] Returning RESULT: !RESULT!)
goto :eof

:: #############################
:GetRegistryValue
:: %1 = registry path
:: %2 = value name
:: %3 = output variable name
setlocal enabledelayedexpansion
set "outval=0"

for /f "tokens=3" %%A in ('reg query "%~1" /v %2 2^>nul') do (
    set "outval=%%A"
)

endlocal & set "%~3=%outval%"
goto :eof

:: #############################
:: Helper Functions - Specific Checks
:: #############################

:: #############################
:: System Info Checks
:: #############################

:: #############################
:CheckSMBRegQuery
@echo off
setlocal EnableDelayedExpansion

set "v=%~1"
if "!TESTING!"=="true" (
    echo [DEBUG] Called CheckSMBRegQuery
    echo [DEBUG] v: !v!
    echo [DEBUG] Trying reg query "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "!v!"
)

for /f "skip=1 tokens=3" %%A in ('
  reg query "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "!v!" 2^>nul
') do set "SMB_VAL=%%A"

if "!SMB_VAL!"=="1" (
  echo [DEBUG] !v! SERVER protocol: ENABLED
  endlocal & set "RESULT=ENABLED"
) else if "%SMB1%"=="0" (
  echo [DEBUG] !v! SERVER protocol: DISABLED
  endlocal & set "RESULT=DISABLED"
) else (
  echo [DEBUG] !v! SERVER protocol: not set
  endlocal & set "RESULT="
)

if "!TESTING!"=="true" (echo [DEBUG] Returning RESULT: "!RESULT!")
goto :eof 

:: #############################
:: Check AlwaysInstallElevated settings (HKLM and HKCU)
:CheckAlwaysInstallElevated
if "!TESTING!"=="true" echo [DEBUG] Called CheckAlwaysInstallElevated

:: Initialize default values
set "HKLM_AIE=0"
set "HKCU_AIE=0"

if "!TESTING!"=="true" (
    echo [DEBUG] Default HKLM_AIE: !HKLM_AIE!
    echo [DEBUG] Default HKCU_AIE: !HKCU_AIE!
)

:: Check HKLM
if "!TESTING!"=="true" echo [DEBUG] Calling :GetRegistryValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" "AlwaysInstallElevated" HKLM_AIE
call :GetRegistryValue "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" "AlwaysInstallElevated" HKLM_AIE

:: Check HKCU
if "!TESTING!"=="true" echo [DEBUG] Calling :GetRegistryValue "HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer" "AlwaysInstallElevated" HKCU_AIE 
call :GetRegistryValue "HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer" "AlwaysInstallElevated" HKCU_AIE

if "!TESTING!"=="true" (
    echo [DEBUG] HKLM_AIE: !HKLM_AIE!
    echo [DEBUG] HKCU_AIE: !HKCU_AIE!
)

:: Remove 0x prefix if it esists
if "!TESTING!"=="true" (echo [DEBUG] Checking if 0x prefix exists)
echo !HKLM_AIE! | findstr /i "^0x" >nul
if !errorlevel! == 0 (
    if "!TESTING!"=="true" (echo [DEBUG] Stripping 0x prefix from HKLM)
    set "HKLM_AIE=!HKLM_AIE:0x=!"
)
echo !HKCU_AIE! | findstr /i "^0x" >nul
if !errorlevel! == 0 (
    if "!TESTING!"=="true" (echo [DEBUG] Stripping 0x prefix from HKCU)
    set "HKCU_AIE=!HKCU_AIE:0x=!"
)

if "!TESTING!"=="true" (
    echo [DEBUG] Normalized HKLM_AIE: !HKLM_AIE!
    echo [DEBUG] Normalized HKCU_AIE: !HKCU_AIE!
)

:: Now check values
if "!HKLM_AIE!"=="1" (
    if "!HKCU_AIE!"=="1" (
        echo [-] Users can install software as NT AUTHORITY\SYSTEM >> "%OUTFILE%"
        echo [-] AlwaysInstallElevated registry values ^(HKLM and HKCU^) = 1 >> "%OUTFILE%"
        if "!TESTING!"=="true" (
            echo [-] Users can install software as NT AUTHORITY\SYSTEM. ^(HKLM and HKCU^) = 1
            echo [-] AlwaysInstallElevated registry values ^(HKLM and HKCU^) = 1
        )
    ) else (
        goto :not_elevated
    )
) else (
    goto :not_elevated
)
goto :AEI_check_done

:not_elevated
echo [+] Users cannot install software as NT AUTHORITY\SYSTEM >> "%OUTFILE%"
echo [*] AlwaysInstallElevated Registry Values: ^(HKLM=!HKLM_AIE!, HKCU=!HKCU_AIE!^) >> "%OUTFILE%"
if "!TESTING!"=="true" (
    echo [+] Users cannot install software as NT AUTHORITY\SYSTEM
    echo [*] AlwaysInstallElevated Registry Values: ^(HKLM=!HKLM_AIE!, HKCU=!HKCU_AIE!^)
)
:AEI_check_done
if "!TESTING!"=="true" (echo [DEBUG] Completed :CheckAlwaysInstallElevated)
goto :eof 

:: #############################
:: Check Anonymous Access Restrictions settings
:CheckRestrictAnonymous
if "!TESTING!"=="true" echo [DEBUG] Called CheckRestrictAnonymous

:: Initialize default values
set "HKLM_AAR=0"

if "!TESTING!"=="true" (
    echo [DEBUG] Default HKLM_AIE: !HKLM_AAR!
)

:: Check HKLM
if "!TESTING!"=="true" echo [DEBUG] Calling :GetRegistryValue "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictAnonymous" HKLM_AAR
call :GetRegistryValue "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictAnonymous" HKLM_AAR

if "!TESTING!"=="true" (
    echo [DEBUG] HKLM_ARR: !HKLM_AAR!
)

:: Remove 0x prefix if it esists
if "!TESTING!"=="true" (echo [DEBUG] Checking if 0x prefix exists)
echo !HKLM_AAR! | findstr /i "^0x" >nul
if !errorlevel! == 0 (
    if "!TESTING!"=="true" (echo [DEBUG] Stripping 0x prefix from HKLM)
    set "HKLM_AAR=!HKLM_AAR:0x=!"
)

if "!TESTING!"=="true" (
    echo [DEBUG] Normalized HKLM_AAR: !HKLM_AAR!
)

:: Now check values
if "!HKLM_AAR!"=="0" (
    echo [-] RestrictAnonymous registry key is not configured >> "%OUTFILE%"
    if "!TESTING!"=="true" (
        echo [-] RestrictAnonymous registry key is not configured
        )
) else (
    goto :AAR_configured
)
goto :AAR_check_done

:AAR_configured
echo [+] RestrictAnonymous registry key is configured >> "%OUTFILE%"
echo [*] LSA.RestrictAnonymous Registry HKLM Value: !HKLM_AAR! >> "%OUTFILE%"
if "!TESTING!"=="true" (
    echo [+] RestrictAnonymous registry key is configured
    echo [*] LSA.RestrictAnonymous Registry HKLM Value: !HKLM_AAR!
)
:AAR_check_done
if "!TESTING!"=="true" (echo [DEBUG] Completed :CheckRestrictAnonymous)
goto :eof 

:: #############################
:: Check Cached Logon settings
:CheckCachedLogons
if "!TESTING!"=="true" echo [DEBUG] Called CheckCachedLogons

:: Initialize default values
set "HKLM_CLO=0"

if "!TESTING!"=="true" (
    echo [DEBUG] Default HKLM_CLO !HKLM_CLO!
)

:: Check HKLM
if "!TESTING!"=="true" echo [DEBUG] Calling :GetRegistryValue "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" "CachedLogonsCount" HKLM_CLO
call :GetRegistryValue "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" "CachedLogonsCount" HKLM_CLO

if "!TESTING!"=="true" (
    echo [DEBUG] HKLM_CLO: !HKLM_CLO!
)

:: Now check values
if not defined HKLM_CLO (
    echo [*] CachedLogonsCount is not configured >> "%OUTFILE%"
    if "!TESTING!"=="true" (
        echo [*] CachedLogonsCount is not configured
        )
) else (
    if "!TESTING!"=="true" (
        echo [DEBUG] Converting HKLM_CLO to numeric
    )
    set /a HKLM_CLO_NUM=!HKLM_CLO!
    if "!TESTING!"=="true" (
        echo [DEBUG] Converted HKLM_CLO to numeric
    )
    if !HKLM_CLO_NUM! LSS 2 (
        echo [+] CachedLogonsCount is set to: !HKLM_CLO_NUM! >> "%OUTFILE%"
        if "!TESTING!"=="true" (
            echo [+] CachedLogonsCount is set to: !HKLM_CLO_NUM!
        )
        goto :CLO_check_done
    ) else (
        echo [-] CachedLogonsCount is set to: !HKLM_CLO_NUM! >> "%OUTFILE%"
        if "!TESTING!"=="true" (
            echo [-] CachedLogonsCount is set to !HKLM_CLO_NUM!
        )
        goto :CLO_check_done
    )
)

:CLO_check_done
if "!TESTING!"=="true" (echo [DEBUG] Completed :CheckCachedLogons)
goto :eof 

:: #############################
:: Check RPC RestrictRemoteClients Configuration
:CheckRestrictRemoteClients
if "!TESTING!"=="true" echo [DEBUG] Called CheckRestrictRemoteClients

:: Initialize default values
set "HKLM_RRC=0"

if "!TESTING!"=="true" (
    echo [DEBUG] Default HKLM_RRC !HKLM_RRC!
)

:: Check HKLM
if "!TESTING!"=="true" echo [DEBUG] Calling :GetRegistryValue "HKLM\Software\Policies\Microsoft\Windows NT\Rpc" "RestrictRemoteClients" HKLM_RRC
call :GetRegistryValue "HKLM\Software\Policies\Microsoft\Windows NT\Rpc" "RestrictRemoteClients" HKLM_RRC

if "!TESTING!"=="true" (
    echo [DEBUG] HKLM_RRC: !HKLM_RRC!
)

:: Remove 0x prefix if it esists
if "!TESTING!"=="true" (echo [DEBUG] Checking if 0x prefix exists)
echo !HKLM_RRC! | findstr /i "^0x" >nul
if !errorlevel! == 0 (
    if "!TESTING!"=="true" (echo [DEBUG] Stripping 0x prefix from HKLM)
    set "HKLM_RRC=!HKLM_RRC:0x=!"
)

if "!TESTING!"=="true" (
    echo [DEBUG] Normalized HKLM_RRC: !HKLM_RRC!
)
:: Now check values
if not defined HKLM_RRC (
    echo [-] RPC RestrictRemoteClients is not configured >> "%OUTFILE%"
    if "!TESTING!"=="true" (
        echo [-] RPC RestrictRemoteClients is not configured
        )
    goto :RRC_check_done
) else if "!HKLM_RRC!"=="1" (
    echo [+] RPC RestrictRemoteClients is set to: !HKLM_RRC! - Enabled >> "%OUTFILE%"
    if "!TESTING!"=="true" (
        echo [+] RPC RestrictRemoteClients is set to: !HKLM_RRC! - Authenticated
    )
    goto :RRC_check_done
) else if "!HKLM_RRC!"=="2" (
    echo [-] RPC RestrictRemoteClients is set to: !HKLM_RRC! - Authenticated without exceptions >> "%OUTFILE%"
    if "!TESTING!"=="true" (
        echo [-] RPC RestrictRemoteClients is set to: !HKLM_RRC! - Authenticated without exceptions
    )
    goto :RRC_check_done
) else (
    echo [-] RPC RestrictRemoteClients is not enabled ^(invalid setting^): !HKLM_RRC!  >> "%OUTFILE%"
    if "!TESTING!"=="true" (
        echo [-] RPC RestrictRemoteClients is not enabled ^(invalid setting^): !HKLM_RRC! 
        )
    goto :RRC_check_done
)

:RRC_check_done
if "!TESTING!"=="true" (echo [DEBUG] Completed :CheckRestrictRemoteClients)
goto :eof

:: #############################
:: Check Windows Script Host Configuration
:CheckWindowsScriptHost
if "!TESTING!"=="true" echo [DEBUG] Called CheckWindowsScriptHost

:: Initialize default value
set "HKLM_WSH=0"

if "!TESTING!"=="true" (
    echo [DEBUG] Default HKLM_WSH: !HKLM_WSH!
)

:: Check HKLM
if "!TESTING!"=="true" echo [DEBUG] Calling :GetRegistryValue "HKLM\Software\Microsoft\Windows Script Host\Settings" "Enabled" HKLM_WSH
call :GetRegistryValue "HKLM\Software\Microsoft\Windows Script Host\Settings" "Enabled" HKLM_WSH


if "!TESTING!"=="true" (
    echo [DEBUG] HKLM_WSH: !HKLM_WSH!
    echo [DEBUG] HKCU_WSH: !HKCU_WSH!
)

:: Remove 0x prefix if it esists
if "!TESTING!"=="true" (echo [DEBUG] Checking if 0x prefix exists)
echo !HKLM_WSH! | findstr /i "^0x" >nul
if !errorlevel! == 0 (
    if "!TESTING!"=="true" (echo [DEBUG] Stripping 0x prefix from HKLM)
    set "HKLM_WSH=!HKLM_WSH:0x=!"
)

if "!TESTING!"=="true" (
    echo [DEBUG] Normalized HKLM_WSH: !HKLM_WSH!
)

:: Now check values
if "!HKLM_WSH!"=="1" (
    echo [-] Windows Script Host is Enabled: HKLM = !HKLM_WSH! >> "%OUTFILE%"
    if "!TESTING!"=="true" (
        echo [-] Windows Script Host is Enabled: HKLM = !HKLM_WSH!
    )
) else (
    echo [+] Windows Script Host is Not Enabled >> "%OUTFILE%"
    if "!TESTING!"=="true" (
        echo [+] Windows Script Host is Not Enabled
    )
)

if "!TESTING!"=="true" (echo [DEBUG] Completed :CheckWindowsScriptHost)
goto :eof 

:: #############################
:: Check NTLMv2 Session Security Configuration
:CheckNTLMSessionSec
if "!TESTING!"=="true" (echo [DEBUG] Called CheckNTLMSessionSec)

:: Initialize default values
set "HKLM_NSS=0"

if "!TESTING!"=="true" (
    echo [DEBUG] Default HKLM_NSS: !HKLM_NSS!
)

:: Check Server Session Security
if "!TESTING!"=="true" echo [DEBUG] Calling :GetRegistryValue "HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0" "NtlmMinServerSec" HKLM_NSS
call :GetRegistryValue "HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0" "NtlmMinServerSec" HKLM_NSS

if "!TESTING!"=="true" (
    echo [DEBUG] HKLM_NSS: !HKLM_NSS!
)

:: Convert from Hex to Dec
if "!TESTING!"=="true" (echo [DEBUG] Checking if 0x prefix exists)
echo !HKLM_NSS! | findstr /i "^0x" >nul
if !errorlevel! == 0 (
    if "!TESTING!"=="true" (echo [DEBUG] Converting to Decimal value)
    set /a "HKLM_NSS_DEC=!HKLM_NSS!"
)

if "!TESTING!"=="true" (
    echo [DEBUG] Converted HKLM_NSS_DEC: !HKLM_NSS_DEC!
)

:: Now check values
if "!HKLM_NSS_DEC!"=="537395200" (
    echo [+] NTLMv2 server session security is required >> "%OUTFILE%"
    echo [+] NTLM SSP server 128-bit encryption is required >> "%OUTFILE%"
    echo [-] NTLM SSP server message integrity is not required >> "%OUTFILE%"
    echo [-] NTLM SSP server message confidentiality is not required >> "%OUTFILE%"
    if "!TESTING!"=="true" (
        echo [+] NTLMv2 server session security is required
        echo [+] NTLM SSP server 128-bit encryption is required
        echo [-] NTLM SSP server message integrity not required
        echo [-] NTLM SSP server message confidentiality not required
    )
) else if "!HKLM_NSS_DEC!"=="537395232" (
    echo [+] NTLMv2 server session security is required >> "%OUTFILE%"
    echo [+] NTLM SSP server 128-bit encryption is required >> "%OUTFILE%"
    echo [-] NTLM SSP server message integrity is not required >> "%OUTFILE%"
    echo [+] NTLM SSP server message confidentiality is required >> "%OUTFILE%"
    if "!TESTING!"=="true" (
        echo [+] NTLMv2 server session security is required
        echo [+] NTLM SSP server 128-bit encryption is required
        echo [-] NTLM SSP server message integrity not required
        echo [+] NTLM SSP server message confidentiality is required
    )
) else if "!HKLM_NSS_DEC!"=="537395248" (
    echo [+] NTLMv2 server session security is required >> "%OUTFILE%"
    echo [+] NTLM SSP server 128-bit encryption is required >> "%OUTFILE%
    echo [+] NTLM SSP server message integrity is required >> "%OUTFILE%
    echo [+] NTLM SSP server message confidentiality is required >> "%OUTFILE%
    if "!TESTING!"=="true" (
        echo [+] NTLMv2 server session security is required
        echo [+] NTLM SSP server 128-bit encryption is required
        echo [+] NTLM SSP server message integrity is required
        echo [+] NTLM SSP server message confidentiality is required
    )
) else if "!HKLM_NSS_DEC!"=="537395216" (
    echo [+] NTLMv2 server session security is required >> "%OUTFILE%"
    echo [+] NTLM SSP server 128-bit encryption is required >> "%OUTFILE%"
    echo [+] NTLM SSP server message integrity is required >> "%OUTFILE%"
    echo [-] NTLM SSP server message confidentiality is not required >> "%OUTFILE%"
    if "!TESTING!"=="true" (
        echo [+] NTLMv2 server session security is required
        echo [+] NTLM SSP server 128-bit encryption is required
        echo [+] NTLM SSP server message integrity is required
        echo [-] NTLM SSP server message confidentiality is not required
    )
) else if "!HKLM_NSS_DEC!"=="536870912" (
    echo [-] NTLMv2 server session security is not required >> "%OUTFILE%"
    echo [+] NTLM SSP server 128-bit encryption is required >> "%OUTFILE%"
    echo [-] NTLM SSP server message integrity is not required >> "%OUTFILE%"
    echo [-] NTLM SSP server message confidentiality is not required >> "%OUTFILE%"
    if "!TESTING!"=="true" (
        echo [-] NTLMv2 server session security is not required
        echo [+] NTLM SSP server 128-bit encryption is required
        echo [-] NTLM SSP server message integrity is not required
        echo [-] NTLM SSP server message confidentiality is not required
    )
) else if "!HKLM_NSS_DEC!"=="536870944" (
    echo [-] NTLMv2 server session security is not required >> "%OUTFILE%"
    echo [+] NTLM SSP server 128-bit encryption is required >> "%OUTFILE%"
    echo [-] NTLM SSP server message integrity is not required >> "%OUTFILE%"
    echo [+] NTLM SSP server message confidentiality is required >> "%OUTFILE%"
    if "!TESTING!"=="true" (
        echo [-] NTLMv2 server session security is not required
        echo [+] NTLM SSP server 128-bit encryption is required
        echo [-] NTLM SSP server message integrity is not required
        echo [+] NTLM SSP server message confidentiality is required
    )
) else if "!HKLM_NSS_DEC!"=="536870960" (
    echo [-] NTLMv2 server session security is not required >> "%OUTFILE%"
    echo [+] NTLM SSP server 128-bit encryption is required >> "%OUTFILE%"
    echo [+] NTLM SSP server message integrity is required >> "%OUTFILE%"
    echo [+] NTLM SSP server message confidentiality is required >> "%OUTFILE%"
    if "!TESTING!"=="true" (
        echo [-] NTLMv2 server session security is not required
        echo [+] NTLM SSP server 128-bit encryption is required
        echo [+] NTLM SSP server message integrity is required
        echo [+] NTLM SSP server message confidentiality is required
    )
) else if "!HKLM_NSS_DEC!"=="524336" (
    echo [+] NTLMv2 server session security is required >> "%OUTFILE%"
    echo [-] NTLM SSP server 128-bit encryption is not required >> "%OUTFILE%"
    echo [+] NTLM SSP server message integrity is required >> "%OUTFILE%"
    echo [+] NTLM SSP server message confidentiality is required >> "%OUTFILE%"
    if "!TESTING!"=="true" (
        echo [+] NTLMv2 server session security is required
        echo [-] NTLM SSP server 128-bit encryption is not required
        echo [+] NTLM SSP server message integrity is required
        echo [+] NTLM SSP server message confidentiality is required
    )
) else if "!HKLM_NSS_DEC!"=="524320" (
    echo [+] NTLMv2 server session security is required >> "%OUTFILE%"
    echo [-] NTLM SSP server 128-bit encryption is not required >> "%OUTFILE%"
    echo [-] NTLM SSP server message integrity is not required >> "%OUTFILE%"
    echo [+] NTLM SSP server message confidentiality is required >> "%OUTFILE%"
    if "!TESTING!"=="true" (
        echo [+] NTLMv2 server session security is required
        echo [-] NTLM SSP server 128-bit encryption is not required
        echo [-] NTLM SSP server message integrity is not required
        echo [+] NTLM SSP server message confidentiality is required
    )
) else if "!HKLM_NSS_DEC!"=="524304" (
    echo [+] NTLMv2 server session security is required >> "%OUTFILE%"
    echo [-] NTLM SSP server 128-bit encryption is not required >> "%OUTFILE%"
    echo [+] NTLM SSP server message integrity is required >> "%OUTFILE%"
    echo [-] NTLM SSP server message confidentiality is not required >> "%OUTFILE%"
    if "!TESTING!"=="true" (
        echo [+] NTLMv2 server session security is required
        echo [-] NTLM SSP server 128-bit encryption is not required
        echo [+] NTLM SSP server message integrity is required
        echo [-] NTLM SSP server message confidentiality is not required
    )
) else if "!HKLM_NSS_DEC!"=="524288" (
    echo [+] NTLMv2 server session security is required >> "%OUTFILE%"
    echo [-] NTLM SSP server 128-bit encryption is not required >> "%OUTFILE%"
    echo [-] NTLM SSP server message integrity is not required >> "%OUTFILE%"
    echo [-] NTLM SSP server message confidentiality is not required >> "%OUTFILE%"
    if "!TESTING!"=="true" (
        echo [+] NTLMv2 server session security is required
        echo [-] NTLM SSP server 128-bit encryption is not required
        echo [-] NTLM SSP server message integrity is not required
        echo [-] NTLM SSP server message confidentiality is not required
    )
) else if "!HKLM_NSS_DEC!"=="16" (
    echo [-] NTLMv2 server session security is not required >> "%OUTFILE%"
    echo [-] NTLM SSP server 128-bit encryption is not required >> "%OUTFILE%"
    echo [+] NTLM SSP server message integrity is required >> "%OUTFILE%"
    echo [-] NTLM SSP server message confidentiality is not required >> "%OUTFILE%"
    if "!TESTING!"=="true" (
        echo [-] NTLMv2 server session security is not required
        echo [-] NTLM SSP server 128-bit encryption is not required
        echo [+] NTLM SSP server message integrity is required
        echo [-] NTLM SSP server message confidentiality is not required
    )
) else if "!HKLM_NSS_DEC!"=="48" (
    echo [-] NTLMv2 server session security is not required >> "%OUTFILE%"
    echo [-] NTLM SSP server 128-bit encryption is not required >> "%OUTFILE%"
    echo [+] NTLM SSP server message integrity is required >> "%OUTFILE%"
    echo [+] NTLM SSP server message confidentiality is required >> "%OUTFILE%"
    if "!TESTING!"=="true" (
        echo [-] NTLMv2 server session security is not required
        echo [-] NTLM SSP server 128-bit encryption is not required
        echo [+] NTLM SSP server message integrity is required
        echo [+] NTLM SSP server message confidentiality is required
    )
) else if "!HKLM_NSS_DEC!"=="32" (
    echo [-] NTLMv2 server session security is not required >> "%OUTFILE%"
    echo [-] NTLM SSP server 128-bit encryption is not required >> "%OUTFILE%"
    echo [-] NTLM SSP server message integrity is not required >> "%OUTFILE%"
    echo [+] NTLM SSP server message confidentiality is required >> "%OUTFILE%"
    if "!TESTING!"=="true" (
        echo [-] NTLMv2 server session security is not required
        echo [-] NTLM SSP server 128-bit encryption is not required
        echo [-] NTLM SSP server message integrity is not required
        echo [+] NTLM SSP server message confidentiality is required
    )
)

echo [*] NtlmMinServerSec registry value: !HKLM_NSS_DEC! >> "%OUTFILE%"
if "!TESTING!"=="true" (
    echo [*] NtlmMinServerSec registry value: !HKLM_NSS_DEC!
    echo [DEBUG] Completed NTLM Session Security Server check 
)

:: Check Client Session Security
if "!TESTING!"=="true" echo [DEBUG] Calling :GetRegistryValue "HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0" "NtlmMinClientSec" HKLM_NSC
call :GetRegistryValue "HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0" "NtlmMinClientSec" HKLM_NSC
if "!TESTING!"=="true" (
    echo [DEBUG] HKLM_NSC: !HKLM_NSC!
)

:: Convert from Hex to Dec
if "!TESTING!"=="true" (echo [DEBUG] Checking if 0x prefix exists)
echo !HKLM_NSC! | findstr /i "^0x" >nul
if !errorlevel! == 0 (
    if "!TESTING!"=="true" (echo [DEBUG] Converting to Decimal value)
    set /a "HKLM_NSC_DEC=!HKLM_NSC!"
)

if "!TESTING!"=="true" (
    echo [DEBUG] Converted HKLM_NSC_DEC: !HKLM_NSC_DEC!
)

:: Now check values
if "!HKLM_NSC_DEC!"=="537395200" (
    echo [+] NTLMv2 client session security is required >> "%OUTFILE%"
    echo [+] NTLM SSP client 128-bit encryption is required >> "%OUTFILE%"
    echo [-] NTLM SSP client message integrity is not required >> "%OUTFILE%"
    echo [-] NTLM SSP client message confidentiality is not required >> "%OUTFILE%"
    if "!TESTING!"=="true" (
        echo [+] NTLMv2 client session security is required
        echo [+] NTLM SSP client 128-bit encryption is required
        echo [-] NTLM SSP client message integrity not required
        echo [-] NTLM SSP client message confidentiality not required
    )
) else if "!HKLM_NSC_DEC!"=="537395232" (
    echo [+] NTLMv2 client session security is required >> "%OUTFILE%"
    echo [+] NTLM SSP client 128-bit encryption is required >> "%OUTFILE%"
    echo [-] NTLM SSP client message integrity is not required >> "%OUTFILE%"
    echo [+] NTLM SSP client message confidentiality is required >> "%OUTFILE%"
    if "!TESTING!"=="true" (
        echo [+] NTLMv2 server session security is required
        echo [+] NTLM SSP client 128-bit encryption is required
        echo [-] NTLM SSP client message integrity not required
        echo [+] NTLM SSP client message confidentiality is required
    )
) else if "!HKLM_NSC_DEC!"=="537395248" (
    echo [+] NTLMv2 client session security is required >> "%OUTFILE%"
    echo [+] NTLM SSP client 128-bit encryption is required >> "%OUTFILE%
    echo [+] NTLM SSP client message integrity is required >> "%OUTFILE%
    echo [+] NTLM SSP client message confidentiality is required >> "%OUTFILE%
    if "!TESTING!"=="true" (
        echo [+] NTLMv2 client session security is required
        echo [+] NTLM SSP client 128-bit encryption is required
        echo [+] NTLM SSP client message integrity is required
        echo [+] NTLM SSP client message confidentiality is required
    )
) else if "!HKLM_NSC_DEC!"=="537395216" (
    echo [+] NTLMv2 client session security is required >> "%OUTFILE%"
    echo [+] NTLM SSP client 128-bit encryption is required >> "%OUTFILE%"
    echo [+] NTLM SSP client message integrity is required >> "%OUTFILE%"
    echo [-] NTLM SSP client message confidentiality is not required >> "%OUTFILE%"
    if "!TESTING!"=="true" (
        echo [+] NTLMv2 client session security is required
        echo [+] NTLM SSP client 128-bit encryption is required
        echo [+] NTLM SSP client message integrity is required
        echo [-] NTLM SSP client message confidentiality is not required
    )
) else if "!HKLM_NSC_DEC!"=="536870912" (
    echo [-] NTLMv2 client session security is not required >> "%OUTFILE%"
    echo [+] NTLM SSP client 128-bit encryption is required >> "%OUTFILE%"
    echo [-] NTLM SSP client message integrity is not required >> "%OUTFILE%"
    echo [-] NTLM SSP client message confidentiality is not required >> "%OUTFILE%"
    if "!TESTING!"=="true" (
        echo [-] NTLMv2 client session security is not required
        echo [+] NTLM SSP client 128-bit encryption is required
        echo [-] NTLM SSP client message integrity is not required
        echo [-] NTLM SSP client message confidentiality is not required
    )
) else if "!HKLM_NSC_DEC!"=="536870944" (
    echo [-] NTLMv2 client session security is not required >> "%OUTFILE%"
    echo [+] NTLM SSP client 128-bit encryption is required >> "%OUTFILE%"
    echo [-] NTLM SSP client message integrity is not required >> "%OUTFILE%"
    echo [+] NTLM SSP client message confidentiality is required >> "%OUTFILE%"
    if "!TESTING!"=="true" (
        echo [-] NTLMv2 client session security is not required
        echo [+] NTLM SSP client 128-bit encryption is required
        echo [-] NTLM SSP client message integrity is not required
        echo [+] NTLM SSP client message confidentiality is required
    )
) else if "!HKLM_NSC_DEC!"=="536870960" (
    echo [-] NTLMv2 client session security is not required >> "%OUTFILE%"
    echo [+] NTLM SSP client 128-bit encryption is required >> "%OUTFILE%"
    echo [+] NTLM SSP client message integrity is required >> "%OUTFILE%"
    echo [+] NTLM SSP client message confidentiality is required >> "%OUTFILE%"
    if "!TESTING!"=="true" (
        echo [-] NTLMv2 client session security is not required
        echo [+] NTLM SSP client 128-bit encryption is required
        echo [+] NTLM SSP client message integrity is required
        echo [+] NTLM SSP client message confidentiality is required
    )
) else if "!HKLM_NSC_DEC!"=="524336" (
    echo [+] NTLMv2 client session security is required >> "%OUTFILE%"
    echo [-] NTLM SSP client 128-bit encryption is not required >> "%OUTFILE%"
    echo [+] NTLM SSP client message integrity is required >> "%OUTFILE%"
    echo [+] NTLM SSP client message confidentiality is required >> "%OUTFILE%"
    if "!TESTING!"=="true" (
        echo [+] NTLMv2 client session security is required
        echo [-] NTLM SSP client 128-bit encryption is not required
        echo [+] NTLM SSP client message integrity is required
        echo [+] NTLM SSP client message confidentiality is required
    )
) else if "!HKLM_NSC_DEC!"=="524320" (
    echo [+] NTLMv2 client session security is required >> "%OUTFILE%"
    echo [-] NTLM SSP client 128-bit encryption is not required >> "%OUTFILE%"
    echo [-] NTLM SSP client message integrity is not required >> "%OUTFILE%"
    echo [+] NTLM SSP client message confidentiality is required >> "%OUTFILE%"
    if "!TESTING!"=="true" (
        echo [+] NTLMv2 client session security is required
        echo [-] NTLM SSP client 128-bit encryption is not required
        echo [-] NTLM SSP client message integrity is not required
        echo [+] NTLM SSP client message confidentiality is required
    )
) else if "!HKLM_NSC_DEC!"=="524304" (
    echo [+] NTLMv2 client session security is required >> "%OUTFILE%"
    echo [-] NTLM SSP client 128-bit encryption is not required >> "%OUTFILE%"
    echo [+] NTLM SSP client message integrity is required >> "%OUTFILE%"
    echo [-] NTLM SSP client message confidentiality is not required >> "%OUTFILE%"
    if "!TESTING!"=="true" (
        echo [+] NTLMv2 client session security is required
        echo [-] NTLM SSP client 128-bit encryption is not required
        echo [+] NTLM SSP client message integrity is required
        echo [-] NTLM SSP client message confidentiality is not required
    )
) else if "!HKLM_NSC_DEC!"=="524288" (
    echo [+] NTLMv2 client session security is required >> "%OUTFILE%"
    echo [-] NTLM SSP client 128-bit encryption is not required >> "%OUTFILE%"
    echo [-] NTLM SSP client message integrity is not required >> "%OUTFILE%"
    echo [-] NTLM SSP client message confidentiality is not required >> "%OUTFILE%"
    if "!TESTING!"=="true" (
        echo [+] NTLMv2 client session security is required
        echo [-] NTLM SSP client 128-bit encryption is not required
        echo [-] NTLM SSP client message integrity is not required
        echo [-] NTLM SSP client message confidentiality is not required
    )
) else if "!HKLM_NSC_DEC!"=="16" (
    echo [-] NTLMv2 client session security is not required >> "%OUTFILE%"
    echo [-] NTLM SSP client 128-bit encryption is not required >> "%OUTFILE%"
    echo [+] NTLM SSP client message integrity is required >> "%OUTFILE%"
    echo [-] NTLM SSP client message confidentiality is not required >> "%OUTFILE%"
    if "!TESTING!"=="true" (
        echo [-] NTLMv2 client session security is not required
        echo [-] NTLM SSP client 128-bit encryption is not required
        echo [+] NTLM SSP client message integrity is required
        echo [-] NTLM SSP client message confidentiality is not required
    )
) else if "!HKLM_NSC_DEC!"=="48" (
    echo [-] NTLMv2 client session security is not required >> "%OUTFILE%"
    echo [-] NTLM SSP client 128-bit encryption is not required >> "%OUTFILE%"
    echo [+] NTLM SSP client message integrity is required >> "%OUTFILE%"
    echo [+] NTLM SSP client message confidentiality is required >> "%OUTFILE%"
    if "!TESTING!"=="true" (
        echo [-] NTLMv2 client session security is not required
        echo [-] NTLM SSP client 128-bit encryption is not required
        echo [+] NTLM SSP client message integrity is required
        echo [+] NTLM SSP client message confidentiality is required
    )
) else if "!HKLM_NSC_DEC!"=="32" (
    echo [-] NTLMv2 client session security is not required >> "%OUTFILE%"
    echo [-] NTLM SSP client 128-bit encryption is not required >> "%OUTFILE%"
    echo [-] NTLM SSP client message integrity is not required >> "%OUTFILE%"
    echo [+] NTLM SSP client message confidentiality is required >> "%OUTFILE%"
    if "!TESTING!"=="true" (
        echo [-] NTLMv2 client session security is not required
        echo [-] NTLM SSP client 128-bit encryption is not required
        echo [-] NTLM SSP client message integrity is not required
        echo [+] NTLM SSP client message confidentiality is required
    )
)

echo [*] NtlmMinClientSec registry value: !HKLM_NSC_DEC! >> "%OUTFILE%"
if "!TESTING!"=="true" (
    echo [*] NtlmMinClientSec registry value: !HKLM_NSC_DEC!
    echo [DEBUG] Completed NTLM Session Security Client check 
    echo [DEBUG] Completed :CheckNTLMSessionSec
)
goto :eof 

:: #############################
:: Check LANMAN Security Configuration
:CheckLanman
if "!TESTING!"=="true" (echo [DEBUG] Called CheckLanman)

:: Check LANMAN Authentication Compatability Level
:: Initialize default values
set "HKLM_LAC=0"

if "!TESTING!"=="true" (
    echo [DEBUG] Default HKLM_LAC: !HKLM_LAC!
)

if "!TESTING!"=="true" (echo [DEBUG] Calling :GetRegistryValue "HKLM\System\CurrentControlSet\Control\Lsa" "LmCompatibilityLevel" HKLM_LAC)
call :GetRegistryValue "HKLM\System\CurrentControlSet\Control\Lsa" "LmCompatibilityLevel" HKLM_LAC

if "!TESTING!"=="true" (echo [DEBUG] HKLM_LAC: !HKLM_LAC!)

:: Remove 0x prefix if it esists
if "!TESTING!"=="true" (echo [DEBUG] Checking if 0x prefix exists)
echo !HKLM_LAC! | findstr /i "^0x" >nul
if !errorlevel! == 0 (
    if "!TESTING!"=="true" (echo [DEBUG] Stripping 0x prefix from HKLM_LAC)
    set "HKLM_LAC=!HKLM_LAC:0x=!"
)

if "!TESTING!"=="true" (echo [DEBUG] Normalized HKLM_LAC: !HKLM_LAC!)

if "!HKLM_LAC!"=="5" (
    echo [+] LM Compatability Level is configured correctly: !HKLM_LAC! - Send NTLMv2 response only, refuse LM and NTLM >> "%OUTFILE%"
    if "!TESTING!"=="true" (echo [+] LM Compatability Level is configured correctly: !HKLM_LAC! - Send NTLMv2 response only, refuse LM and NTLM)
) else if "!HKLM_LAC!"=="4" (
    echo [-] LM Compatability Level is not configured to prevent NTLM: !HKLM_LAC! - Send NTLMv2 response only, refuse LM, Allow NTLM >> "%OUTFILE%"
    if "!TESTING!"=="true" (echo [-] LM Compatability Level is not configured to prevent NTLM: !HKLM_LAC! - Send NTLMv2 response only, refuse LM)
) else if "!HKLM_LAC!"=="3" (
    echo [-] LM Compatability Level is not configured to prevent NTLM or LM: !HKLM_LAC! - Send NTLMv2 response only >> "%OUTFILE%"
    if "!TESTING!"=="true" (echo [-] LM Compatability Level is not configured to prevent NTLM: !HKLM_LAC! - Send NTLMv2 response only)
) else if "!HKLM_LAC!"=="2" (
    echo [-] LM Compatability Level is not configured to use NTLMv2: !HKLM_LAC! - Send NTLM response only >> "%OUTFILE%"
    if "!TESTING!"=="true" (echo [-] LM Compatability Level is not configured to use NTLMv2: !HKLM_LAC! - Send NTLM response only)
) else if "!HKLM_LAC!"=="1" (
    echo [-] LM Compatability Level is not configured to use NTLMv2: !HKLM_LAC! - Send LM and NTLM response, use NTLMv2 session security if negotiated >> "%OUTFILE%"
    if "!TESTING!"=="true" (echo [-] LM Compatability Level is not configured to use NTLMv2: !HKLM_LAC! - Send LM and NTLM response, use NTLMv2 session security if negotiated)
) else if "!HKLM_LAC!"=="0" (
    echo [-] LM Compatability Level is not configured to use NTLMv2: !HKLM_LAC! - Send LM and NTLM responses >> "%OUTFILE%"
    if "!TESTING!"=="true" (echo [-] LM Compatability Level is not configured to use NTLMv2: !HKLM_LAC! - Send LM and NTLM responses)
)

:: Check LANMAN Hash Storage
:: Initialize default values
set "HKLM_LMH=0"

if "!TESTING!"=="true" (
    echo [DEBUG] Default HKLM_LMH: !HKLM_LMH!
    echo [DEBUG] Calling :GetRegistryValue "HKLM\System\CurrentControlSet\Control\Lsa" "NoLmHash" HKLM_LMH
    )
call :GetRegistryValue "HKLM\System\CurrentControlSet\Control\Lsa" "NoLmHash" HKLM_LMH

if "!TESTING!"=="true" (
    echo [DEBUG] HKLM_LMH: !HKLM_LMH!
)

:: Remove 0x prefix if it esists
if "!TESTING!"=="true" (echo [DEBUG] Checking if 0x prefix exists)
echo !HKLM_LMH! | findstr /i "^0x" >nul
if !errorlevel! == 0 (
    if "!TESTING!"=="true" (echo [DEBUG] Stripping 0x prefix from HKLM_LMH)
    set "HKLM_LMH=!HKLM_LMH:0x=!"
)

if "!TESTING!"=="true" (echo [DEBUG] Normalized HKLM_LMH: !HKLM_LMH!)

if "!HKLM_LMH!"=="1" (
    echo [+] NoLmHash registry key is configured: !HKLM_LMH! >> "%OUTFILE%"
    if "!TESTING!"=="true" (echo [+] NoLmHash registry key is configured: !HKLM_LMH!)
) else (
    echo [-] NoLmHash registry key is not configured >> "%OUTFILE%"
    if "!TESTING!"=="true" (echo [-] NoLmHash registry key is not configured)
) 

if "!TESTING!"=="true" (echo [DEBUG] Completed :CheckLanman)
goto :eof 

:: #############################
:: Check RDP Deny
:CheckRDPDeny
if "!TESTING!"=="true" (echo [DEBUG] Called CheckRDPDeny)

:: Check AllowRemoteRPC Disabled
:: Initialize default values
set "HKLM_RPC=0"

if "!TESTING!"=="true" (
    echo [DEBUG] Default HKLM_RPC: !HKLM_RPC!
)

if "!TESTING!"=="true" (echo [DEBUG] Calling :GetRegistryValue "HKLM\System\CurrentControlSet\Control\Terminal Server" "AllowRemoteRPC" HKLM_RPC)
call :GetRegistryValue "HKLM\System\CurrentControlSet\Control\Terminal Server" "AllowRemoteRPC" HKLM_RPC

if "!TESTING!"=="true" (
    echo [DEBUG] HKLM_RPC: !HKLM_RPC!
)

:: Remove 0x prefix if it esists
if "!TESTING!"=="true" (echo [DEBUG] Checking if 0x prefix exists)
echo !HKLM_RPC! | findstr /i "^0x" >nul
if !errorlevel! == 0 (
    if "!TESTING!"=="true" (echo [DEBUG] Stripping 0x prefix from HKLM_RPC)
    set "HKLM_RPC=!HKLM_RPC:0x=!"
)

if "!TESTING!"=="true" (
    echo [DEBUG] Normalized HKLM_RPC: !HKLM_RPC!
)

if "!HKLM_RPC!"=="0" (
    echo [+] AllowRemoteRPC is not enabled: !HKLM_RPC! >> "%OUTFILE%"
    if "!TESTING!"=="true" (echo [+] AllowRemoteRPC is not enabled: !HKLM_RPC!)
) else (
    echo [-] AllowRemoteRPC is enabled: !HKLM_RPC! >> "%OUTFILE%"
    if "!TESTING!"=="true" (echo [-] AllowRemoteRPC is enabled: !HKLM_RPC!)
)

:: Check fDenyTSConnections Enabled
:: Initialize default values
set "HKLM_DTS=1"

if "!TESTING!"=="true" (
    echo [DEBUG] Default HKLM_DTS: !HKLM_DTS!
)

if "!TESTING!"=="true" (echo [DEBUG] Calling :GetRegistryValue "HKLM\System\CurrentControlSet\Control\Terminal Server" "fDenyTSConnections" HKLM_DTS)
call :GetRegistryValue "HKLM\System\CurrentControlSet\Control\Terminal Server" "fDenyTSConnections" HKLM_DTS

if "!TESTING!"=="true" (
    echo [DEBUG] HKLM_DTS: !HKLM_DTS!
)

:: Remove 0x prefix if it esists
if "!TESTING!"=="true" (echo [DEBUG] Checking if 0x prefix exists)
echo !HKLM_DTS! | findstr /i "^0x" >nul
if !errorlevel! == 0 (
    if "!TESTING!"=="true" (echo [DEBUG] Stripping 0x prefix from HKLM_DTS)
    set "HKLM_DTS=!HKLM_DTS:0x=!"
)

if "!TESTING!"=="true" (
    echo [DEBUG] Normalized HKLM_DTS: !HKLM_DTS!
)

if "!HKLM_DTS!"=="1" (
    echo [+] fDenyTSConnections is enabled: !HKLM_DTS! >> "%OUTFILE%"
    if "!TESTING!"=="true" (echo [+] fDenyTSConnections is enabled: !HKLM_DTS!)
) else (
    echo [-] fDenyTSConnections is not enabled: !HKLM_DTS! >> "%OUTFILE%"
    if "!TESTING!"=="true" (echo [-] fDenyTSConnections is not enabled: !HKLM_DTS!)
)

if "!TESTING!"=="true" (echo [DEBUG] Completed :CheckRDPDeny)
goto :eof

:: #############################
:: Check CheckWDigest Credential Storage
:CheckWDigest
if "!TESTING!"=="true" ( echo [DEBUG] Called CheckWDigest )

:: Initialize default values
set "HKLM_WDC=0"

if "!TESTING!"=="true" ( echo [DEBUG] Default HKLM_WDC: !HKLM_WDC! )

:: Check HKLM
if "!TESTING!"=="true" ( echo [DEBUG] Calling :GetRegistryValue "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" "UseLogonCredential" HKLM_WDC )
call :GetRegistryValue "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" "UseLogonCredential" HKLM_WDC

if "!TESTING!"=="true" ( echo [DEBUG] HKLM_WDC: !HKLM_WDC! )

:: Remove 0x prefix if it esists
if "!TESTING!"=="true" ( echo [DEBUG] Checking if 0x prefix exists )
echo !HKLM_WDC! | findstr /i "^0x" >nul
if !errorlevel! == 0 (
    if "!TESTING!"=="true" ( echo [DEBUG] Stripping 0x prefix from HKLM_WDC )
    set "HKLM_WDC=!HKLM_WDC:0x=!"
)

if "!TESTING!"=="true" ( echo [DEBUG] Normalized HKLM_WDC: !HKLM_WDC! )

:: Now check values
if "!HKLM_WDC!"=="0" (
    echo [+] WDigest UseLogonCredential key is Disabled >> "%OUTFILE%"
    if "!TESTING!"=="true" ( echo [+] WDigest UseLogonCredential key is Disabled: !HKLM_WDC! )
) else if "!HKLM_WDC!"=="1" (
    echo [-] WDigest UseLogonCredential key is Enabled: !HKLM_WDC! >> "%OUTFILE%"
    if "!TESTING!"=="true" ( echo [-] WDigest UseLogonCredential key is Enabled: !HKLM_WDC!)
) 

if "!TESTING!"=="true" (echo [DEBUG] Completed :CheckWDigest)
goto :eof 

:: #############################
:: Check Interactive Login Configuration
:CheckInteractiveLogin
if "!TESTING!"=="true" echo [DEBUG] Called CheckInteractiveLogin

:: Check CurrentControlSet Configuration
:: Initialize default values
set "HKLM_LAT=0"

if "!TESTING!"=="true" (
    echo [DEBUG] Default HKLM_LAT: !HKLM_LAT!
)

:: Check HKLM
if "!TESTING!"=="true" echo [DEBUG] Calling :GetRegistryValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\system" "LocalAccountTokenFilterPolicy" HKLM_LAT
call :GetRegistryValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\system" "LocalAccountTokenFilterPolicy" HKLM_LAT

if "!TESTING!"=="true" (
    echo [DEBUG] HKLM_LAT: !HKLM_LAT!
)

:: Remove 0x prefix if it esists
if "!TESTING!"=="true" ( echo [DEBUG] Checking if 0x prefix exists)
echo !HKLM_LAT! | findstr /i "^0x" >nul
if !errorlevel! == 0 (
    if "!TESTING!"=="true" ( echo [DEBUG] Stripping 0x prefix from HKLM_LAT)
    set "HKLM_LAT=!HKLM_LAT:0x=!"
)

if "!TESTING!"=="true" ( echo [DEBUG] Normalized HKLM_LAT: !HKLM_LAT! )

:: Now check values
if "!HKLM_LAT!"=="1" (
    echo [-] LocalAccountTokenFilterPolicy Is Set: !HKLM_LAT! >> "%OUTFILE%"
    if "!TESTING!"=="true" ( echo [-] LocalAccountTokenFilterPolicy is set: !HKLM_LAT! )
) else (
    echo [+] LocalAccountTokenFilterPolicy is not set: !HKLM_LAT! >> "%OUTFILE%"
    if "!TESTING!"=="true" ( echo [+] LocalAccountTokenFilterPolicy is not set: !HKLM_LAT! )
)

:: Check Wow6432 Version
:: Initialize default values
set "HKLM_WowLAT=0"

if "!TESTING!"=="true" (
    echo [DEBUG] Default HKLM_WowLAT: !HKLM_WowLAT!
)

:: Check HKLM
if "!TESTING!"=="true" echo [DEBUG] Calling :GetRegistryValue "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\policies\system" "LocalAccountTokenFilterPolicy" HKLM_WowLAT
call :GetRegistryValue "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\policies\system" "LocalAccountTokenFilterPolicy" HKLM_WowLAT

if "!TESTING!"=="true" (
    echo [DEBUG] HKLM_WowLAT: !HKLM_WowLAT!
)

:: Remove 0x prefix if it esists
if "!TESTING!"=="true" ( echo [DEBUG] Checking if 0x prefix exists)
echo !HKLM_WowLAT! | findstr /i "^0x" >nul
if !errorlevel! == 0 (
    if "!TESTING!"=="true" ( echo [DEBUG] Stripping 0x prefix from HKLM_WowLAT)
    set "HKLM_WowLAT=!HKLM_WowLAT:0x=!"
)

if "!TESTING!"=="true" (
    echo [DEBUG] Normalized HKLM_WowLAT: !HKLM_WowLAT!
)

:: Now check values
if "!HKLM_WowLAT!"=="1" (
    echo [-] LocalAccountTokenFilterPolicy in Wow6432 Node is set: !HKLM_WowLAT! >> "%OUTFILE%"
    if "!TESTING!"=="true" ( echo [-] LocalAccountTokenFilterPolicy in Wow6432 Node is set: !HKLM_WowLAT! )
) else (
    echo [+] LocalAccountTokenFilterPolicy in Wow6432 Node is not set: !HKLM_WowLAT! >> "%OUTFILE%"
    if "!TESTING!"=="true" ( echo [+] LocalAccountTokenFilterPolicy in Wow6432 Node is not set: !HKLM_WowLAT! )
)

if "!TESTING!"=="true" ( echo [DEBUG] Completed :CheckInteractiveLogin)
goto :eof 

:: #############################
:: Check GPO Pre-processing Configuration
:CheckGPOProcessing
if "!TESTING!"=="true" echo [DEBUG] Called CheckGPOProcessing

:: Initialize default values
set "HKLM_GPP=0"

if "!TESTING!"=="true" (
    echo [DEBUG] Default HKLM_GPP: !HKLM_GPP!
)

:: Check HKLM
if "!TESTING!"=="true" echo [DEBUG] Calling :GetRegistryValue "HKLM\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" "NoGPOListChanges" HKLM_GPP
call :GetRegistryValue "HKLM\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" "NoGPOListChanges" HKLM_GPP

if "!TESTING!"=="true" (
    echo [DEBUG] HKLM_GPP: !HKLM_GPP!
)

:: Remove 0x prefix if it esists
if "!TESTING!"=="true" (echo [DEBUG] Checking if 0x prefix exists)
echo !HKLM_GPP! | findstr /i "^0x" >nul
if !errorlevel! == 0 (
    if "!TESTING!"=="true" (echo [DEBUG] Stripping 0x prefix from HKLM_GPP)
    set "HKLM_GPP=!HKLM_GPP:0x=!"
)

if "!TESTING!"=="true" (
    echo [DEBUG] Normalized HKLM_GPP: !HKLM_GPP!
)

:: Now check values
if "!HKLM_GPP!"=="0" (
    echo [+] GPO NoGPOListChanges setting requires GPOs to be reapplied when processed: !HKLM_GPP! >> "%OUTFILE%"
    if "!TESTING!"=="true" ( echo [+] GPO settings are configured to be applied when GPOs are processed: !HKLM_GPP!)
) else (
    echo [-] GPO NoGPOListChanges setting does not require GPOs to be applied when processed: !HKLM_GPP! >> "%OUTFILE%"
    if "!TESTING!"=="true" ( echo [-] GPO NoGPOListChanges setting does not require GPOs to be applied when processed: !HKLM_GPP!)
)

:: Check NoBackgroundPolicy Setting
:: Initialize default values
set "HKLM_GNB=0"

if "!TESTING!"=="true" (
    echo [DEBUG] Default HKLM_GNB: !HKLM_GNB!
)

:: Check HKLM
if "!TESTING!"=="true" echo [DEBUG] Calling :GetRegistryValue "HKLM\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" "NoBackgroundPolicy" HKLM_GNB
call :GetRegistryValue "HKLM\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" "NoBackgroundPolicy" HKLM_GNB

if "!TESTING!"=="true" (
    echo [DEBUG] HKLM_GNB: !HKLM_GNB!
)

:: Remove 0x prefix if it esists
if "!TESTING!"=="true" (echo [DEBUG] Checking if 0x prefix exists)
echo !HKLM_GNB! | findstr /i "^0x" >nul
if !errorlevel! == 0 (
    if "!TESTING!"=="true" (echo [DEBUG] Stripping 0x prefix from HKLM_GNB)
    set "HKLM_GNB=!HKLM_GNB:0x=!"
)

if "!TESTING!"=="true" (
    echo [DEBUG] Normalized HKLM_GNB: !HKLM_GNB!
)

:: Now check values
if "!HKLM_GNB!"=="0" (
    echo [+] GPO NoBackgroundPolicy setting is configured to process GPOs even while computer is in use: !HKLM_GNB! >> "%OUTFILE%"
    if "!TESTING!"=="true" ( echo [+] GPO NoBackgroundPolicy setting is configured to process GPOs even while computer is in use: !HKLM_GNB!)
) else (
    echo [-] GPO NoBackgroundPolicy setting is configured not to process GPOs if computer is in use: !HKLM_GNB! >> "%OUTFILE%"
    if "!TESTING!"=="true" ( echo [-] GPO NoBackgroundPolicy setting is configured not to process GPOs if computer is in use: !HKLM_GNB!)
)

if "!TESTING!"=="true" (echo [DEBUG] Completed :CheckGPOProcessing)
goto :eof 

:: #############################
:: Check WINSConfig
:CheckWINSConfig
setlocal EnableDelayedExpansion

if "!TESTING!"=="true" (
    echo [DEBUG] Called CheckWINSConfig
    echo [DEBUG] Calling :GetWMICValue nicconfig DNSEnabledForWINSResolution value IPEnabled TRUE
)

call :GetWMICValue nicconfig DNSEnabledForWINSResolution value IPEnabled TRUE
if "!TESTING!"=="true" ( echo [DEBUG] Returned from :GetWMICValue)
set "WINS_DNS=!RESULT!"
if "!TESTING!"=="true" ( echo [DEBUG] WINS_DNS: !WINS_DNS!)
if "!WINS_DNS!"=="TRUE" (
    echo [-] WINSConfig DNSEnabledForWINSResolution is enabled >> %OUTFILE%
    if "!TESTING!"=="true" ( echo [-] WINSConfig DNSEnabledForWINSResolution is enabled)
) else if "!WINS_DNS!"=="FALSE" (
    echo [+] WINSConfig DNSEnabledForWINSResolution is disabled >> %OUTFILE%
    if "!TESTING!"=="true" ( echo [+] WINSConfig DNSEnabledForWINSResolution is disabled)
) else (
    echo [*] Testing for WINS DNSEnabledForWINSResolution failed >> %OUTFILE%
    if "!TESTING!"=="true" ( echo [*] Testing for WINS DNSEnabledForWINSResolution failed )
)

if "!TESTING!"=="true" ( echo [DEBUG] Calling :GetWMICValue nicconfig WINSEnableLMHostsLookup value IPEnabled TRUE)
call :GetWMICValue nicconfig WINSEnableLMHostsLookup value IPEnabled TRUE
if "!TESTING!"=="true" ( echo [DEBUG] Returned from :GetWMICValue)
set "WINS_LM=!RESULT!"
if "!TESTING!"=="true" ( echo [DEBUG] WINS_LM: !WINS_LM!)
if "!WINS_LM!"=="TRUE" (
    echo [-] WINSConfig WINSEnableLMHostsLookup is enabled >> %OUTFILE%
    if "!TESTING!"=="true" ( echo [-] WINSConfig WINSEnableLMHostsLookup is enabled)
) else if "!WINS_LM!"=="FALSE" (
    echo [+] WINSConfig WINSEnableLMHostsLookup is disabled >> %OUTFILE%
    if "!TESTING!"=="true" ( echo [+] WINSConfig WINSEnableLMHostsLookup is disabled)
) else (
    echo [*] Testing for WINS WINSEnableLMHostsLookup failed >> %OUTFILE%
    if "!TESTING!"=="true" ( echo [*] Testing for WINS WINSEnableLMHostsLookup failed )
)
endlocal & goto :eof 

