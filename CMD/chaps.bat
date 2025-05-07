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
set "COMPANY=Cutaway Security, LLC"
set "SITENAME=Plant 1"

:: Set CUTSEC_FOOTER to false to disable
set "CUTSEC_FOOTER=true"

:: Get the current date and time components for setting output directory
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
:: Format as yyyyddMM_HHmmss for the filename
if "!TESTING!"=="true" (echo [DEBUG] Setting FILENAME_DATE: %yyyy%%dd%%MONTH%_%HH%%mm%%ss%)
set "FILENAME_DATE=%yyyy%%dd%%MONTH%_%HH%%mm%%ss%"
:: Format as MM/dd/yyyy HH:mm:ss K for readable date in report
if "!TESTING!"=="true" (echo [DEBUG] Setting timezone: %dt:~21,3%)
set "timezone=UTC%dt:~21,3%"
set "READABLE_DATE=%MONTH%/%dd%/%yyyy% %HH%:%mm%:%ss% %timezone%"

:: Report is saved to user's temp directory and uses computer name in filename by default
set "OUTDIR=%TEMP%\%COMPUTERNAME%_%FILENAME_DATE%"
set "OUTFILENAME=%COMPUTERNAME%_chaps.txt"
set "SYSINFO_FILENAME=%COMPUTERNAME%_sysinfo.txt"

:: #############################
:: Set Non-Configurable Variables
:: #############################

set "SCRIPTNAME=chaps.bat"
set "SCRIPTVERSION=1.0.0"
set "OUTFILE=%OUTDIR%\%OUTFILENAME%"
set "SYSINFO_FILE=%OUTDIR%\%SYSINFO_FILENAME%"

:: Check if WMIC is available and set flag
if "!TESTING!"=="true" (echo [DEBUG] Testing if WMIC is available)
where wmic >nul 2>&1
if %errorlevel%==0 (
    set "WMIC_PRESENT=true"
    if "!TESTING!"=="true" (echo [DEBUG] Setting WMIC_PRESENT to true)
) else (
    if "!TESTING!"=="true" (echo [DEBUG] Setting WMIC_PRESENT to false)
    set "WMIC_PRESENT=false"
)
if "!TESTING!"=="true" (echo [DEBUG] WMIC_PRESENT: !WMIC_PRESENT!)

:: Create output directory if it doesn't exist
if "!TESTING!"=="true" (echo [DEBUG] Checking for !OUTDIR!)
if not exist "!OUTDIR!" (
    if "!TESTING!"=="true" (echo [DEBUG] Creating OUTDIR: !OUTDIR!)
    mkdir "!OUTDIR!" >nul 2>&1
)

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
    if defined COMPANY (echo # Auditing Company: %COMPANY%)
    if defined SITENAME (echo # Site/Plant: %SITENAME%)
    echo ##########################
    echo # Computer Name: %COMPUTERNAME%
    echo # Start Time: %READABLE_DATE%
)
echo ########################## > "%OUTFILE%"
echo # CHAPS Audit Script: %SCRIPTNAME% %SCRIPTVERSION% >> "%OUTFILE%"
if defined COMPANY (echo # Auditing Company: %COMPANY% >> "%OUTFILE%")
if defined SITENAME (echo # Site/Plant: %SITENAME% >> "%OUTFILE%")
echo ########################## >> "%OUTFILE%"
echo # Computer Name: %COMPUTERNAME% >> "%OUTFILE%"
echo # Start Time: %READABLE_DATE% >> "%OUTFILE%"

:: ###########################
:: Check Admin Rights
:: ###########################
if "!TESTING!"=="true" (
    echo [DEBUG] Checking Admin Rights
    echo [DEBUG] Setting ADMIN_RIGHTS to false
)
set "ADMIN_RIGHTS=false"
if "!TESTING!"=="true" (
    echo [DEBUG] Checking Administrator permissions using whoami
)
whoami /groups | findstr /i "S-1-5-32-544" >nul
if "!TESTING!"=="true" (echo [DEBUG] whoami errorlevel: %errorlevel%)
if %errorlevel%==0 (
    if "!TESTING!"=="true" (
        echo [+] Script running as Administrator
        echo [DEBUG] Setting ADMIN_RIGHTS to true
    )
    set "ADMIN_RIGHTS=true"
    echo [+] Script running as Administrator >> "%OUTFILE%"
) else (
    if "!TESTING!"=="true" (echo [x] Script NOT running as Administrator)
    echo [x] Script NOT running as Administrator >> "%OUTFILE%"
)

if "!TESTING!"=="true" (
    echo [DEBUG] ADMIN_RIGHTS: !ADMIN_RIGHTS!
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
    if "!TESTING!"=="true" (echo [DEBUG] Calling :GETWMICValue os Caption)
    call :GetWMICValue os Caption
    if "!TESTING!"=="true" (echo [DEBUG] Setting OS_NAME using RESULT: !RESULT!)
    set "OS_NAME=!RESULT!"
)

:: Get System Type
if "!TESTING!"=="true" (echo [DEBUG] Attempting to get System Type)
if "!WMIC_PRESENT!"=="true" (
    if "!TESTING!"=="true" (echo [DEBUG] Calling GetWMICValue computersystem SystemType)
    call :GetWMICValue computersystem SystemType
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
     if "!TESTING!"=="true" (echo [DEBUG] Calling :GETWMICValue os Version)
     call :GetWMICValue os Version
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
    if "!TESTING!"=="true" (echo [DEBUG] Calling :GETWMICValue os OSArchitecture)
    call :GetWMICValue os OSArchitecture
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
    if "!TESTING!"=="true" (echo [DEBUG] Calling GetWMICValue computersystem Domain)
    call :GetWMICValue computersystem Domain
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

:: — Loop through each line of the net localgroup output
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
    if "!TESTING!"=="true" echo [-] More than one account is in local Administrators group: %numAdmins%
    echo [-] More than one account is in local Administrators group: %numAdmins% >> "%OUTFILE%"
) else (
    if "!TESTING!"=="true" echo [+] One account in local Administrators group
    echo [+] One account in local Administrators group >> "%OUTFILE%"
)
if "!TESTING!"=="true" echo [*] Administrator Account Groups: !adminList!
echo [*] Administrator Accounts: !adminList! >> "%OUTFILE%"

:: #############################
:: Check AlwaysInstallElevated Privileges
if "!TESTING!"=="true" (echo [DEBUG] Calling :CheckAlwaysInstallElevated)
call :CheckAlwaysInstallElevated
if "!TESTING!"=="true" (echo [DEBUG] Returned from :CheckAlwaysInstallElevated)


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

:: Get date formatted for report output - MM/dd/yyyy HH:mm:ss K 
:GetReadableDate
setlocal enabledelayedexpansion
if "!TESTING!"=="true" (echo [DEBUG] Entered :GetReadableDate)
set "READABLE_DATE="
if "!WMIC_PRESENT!"=="true" (
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
    if "!TESTING!"=="true" (echo [DEBUG] Setting timezone: %dt:~21,3%)
    set "timezone=UTC%dt:~21,3%"
    set "READABLE_DATE=%MONTH%/%dd%/%yyyy% %HH%:%mm%:%ss% %timezone%"
) else (
    :: Parsing DATE and TIME depends on locale settings, we'll just use them as the output for simplicity
    set "RAW_DATE=%DATE%"
    set "RAW_TIME=%TIME%"
    if "!TESTING!"=="true" (
        echo [DEBUG] RAW_DATE: %RAW_DATE%
        echo [DEBUG] RAW_TIME: %RAW_TIME%
    )
    set "READABLE_DATE=%RAW_DATE% %RAW_TIME%"
)
if "!TESTING!"=="true" (echo [DEBUG] Returning: %READABLE_DATE%)
endlocal & set "RESULT=%READABLE_DATE%"
goto :eof 


:: #############################
:GetWMICValue
@echo off
setlocal enabledelayedexpansion

:: Cache parameters to local variables
set "WMIC_CLASS=%~1"
set "WMIC_PROPERTY=%~2"
if "!TESTING!"=="true" (
    echo [DEBUG] Called GetWMICValue
    echo [DEBUG] WMIC_CLASS: !WMIC_CLASS!
    echo [DEBUG] WMIC_PROPERTY: !WMIC_PROPERTY!  
)

:: Set WMIC_EXE based on 32- or 64-bit Windows
if exist "%windir%\sysnative\wbem\wmic.exe" (
    set "WMIC_EXE=%windir%\sysnative\wbem\wmic.exe"
) else (
    set "WMIC_EXE=%windir%\system32\wbem\wmic.exe"
)
if "!TESTING!"=="true" (echo [DEBUG] WMIC_EXE: !WMIC_EXE!)

if "!TESTING!"=="true" (echo [DEBUG] Attempting: wmic !WMIC_CLASS! get !WMIC_PROPERTY!)
for /f "tokens=2 delims==" %%L in ('"%WMIC_EXE%" !WMIC_CLASS! get !WMIC_PROPERTY! /format:list 2^>nul') do (
    if "!TESTING!"=="true" (echo [DEBUG] WMIC Result: %%L)
    endlocal & set "RESULT=%%L"
    goto :wmic_returned
)

:: If we fell through, there was nothing
if "!TESTING!"=="true" (echo [DEBUG] WMIC returned nothing)
endlocal & set "RESULT=Unknown"
goto :wmic_returned

:wmic_returned
if "!TESTING!"=="true" (echo [DEBUG] Returning RESULT: "!RESULT!")
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
:: Print Helper Functions
:: #############################

:: Print Section Header
:: #############################
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

:: Print Cutsec Footer
:: #############################
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
:: Modularized function checks
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
    echo [DEBUG] HKLM_AIE: !HKLM_AIE!
    echo [DEBUG] HKCU_AIE: !HKCU_AIE!
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
goto :check_done

:not_elevated
echo [+] Users cannot install software as NT AUTHORITY\SYSTEM >> "%OUTFILE%"
echo [*] AlwaysInstallElevated Registry Values: ^(HKLM=!HKLM_AIE!, HKCU=!HKCU_AIE!^) >> "%OUTFILE%"
if "!TESTING!"=="true" (
    echo [+] Users cannot install software as NT AUTHORITY\SYSTEM
    echo [*] AlwaysInstallElevated Registry Values: ^(HKLM=!HKLM_AIE!, HKCU=!HKCU_AIE!^)
)
:check_done
if "!TESTING!"=="true" (echo [DEBUG] Completed :CheckAlwaysInstallElevated)
goto :eof 

