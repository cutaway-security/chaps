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
set "TESTING=false"

:: Set COMPANY and SITENAME to empty string to disable
set "COMPANY=Cutaway Security, LLC"
set "SITENAME=Plant 1"
:: Set CUTSEC_FOOTER to false to disable
set "CUTSEC_FOOTER=true"

:: Get the current date and time components for setting output directory
for /f "tokens=2 delims==" %%i in ('"wmic os get localdatetime /value"') do set dt=%%i 
set "yyyy=%dt:~0,4%"
set "dd=%dt:~6,2%"
set "MM=%dt:~4,2%"
set "HH=%dt:~8,2%"
set "mm=%dt:~10,2%"
set "ss=%dt:~12,2%"
:: Format as yyyyddMM_HHmmss for the filename
set "FILENAME_DATE=%yyyy%%dd%%MM%_%HH%%mm%%ss%"
:: Format as MM/dd/yyyy HH:mm:ss K for readable date in report
set "timezone=UTC%dt:~21,3%"
set "READABLE_DATE=%MM%/%dd%/%yyyy% %HH%:%mm%:%ss% %timezone%"

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
) else (
    set "WMIC_PRESENT=false"
)

:: Create output directory if it doesn't exist
if "!TESTING!"=="true" (echo [DEBUG] Creating !OUTDIR!)
if not exist "!OUTDIR!" (
    mkdir "!OUTDIR!" >nul 2>&1
)

if "!TESTING!"=="true" (
    echo [DEBUG] Script running in DEBUG mode
    echo [DEBUG] COMPANY: !COMPANY!
    echo [DEBUG] SITENAME: !SITENAME!
    echo [DEBUG] CUTSEC_FOOTER: !CUTSEC_FOOTER!
    echo [DEBUG] FILENAME_DATE: FILENAME_DATE
    echo [DEBUG] timezone: timezone
    echo [DEBUG] READABLE_DATE: READABLE_DATE
    echo [DEBUG] OUTDIR: OUTDIR
    echo [DEBUG] OUTFILENAME: OUTFILENAME
    echo [DEBUG] SYSINFO_FILENAME: SYSINFO_FILENAME
    echo [DEBUG] SCRIPTNAME: SCRIPTNAME
    echo [DEBUG] SCRIPTVERSION: SCRIPTVERSION
    echo [DEBUG] OUTFILE: OUTFILE
    echo [DEBUG] SYSINFO_FILE: SYSINFO_FILE
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

:: Check Admin Rights
if "!TESTING!"=="true" (echo [DEBUG] Checkign Administrator permissions)
whoami /groups | findstr /i "S-1-5-32-544" >nul
if %errorlevel%==0 (
    if "!TESTING!"=="true" (echo [+] Script running as Administrator)
    echo [+] Script running as Administrator >> "%OUTFILE%"
) else (
    if "!TESTING!"=="true" (echo [x] Script NOT running as Administrator)
    echo [x] Script NOT running as Administrator >> "%OUTFILE%"
)
if "!TESTING!"=="true" (echo ##########################)
echo ########################## >> "%OUTFILE%"

:: ###########################
:: System Info Checks
:: ###########################
if "!TESTING!"=="true" (echo [DEBUG] Calling PrtSectionHeader System Info)
call :PrtSectionHeader System Info
if "!TESTING!"=="true" (echo [DEBUG] Returned from PrtSectionHeader)
echo [*] Collecting systeminfo to: %SYSINFO_FILE%
systeminfo > "%SYSINFO_FILE%"

:: Get Poduct Name
if "!TESTING!"=="true" (echo [DEBUG] Attempting to get Product Name)
if "!WMIC_PRESENT"=="true" (
    if "!TESTING!"=="true" (echo [DEBUG] Calling :GETWMICValue os Caption)
    call :GetWMICValue os Caption
    if "!TESTING!"=="true" (echo [DEBUG] Setting OS_NAME: !RESULT!)
    set "OS_NAME=!RESULT!"
) else (
    if "!TESTING!"=="true" (echo [DEBUG] Setting OS_NAME: Unknown WMIC not available)
    set "OS_NAME=Unknown (WMIC not available)"
)

:: Get OS Version
if "!TESTING!"=="true" (echo [DEBUG] Attempting to get OS Version)
if "!WMIC_PRESENT!"=="true" (
    if "!TESTING!"=="true" (echo [DEBUG] Calling :GETWMICValue os Version)
    call :GetWMICValue os Version
    if "!TESTING!"=="true" (echo [DEBUG] Setting OS_VERSION: !RESULT!)
    set "OS_VERSION=!RESULT!"
) else (
    if "!TESTING!"=="true" (echo [DEBUG] Attempting to use 'ver' command)
    for /f "tokens=2 delims=[]" %%A in ('ver') do set "OS_VERSION=%%A"
)

:: Get Architecture
if "!TESTING!"=="true" (echo [DEBUG] Attempting to get OS Architecture)
if "!WMIC_PRESENT!"=="true" (    
    if "!TESTING!"=="true" (echo [DEBUG] Calling :GETWMICValue os OSArchitecture)
    call :GetWMICValue os OSArchitecture
    if "!TESTING!"=="true" (echo [DEBUG] Setting OS_ARCH: !RESULT!)
    set "OS_ARCH=!RESULT!"
) else (
    if "!TESTING!"=="true" (echo [DEBUG] Attempting to use PROCESSOR_ARCHITEW6432 environment value)
    set "OS_ARCH=x86"
    if defined PROCESSOR_ARCHITEW6432 set "OS_ARCH=x64"
)

:: Get System Type
if "!TESTING!"=="true" (echo [DEBUG] Attempting to get System Type)
if "!WMIC_PRESENT!"=="true" (
    if "!TESTING!"=="true" (echo [DEBUG] Calling GetWMICValue computersystem SystemType)
    call :GetWMICValue computersystem SystemType
    if "!TESTING!"=="true" (echo [DEBUG] Setting SYS_TYPE: !RESULT!)
    set "SYS_TYPE=!RESULT!"
) else (
    if "!TESTING!"=="true" (echo [DEBUG] Attempting to use PROCESSOR_ARCHITECTURE environment value)
    set "SYS_TYPE=%PROCESSOR_ARCHITECTURE%"
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
    echo [*] OS Version: !OS_VERSION!
    echo [*] OS Architecture: !OS_ARCH!
    echo [*] System Type: !SYS_TYPE!
    echo [*] Domain/Workgroup: !DOMAIN!
    echo [*] Effective Path: %PATH%    
)
echo [*] Windows Product: !OS_NAME! >> "%OUTFILE%"
echo [*] OS Version: !OS_VERSION! >> "%OUTFILE%"
echo [*] OS Architecture: !OS_ARCH! >> "%OUTFILE%"
echo [*] System Type: !SYS_TYPE! >> "%OUTFILE%"
echo [*] Domain/Workgroup: !DOMAIN! >> "%OUTFILE%"
echo [*] Effective Path: %PATH% >> "%OUTFILE%"

:: Auto Update Registry Check
echo. >> "%OUTFILE%"
:: Query AUOptions value from registry
for /f "tokens=3" %%A in ('reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v AUOptions 2^>nul') do (
    set "AU_VAL=%%A"
)

:: Decode the value (if present)
if defined AU_VAL (
    if "!AU_VAL!"=="1" set "AU_DESC=Disabled"
    if "!AU_VAL!"=="2" set "AU_DESC=Notify before download"
    if "!AU_VAL!"=="3" set "AU_DESC=Notify before installation"
    if "!AU_VAL!"=="4" set "AU_DESC=Scheduled installation"
    if "!AU_VAL!"=="0" set "AU_DESC=Not configured"

    set /a AU_NUM=!AU_VAL! >nul 2>&1
    if !AU_NUM! EQU 4 (
        echo [+] Auto Update setting: !AU_VAL! - !AU_DESC! >> "%OUTFILE%"
    ) else (
        echo [-] Auto Update setting: !AU_VAL! - !AU_DESC! >> "%OUTFILE%"
    )
) else (
    echo [x] Windows AutoUpdate test failed (AUOptions registry value not found) >> "%OUTFILE%"
)

:: Check IPv4 Address
echo. >> "%OUTFILE%"
echo [*] Network Interfaces (IPv4): >> "%OUTFILE%"
for /f "tokens=2 delims=:" %%A in ('ipconfig ^| findstr /C:"IPv4 Address"') do (
    echo    %%A >> "%OUTFILE%"
)

:: BitLocker Status
echo. >> "%OUTFILE%"
echo [*] BitLocker Status (Drive C:): >> "%OUTFILE%"
manage-bde -status C: >> "%OUTFILE%" 2>nul

:: SMBv1 Status
echo. >> "%OUTFILE%"
echo [*] Checking if SMBv1 is enabled: >> "%OUTFILE%"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v SMB1 >> "%OUTFILE%" 2>nul


:: #############################
:: Print Document Footer
:: #############################

if "!TESTING!"=="true" (echo [DEBUG] Printing document footer)
:: Get the current date and time components
for /f "tokens=2 delims==" %%i in ('"wmic os get localdatetime /value"') do set dt=%%i 
set "yyyy=%dt:~0,4%"
set "dd=%dt:~6,2%"
set "MM=%dt:~4,2%"
set "HH=%dt:~8,2%"
set "mm=%dt:~10,2%"
set "ss=%dt:~12,2%"
:: Format as MM/dd/yyyy HH:mm:ss K for readable date in report
set "timezone=UTC%dt:~21,3%"
set "STOP_TIME_READABLE=%MM%/%dd%/%yyyy% %HH%:%mm%:%ss% %timezone%"

if "!TESTING!"=="true" (
    echo ##########################
    echo # %SCRIPTNAME% completed
    echo # Stop Time: %STOP_TIME_READABLE%
)
echo. >> "%OUTFILE%"
echo ########################## >> "%OUTFILE%"
echo # %SCRIPTNAME% completed >> "%OUTFILE%"
echo # Stop Time: %STOP_TIME_READABLE% >> "%OUTFILE%"
echo # Report saved to: %OUTFILE%
if "!TESTING!"=="true" (echo ##########################)
echo ########################## >> "%OUTFILE%"

:: #############################
:: Print Cutsec Footer
:: #############################

if "!CUTSEC_FOOTER!"=="true" (
    if "!TESTING!"=="true" (
        echo ##########################
        echo # CHAPS Audit Script: %SCRIPTNAME% %SCRIPTVERSION%
        echo # Brought to you by Cutaway Security, LLC
        echo # For assessment and auditing help, contact info [@] cutawaysecurity.com
        echo # For script help, contact dev [@] cutawaysecurity.com
        echo ##########################
    )
    echo. >> "%OUTFILE%"
    echo ########################## >> "%OUTFILE%"
    echo # CHAPS Audit Script: %SCRIPTNAME% %SCRIPTVERSION% >> "%OUTFILE%"
    echo # Brought to you by Cutaway Security, LLC >> "%OUTFILE%"
    echo # For assessment and auditing help, contact info [@] cutawaysecurity.com >> "%OUTFILE%"
    echo # For script help, contact dev [@] cutawaysecurity.com >> "%OUTFILE%"
    echo ########################## >> "%OUTFILE%"
)

:: #############################
:: Helper Functions
:: #############################

:: #############################
:GetWMICValue
setlocal enabledelayedexpansion
if !TESTING!=="true" (echo [DEBUG] Called GetWMICValue)
set "RESULT="

:: Run WMIC, skip the header, throw away blank lines
for /f "skip=1 tokens=*" %%i in ('
        wmic %1 get %2 2^>nul ^
          ^| findstr /r /v "^$"
    ') do (
        if "!TESTING!"=="true" (echo [DEBUG] WMIC found result)
        :: Immediately capture %%i into the parent environment, then return
        endlocal & set "RESULT=%%i"
        if "!TESTING!"=="true" (echo [DEBUG] WMIC returning: !RESULT!)
        goto :EOF
    )

:: If we fell through, there was nothing
endlocal & set "RESULT="
if "!TESTING!"=="true" (
    echo [DEBUG] WMIC did not find a value 
    echo [DEBUG] Returning RESULT: !RESULT!
)
goto :eof

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
