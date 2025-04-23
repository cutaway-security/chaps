:: chaps.bat - a Windows batch script for checking system security
:: when conducting an assessment of systems where the Microsoft 
:: Policy Analyzer and other assessment tools cannot be installed.

:: Author: Don C. Weber (@cutaway)
:: Date:   April 22, 2025
@echo off
setlocal enabledelayedexpansion


:: #############################
:: Set User-Configurable Variables
:: #############################

:: Set COMPANY, SITENAME, and CUTSEC_FOOTER to empty string to disable
set "COMPANY=Cutaway Security, LLC"
set "SITENAME=Plant 1"
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

:: Report is saved to user's temp directory by default
set "OUTFILE=%TEMP%\%COMPUTERNAME%_%FILENAME_DATE%\%COMPUTERNAME%_chaps.txt"
set "SYSINFO_FILE=%TEMP%\%COMPUTERNAME%_%FILENAME_DATE%\%COMPUTERNAME%_sysinfo.txt""

:: #############################
:: Set Non-Configurable Variables
:: #############################

set "SCRIPTNAME=chaps.bat"
set "SCRIPTVERSION=1.0.0"

:: Check if WMIC is available and set flag
where wmic >nul 2>&1
if %errorlevel%==0 (
    set "WMIC_PRESENT=true"
) else (
    set "WMIC_PRESENT=false"
)

:: #############################
:: Print Document Header
:: #############################

:: Show where document is saved to (not written to report)
echo ##########################
echo # Saving output to: %OUTFILE%
echo ##########################

:: Create outfile and begin writing to it.
echo ########################## > "%OUTFILE%"
echo # CHAPS Audit Script: %SCRIPTNAME% %SCRIPTVERSION% >> "%OUTFILE%"
if defined COMPANY (echo # Auditing Company: %COMPANY% >> "%OUTFILE%")
if defined SITENAME (echo # Site/Plant: %SITENAME%) >> "%OUTFILE%"
echo ########################## >> "%OUTFILE%"
echo # %COMPUTERNAME% >> "%OUTFILE%"
echo # Start Time: %READABLE_DATE% >> "%OUTFILE%"

:: Check Admin Rights
whoami /groups | findstr /i "S-1-5-32-544" >nul
if %errorlevel%==0 (
    echo [+] Script running as Administrator >> "%OUTFILE%"
) else (
    echo [x] Script NOT running as Administrator >> "%OUTFILE%"
)
echo ########################## >> "%OUTFILE%"

:: ###########################
:: System Info Checks
:: ###########################
call :PrtSectionHeader "System Info"

echo [*] Collecting systeminfo to: %SYSINFO_FILE%
systeminfo > "%SYSINFO_FILE%"

if "!WMIC_PRESENT!"=="true" (
    :: Product Name
    for /f "skip=1 tokens=*" %%i in ('wmic os get Caption') do (
        if not "%%i"=="" set "OS_NAME=%%i"
    )

    :: OS Version
    for /f "skip=1 tokens=*" %%i in ('wmic os get Version') do (
        if not "%%i"=="" set "OS_VERSION=%%i"
    )

    :: Architecture
    for /f "skip=1 tokens=*" %%i in ('wmic os get OSArchitecture') do (
        if not "%%i"=="" set "OS_ARCH=%%i"
    )

    :: System Type
    for /f "skip=1 tokens=*" %%i in ('wmic computersystem get SystemType') do (
        if not "%%i"=="" set "SYS_TYPE=%%i"
    )

    :: Domain / Workgroup
    for /f "skip=1 tokens=*" %%i in ('wmic computersystem get Domain') do (
        if not "%%i"=="" set "DOMAIN=%%i"
    )
) else (
    :: Product Name
    set "OS_NAME=Unknown (WMIC not available)"

    :: OS Version
    for /f "tokens=2 delims=[]" %%A in ('ver') do set "OS_VERSION=%%A"

    :: Architecture
    set "OS_ARCH=x86"
    if defined PROCESSOR_ARCHITEW6432 set "OS_ARCH=amd64"

    :: System Type
    set "SYS_TYPE=%PROCESSOR_ARCHITECTURE%"

    :: Product Name & Domain not available without WMIC
    set "DOMAIN=Unknown (WMIC not available)"
)

echo [*] Windows Product: !OS_NAME! >> "%OUTFILE%"
echo [*] OS Version: !OS_VERSION! >> "%OUTFILE%"
echo [*] OS Architecture: !OS_ARCH! >> "%OUTFILE%"
echo [*] System Type: !SYS_TYPE! >> "%OUTFILE%"
echo [*] Domain/Workgroup: !DOMAIN! >> "%OUTFILE%"
echo [*] Effective Path: %PATH% >> "%OUTFILE%"

:PrtSectionHeader
set "SectionName=%~1"
>> "%OUTFILE%" echo.
>> "%OUTFILE%" echo ##########################
>> "%OUTFILE%" echo # %SectionName%
>> "%OUTFILE%" echo ##########################
goto :eof



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

echo. >> "%OUTFILE%"
echo ########################## >> "%OUTFILE%"
echo # %SCRIPTNAME% completed >> "%OUTFILE%"
echo # Stop Time: %STOP_TIME_READABLE% >> "%OUTFILE%"
echo # Report saved to: %OUTFILE%
echo ########################## >> "%OUTFILE%"

:: #############################
:: Print Cutsec Footer
:: #############################

if "!CUTSEC_FOOTER!"=="true" (
    echo. >> "%OUTFILE%"
    echo ########################## >> "%OUTFILE%"
    echo # CHAPS Audit Script: %SCRIPTNAME% %SCRIPTVERSION% >> "%OUTFILE%"
    echo # Brought to you by Cutaway Security, LLC >> "%OUTFILE%"
    echo # For assessment and auditing help, contact info [@] cutawaysecurity.com >> "%OUTFILE%"
    echo # For script help, contact dev [@] cutawaysecurity.com >> "%OUTFILE%"
    echo ########################## >> "%OUTFILE%"
)

endlocal