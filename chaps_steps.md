# CHAPS Assessment Steps
Running CHAPS may be confusing. The following list is a simple process for running an assessment to obtain configuration / hardening information from a Windows workstation or server. The first set of steps are scripts that can be used to gather information about the system using Administrator privileges on the local system. None of these checks will trigger anti-virus as long as the PowerShell execution policy is set to ```bypass```. The steps marked **AV TRIGGER** will trigger Windows Defender and, possibly, other AV / EDR solutions. These steps should be run as a local user, NOT Administrator, to limit false positives for Elevation of Privilege (EoP) vulnerabilities.

# Run CHAPS
## Start Web Server

On Linux system with CHAPS and other tools installed, note the IP address and start a Python web server. For this example, all tools are installed in the user's home directory in a subdirectory named Tools.

```
cd ~/Tools
ip addr
python3 -m http.server 8181
```

## Start Powershell or Windows Terminal as Administrator

Locate PowerShell or Windows Terminal in start menu, hold shift, right click, and select "Run as administrator".

## Allow Powershell to run scripts

```Set-ExecutionPolicy Bypass -scope Process```

## Run Chaps 

```IEX (New-Object Net.WebClient).DownloadString('http://<web server IP>:8181/chaps/chaps.ps1')```


## Review CHAPS Tool Output 
Check the user's AppData temp directory. In a Windows Explorer terminal, type the following in the address bar. Find the latest run of CHAPS and check output.

```%temp%```

# Run Active Directory Recon Scripts
## Run Trimarc AD Script. 
See: [Trimarc: Securing Active Directory: Performing an Active Directory Security Review](https://www.hub.trimarcsecurity.com/post/securing-active-directory-performing-an-active-directory-security-review)

```IEX (New-Object Net.WebClient).DownloadString('http://<web server IP>:8181/TrimarcAD/Invoke-TrimarcADChecks.ps1')```

## Review Tool output 

```c:\temp\Trimarc-ADReports```

# Run Third-Party OS Hardening Evaluation Scripts
Examples of how to run other hardening assessment scripts.

## Run Otorio PCS7 Hardening. 
See [Otorio: Siemens Simatic PCS 7 Hardening Tool](https://github.com/otoriocyber/PCS7-Hardening-Tool). Output is written to the screen.

```IEX (New-Object Net.WebClient).DownloadString('http://<web server IP>:8181/Otorio/PCS7-Hardening-Tool/PCS7Hardening.ps1')```
