# CHAPS Assessment Guide
Running CHAPS may be confusing. The following list is a simple process for running an assessment to obtain configuration / hardening information from a Windows workstation or server. The first set of steps are scripts that can be used to gather information about the system using Administrator privileges on the local system. None of these checks will trigger anti-virus as long as the PowerShell execution policy is set to `bypass`. The steps marked **AV TRIGGER** will trigger Windows Defender and, possibly, other AV / EDR solutions. These steps should be run as a local user, NOT Administrator, to limit false positives for Elevation of Privilege (EoP) vulnerabilities.

## Run CHAPS
### Start Web Server

On a Linux system with `chaps.ps1` installed, open a command prompt and navigate to the directory containing the `chaps.ps1` script. Note the IP address and start a Python web server. For this example, the script is installed in the user's home directory in a subdirectory named CHAPS.

`cd ~/CHAPS`

Note the IP address of the system hosting the `chaps.ps1` script.

`ip addr`

Use Python to start a webserver on port 8181.

`python3 -m http.server 8181`

### Start Powershell as Administrator and Allow Script Execution
Locate PowerShell or Windows Terminal in start menu, hold shift, right click, and select "Run as administrator".

#### Allow PowerShell to run scripts by starting from command prompt
From the cmd.exe prompt, run the following command  to begin a PowerShell prompt.

`powershell.exe -exec bypass`

#### Allow PowerShell to run scripts by setting ExecutionPolicy from PowerShell
From a PowerShell prompt, run the following command.

`Set-ExecutionPolicy Bypass -scope Process`.

### Run Chaps 
From the PowerShell prompt, run the folllowing command to execute the `chaps.ps1` script.

`IEX (New-Object Net.WebClient).DownloadString('http://<web server IP>:8181/chaps.ps1')`

### Review CHAPS Tool Output 
#### Navigate to CHAPS Output Directory
The `chaps.ps1` script saves the ouptut to the user's `%TEMP` directory. One way to navigate to this directory is to open Windows Explorer and type the following in the address bar.

`%temp%`

The CHAPS output is saved in a subdirectory named `chaps-<DATE>-<TIME>`. Navigate to this subdirectory to view the output.

#### Review Tool output 
The script results are saved in a file named `<Computer Name>-chaps.txt`. Findings in the report output are represented by a flag at the start of each line.

`[+]` Positive Findings: System is configured to recommendation
`[-]` Negative Findings: System is configured against security/audit recommmendation
`[x]` Error Reports: A check failed and so the configuration is unknown
`[*]` Informational Text: Information about the script and/or checks being performed
`[$]` Report Information: Information about the report generation (e.g. time it was run)