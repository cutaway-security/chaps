# CHAPS Usage Guide

This document covers running CHAPS on a target Windows system: prerequisites, invocation, output handling, and troubleshooting.

For the check list, see [CHECKS.md](CHECKS.md). For interpreting the report, see [INTERPRETING_REPORTS.md](INTERPRETING_REPORTS.md).

## Prerequisites

- **Administrator privileges.** Most checks require elevation. The script will run as a non-administrator but will skip or report `[x]` on checks that need elevated access. See [Non-Administrator Execution](#non-administrator-execution) below.
- **Target version of the script.** Verify the target's PowerShell version before copying a script onto it:
  - PowerShell 5.1 / 3.0+ → `PowerShellv3/chaps_PSv3.ps1`
  - PowerShell 2.0 only → `PowerShellv2/chaps_PSv2.ps1`
  - No PowerShell, or PowerShell fully locked down → `CMD/chaps.bat`
- **Execution policy (PowerShell scripts only).** Scripts are unsigned. Set the policy for the current process:
  ```powershell
  Set-ExecutionPolicy Bypass -Scope Process
  ```
  This does not persist outside the current shell.

## Running the Scripts

Open PowerShell (or CMD for the batch script) **as Administrator** on the target system. Change to the folder containing the script.

All three scripts write Markdown to **stdout**. The operator controls where the report goes by redirecting output.

### PowerShell 3+

```powershell
Set-ExecutionPolicy Bypass -Scope Process
.\chaps_PSv3.ps1 > $env:COMPUTERNAME-chaps.md
```

### PowerShell 2

```powershell
Set-ExecutionPolicy Bypass -Scope Process
.\chaps_PSv2.ps1 > $env:COMPUTERNAME-chaps.md
```

The PSv2 script runs correctly on any PowerShell version from 2.0 up. It does not require `-Version 2` on modern systems.

### CMD Batch

```cmd
chaps.bat > %COMPUTERNAME%-chaps.md
```

## Output Patterns

Because CHAPS writes to stdout only, the operator has full control over output destination.

### Save to a file named after the host

```powershell
.\chaps_PSv3.ps1 > $env:COMPUTERNAME-chaps.md
```

### Save with a timestamp

```powershell
.\chaps_PSv3.ps1 > "$env:COMPUTERNAME-chaps-$(Get-Date -Format yyyyMMdd_HHmmss).md"
```

### View on screen (no file)

```powershell
.\chaps_PSv3.ps1
```

### Send to both screen and file (PowerShell only)

```powershell
.\chaps_PSv3.ps1 | Tee-Object -FilePath "$env:COMPUTERNAME-chaps.md"
```

CMD has no built-in equivalent of `Tee-Object`.

### Copy to clipboard (PowerShell only)

```powershell
.\chaps_PSv3.ps1 | Set-Clipboard
```

## Getting the Report Off the Target

CHAPS does not transmit anything. The report is a plain Markdown file sitting in the directory where the script was run. Move it off the target using whatever channel is approved for the environment:

- USB removable media (for air-gapped ICS systems)
- SMB share to a bastion or jump host
- Email to a reviewer (after verifying the file contains no credentials or other sensitive data)

Once the file is transferred, **delete the local copy** on the target.

## Configuration

All three scripts have a small configuration block at the top. You can edit these directly or leave the defaults.

| Setting | Default | Purpose |
|---|---|---|
| `auditor_company` | `Cutaway Security, LLC` | Auditing organization name in the report header. Empty string to omit. |
| `sitename` | `plant1` | Site or plant identifier. Empty string to omit. |
| `cutsec_footer` | `$true` / `true` | Include the Cutaway Security contact footer. |

Individual check toggles (`$get<CheckName>Check = $true`) are also at the top of each script, allowing specific checks to be disabled for a run. See [CHECKS.md](CHECKS.md) for the list.

## Non-Administrator Execution

Some checks can only be performed with administrator privileges (e.g., BitLocker volume status, WinRM service query, admin group membership). When CHAPS runs as a non-administrator:

- The report header shows `Admin Status: Normal User`.
- Admin-only checks emit `[x]` or `[*]` with an explanatory message and continue.
- Checks that can run without elevation still run.
- The script does not fail; the report is complete but less detailed.

For an accurate baseline, run as Administrator.

## Non-Admin Target with no PowerShell

If the target allows no elevation and no PowerShell, `CMD/chaps.bat` still runs most checks:

```cmd
chaps.bat > %COMPUTERNAME%-chaps.md
```

Four checks cannot be performed from CMD and will emit `[*] Not available in CMD ...` messages:

- AppLocker (requires `Get-AppLockerPolicy` cmdlet)
- ASR Rules (requires `Get-MpPreference` cmdlet)
- PowerShell Versions (requires PowerShell runtime)
- PowerShell Language Mode (requires PowerShell runtime)

## Troubleshooting

| Symptom | Cause | Resolution |
|---|---|---|
| `File ... cannot be loaded because running scripts is disabled on this system` | Execution policy blocks unsigned scripts. | Run `Set-ExecutionPolicy Bypass -Scope Process` in the current PowerShell window. |
| Report contains only `ERROR: This script requires PSv3+.` | `chaps_PSv3.ps1` run on PowerShell 2.0. | Use `chaps_PSv2.ps1` or `chaps.bat` instead. |
| Many `[x]` lines for BitLocker, WinRM, or service checks | Script run without Administrator rights. | Re-run as Administrator. |
| `Check for Critical and Important Windows patches test failed: no internet connection.` | Target is air-gapped; Windows Update cannot reach Microsoft. | This is expected in isolated environments. The check is informational only; verify patches by other means. |
| CMD report contains blank `[*]` lines | Known and fixed in version 2.0. Confirm you're running the latest script. | Update to the current `chaps.bat`. |
| PowerShell 2 run over SSH hangs at exit | Known SSH / PS 2.0 interaction on Windows 7. | Run interactively, or capture output inside the VM (`Out-File ...`) and retrieve the file separately. |
| Output contains `Get-ComputerInfo ... Access is denied` | Non-interactive session limitation. | The script's fallback chain (WMI → systeminfo) still produces system info. Ignore the stderr line. |

## What CHAPS Does Not Do

CHAPS is read-only. It does not:

- Modify any registry keys, services, policies, files, or permissions.
- Remediate findings. See [REMEDIATION.md](REMEDIATION.md) for guidance on fixing issues found.
- Scan the network or any remote system. It inspects only the local machine.
- Exfiltrate data. It writes to stdout; the operator chooses what to do with the output.
- Require any installed tools beyond what ships with Windows.

## Removing CHAPS

The scripts are single files. To remove CHAPS from a target:

1. Delete the script file: `del chaps_PSv3.ps1` (or equivalent).
2. Delete the report file(s) after transferring them off the system.

No registry keys, services, scheduled tasks, or other persistent artifacts are created by running CHAPS.
