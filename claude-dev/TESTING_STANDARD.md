# TESTING_STANDARD.md

How to test the CHAPS scripts (`chaps_PSv3.ps1`, `chaps_PSv2.ps1`, `chaps.bat`) across the development VM fleet. This standard governs what is tested, how tests are run, and how results are recorded.

For VM setup, connectivity, and lifecycle details see `claude-dev/REMOTE_TESTING.md`.

---

## 1. Scope

This standard covers three categories of testing, performed in this order:

1. **Script testing** -- does the script run to completion on the target OS without crashing?
2. **Output validation** -- is the output valid markdown with all expected sections, correct status prefixes, and no unhandled errors?
3. **Parity testing** -- do all three scripts produce equivalent check coverage on the same VM?

Each category has its own procedures and pass/fail criteria defined below. Do not proceed to a later category until the earlier one passes.

---

## 2. Test Environment

### 2.1 Available systems

| SSH Alias | VMID | Proxmox | OS | PS Version | Scripts Supported | Notes |
|---|---|---|---|---|---|---|
| Win7Pro-Dev | 107 | proxmox0 | Windows 7 Pro | 2.0 | PSv2, CMD | PSv3 will exit with version error (expected). Limited cmdlet availability. |
| Win10Pro-Dev | 108 | proxmox0 | Windows 10 Pro (1809) | 5.1.17763.1 | PSv3, PSv2, CMD | Primary parity test target. |
| Win11Pro-Dev | 102 | proxmox0 | Windows 11 Pro | 5.1.22621.4249 | PSv3, PSv2, CMD | `[System.Environment]::OSVersion.Version.Major` still reports 10. |
| WinServer2016-Dev | 110 | proxmox0 | Windows Server 2016 | 5.1.14393.693 | PSv3, PSv2, CMD | No SecurityCenter2 namespace. |
| WinServer2019-Dev | 109 | proxmox0 | Windows Server 2019 | 5.1.17763.8510 | PSv3, PSv2, CMD | No SecurityCenter2 namespace. `Get-MpComputerStatus` fallback used. |
| WinServer2022-Dev | 111 | proxmox0 | Windows Server 2022 | 5.1.20348.4294 | PSv3, PSv2, CMD | Windows LAPS may be built-in. |

Systems aliased but not yet built (VMID = N/A): WinServer2012-Dev, WinServer2025-Dev. Do not include in test runs until installed and added to this table.

### 2.2 VM lifecycle rules

- **Maximum 3 VMs running concurrently.** The Proxmox hosts are Intel NUCs with limited RAM.
- **Start before testing, stop when done.** Do not leave VMs running overnight or between sessions.
- Start/stop via SSH to the Proxmox host using the VMID (look up via `claude-dev/vm-lookup vmid <alias>` or read from the table above):
  ```
  ssh proxmox0 "qm start <VMID>"
  ssh proxmox0 "qm stop <VMID>"
  ssh proxmox0 "qm status <VMID>"
  ```
- **Single source of truth: `~/.ssh/config`.** The developer workstation's SSH config holds the host alias, IP, user, key, and VMID for every test VM. The VMID is stored as a structured comment on each host entry (format: `# VMID=<id> PROXMOX=<alias>`). Use SSH aliases (e.g., `Win10Pro-Dev`) for all test commands, not raw IPs.

### 2.3 File transfer pattern

```
# Copy a script to a VM
scp <local-script> <SSH-Alias>:C:/Temp/<filename>

# Run and capture markdown output locally
ssh <SSH-Alias> "<shell-command-invoking-script>" > claude-dev/results/<alias>-<script>.md

# Clean up
ssh <SSH-Alias> "del C:\Temp\<filename>"
```

The `C:\Temp` directory must exist on the VM. Create it with `ssh <alias> "mkdir C:\Temp"` if needed.

Result files land in `claude-dev/results/` (gitignored).

---

## 3. Script Testing

### 3.1 Invocation matrix

How each CHAPS script is invoked on each VM:

| Script | File | Invocation |
|---|---|---|
| PSv3 | `PowerShellv3/chaps_PSv3.ps1` | `powershell -ExecutionPolicy Bypass -File C:/Temp/chaps_PSv3.ps1` |
| PSv2 | `PowerShellv2/chaps_PSv2.ps1` | `powershell -Version 2 -ExecutionPolicy Bypass -File C:/Temp/chaps_PSv2.ps1` |
| CMD | `CMD/chaps.bat` | `cmd /c C:/Temp/chaps.bat` |

### 3.2 Test matrix -- PSv3

| Result | Win10 | Win11 | Srv 2016 | Srv 2019 | Srv 2022 | Win7 (expect version error) |
|---|---|---|---|---|---|---|
| Script completes | PASS 2026-04-13 | PASS 2026-04-13 | PASS 2026-04-13 | PASS 2026-04-13 | PASS 2026-04-13 | PASS 2026-04-13 (clean version error) |
| Admin checks run | PASS 2026-04-13 | PASS 2026-04-13 | PASS 2026-04-13 | PASS 2026-04-13 | PASS 2026-04-13 | N/A |
| Non-admin graceful | Not yet tested | Not yet tested | Not yet tested | Not yet tested | Not yet tested | N/A |

### 3.3 Test matrix -- PSv2

| Result | Win7 | Win10 | Win11 | Srv 2016 | Srv 2019 | Srv 2022 |
|---|---|---|---|---|---|---|
| Script completes | PASS 2026-04-13 | PASS 2026-04-13 | PASS 2026-04-13 | PASS 2026-04-13 | PASS 2026-04-13 | PASS 2026-04-13 |
| Admin checks run | PASS 2026-04-13 | PASS 2026-04-13 | PASS 2026-04-13 | PASS 2026-04-13 | PASS 2026-04-13 | PASS 2026-04-13 |
| Non-admin graceful | Not yet tested | Not yet tested | Not yet tested | Not yet tested | Not yet tested | Not yet tested |

### 3.4 Test matrix -- CMD

| Result | Win7 | Win10 | Win11 | Srv 2016 | Srv 2019 | Srv 2022 |
|---|---|---|---|---|---|---|
| Script completes | PASS 2026-04-13 | PASS 2026-04-13 | PASS 2026-04-13 | PASS 2026-04-13 | PASS 2026-04-13 | PASS 2026-04-13 |
| Admin checks run | PASS 2026-04-13 | PASS 2026-04-13 | PASS 2026-04-13 | PASS 2026-04-13 | PASS 2026-04-13 | PASS 2026-04-13 |
| Non-admin graceful | Not yet tested | Not yet tested | Not yet tested | Not yet tested | Not yet tested | Not yet tested |

Result format: `PASS YYYY-MM-DD` or `FAIL YYYY-MM-DD: <reason>`.

### 3.4.1 Bugs surfaced and fixed during 2026-04-13 test run

- **CMD/chaps.bat had LF line endings** -- Windows CMD parser silently skipped Checks 11-33 on all VMs. Fixed by converting to CRLF. All 59 checks now emit.
- **Get-BitLocker manage-bde fallback threw CommandNotFound** on Server editions where BitLocker feature isn't installed. Fixed with a `Get-Command manage-bde.exe` probe before calling; emits an `[*]` info line when neither path is available.
- **PSv2 Get-CredDeviceGuard and Get-AntiVirus used `-ClassName`** (Cim parameter) with `Get-WmiObject` (which uses `-Class`). Also had Unicode en-dash characters inherited from earlier branch history. Fixed both.
- **Get-SystemInfo** already wrapped in try/catch chain with Get-ComputerInfo -> WMI -> systeminfo fallback from prior fix; behaved correctly on all VMs.

### 3.5 Procedure

For each script on each VM:

1. Deploy script to `C:\Temp\` via scp.
2. Execute remotely using the invocation from Section 3.1, redirecting stdout to `claude-dev/results/<alias>-<script>.md`.
3. Check exit status: no crash, no unhandled exceptions.
4. Proceed to Section 4 (Output Validation) for the result file.
5. Record the result in the appropriate matrix above.
6. Clean up the script on the VM (`del`).

### 3.6 Pass criteria

A script **passes** on a given system if:
- It runs to completion with exit code 0 (or the expected error code for negative tests like PSv3 on Win7).
- Output matches the markdown structure in Section 4.1.
- Non-admin execution: admin-required checks report `[x]` or `[*]` gracefully; the script continues and completes.

A script **fails** if:
- It crashes, hangs, or produces a PowerShell/batch error that leaks past the try/catch harness.
- Expected section headers are missing from the output.
- The script silently skips checks that should run on the target OS (no output at all for a check).

### 3.7 Failure handling

If a test fails:
1. Record the failure with error details in the matrix.
2. Snapshot the VM state if needed for debugging.
3. Fix the script.
4. Re-test on the same VM.
5. Re-test on other VMs to verify no regression.

---

## 4. Output Validation

### 4.1 Markdown structure check

Every output file must contain:

```
# CHAPS Report: <name> <version>

| Field | Value |
|-------|-------|
| Hostname | ... |
...

## System Info Checks
...
## Security Checks
...
## Authentication Checks
...
## Network Checks
...
## PowerShell Checks
...
## Logging Checks
...
---
**<name> completed** -- Stop Time: ...
```

### 4.2 Validation commands

Run these from the developer workstation against the captured result file:

```
# Check report header exists
head -1 claude-dev/results/Win10Pro-Dev-psv3.md | grep "# CHAPS Report:"

# Count section headers (expected: 6)
grep -c "^## " claude-dev/results/Win10Pro-Dev-psv3.md

# Count findings by type
grep -c "^\[+\]" claude-dev/results/Win10Pro-Dev-psv3.md    # Positive
grep -c "^\[-\]" claude-dev/results/Win10Pro-Dev-psv3.md    # Negative
grep -c "^\[\*\]" claude-dev/results/Win10Pro-Dev-psv3.md   # Informational
grep -c "^\[x\]" claude-dev/results/Win10Pro-Dev-psv3.md    # Errors
```

### 4.3 Pass criteria

- First line of output is `# CHAPS Report: <script-name> <version>`.
- Exactly 6 top-level `## ` section headers (System Info, Security, Authentication, Network, PowerShell, Logging).
- No `[x]` errors for checks that should succeed on the target OS. `[x]` errors are expected for unreachable/unconfigured checks (e.g., antivirus on a server without SecurityCenter2) -- these should be followed by `[*]` info messages explaining why.
- Closing footer line present.

---

## 5. Parity Testing

### 5.1 When

Before any release. Run all three scripts on the same VM (Win10Pro-Dev is the primary parity target because all three scripts are supported there).

### 5.2 Procedure

1. Run PSv3, PSv2, and CMD on Win10Pro-Dev, capturing output to three separate files in `claude-dev/results/`.
2. Compare section headers: must be identical across all three (same six `## ` headers, same order).
3. Compare check coverage: each canonical check must appear in all three outputs. Findings may differ in detail (different methods produce different wording) but every check must be attempted.
4. Verify N/A checks in CMD (AppLocker, ASR Rules, PowerShell Versions, PowerShell Language Mode) output `[*]` info messages referencing PowerShell-only cmdlets or runtime requirements.

### 5.3 Parity matrix

Parity run on Win10Pro-Dev, 2026-04-13:

| Measure | PSv3 | PSv2 | CMD |
|---|---|---|---|
| Output lines | 182 | 192 | 554 |
| `## ` section headers | 6 | 6 | 7 (6 + footer) |
| `### Check N:` subheaders | (not used) | (not used) | 59 |
| `[+]` positive | 36 | 34 | 22 |
| `[-]` negative | 53 | 63 | 16 |
| `[*]` informational | 54 | 56 | 299 |
| `[x]` error | 1 (no internet) | 1 (no internet) | 0 |

The CMD script's higher `[*]` count is expected -- it prefixes each line of `net accounts`, `netstat -ano`, installed-software enumeration, and similar raw-output checks with `[*]`. PowerShell scripts summarize the same information more compactly. Check coverage is equivalent across all three scripts; every canonical check is attempted.

---

## 6. Test Run Documentation

### 6.1 During a test run

Record the following for each test:
- Date
- VM alias (e.g., Win10Pro-Dev)
- Script tested (PSv3 / PSv2 / CMD)
- Admin or non-admin execution
- Result (PASS / FAIL)
- Error details if FAIL
- Any new per-OS quirks discovered

### 6.2 After a test run

Update:
- Test matrices in this file (date-stamped results, Sections 3.2-3.4)
- Parity matrix if a parity run (Section 5.3)
- `claude-dev/RESUME.md` with a test summary
- Per-OS quirks in Section 7 below

### 6.3 Re-testing after changes

After any script change:
- Re-test on Win10Pro-Dev (primary target) at minimum.
- Re-test on Win7Pro-Dev if PSv2 or CMD was changed.
- Re-test on one Server edition if server-specific checks were changed.
- Full fleet re-test before any release tag.

---

## 7. Version-Specific Notes

Known per-OS behavior observed during development. Update this as real test runs surface additional quirks.

### 7.1 Win7Pro-Dev (PS 2.0)

- PSv3 exits with a version-check error. This is a PASS (the script handles version gracefully), not a FAIL.
- PSv2 runs but several cmdlets are unavailable: `Get-PnpDevice`, `Get-MpPreference`, `Get-MpComputerStatus`, `Get-NetTCPConnection`, `Get-NetFirewallProfile`, `Get-ProcessMitigation`, `Confirm-SecureBootUEFI`, `Get-LocalUser`. The script falls back to WMI / registry / native commands behind `Test-CommandExists` gates.
- CMD runs without issue; most checks work via `reg query`, `sc query`, `wmic`.
- SecurityCenter2 namespace behavior on Win7 is inconsistent; the script catches and falls back.

### 7.2 Win10Pro-Dev / Win11Pro-Dev (PS 5.1)

- All three scripts are fully supported. Primary parity target.
- Win11 reports `OSVersion.Version.Major = 10`. Checks using `-ge 10` work correctly; checks using `-eq 10` would incorrectly treat Win11 as Win10. All CHAPS PSv3 checks use `-ge 10` (fixed in Phase 2).
- Win10Pro-Dev in the lab is build 1809 (17763) -- older than typical workstation 22H2 but sufficient for PSv3 testing.
- **Known issue observed during connection testing:** `Get-ComputerInfo` fails under non-interactive SSH sessions with `Win32 internal error "Access is denied" ... while reading the console output buffer`. This affects `Get-SystemInfo` in the PSv3 script (line ~274). The function's `Test-CommandExists` gate returns true (the cmdlet is present), but the cmdlet throws at runtime. Needs fix during script testing: wrap `Get-ComputerInfo` in try/catch and fall back to `systeminfo` parsing on failure.

### 7.3 Server VMs (2016, 2019, 2022)

- Use `Administrator` (not `<lab-user>`) as the SSH user. Configured in `~/.ssh/config` wildcard block.
- These VMs are stopped by default. Start them before testing and stop them when done.
- No `SecurityCenter2` WMI namespace -- `Get-AntiVirus` falls back to `Get-MpComputerStatus` (Defender-only).
- PS version on each should be verified on first test and recorded in the Section 2.1 table.

---

## 8. Adding a New Test System

When a new VM is added to the fleet (e.g., Server 2012, Server 2025):

1. Add a `Host <alias>` block to `~/.ssh/config` with `HostName` and a `# VMID=<id> PROXMOX=<alias>` comment line.
2. Add a row to the "Available systems" table in Section 2.1 (SSH alias, VMID, Proxmox, OS, PS Version, Scripts Supported, Notes).
3. Add a column to the test matrices in Sections 3.2-3.4.
4. Run the full script test suite against the new system.
5. Update Section 7 with any new per-OS quirks discovered.
