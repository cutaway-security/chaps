# TESTING_STANDARD.md

Standard for testing CHAPS scripts across the development VM fleet.

## 1. Scope

Three categories of testing:

| Category | What | When |
|---|---|---|
| Script Testing | Each CHAPS script runs to completion on target OS | Every script change |
| Output Validation | Markdown output renders correctly and contains expected sections | Every output format change |
| Parity Testing | All three scripts produce equivalent checks on the same VM | Before release |

## 2. Test Environment

### 2.1 VM Fleet

| VM Alias | OS | PS Version | Scripts to Test |
|---|---|---|---|
| Win7Pro-Dev | Windows 7 Pro | 2.0 | PSv2, CMD |
| Win10Pro-Dev | Windows 10 Pro | 5.1 | PSv3, PSv2, CMD |
| Win11Pro-Dev | Windows 11 Pro | 5.1 | PSv3, PSv2, CMD |
| WinServer2016-Dev | Windows Server 2016 | 5.1 | PSv3, PSv2, CMD |
| WinServer2019-Dev | Windows Server 2019 | 5.1 | PSv3, PSv2, CMD |
| WinServer2022-Dev | Windows Server 2022 | 5.1 | PSv3, PSv2, CMD |

### 2.2 VM Lifecycle Rules

- Maximum 3 VMs running concurrently
- Snapshot before test runs
- Roll back wedged VMs, don't debug in place
- Coordinate with ICSWatchDog project (shared fleet)

### 2.3 File Transfer

```bash
# Deploy
scp -i $SSH_KEY_PATH <script> $VM_<alias>:C:/Temp/

# Retrieve output
ssh -i $SSH_KEY_PATH $VM_<alias> "powershell -ExecutionPolicy Bypass -File C:\Temp\<script>" > results/<alias>-<script>.md

# Clean up
ssh -i $SSH_KEY_PATH $VM_<alias> "del C:\Temp\<script>"
```

## 3. Script Testing

### 3.1 Test Matrix -- PSv3

| Check | Win10 | Win11 | Srv 2016 | Srv 2019 | Srv 2022 |
|---|---|---|---|---|---|
| Script completes | | | | | |
| No error output | | | | | |
| Markdown valid | | | | | |
| Admin checks run | | | | | |
| Non-admin graceful | | | | | |

Result format: `PASS YYYY-MM-DD` or `FAIL YYYY-MM-DD: <reason>`

### 3.2 Test Matrix -- PSv2

| Check | Win7 | Win10 | Win11 | Srv 2016 | Srv 2019 | Srv 2022 |
|---|---|---|---|---|---|---|
| Script completes | | | | | | |
| No error output | | | | | | |
| Markdown valid | | | | | | |
| Admin checks run | | | | | | |
| Non-admin graceful | | | | | | |

### 3.3 Test Matrix -- CMD

| Check | Win7 | Win10 | Win11 | Srv 2016 | Srv 2019 | Srv 2022 |
|---|---|---|---|---|---|---|
| Script completes | | | | | | |
| No error output | | | | | | |
| Markdown valid | | | | | | |
| Admin checks run | | | | | | |
| Non-admin graceful | | | | | | |

### 3.4 Procedure

For each script on each VM:

1. Deploy script to `C:\Temp\` via scp
2. Execute remotely, capture stdout to local file
3. Check exit: no crash, no unhandled exceptions
4. Validate output starts with `# CHAPS Report:`
5. Validate all 6 section headers present (`## System Info Checks` through `## Logging Checks`)
6. Count `[+]`, `[-]`, `[*]`, `[x]` prefixes -- zero `[x]` expected for checks that should work on that OS
7. Record result in test matrix

### 3.5 Pass Criteria

- Script exits cleanly (no crash, no hung process)
- Output is valid markdown (renders in VS Code preview)
- All section headers present
- Expected checks produce output (not silently skipped)
- Checks that cannot run on the OS output `[*]` info message with reason
- No `[x]` errors for checks that should work on the target OS
- Non-admin execution: admin-required checks report `[x]` or `[*]` gracefully, script continues

### 3.6 Failure Handling

If a test fails:
1. Record the failure with error details
2. Create a snapshot of the VM state if needed for debugging
3. Fix the script
4. Re-test on the same VM
5. Re-test on other VMs to verify no regression

## 4. Output Validation

### 4.1 Markdown Structure Check

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

### 4.2 Validation Commands

```bash
# Check report header exists
head -1 results/win10-psv3.md | grep "# CHAPS Report:"

# Count section headers
grep -c "^## " results/win10-psv3.md
# Expected: 6

# Count findings by type
grep -c "^\[+\]" results/win10-psv3.md    # Positive
grep -c "^\[-\]" results/win10-psv3.md    # Negative
grep -c "^\[\*\]" results/win10-psv3.md   # Informational
grep -c "^\[x\]" results/win10-psv3.md    # Errors
```

## 5. Parity Testing

### 5.1 When

Before any release. Run all three scripts on the same VM (Win10 is the primary parity target).

### 5.2 Procedure

1. Run PSv3, PSv2, and CMD on Win10Pro-Dev
2. Capture output to three separate files
3. Compare section headers: must be identical across all three
4. Compare check names: each check present in all three scripts
5. Findings may differ in detail (different methods) but check coverage must match
6. Checks marked N/A in CMD (PSVersions, PSLanguage) must output info message

### 5.3 Parity Matrix

| Check Category | PSv3 Count | PSv2 Count | CMD Count | Notes |
|---|---|---|---|---|
| System Info | | | | |
| Security | | | | |
| Authentication | | | | |
| Network | | | | |
| PowerShell | | | | CMD: 2 N/A, 4 via registry |
| Logging | | | | |
| **Total** | | | | |

## 6. Test Run Documentation

### 6.1 During Test Run

Record for each script/VM combination:
- Date
- VM alias
- Script tested (PSv3/PSv2/CMD)
- Admin or non-admin execution
- Result (PASS/FAIL)
- Error details if FAIL
- Any new per-OS quirks discovered

### 6.2 After Test Run

Update:
- Test matrices in this file (date-stamped results)
- RESUME.md with test summary
- Known quirks in REMOTE_TESTING.md Section 8

### 6.3 Re-Testing After Changes

After any script change:
- Re-test on Win10 (primary target) at minimum
- Re-test on Win7 if PSv2 or CMD changed
- Re-test on one Server edition if server-specific checks changed
- Full fleet re-test before release

## 7. Adding a New Test System

1. Clone from Proxmox template (see ICSWatchDog REMOTE_TESTING.md for template setup)
2. Configure OpenSSH server with key auth
3. Add VM alias and connection to `remote-testing.example.conf` and local copy
4. Add row to VM Fleet table (Section 2.1)
5. Add column to all test matrices
6. Run initial test of all scripts
7. Document any quirks
