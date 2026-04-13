# REMOTE_TESTING.md

Remote testing guide for validating CHAPS scripts against Windows VMs on Proxmox VE.

## CRITICAL: Public Branch Hygiene

The `claude-dev` branch is public. NEVER commit real infrastructure details.

| Placeholder | Meaning |
|---|---|
| `<lab-host>` | Proxmox VE host on lab network |
| `<vm-name>` | Test VM hostname or IP |
| `<lab-user>` | Windows account used for testing |
| `~/.ssh/chaps_dev_ed25519` | SSH key path (key file never committed) |
| `<lab-network>` | Lab subnet |

Real values go in `remote-testing.local.conf` which is gitignored. If you find a real hostname, IP, username, or key in any committed file, remove it immediately.

## 1. Goals

1. Run all three CHAPS scripts (PSv3, PSv2, CMD) against real Windows installations
2. Validate markdown output renders correctly when redirected to file
3. Verify check parity across script variants on the same VM
4. Confirm graceful handling of non-admin execution
5. Document per-OS quirks and check availability differences

## 2. Non-Goals

- Automated CI/CD pipeline (manual SSH-based testing is sufficient)
- Performance benchmarking
- Testing against domain-joined systems (standalone/workgroup only)

## 3. Topology

```
Linux Developer Workstation (SSH client)
    |
    | SSH (key-based auth, port 22)
    v
Proxmox VE Host <lab-host>
    |
    | VM Bridge (vmbr0)
    v
6 Windows Test VMs (OpenSSH server, key auth)
    - Win7Pro-Dev         (PSv2 + CMD)
    - Win10Pro-Dev        (PSv3 + PSv2 + CMD)
    - Win11Pro-Dev        (PSv3 + PSv2 + CMD)
    - WinServer2016-Dev   (PSv3 + PSv2 + CMD)
    - WinServer2019-Dev   (PSv3 + PSv2 + CMD)
    - WinServer2022-Dev   (PSv3 + PSv2 + CMD)
```

This is the same VM fleet used by the ICSWatchDog project. VMs are shared -- do not modify VM configurations without coordinating.

## 4. Why SSH and Not WinRM

| Factor | SSH | WinRM |
|---|---|---|
| Auth setup | Key-based, simple | NTLM/Kerberos, complex |
| Cross-platform | Standard `ssh`/`scp` | Requires PS remoting config |
| Firewall | TCP 22 | TCP 5985/5986 |
| File transfer | `scp` built-in | Requires separate mechanism |

SSH is already configured on all VMs from ICSWatchDog setup. See that project's REMOTE_TESTING.md for OpenSSH server installation and key auth configuration details.

## 5. VM Access

### 5.1 Prerequisites

- SSH key pair for lab VMs (same key as ICSWatchDog)
- Local copy of `remote-testing.local.conf` with real VM connection details
- Maximum 3 VMs running concurrently (Proxmox NUC RAM limitation)

### 5.2 Starting/Stopping VMs

```bash
# Via SSH to Proxmox host
ssh <lab-user>@<lab-host> "qm start <vmid>"
ssh <lab-user>@<lab-host> "qm status <vmid>"
ssh <lab-user>@<lab-host> "qm stop <vmid>"
```

### 5.3 VM Snapshots

| Snapshot | Purpose |
|---|---|
| `clean` | Post-install baseline (OS + SSH + updates) |
| `pre-test` | Before each test run (cheap rollback) |

Wedged VMs are rolled back, not debugged in place:
```bash
ssh <lab-user>@<lab-host> "qm rollback <vmid> clean"
```

## 6. Local Configuration File

### 6.1 Template

Copy `remote-testing.example.conf` to `remote-testing.local.conf` and fill in real values. The local file is gitignored.

### 6.2 Loading Configuration

```bash
source claude-dev/remote-testing.local.conf
```

### 6.3 Gitignore

The following entry in `.gitignore` prevents committing the local config:
```
claude-dev/remote-testing.local.conf
```

## 7. Test Run Pattern

### 7.1 Deploy Script to VM

```bash
# PSv3
scp -i $SSH_KEY_PATH PowerShellv3/chaps_PSv3.ps1 $VM_WIN10:C:/Temp/

# PSv2
scp -i $SSH_KEY_PATH PowerShellv2/chaps_PSv2.ps1 $VM_WIN10:C:/Temp/

# CMD
scp -i $SSH_KEY_PATH CMD/chaps.bat $VM_WIN10:C:/Temp/
```

### 7.2 Execute Remotely

```bash
# PSv3 -- run and save output as markdown
ssh -i $SSH_KEY_PATH $VM_WIN10 "powershell -ExecutionPolicy Bypass -File C:\Temp\chaps_PSv3.ps1" > results/win10-psv3.md

# PSv2 -- run and save output
ssh -i $SSH_KEY_PATH $VM_WIN10 "powershell -Version 2 -ExecutionPolicy Bypass -File C:\Temp\chaps_PSv2.ps1" > results/win10-psv2.md

# CMD -- run and save output
ssh -i $SSH_KEY_PATH $VM_WIN10 "C:\Temp\chaps.bat" > results/win10-cmd.md
```

### 7.3 Validate Output

1. Check file is non-empty and starts with `# CHAPS Report:`
2. Verify markdown renders in VS Code or GitHub preview
3. Check all section headers present (## System Info Checks, ## Security Checks, etc.)
4. Verify no PowerShell error messages in output (red text won't show, but error strings will)
5. Compare check count across script variants for same VM

### 7.4 Clean Up

```bash
ssh -i $SSH_KEY_PATH $VM_WIN10 "del C:\Temp\chaps_PSv3.ps1"
```

## 8. Known Per-OS Quirks

| OS | Quirk |
|---|---|
| Win7 | PSv2 only. No Get-PnpDevice, Get-MpPreference, Get-NetTCPConnection, SecurityCenter2 may behave differently |
| Win10 | Primary test target. All checks should work. |
| Win11 | Same as Win10. OS version Major is still 10. |
| Server 2016 | Uses 32-bit executables on some installs. No SecurityCenter2 namespace. |
| Server 2019 | No SecurityCenter2 namespace. Get-MpComputerStatus available. |
| Server 2022 | Same as 2019. Windows LAPS may be built-in. |
| All Servers | SecurityCenter2 not available -- antivirus check falls back to Get-MpComputerStatus |

## 9. Open Items

- [ ] Create local results/ directory for storing test output (gitignored)
- [ ] First full test run of PSv3 across all VMs
- [ ] Document any additional per-OS quirks discovered during testing
- [ ] Consider test orchestration script for future automation
