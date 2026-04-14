# REMOTE_TESTING.md

How to set up a remote Windows test environment on a Proxmox VE host so the CHAPS scripts (`PowerShellv3/chaps_PSv3.ps1`, `PowerShellv2/chaps_PSv2.ps1`, `CMD/chaps.bat`) can be exercised against real Windows systems without needing a local Windows workstation.

This document is a development aid. It is not user-facing. It lives under `claude-dev/` and is stripped from releases.

---

## CRITICAL: Public Branch Hygiene

**The `claude-dev` branch is publicly accessible on GitHub.** Anything committed here is world-readable.

The following MUST NEVER appear in any file under this repository:

- Real hostnames, IP addresses, or DNS names of any test or production system
- SSH private keys or public keys (even public keys can identify hosts)
- Passwords, API tokens, license keys, certificate material
- Real usernames associated with real hosts
- Network names (SSIDs, VPN names, AD domain names)
- Internal URLs, internal paths that reveal organization structure

**Use only generic placeholders in this document and in committed config templates:**

| Placeholder | Meaning |
|-------------|---------|
| `<lab-host>` | The Proxmox host on the lab network |
| `<vm-name>` | A test VM, e.g. `<vm-win10-dev>`, `<vm-win11-dev>` |
| `<lab-user>` | Local Windows account used for testing |
| `~/.ssh/<lab-key>` | Local-only SSH key path. The key file itself is never committed. |
| `<lab-network>` | The lab subnet, e.g. `<lab-network>/24` |

If you find yourself wanting to type a real hostname into a committed file, stop. Put it in `~/.ssh/config` instead (see Section 7).

---

## 1. Goals

- Run all three CHAPS scripts (PowerShell v3+, PowerShell v2, CMD batch) against real Windows installations of varying versions (Windows 7, 10, 11, Server 2016, Server 2019, Server 2022).
- Validate that the scripts produce valid markdown output when stdout is redirected to a file.
- Verify check parity: all three scripts produce equivalent findings on the same VM.
- Confirm graceful handling of non-admin execution.
- Be scriptable from a Linux developer workstation via SSH and key-based auth. No interactive RDP for routine test runs.

## 2. Non-Goals

- Production deployment infrastructure. This is dev-only.
- Multi-tenant lab access. One developer at a time.
- Domain joining or AD integration.
- Hardening the test VMs against attack. They are throwaway.
- Automated CI/CD. Manual SSH-driven testing is sufficient at this scale.

---

## 3. Topology

```
+----------------------------------+
|  Developer workstation (Linux)   |
|  - CHAPS scripts                 |
|  - SSH client                    |
|  - ~/.ssh/config  (host aliases, |
|    VMIDs, keys -- never in repo) |
+----------------------------------+
              |
              | SSH (key-based, port 22)
              v
+----------------------------------+
|  Proxmox VE host <lab-host>      |
|  - hosts Windows test VMs        |
|  - bridges VMs to <lab-network>  |
+----------------------------------+
              |
              | (VM bridge)
              v
+----------------------------------+
|  Windows test VMs                |
|  - <vm-name> with OpenSSH server |
|  - SSH key auth, no passwords    |
+----------------------------------+
```

The developer SSHes directly to each Windows VM by alias resolved via `~/.ssh/config`. The Proxmox host itself is only touched for VM lifecycle (start/stop/snapshot), not for routine test runs.

VM fleet is shared with the ICSWatchDog project. Do not modify VM configurations without coordinating.

---

## 4. Why SSH and Not WinRM

WinRM is the Windows-native remoting story but has friction for cross-platform automation:

| Concern | WinRM | OpenSSH on Windows |
|---------|-------|--------------------|
| Cross-platform client | Limited (PowerShell Core, pwsh-omi) | Standard OpenSSH client, works everywhere |
| Auth | NTLM/Kerberos/Cert (complex) | SSH key-based, simple |
| Firewall | TCP 5985/5986, often blocked | TCP 22, conventional |
| Scripting | `Invoke-Command` with sessions | Plain `ssh <host> "command"` |
| Idle complexity | Trusted hosts, listener config, SPN | None |

OpenSSH Server is a built-in Windows optional feature (Server 2019+, Windows 10 1809+) and is fully supported by Microsoft. For dev/test work, key-based SSH is the simpler path.

WinRM is documented as an alternative in Section 9 but is not the recommended default.

---

## 5. Proxmox VE Host Setup

Assumptions: Proxmox VE 8.x already installed on `<lab-host>`. Network bridge `vmbr0` exists and routes to `<lab-network>`.

### 5.1 Storage layout

Create a dedicated storage pool for test VM images and snapshots so they can be deleted/rebuilt without affecting other VMs. Recommended:

- ZFS pool or LVM-thin volume of at least 200 GB for VM disks
- Separate ISO storage for Windows install media and VirtIO drivers

### 5.2 Required ISOs

Download and store on the Proxmox host's ISO storage:

- Windows Server 2019 Evaluation ISO (Microsoft Evaluation Center)
- Windows Server 2022 Evaluation ISO
- Windows 10 Enterprise Evaluation ISO
- Windows 11 Enterprise Evaluation ISO
- Windows 7 install media (if still needed for legacy PSv2/CMD testing)
- VirtIO drivers ISO (`virtio-win.iso` from Fedora project)

Evaluation editions are time-limited but suffice for ephemeral test VMs that get rebuilt frequently.

### 5.3 VM template

Create a single Windows base template per OS version, then clone it for each test scenario. Template settings:

| Setting | Value |
|---------|-------|
| BIOS | OVMF (UEFI) |
| Machine | q35 |
| CPU | 2 cores, host type |
| RAM | 4096 MB minimum |
| Disk | 60 GB, VirtIO SCSI, discard on |
| Network | VirtIO, bridge vmbr0 |
| QEMU agent | Enabled |
| SCSI controller | VirtIO SCSI single |

After Windows install in the template:

1. Install VirtIO drivers from the mounted virtio-win.iso
2. Install QEMU guest agent
3. Apply latest Windows updates (one round)
4. Install OpenSSH Server (Section 6)
5. Sysprep with `/generalize /oobe /shutdown` so clones get unique SIDs
6. Snapshot as `template-clean`

### 5.4 Cloning a test VM

```
qm clone <template-vmid> <new-vmid> --name <vm-name> --full
qm start <new-vmid>
```

The cloned VM picks up a new MAC, gets a new DHCP lease, and on first boot completes OOBE.

---

## 6. Windows VM Setup: OpenSSH Server with Key Auth

Run inside each test VM (as Administrator):

### 6.1 Install OpenSSH Server

```powershell
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Start-Service sshd
Set-Service -Name sshd -StartupType Automatic
New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server (sshd)' `
    -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
```

### 6.2 Disable password auth, enable key auth

Edit `C:\ProgramData\ssh\sshd_config`:

```
PasswordAuthentication no
PubkeyAuthentication yes
PermitRootLogin no
```

For an administrator account, the authorized keys file must live at `C:\ProgramData\ssh\administrators_authorized_keys` with these ACLs (Microsoft's documented requirement):

```powershell
$acl = Get-Acl C:\ProgramData\ssh\administrators_authorized_keys
$acl.SetAccessRuleProtection($true, $false)
$rules = @(
    New-Object System.Security.AccessControl.FileSystemAccessRule('Administrators','FullControl','Allow'),
    New-Object System.Security.AccessControl.FileSystemAccessRule('SYSTEM','FullControl','Allow')
)
foreach ($r in $rules) { $acl.AddAccessRule($r) }
Set-Acl C:\ProgramData\ssh\administrators_authorized_keys $acl

Restart-Service sshd
```

For a non-admin test user, the key goes in `C:\Users\<lab-user>\.ssh\authorized_keys` with that user as owner.

### 6.3 Default shell

To make remote command execution feel natural, set PowerShell as the default shell:

```powershell
New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell `
    -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force
```

### 6.4 Test from the developer workstation

```
ssh <vm-alias> "Get-Host | Select-Object Version"
```

Should return the PowerShell version with no password prompt.

---

## 7. VM Tracking: `~/.ssh/config` as Single Source of Truth

Real hostnames, IPs, usernames, key paths, and Proxmox VMIDs all live in the developer workstation's `~/.ssh/config` file. That file is never in the repo, so real data cannot leak through it. There is no per-project local conf file, no inventory CSV, and no Proxmox API credentials file -- direct SSH to the Proxmox host is the lifecycle channel.

### 7.1 Required format

Each test VM gets a `Host` block with `HostName`, and a structured VMID comment. Shared settings (user, key, known-hosts behavior) use wildcard blocks:

```
# Proxmox hosts
Host proxmox0
    HostName <real-ip>
    User root
    IdentityFile ~/.ssh/<lab-key>
    StrictHostKeyChecking accept-new

# Dev VMs
Host Win10Pro-Dev
    HostName <real-ip>
    # VMID=108 PROXMOX=proxmox0

Host Win11Pro-Dev
    HostName <real-ip>
    # VMID=102 PROXMOX=proxmox0

# Shared settings for all workstation dev VMs
Host Win*Pro-Dev
    User <lab-user>
    IdentityFile ~/.ssh/<lab-key>
    StrictHostKeyChecking accept-new
    UserKnownHostsFile /dev/null

# Shared settings for all server dev VMs
Host WinServer*-Dev
    User Administrator
    IdentityFile ~/.ssh/<lab-key>
    StrictHostKeyChecking accept-new
    UserKnownHostsFile /dev/null
```

The **VMID comment format is mandatory**: `# VMID=<id> PROXMOX=<alias>` on its own line, no other text. Use `VMID=N/A PROXMOX=N/A` for placeholder entries (VMs that are aliased but not yet built). This exact format lets helper scripts parse VMID with a one-line `awk`. See `claude-dev/vm-lookup` for the parser used by CHAPS test runs.

### 7.2 Why no local conf file

Every field that a `remote-testing.local.conf` would hold is already in `~/.ssh/config`: host alias, IP, user, key path, Proxmox host, VMID. Duplicating into a second file creates drift. The project's `TESTING_STANDARD.md` Section 2.1 table holds the non-SSH metadata (OS version, PS version, scripts supported) because that's documentation, not connection data.

### 7.3 Rebuilding `~/.ssh/config` after loss

If the workstation is rebuilt, recreate the SSH config by:

1. Running `ssh <any-reachable-proxmox-host> "qm list"` against the remembered Proxmox IP. This gives VMID -> VM name for every configured VM.
2. Getting IPs from the Proxmox VM configs: `ssh proxmox0 "qm config <vmid>"` shows network and hostname.
3. Restoring the SSH private key from its backup location (the key is not in this repo and is not reconstructible from anything here).
4. Populating `~/.ssh/config` using the format in Section 7.1.

The `TESTING_STANDARD.md` Section 2.1 table is a partial safety net -- it holds SSH alias and VMID. If that's the only surviving source, combine it with `qm list` on the Proxmox host to fully reconstruct.

---

## 8. Test Run Pattern

Once a VM is reachable via SSH, a typical test session uses SSH aliases directly -- no conf file to source, no `-i <key>` flag (the key is resolved from `~/.ssh/config`):

```
# Start the target VM via the Proxmox host (VMID resolved via vm-lookup helper)
ssh proxmox0 "qm start $(claude-dev/vm-lookup vmid Win10Pro-Dev)"

# Create a temp directory on the VM if needed
ssh Win10Pro-Dev "mkdir C:\Temp 2>NUL"

# Copy a script to the VM
scp PowerShellv3/chaps_PSv3.ps1 Win10Pro-Dev:C:/Temp/

# Run it remotely and capture markdown output locally
ssh Win10Pro-Dev "powershell -ExecutionPolicy Bypass -File C:/Temp/chaps_PSv3.ps1" > claude-dev/results/Win10Pro-Dev-psv3.md

# Copy the PSv2 script and run with -Version 2
scp PowerShellv2/chaps_PSv2.ps1 Win10Pro-Dev:C:/Temp/
ssh Win10Pro-Dev "powershell -Version 2 -ExecutionPolicy Bypass -File C:/Temp/chaps_PSv2.ps1" > claude-dev/results/Win10Pro-Dev-psv2.md

# Copy the CMD script and run it
scp CMD/chaps.bat Win10Pro-Dev:C:/Temp/
ssh Win10Pro-Dev "cmd /c C:/Temp/chaps.bat" > claude-dev/results/Win10Pro-Dev-cmd.md

# Clean up on the VM
ssh Win10Pro-Dev "del C:\Temp\chaps_PSv3.ps1 C:\Temp\chaps_PSv2.ps1 C:\Temp\chaps.bat"

# Stop the VM when done
ssh proxmox0 "qm stop $(claude-dev/vm-lookup vmid Win10Pro-Dev)"
```

The VM is treated as a black box. Scripts are copied in, run, results pulled out via stdout redirect. The VM does not need to know anything about the developer workstation.

Test output files land in `claude-dev/results/` (gitignored by the `claude-dev/*.local.*` and `results/` patterns in `.gitignore`).

---

## 9. WinRM Alternative (Not Recommended)

If SSH on Windows is unavailable for some reason (very old Server 2016, restrictive policy), WinRM over HTTPS with certificate auth is the fallback. Outline only -- not the recommended path:

1. Generate a self-signed cert on the VM with `New-SelfSignedCertificate`
2. Configure WinRM HTTPS listener bound to that cert
3. Add the developer's client cert thumbprint as a trusted user mapping
4. From Linux, use `pwsh` with `Enter-PSSession -ConnectionUri https://...` and `-CertificateThumbprint`

The complexity is not worth it for dev/test. Use SSH unless you have a hard reason not to.

---

## 10. Snapshots and Rebuilds

Snapshot strategy for each VM:

| Snapshot name | When taken | Purpose |
|---------------|------------|---------|
| `clean` | After OS install + SSH configured, before any test runs | Roll back to a known-clean state |
| `pre-test` | Before a test run that may mutate state (e.g., checks that require elevated probing) | Cheap rollback |

```
qm snapshot <vmid> clean --description "post-install baseline"
qm rollback <vmid> clean
```

A test VM that becomes wedged should be rolled back, not debugged in place.

---

## 11. Open Items (TODO)

- [ ] First full test run of all three scripts across the fleet; populate TESTING_STANDARD.md Section 2.1 PS Version column for Server VMs
- [ ] Document any additional per-OS quirks discovered during real test runs (extend TESTING_STANDARD.md Section 7)
- [ ] Decide whether any test orchestration script (beyond `vm-lookup`) is worth adding

---

## 12. Threat Model for the Test Lab

Brief, because this is a dev-only lab on an isolated network:

- **Test VMs are untrusted by default.** They may have Defender disabled for testing. Do not give them access to anything outside the lab network.
- **The developer SSH key is the crown jewel.** Lose it and an attacker gets access to every test VM. Keep the private key on the developer workstation only, never on a VM, never in the repo.
- **Proxmox host management interface** must not be exposed to the public internet. Keep it on a management network only reachable from the dev workstation.
- **Test output is not real assessment data.** CHAPS reports captured from these VMs can be shared (after sanitization) without operational risk because nothing in them came from a real target system.
