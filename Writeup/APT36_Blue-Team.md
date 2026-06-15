# Operation PHANTOM RELAY — Blue Team Writeup
## Range 5 (APT36) · Domain: corp.prabalurja.in (CORPPUL)

Range 5 is the second red-versus-blue range and the most relay-heavy of the set. Starting from a low-privileged `svc-monitor` account, the chain runs mitm6 IPv6 DNS poisoning into an NTLM relay, a GPP cpassword leak, the CVE-2025-33073 NTLM reflection for SYSTEM, DCOM lateral movement, and finally unconstrained delegation plus the printer bug to capture the DC's ticket and DCSync. The defining detection theme is coerced and relayed authentication, so machine-account behaviour on the network is where most of the signal lives. Two single controls — enforcing SMB signing and removing unconstrained delegation — break most of this chain, which is worth stating up front.

Severity scale: Informational, Low, Medium, High, Critical.

SIEM examples are Splunk SPL against Windows logs (with network sourcetypes for Stage 1) ingested via the Splunk Add-on for Windows; field names depend on your add-on and may need adjusting.

## Detection prerequisites

- Network sensors for DHCPv6/IPv6 router advertisements and LLMNR/NBT-NS, plus WPAD request visibility.
- Logon auditing (4624/4625 with logon type and authentication package) on all member servers and the DC.
- Account Management (4724, 4738, 4741) and Directory Service Changes (5136) on the DC; DNS Server audit logging.
- Detailed Tracking (4688) and Sysmon (process, DCOM) on member servers; File Share auditing (5145) on the file server.
- An inventory of which non-DC computers have `TrustedForDelegation` set, so unconstrained delegation is a known, watched condition.

## Stage 1 — mitm6 IPv6 takeover and NTLM relay to LDAP

Attacker action: mitm6 answers DHCPv6 and poisons IPv6 DNS so the WPAD lookup from SRV-PORTAL resolves to the attacker. The coerced machine-account authentication is relayed to the DC over LDAP and used to reset `svc_file` (via a pre-staged GenericAll held by SRV-PORTAL$).

Telemetry and what you see:
- Network: rogue DHCPv6 advertise/reply traffic on a network that otherwise does not use IPv6, a new IPv6 DNS server, and WPAD/HTTP requests heading to the attacker host.
- On the DC, the relayed action against `svc_file` appears as Security 4724 (password reset attempt) and 4738 (user account changed), with the actor being the machine account `SRV-PORTAL$`. A computer account resetting a service account's password is the anomaly.
- The relayed authentication also shows as Security 4624 Logon Type 3 (NTLM) where the network source does not match the account's real host.
- Contingency paths leave their own marks: Responder-based LLMNR/NBT-NS poisoning shows attacker responses on the wire and captured NTLMv2; a `/web.config.bak` pull is an HTTP 200 in the SRV-PORTAL access log.

Severity: High.

Detection: alert on unexpected DHCPv6/router-advertisement traffic, on machine accounts performing password resets, and on NTLM Type 3 logons whose source host is inconsistent with the account.

```spl
index=wineventlog host=DC-CORPUL EventCode IN (4724,4738) Account_Name="*$"
| search Target_Account_Name=svc_file
```
```spl
index=network sourcetype=zeek_dhcp OR sourcetype=zeek_conn dest_port=547
| search NOT src IN ("<approved-dhcpv6-servers>")
```

Response: filter rogue DHCPv6 (RA Guard / DHCPv6 Guard), disable IPv6 if unused, remove WPAD, and reset `svc_file`.

## Stage 2 — GPP cpassword from a SYSVOL backup share (SRV-NAS)

Attacker action: as `svc_file`, reads `Groups.xml` from the `SYSVOLBackup` share and decrypts the `cpassword` to recover `svc_build`. The GPP encryption key is public, so any cpassword is effectively plaintext.

Telemetry and what you see:
- Security 5145 on SRV-NAS showing `svc_file` reading the `...\Groups\Groups.xml` path under the backup share.
- The real finding is the existence of a `cpassword` attribute anywhere in SYSVOL or its backups — that file should not exist post-MS14-025.

Severity: Medium to High. The read is quiet; the leaked credential is the problem.

Detection: hunt for any file containing a `cpassword` attribute across SYSVOL and file shares, and alert on access to Groups.xml in backup locations.

```spl
index=wineventlog host=SRV-NAS EventCode=5145 Relative_Target_Name="*Groups.xml"
| table _time Account_Name Share_Name Relative_Target_Name
```

Response: delete the offending GPP file, rotate `svc_build`, and scope `svc_file`'s share access.

## Stage 3 — CVE-2025-33073 NTLM reflection to SYSTEM (SRV-CI)

Attacker action: adds a crafted DNS record (marshalled target name) via LDAP as `svc_build`, coerces SRV-CI to authenticate to that name, and reflects the authentication back to SRV-CI's own SMB — gaining SYSTEM because SRV-CI does not enforce SMB signing. Credentials for `svc_admin` (and a bonus Domain Admin, `svc_dadmin`) come out of the dump.

Telemetry and what you see:
- The crafted DNS record being added shows as a directory/DNS change on the DC (5136 on the DNS zone object, or a Microsoft-Windows-DNS-Server audit entry); the record name is abnormally long because it carries marshalled metadata.
- The coercion uses an RPC primitive (PetitPotam over MS-EFSRPC here), visible as the corresponding RPC call against SRV-CI.
- The reflection itself is the signature: Security 4624 Logon Type 3 (NTLM) on SRV-CI where the authenticating account is `SRV-CI$` — the machine authenticating to itself. Microsoft patched this on 10 June 2025, and enforced SMB signing blocks it even unpatched.

Severity: Critical, mitigated where the June 2025 patch or SMB signing is in place.

Detection: alert on a host's machine account authenticating to itself over NTLM, on unusually long/crafted DNS records being created, and on known coercion RPC calls (EFSRPC/MS-RPRN).

```spl
index=wineventlog host=SRV-CI EventCode=4624 Logon_Type=3 Authentication_Package=NTLM Account_Name="SRV-CI$"
| table _time Account_Name Source_Network_Address Workstation_Name
```

Response: apply the June 2025 update, enforce SMB signing on all member servers, remove the crafted DNS record, and rotate `svc_admin` and `svc_dadmin`.

## Stage 4 — DCOM lateral movement (SRV-BASTION)

Attacker action: uses the `MMC20.Application` DCOM object with `svc_admin` to execute commands on SRV-BASTION.

Telemetry and what you see:
- Security 4624 Logon Type 3 for `svc_admin` on SRV-BASTION.
- System log DistributedCOM events (activation/launch) and Security 4688 showing `mmc.exe` spawning a child process such as `cmd.exe` — `mmc.exe` as a parent of a shell is the DCOM-execution tell.

Severity: High.

Detection: alert on `mmc.exe` (and other DCOM hosts like `mshta`/`excel`) spawning command interpreters, and on remote DCOM activations to servers that do not normally receive them.

```spl
index=wineventlog host=SRV-BASTION EventCode=4688 ParentProcessName="*\\mmc.exe"
NewProcessName IN ("*\\cmd.exe","*\\powershell.exe")
```

Response: restrict DCOM launch/activation permissions, and rotate `svc_admin`.

## Stage 5 — Unconstrained delegation and the printer bug to DCSync

Attacker action: SRV-BASTION is configured for unconstrained delegation. The attacker coerces DC-CORPUL via the printer bug (MS-RPRN) to authenticate to SRV-BASTION, captures the DC's TGT from memory, and uses it for DCSync.

Telemetry and what you see:
- The coercion is an MS-RPRN RPC call against the DC's print spooler.
- The high-fidelity event is Security 4624 Logon Type 3 on SRV-BASTION where the account is `DC-CORPUL$` — a domain controller's machine account authenticating to a member server is almost never legitimate.
- Unconstrained delegation on SRV-BASTION (`TrustedForDelegation = True` on a non-DC) is a standing condition that should already be alerting.
- DCSync that follows: Security 4662 on the domain object from a non-DC principal carrying `DS-Replication-Get-Changes` (`1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`).

Severity: Critical.

Detection: alert on DC machine accounts authenticating to non-DC hosts, on any host with unconstrained delegation receiving DC authentication, and on replication from non-DC principals.

```spl
index=wineventlog host=SRV-BASTION EventCode=4624 Logon_Type=3 Account_Name="DC-CORPUL$"
```
```spl
index=wineventlog host=DC-CORPUL EventCode=4662 Properties="*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*"
| search NOT Account_Name="DC-CORPUL$"
```

Response: treat as full domain compromise. Remove unconstrained delegation from SRV-BASTION, disable the Print Spooler on the DC, rotate all privileged credentials, and reset `krbtgt` twice.

## Root-cause remediation

1. mitm6/relay: enforce SMB signing on all member servers, filter rogue DHCPv6 (RA/DHCPv6 Guard), disable IPv6 if unused, and remove WPAD. SMB signing alone neutralises both the relay and Stage 3.
2. GPP cpassword: remove the file from SYSVOL/backups and rotate the exposed account; the key is public.
3. CVE-2025-33073: apply the June 2025 update and enforce SMB signing.
4. DCOM lateral movement: restrict DCOM launch/activation rights and protect LSASS on SRV-CI.
5. Unconstrained delegation: remove `TrustedForDelegation` from SRV-BASTION (use constrained delegation or RBCD), add DC and privileged accounts to Protected Users / mark them sensitive and not delegable, and disable the DC's Print Spooler.

## Detection coverage summary

| Stage | ATT&CK | Primary log source | Event ID(s) / signal | Severity |
|---|---|---|---|---|
| 1 mitm6 + relay | T1557.001 / T1207 | Network + DC Security | DHCPv6, WPAD, 4724, 4738, 4624 (NTLM) | High |
| 2 GPP cpassword | T1552.006 | SRV-NAS Security | 5145 (Groups.xml), cpassword presence | Medium–High |
| 3 CVE-2025-33073 | T1557 / T1068 | SRV-CI Security + DC DNS | 4624 (self-auth NTLM), 5136 (DNS record) | Critical |
| 4 DCOM lateral | T1021.003 | SRV-BASTION Security / System | 4624 (Type 3), DistributedCOM, 4688 (mmc parent) | High |
| 5 Unconstrained + PrinterBug | T1187 / T1003.006 | SRV-BASTION + DC Security | 4624 (DC$ on member), MS-RPRN, 4662 (repl GUID) | Critical |

