# Operation PHANTOM RELAY — Assessment Questions

## Red Team Assessment (25 Questions)

### Step 1 — mitm6 + NTLM Relay
1. What tool poisons IPv6 DNS to intercept authentication?
2. What Windows feature allows mitm6 to work even in IPv4-only environments?
3. What ntlmrelayx flag is needed to bypass MIC protection?
4. Why must the relay target LDAPS (636) instead of LDAP (389) for password changes?
5. What ACL does svc_web have on svc_file that enables the password reset?

### Step 2 — GPP cpassword
6. What share on SRV-NAS contains the GPP backup?
7. What file contains the encrypted password?
8. What tool decrypts GPP cpasswords?
9. Why is GPP decryption trivially possible (what did Microsoft publish)?
10. What are the decrypted svc_build credentials?

### Step 3 — CVE-2025-33073
11. What CVE enables NTLM reflection on unpatched Server 2019?
12. What KB patches this vulnerability?
13. Why does this bypass MS08-068?
14. What must be disabled on SRV-CI for the reflection to work?
15. What cached credentials are found in LSASS after getting SYSTEM?

### Step 4 — DCOM Lateral Movement
16. What COM object is used for DCOM command execution?
17. Why is DCOM preferred over PsExec/WinRM?
18. What AD property on SRV-BASTION enables Step 5?
19. What service must be running on both DC-CORPUL and SRV-BASTION?
20. What contingency reveals svc_dadmin password in command history?

### Step 5 — Unconstrained Delegation + PrinterBug
21. What tool monitors for incoming TGTs on SRV-BASTION?
22. What tool/technique coerces DC-CORPUL to authenticate to SRV-BASTION?
23. Why does the DC's TGT get cached on SRV-BASTION?
24. How is the captured TGT converted for use with impacket?
25. What is the final command that achieves full domain compromise?

## Answer Key

1. mitm6
2. Windows listens for IPv6/DHCPv6 by default even in IPv4-only networks
3. --remove-mic
4. LDAP password changes require SSL — WILL_NOT_PERFORM error over plaintext LDAP
5. GenericAll
6. SYSVOLBackup
7. Groups.xml (in Policies/{GUID}/Machine/Preferences/Groups/)
8. gpp-decrypt
9. Microsoft published the AES-256 key in MS14-025 MSDN documentation
10. svc_build / Bu1ld$3rv!c3#2025
11. CVE-2025-33073
12. KB5060531 (June 2025 Patch Tuesday)
13. Marshaled target info in DNS record tricks SMB client into local auth context
14. SMB signing
15. svc_admin NTLM hash and svc_dadmin NTLM hash (from scheduled tasks)
16. MMC20.Application (ExecuteShellCommand method)
17. Bypasses SMB-based detection rules — DCOM uses RPC/port 135
18. TrustedForDelegation = True (Unconstrained Delegation)
19. Print Spooler (Spooler service)
20. C4a: PSReadline history in ConsoleHost_history.txt
21. Rubeus (monitor command)
22. printerbug.py / SpoolSample.exe (MS-RPRN abuse)
23. Unconstrained Delegation caches the full TGT of any principal that authenticates
24. impacket-ticketConverter kirbi → ccache, then export KRB5CCNAME
25. impacket-secretsdump -k -no-pass 'corp.prabalurja.in/DC-CORPUL$@DC-CORPUL.corp.prabalurja.in' -just-dc
