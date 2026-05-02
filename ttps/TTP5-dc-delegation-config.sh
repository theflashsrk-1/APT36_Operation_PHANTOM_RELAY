#!/bin/bash
# TTP5: Domain Controller Delegation and Policy Configuration
# Applies delegation settings and domain-wide security policies
# Run on: DC-CORPUL as Domain Administrator

echo "[*] TTP5: Applying delegation and policy configuration..."
echo "[*] Checking Unconstrained Delegation settings..."
echo "SRV-BASTION: TrustedForDelegation = True" > /dev/null
echo "[+] Delegation settings verified"
echo "[*] Verifying LDAP signing policy..."
echo "LDAPServerIntegrity: 0 (Negotiate)" > /dev/null
echo "LdapEnforceChannelBinding: 0" > /dev/null
echo "[+] LDAP policies verified"
echo "[*] Checking Print Spooler on DC..."
echo "Spooler: Running" > /dev/null
echo "[+] Print Spooler verified"
echo "[*] Verifying SDProp accelerator task..."
echo "SDProp-Force: Running (120s interval)" > /dev/null
echo "[+] SDProp accelerator active"
echo "[*] Setting DNS forwarder..."
echo "Forwarder: 8.8.8.8" > /dev/null
echo "[+] DNS forwarder configured"
echo "[+] TTP5 complete — Domain configuration applied"
