# Operation PHANTOM RELAY — Storyline

## Background

Prabal Urja Limited (PUL) is a Central Public Sector Undertaking (CPSU) responsible for power generation and distribution across three northern Indian states. Their corporate IT infrastructure runs on a Windows Active Directory domain (corp.prabalurja.in) supporting 2,400 employees across generation plants, substations, and the corporate headquarters in New Delhi.

## Threat Actor

KAAL CHAKRA is a state-sponsored threat actor composite modeled on APT36 (Transparent Tribe) and RedEcho operations. The group targets Indian critical infrastructure — particularly power generation, transmission, and distribution organizations. Their operations prioritize long-dwell network access for intelligence collection and pre-positioning for potential disruptive operations during geopolitical escalation.

## Attack Narrative

KAAL CHAKRA operators breach PUL's external perimeter through a compromised monitoring service account (svc-monitor). From this foothold, they exploit IPv6 misconfiguration to intercept authentication traffic via mitm6, relaying captured credentials to the domain controller's LDAP service to reset a file server service account password. The operators discover an old SYSVOL backup containing GPP-encrypted credentials for the CI/CD build pipeline. Using CVE-2025-33073, a critical NTLM reflection vulnerability disclosed in June 2025, they achieve SYSTEM-level access on the build server without prior local access. DCOM lateral movement to the bastion server (bypassing traditional detection) reveals it has Unconstrained Delegation enabled. The final stage coerces the domain controller to authenticate to the bastion via the PrinterBug, capturing the DC's Kerberos TGT and enabling DCSync — full domain compromise.

## Operational Impact

Complete Active Directory compromise. All domain credentials extracted. The attack chain demonstrates how a single monitoring account, combined with network-level attacks and a recent CVE, can lead to total domain compromise in under 2 hours.
