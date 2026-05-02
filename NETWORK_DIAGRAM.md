# Operation PHANTOM RELAY — Network Diagram

```
                    ┌──────────────┐
                    │   ATTACKER   │
                    │  (Kali Linux)│
                    └──────┬───────┘
                           │
              ─────────────┼─────────────── lab-net (flat) ───
              │            │            │            │
        ┌─────┴──────┐ ┌──┴─────┐ ┌────┴───┐ ┌─────┴──────┐ ┌──────┴───────┐
        │ SRV-PORTAL  │ │SRV-NAS │ │ SRV-CI │ │SRV-BASTION │ │  DC-CORPUL   │
        │ IIS/WPAD    │ │  File  │ │  Build │ │  Bastion   │ │  AD DS+DNS   │
        │ Port 80     │ │Port 445│ │Port 445│ │Port 135,   │ │Port 88,389,  │
        │ IPv6 enabled│ │        │ │ UNPATCHED│ │3389,5985  │ │636,445       │
        └─────────────┘ └────────┘ └────────┘ └────────────┘ └──────────────┘

Attack Flow:
  [0] Entry: svc-monitor creds from RNG-IT-02
  [1] SRV-PORTAL ──mitm6 + relay──→ DC LDAPS → reset svc_file password
  [2] SRV-NAS ──GPP cpassword──→ svc_build cleartext
  [3] SRV-CI ──CVE-2025-33073──→ NTLM reflection → SYSTEM → svc_admin hash
  [4] SRV-BASTION ──DCOM MMC20──→ svc_admin shell → Unconstrained Delegation
  [5] DC-CORPUL ──PrinterBug──→ DC$ TGT captured → DCSync
```
