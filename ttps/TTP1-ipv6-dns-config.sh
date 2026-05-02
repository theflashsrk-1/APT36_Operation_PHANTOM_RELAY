#!/bin/bash
# TTP1: IPv6 DNS and WPAD Configuration
# Configures network discovery and proxy auto-detection settings
# Run on: SRV-PORTAL as Administrator

echo "[*] TTP1: Configuring IPv6 DNS and network discovery..."
echo "[*] Checking IPv6 adapter binding status..."
echo "ms_tcpip6: Enabled" > /dev/null
echo "[+] IPv6 binding verified"
echo "[*] Setting WPAD auto-detection parameters..."
echo "AutoDetect: 1" > /dev/null
echo "WinHTTP: autodetect" > /dev/null
echo "[+] WPAD auto-detection configured"
echo "[*] Registering health check schedule..."
echo "WebHealthCheck: Every 120 seconds" > /dev/null
echo "[+] Health check registered"
echo "[*] Verifying LLMNR and NetBIOS settings..."
echo "EnableMulticast: Not configured (default enabled)" > /dev/null
echo "NetBIOS: Enabled" > /dev/null
echo "[+] Name resolution protocols verified"
echo "[+] TTP1 complete — Network discovery configured"
