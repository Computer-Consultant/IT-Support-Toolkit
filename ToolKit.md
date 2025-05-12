# 🧰 IT Admin Troubleshooting Toolkit

This document provides tools, commands, and techniques for testing, diagnosing, and troubleshooting common issues in Windows and Linux IT environments.

## 🧭 Basic Network Troubleshooting and IP/Subnet Reference

```cmd
ipconfig /all
ping 8.8.8.8
nslookup google.com
```

## 📶 Show Connected Wi-Fi SSID and Password

```cmd
netsh wlan show interfaces
netsh wlan show profile name="SSID" key=clear
```

## 🌐 Finding Your External (Public) IP Address

```powershell
Invoke-RestMethod -Uri "https://api.ipify.org?format=text"
```

## 💾 Check Installed RAM and Storage via Command Line

```powershell
Get-CimInstance Win32_PhysicalMemory
Get-PhysicalDisk
```

## 🔐 Password Reset – SYSTEM Hive CmdLine Method

```cmd
reg load HKLM\offline D:\Windows\System32\Config\SYSTEM
reg add "HKLM\offline\Setup" /v CmdLine /t REG_SZ /d "cmd.exe" /f
reg add "HKLM\offline\Setup" /v SetupType /t REG_DWORD /d 2 /f
reg unload HKLM\offline
```

## 🚀 Startup Programs – Identifying Non-Microsoft Auto-Starts

```cmd
wmic startup get caption, command
Get-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Run
```

Use [Autoruns](https://live.sysinternals.com/tools/autoruns.exe) from Microsoft Sysinternals.

## 🌍 Clean Browser Launch for Troubleshooting

```cmd
start chrome --guest
start firefox -safe-mode
start msedge --inprivate
```

## 🛡️ Antivirus / Malware Detection with EICAR

Download from: [EICAR test file](https://www.eicar.org/download-anti-malware-testfile/)

## 📧 Email Security & SMTP Testing

Use:
- `nslookup -q=mx domain.com`
- `telnet mail.domain.com 25`
- Outlook → Test Email AutoConfiguration (`Ctrl + right-click tray icon`)

## 📨 Autodiscover DNS and Outlook Diagnostics

```powershell
Test-OutlookConnectivity -ProbeIdentity "OutlookRpcSelfTestProbe"
```

## 🧰 Booting to Safe Mode and Removing Updates

```cmd
bcdedit /set {current} safeboot minimal
```

## 🐧 Linux Update Commands

```bash
# Debian/Ubuntu
sudo apt update && sudo apt upgrade

# RHEL/Fedora
sudo dnf upgrade

# Arch
sudo pacman -Syu
```

## 🧬 Active Directory Health Checks

```cmd
dcdiag /v
repadmin /replsummary
```

## 🗄️ SQL Server Testing

```powershell
Invoke-Sqlcmd -ServerInstance "Server\Instance" -Query "SELECT @@VERSION"
```

## 🌐 TCPView and Netstat

```cmd
tcpview.exe
netstat -ano
```

## 📋 Editing Hosts File Safely

Use PowerToys Hosts File Editor or:

```cmd
notepad C:\Windows\System32\drivers\etc\hosts
```

Disable Tamper Protection temporarily if blocked.

## 📱 Microsoft Intune (Endpoint Manager)

```powershell
dsregcmd /status
```

## 👤 Listing Local Accounts

```powershell
Get-LocalUser
Get-WmiObject Win32_UserAccount | Where-Object { $_.LocalAccount -eq $true }
```

---

This document continues to evolve. Use, adapt, and extend to meet your diagnostic needs.
