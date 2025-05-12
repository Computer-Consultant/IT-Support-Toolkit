# IT Admin Testing Toolkit
*By Mark McDow — My Computer Guru, LLC*

A comprehensive, command-line-friendly reference for testing, monitoring, and verifying system health and configuration for Windows and Linux systems.

---

## 35. Basic Network Troubleshooting and IP/Subnet Reference

### 🔍 View Network Details (Windows CMD)

```cmd
ipconfig /all
```

Look for:

- **IPv4 Address** – your current IP (e.g., 192.168.1.50)
- **Default Gateway** – your router's address
- **DNS Servers** – current resolver(s)

> If your IP starts with **169.254.x.x**, it means:
- Your system used **APIPA** (Automatic Private IP Addressing)
- It could **not obtain a DHCP lease** (check router, DHCP server)

---

### 🧪 Common Ping Tests

#### Ping Local Router (Default Gateway)

```cmd
ping 192.168.1.1
```

#### Ping External IP (Test Internet)

```cmd
ping 8.8.8.8
```

#### Ping External Domain (Test DNS)

```cmd
ping google.com
```

---

### 📋 Subnet Mask Reference Table

| CIDR  | Subnet Mask     | Usable Hosts | Host Range              |
|-------|------------------|--------------|--------------------------|
| /30   | 255.255.255.252 | 2            | x.x.x.1 – x.x.x.2        |
| /29   | 255.255.255.248 | 6            | x.x.x.1 – x.x.x.6        |
| /28   | 255.255.255.240 | 14           | x.x.x.1 – x.x.x.14       |
| /27   | 255.255.255.224 | 30           | x.x.x.1 – x.x.x.30       |
| /26   | 255.255.255.192 | 62           | x.x.x.1 – x.x.x.62       |
| /25   | 255.255.255.128 | 126          | x.x.x.1 – x.x.x.126      |
| /24   | 255.255.255.0   | 254          | x.x.x.1 – x.x.x.254      |

> Usable hosts = total - 2 (network + broadcast)

---

### 🔧 Additional Troubleshooting Commands

#### View Routing Table

```cmd
route print
```

#### Release/Renew IP

```cmd
ipconfig /release
ipconfig /renew
```

#### Flush DNS Cache

```cmd
ipconfig /flushdns
```

#### Traceroute

```cmd
tracert google.com
```

#### DNS Resolution Test

```cmd
nslookup google.com
```

---


---

### 📧 Autodiscover DNS and Outlook Diagnostics

#### ✅ Test Autodiscover DNS Records (Microsoft 365 / Exchange)

From **PowerShell** (Windows):

```powershell
Test-OutlookConnectivity -ProbeIdentity "OutlookRpcSelfTestProbe"
```

Or use **Outlook Test E-mail AutoConfiguration**:

1. Hold **Ctrl** and right-click the Outlook icon in the system tray
2. Click **"Test E-mail AutoConfiguration"**
3. Enter email and password, uncheck **"Use Guessmart"**, and click **Test**

Look for:
- `https://autodiscover.domain.com/autodiscover/autodiscover.xml`
- DNS SRV and CNAME resolution results
- Errors in red (e.g., authentication, 401, redirect loop)

#### ✅ External Tools

- **Microsoft Remote Connectivity Analyzer**  
  [https://testconnectivity.microsoft.com](https://testconnectivity.microsoft.com)  
  Includes Autodiscover, Outlook Anywhere, and Microsoft 365 tests.

---

### 🛠 Microsoft Word / Excel Diagnostics

#### Word & Excel: Repair/Reset

- Go to **Control Panel → Programs → Microsoft 365 → Change**
- Select **"Quick Repair"** or **"Online Repair"**

#### Safe Mode Launch (No Add-ins):

```cmd
winword /safe
excel /safe
```

> Disables templates, extensions, and startup macros.

#### Detect/Disable Add-ins

1. File → Options → Add-ins
2. Choose **COM Add-ins** → Manage → Disable anything suspicious

#### Other Useful Tools

- Run **Office Diagnostics** via: `appwiz.cpl → Change Microsoft 365`
- Use **"Office Telemetry Dashboard"** (enterprise use)
- Check `%appdata%\Microsoft\Templates` for corrupt `Normal.dotm`
- Check Excel `.xlb` file in `%appdata%\Microsoft\Excel` for UI layout issues

---

---

## 34. Show Connected Wi-Fi SSID and Password

### ✅ Get Current SSID

```cmd
netsh wlan show interfaces
```

Or:

```powershell
(Get-NetConnectionProfile).Name
```

### ✅ Get Saved Wi-Fi Password (replace with your SSID)

```cmd
netsh wlan show profile name="YourSSID" key=clear
```

Look for `Key Content`.

### ✅ One-Liner PowerShell Combo

```powershell
$ssid = (netsh wlan show interfaces | Select-String 'SSID' | Select-Object -First 1).ToString().Split(':')[1].Trim()
netsh wlan show profile name="$ssid" key=clear | Select-String "Key Content"
```

---


---

## 37. Finding Your External (Public) IP Address

### ✅ PowerShell (Windows)

```powershell
Invoke-RestMethod -Uri "https://api.ipify.org?format=text"
Invoke-RestMethod -Uri "https://ifconfig.me/ip"
Invoke-RestMethod -Uri "https://checkip.amazonaws.com"
```

### ✅ CMD (Windows)

```cmd
curl https://api.ipify.org
curl ifconfig.me
```

> Windows 10+ includes `curl` by default.

---

### ✅ Linux / macOS

```bash
curl -s https://ipinfo.io/ip
curl -s https://icanhazip.com
curl -s ifconfig.me
```

---

### ✅ DNS-Based Lookup (Linux/macOS/WSL)

```bash
dig +short myip.opendns.com @resolver1.opendns.com
```

---

### ✅ Web-Based Tools

- https://whatismyipaddress.com
- https://ipinfo.io
- https://ifconfig.me
- https://checkip.amazonaws.com

---

## 20. Retrieve Manufacturer, Model, and Serial Number

Get-CimInstance Win32_ComputerSystem and Win32_BIOS.

---

## 21. Get Windows Version, Build, and Latest Patch

PowerShell: Get-ComputerInfo, Get-HotFix; systeminfo in CMD.

---

## 22. View Windows Install Date / First Boot Time

Get-CimInstance Win32_OperatingSystem or Event ID 12.

---

## 29. Windows Experience Index (WEI) Score via CLI

winsat formal; Get-CimInstance Win32_WinSAT.

---
---

## 27. Battery Health for Laptops (CLI)

Windows: powercfg /batteryreport; Linux: upower; macOS: system_profiler.

---

## 26. CPU, GPU, and Drive Temperature Checks

LibreHardwareMonitorCLI, smartctl, lm-sensors, nvme-cli.

---

## 25. SMART Drive Health via CLI

smartctl, Get-PhysicalDisk, CrystalDiskInfo, PowerShell health checks.

---

## 23. Check for Bad Clusters on Disk

CHKDSK read-only or /r, PowerShell log parsing, Get-WinEvent.

---

## 24. Estimate Format Date via Volume ID or Root Folder

fsutil, vol, (Get-Item C:\).CreationTime, Registry InstallDate.

---

## 1. Antivirus / Malware Detection

Includes EICAR test file, AMTSO tests, and browser-based security checkers.

---

## 3. Content Filtering & DNS

Test sites for DNSFilter, OpenDNS, NextDNS, FortiGuard, etc.

---

## 4. Email Security & SMTP Testing

Using telnet and PowerShell to verify SMTP, POP3, IMAP, SPF, DKIM, DMARC.

---

## 8. Logging / Endpoint / SIEM Testing

Triggering and detecting USB insertions, login failures, and event log entries.

---

## 7. Authentication, Identity, and Policy

Check MFA, password policies, Secure Score, HaveIBeenPwned.

---

## 9. Web App Headers & Security

SecurityHeaders.com, Mozilla Observatory.

---

## 6. SSL/TLS Certificate & Web Security

SSL Labs, Hardenize, BadSSL, and openssl s_client for manual checks.

---

## 10. Port & Service Discovery

Nmap, netcat, Shodan, banner grabbing.

---

## 18. Manual Protocol Testing

SMTP, POP3, IMAP, HTTP, FTP, SSH, RDP, NTP via telnet, netcat, PowerShell.

---

## 17. Domain & DNS Investigation Tools

whois, dig, host, MXToolbox, ViewDNS, DNSViz.

---

## 32. Startup Programs – Identifying Non-Microsoft Auto-Starts

### ✅ PowerShell

```powershell
Get-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Run
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Run
```

### ✅ Scheduled Tasks That Auto-Start

```powershell
Get-ScheduledTask | Where-Object { $_.TaskPath -like "*\*" -and $_.State -eq "Ready" }
```

### ✅ wmic Startup List

```cmd
wmic startup get caption, command
```

### ✅ Autoruns (Sysinternals)

```cmd
autorunsc.exe -nobanner -h > autoruns_filtered.txt
```

---

## 33. Clean Browser Launch for Troubleshooting

### Microsoft Edge

```cmd
start msedge --guest
start msedge --profile-directory="Profile 2"
```

### Google Chrome

```cmd
start chrome --guest
start chrome --user-data-dir="%TEMP%\ChromeTemp"
```

### Mozilla Firefox

```cmd
firefox --safe-mode
firefox -no-remote -profile "%TEMP%\FirefoxTemp"
```

Use `firefox -P` to manage profiles.

---

## 13. Patch & Deployment Verification

Intune, WSUS, SCCM, Windows Update logs, recent patches.

---

## 15. Certificate Expiration Monitoring

SSL expiration with PowerShell or openssl; internal PKI checks.

---

## 14. User Awareness / Phishing Simulation

Gophish, KnowBe4, user reporting validation.

---

## 16. Misc Tools

CIS-CAT, Microsoft SCT, Wireshark, Netcat, CrystalDiskInfo.

---

## 36. Infrastructure Tests: Intune, Active Directory, Web, SQL, Hypervisors

### 🎯 Microsoft Intune (Endpoint Manager)

- Open **Company Portal** on enrolled devices and check for sync:
  ```powershell
  dsregcmd /status
  ```
  Check `Device State` and `AzureAdJoined`/`Intune MDM`.

- Force sync:
  ```powershell
  Start-ScheduledTask -TaskName "PushLaunch"
  ```

- Review logs:
  - `C:\ProgramData\Microsoft\IntuneManagementExtension\Logs`
  - Event Viewer → Applications and Services Logs → Microsoft → Windows → DeviceManagement-Enterprise-Diagnostics-Provider

---

### 🧪 Active Directory Health Checks

#### ✅ Check Domain Controller Health

```cmd
dcdiag /v
```

#### ✅ Check Replication Status

```cmd
repadmin /replsummary
repadmin /showrepl
```

#### ✅ Confirm AD Auth and DNS

```cmd
nltest /dsgetdc:domain.com
```

---

### 🌐 Web Servers / Websites

#### ✅ Test HTTP/HTTPS Access

```powershell
Invoke-WebRequest -Uri https://yoursite.com -UseBasicParsing
```

#### ✅ DNS and Response Checks

```cmd
nslookup yoursite.com
ping yoursite.com
```

#### ✅ Port and Header Check

```bash
curl -I https://yoursite.com
```

Check for response code (`200 OK`, `403 Forbidden`, etc.)

---

### 🗄 SQL Server Testing

#### ✅ Check SQL Service Status (Windows)

```powershell
Get-Service -Name *SQL*
```

#### ✅ Test SQL Connectivity (PowerShell)

```powershell
Invoke-Sqlcmd -ServerInstance "SQLSERVER\INSTANCE" -Query "SELECT @@VERSION"
```

Requires the **SQL Server module** installed:
```powershell
Install-Module -Name SqlServer
```

#### ✅ T-SQL from SQLCMD (CMD)

```cmd
sqlcmd -S SQLSERVER\INSTANCE -Q "SELECT name FROM sys.databases"
```

---

### 💻 VMware & Hyper-V Testing

#### ✅ VMware PowerCLI (VMware)

- Connect:
  ```powershell
  Connect-VIServer -Server vcenter.domain.com
  ```

- List VMs and power states:
  ```powershell
  Get-VM | Select Name, PowerState
  ```

- Check snapshots:
  ```powershell
  Get-Snapshot
  ```

- Monitor host resource usage:
  ```powershell
  Get-VMHost | Select Name, CpuUsageMHz, MemoryUsageMB
  ```

#### ✅ Hyper-V (Windows PowerShell)

- List VMs:
  ```powershell
  Get-VM
  ```

- Check network adapters:
  ```powershell
  Get-VMNetworkAdapter
  ```

- Test virtual switch:
  ```powershell
  Get-VMSwitch
  ```

---


---

## 28. Reliability Monitor Access via CLI

perfmon /rel; Get-WinEvent -LogName Microsoft-Windows-Reliability-Analysis-Component.

---

## 31. Common Technician Tasks in Safe Mode and How to Enable Them

Safe Mode is a minimal environment useful for diagnostics and repair. Some tools and services require manual enabling.

### ✅ Common Tasks and Requirements

| Task                           | Requires Extra Steps? | Notes |
|--------------------------------|------------------------|-------|
| Uninstall Programs             | ✔️ Yes                | Enable Windows Installer via registry + `net start msiserver` |
| System Restore                 | ❌ No                 | Use `rstrui.exe` or System Restore from Safe Mode |
| Run Anti-Malware Scans         | ❌ CLI / ✔️ GUI       | GUI-based tools may need extra services |
| Edit Registry (`regedit`)      | ❌ No                 | Works natively |
| Disable Startup Items          | ❌ No                 | Use `msconfig` or Registry |
| Run `CHKDSK`, `SFC`, `DISM`    | ❌ Mostly             | `DISM` may need `wuauserv` and `bits` |
| Update Drivers                 | ✔️ Yes                | Driver installation services disabled by default |
| Use Device Manager             | ❌ GUI OK             | May not auto-detect devices |
| Networking Commands (ping, etc.) | ❌ in SM w/ Network  | Requires "Safe Mode with Networking" option |
| View Event Logs                | ❌ No                 | Use `eventvwr.msc` or PowerShell |
| File Recovery / Copy Locked Files | ❌ No              | Safe Mode unlocks many files |
| Create/Delete Local Users      | ❌ No                 | Use `net user` or `lusrmgr.msc` |
| Task Scheduler Use             | ✔️ Yes                | `Schedule` service disabled |
| Run PowerShell Scripts         | ❌ Mostly             | Depends on services used in the script |

---

### 🔧 Registry Keys to Enable Services in Safe Mode

To enable services, use:

```cmd
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal\<ServiceName>" /VE /T REG_SZ /D "Service" /F
```

Common services:

```cmd
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal\MSIServer" /VE /T REG_SZ /D "Service" /F
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal\wuauserv" /VE /T REG_SZ /D "Service" /F
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal\BITS" /VE /T REG_SZ /D "Service" /F
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal\TrustedInstaller" /VE /T REG_SZ /D "Service" /F
```

Start the services (if needed):

```cmd
net start msiserver
net start wuauserv
net start bits
net start trustedinstaller
```

> Use caution: enabling services in Safe Mode should be temporary.

---

---

## 30. Booting to Safe Mode and Removing Updates

### 🧰 Force Boot to Safe Mode (Windows)

#### A. Use System Configuration (GUI or CLI)

```cmd
msconfig
```

- Go to the **Boot** tab
- Check **Safe Boot**
- Choose Minimal, Alternate Shell, or Network

#### B. Force Safe Mode via Command Line

```cmd
bcdedit /set {current} safeboot minimal
```

To include networking:

```cmd
bcdedit /set {current} safeboot network
```

**Revert (boot normal again):**

```cmd
bcdedit /deletevalue {current} safeboot
```

---

### 🖥 Prompt for Boot Options on Next Restart

```cmd
shutdown /r /o /f /t 0
```

- Forces a reboot into **Windows Recovery Options**
- From there, you can select **Startup Settings → Enable Safe Mode**

---

### 🛠 Enable Program Uninstall in Safe Mode

Safe Mode disables the Windows Installer service. To enable it:

```cmd
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal\MSIServer" /VE /T REG_SZ /D "Service" /F
net start msiserver
```

For Safe Mode with Networking:

```cmd
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\MSIServer" /VE /T REG_SZ /D "Service" /F
```

This allows uninstallation of programs while in Safe Mode.

---

### 🔍 List Recently Installed Updates (Even from Safe Mode)

```powershell
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10
```

Or from CMD:

```cmd
wmic qfe list brief /format:table
```

---

### ❌ Uninstall a Problematic Update in Safe Mode or Recovery

#### A. From Safe Mode

```cmd
wusa /uninstall /kb:5037771 /quiet /norestart
```

Replace `5037771` with the KB number.

#### B. From Recovery Command Prompt (WinRE)

1. Boot from installation/recovery media
2. Choose **Repair your computer**
3. Open **Command Prompt**
4. Determine system drive:
   ```cmd
   diskpart
   list volume
   exit
   ```
5. Uninstall update:
   ```cmd
   dism /image:D:\ /remove-package /PackageName:Package_for_KB5037771
   ```

Use:

```cmd
dism /image:D:\ /get-packages
```

To list package names first (replace `D:` with actual Windows partition).

---

## Notes

- Always back up before uninstalling updates manually
- System Restore or full backup tools are safer for rollback

---
---

## 38. Listing Local Accounts and Checking If They're Microsoft or Local

### ✅ PowerShell – List All Local Accounts with Status

```powershell
Get-LocalUser | Select-Object Name, Enabled, LastLogon
```

- Shows local (non-domain) accounts
- `Enabled = False` means the account is disabled

---

### ✅ PowerShell – WMI Query for SID and Account Type

```powershell
Get-WmiObject Win32_UserAccount | Where-Object { $_.LocalAccount -eq $true } |
Select-Object Name, Disabled, SID, LocalAccount
```

- Local SIDs typically start with: `S-1-5-21`
- Microsoft accounts: `S-1-12-1-...` or appear in `C:\Users` as email addresses

---

### ✅ List Profiles and Infer Microsoft vs Local

```powershell
Get-ChildItem 'C:\Users' | Select-Object Name, LastWriteTime
```

Microsoft-connected accounts often have profile names like:
- `user@example.com`
- `MicrosoftAccount\...`

---

### ✅ CMD Tools

```cmd
net user
```

Check details:

```cmd
net user username
```

Look for:
- `Account active`
- Local group membership
- Logon script and password last set

---

### 🛠 Optional: Full PowerShell Script to List Accounts

```powershell
$users = Get-WmiObject Win32_UserAccount | Where-Object { $_.LocalAccount -eq $true }

foreach ($user in $users) {
    $type = if ($user.SID -like "S-1-12-*") { "Microsoft Account" } else { "Local" }
    [PSCustomObject]@{
        Name     = $user.Name
        Enabled  = -not $user.Disabled
        SID      = $user.SID
        Type     = $type
    }
}
```

This script identifies:
- Name
- Whether enabled
- SID
- Whether it appears to be a Microsoft account

---

---

## 39. Activation and User Setup Recovery

### ✅ Check Activation Status

```powershell
slmgr /xpr
```

- Shows if Windows is permanently activated or has a time-limited license.

```powershell
slmgr /dli
slmgr /dlv
```

- DLI = basic license info
- DLV = detailed license view

---

### 🔑 Install or Change Product Key

```powershell
slmgr /ipk XXXXX-XXXXX-XXXXX-XXXXX-XXXXX
slmgr /ato
```

- `/ipk` installs key
- `/ato` activates with Microsoft

---

### 👤 Create Local Account During OOBE (Windows 11/10)

#### Method A: Disconnect from Internet Before Setup

- At OOBE screen:
  - Press **Shift + F10** to open command prompt
  - Run:
    ```cmd
    oobeypassnro
    ```
  - This reboots and skips MSA requirement on next boot

#### Method B: Create Local User from CMD

```cmd
net user LocalAdmin Pa$$word123 /add
net localgroup administrators LocalAdmin /add
```

> Run during setup with Shift + F10 when allowed (offline-only).

---

### 🔐 Reset Forgotten Local Password (Post-Utilman Fix)

**Note:** Microsoft Defender and Secure Boot now block the `utilman.exe` trick in many cases.

#### ✅ Updated Methods:

1. **Boot from Windows or recovery USB**
2. Choose **Repair your computer** → **Troubleshoot** → **Command Prompt**
3. Load offline registry:
    ```cmd
    reg load HKLM\TEMP_HIVE C:\Windows\System32\Config\SAM
    ```

4. Use tools like:
   - **Offline NT Password & Registry Editor** (bootable ISO)
   - **Hiren's BootCD PE** (includes password reset GUI tools)
   - **Reset Windows Password** (commercial tool)
   - **Trinity Rescue Kit** (older but still works on legacy systems)

> If BitLocker is enabled, these methods won't work unless you have the recovery key.

---


---

### 🔐 Advanced: Password Reset by Editing SYSTEM Hive (CmdLine Trick)

This method replaces the older `Utilman.exe` trick by modifying the `SYSTEM` registry hive to run `cmd.exe` at boot.

#### ✅ Requirements

- Bootable Windows installation media or recovery USB
- Access to the target Windows partition (e.g., D:)

#### 🛠 Steps

1. Boot from recovery media → **Troubleshoot** → **Command Prompt**
2. Find the Windows partition:
   ```cmd
   diskpart
   list volume
   exit
   ```

3. Load the SYSTEM hive:
   ```cmd
   reg load HKLM\offline D:\Windows\System32\Config\SYSTEM
   ```

4. Inject command prompt at login:
   ```cmd
   reg add "HKLM\offline\Setup" /v CmdLine /t REG_SZ /d "cmd.exe" /f
   reg add "HKLM\offline\Setup" /v SetupType /t REG_DWORD /d 2 /f
   ```

5. Unload the hive:
   ```cmd
   reg unload HKLM\offline
   ```

6. Reboot the system. It will boot directly to a command prompt.

7. Reset the password:
   ```cmd
   net user Mark NewPassword123
   ```

8. Cleanup (important!):
   ```cmd
   reg load HKLM\offline D:\Windows\System32\Config\SYSTEM
   reg delete "HKLM\offline\Setup" /v CmdLine /f
   reg delete "HKLM\offline\Setup" /v SetupType /f
   reg unload HKLM\offline
   ```

> This method is effective and not currently blocked by most Windows Defender versions. Use responsibly.

---

---

## 40. UUID vs GUID vs MAC Address – Understanding and Retrieving System Identifiers

### 🔍 Definitions

| Term  | Stands For                      | Description |
|-------|----------------------------------|-------------|
| UUID  | Universally Unique Identifier   | A 128-bit number used to uniquely identify information. Used in BIOS, VMware, etc. |
| GUID  | Globally Unique Identifier      | Microsoft's implementation of UUIDs. Used in registry, COM objects, etc. |
| MAC   | Media Access Control Address    | A 48-bit hardware address unique to a network interface (NIC) |

> ❗ UUID and GUID are functionally equivalent formats.  
A MAC address can be **embedded** in a UUID (in UUID version 1).

---

### ✅ Get the System UUID (BIOS/Hardware)

```powershell
Get-CimInstance -Class Win32_ComputerSystemProduct | Select-Object UUID
```

This UUID is often used by asset systems and virtualization platforms (e.g., VMware).

---

### ✅ Get a GUID for Software or Registry Use

To generate a new GUID:

```powershell
[guid]::NewGuid()
```

Example output:
```
guid
----
54a2e3b2-cc4e-4d34-b55a-cf1f9e2112cb
```

Used for scripting, COM, MSI packages, etc.

---

### ✅ Get MAC Addresses

```powershell
Get-NetAdapter | Select Name, MacAddress, Status
```

Or classic CMD:

```cmd
getmac /v
```

---

### 🔄 Can You Convert Between Them?

- **UUID v1** includes a timestamp + MAC address.  
You can extract the MAC if the UUID was generated that way.
- UUIDs from BIOS or VMs may not follow UUIDv1 spec → can't extract MAC.
- GUIDs are just formatted UUIDs — not convertible to MAC directly.

---

### 📌 When They're Used

| Use Case                   | ID Type  |
|----------------------------|----------|
| BIOS/VM Hardware Identity  | UUID     |
| COM/Registry/Installers    | GUID     |
| Network Device ID          | MAC      |
| AD Computer Objects        | GUID     |

---

