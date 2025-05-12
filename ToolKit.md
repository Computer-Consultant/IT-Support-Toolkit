---
title: "The IT Admin's Troubleshooting Toolkit"
layout: default
---



# 🧰 The IT Admin's Troubleshooting Toolkit
## Practical Fixes, Diagnostics & Recovery for Windows Systems

> 🗡️ Your Swiss Army Knife of IT Diagnostics & Fixes You’ll Actually Use


A comprehensive reference for system troubleshooting and repair tools, processes, and diagnostics.

---

## 🛠️ Safe Mode & Uninstalling Programs

- Boot into Safe Mode via `msconfig` or `Shift + Restart`.
- Enable Windows Installer in Safe Mode to uninstall apps:
  ```cmd
  REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal\MSIServer" /VE /T REG_SZ /F /D "Service"
  net start msiserver
  ```

---

## 🔄 Windows Update Troubleshooting & Repair

- Run built-in and downloadable troubleshooters
- Reset Windows Update components
- Use `DISM` and `sfc` for image and file repair
- Cleanup superseded components

---

## 🚀 Startup Programs & Autoruns

- View startup programs in Task Manager, shell:startup, registry
- Use `autoruns.exe` for deep analysis
- Can be run via `\live.sysinternals.com\tools\autoruns.exe`

---

## 🌐 Network Diagnostics & Winsock Reset

```cmd
netsh winsock reset
netsh int ip reset
ipconfig /flushdns
```

---

## 📶 Wi-Fi SSID & Password Discovery

```cmd
netsh wlan show profile name="SSID" key=clear
```

---

## 🌍 External IP Address Discovery

```cmd
curl ifconfig.me
```

---

## 🏬 Microsoft Store & Winget Repair

```powershell
wsreset.exe
winget upgrade --all --accept-source-agreements --accept-package-agreements
```

---

## 🧼 Clean Up Superseded Components (WinSxS)

```cmd
DISM /Online /Cleanup-Image /StartComponentCleanup
DISM /Online /Cleanup-Image /StartComponentCleanup /ResetBase
```

---

## 🛠️ System File Checker and DISM

```cmd
sfc /scannow
DISM /Online /Cleanup-Image /RestoreHealth
```

---

## 🧩 Windows Apps, Search, DLLs, In-Place Repair

- Re-register apps and DLLs
- Rebuild search index
- Use Setup.exe for in-place repair

---

## 🐧🍎 Linux and macOS Integrity Tools

- `fsck`, `debsums`, `diskutil`, `csrutil status`
- SMART diagnostics with `smartctl`

---

## 🆔 UUID, GUID, and MAC Address Retrieval

```powershell
Get-CimInstance -Class Win32_ComputerSystemProduct | Select UUID
Get-NetAdapter | Select Name, MacAddress
[guid]::NewGuid()
```

---

## 🧰 Sysinternals Tools

- `autoruns`, `tcpview`, `procexp`, `procmon`
- Run from `\live.sysinternals.com\tools\<tool>.exe`

---

## 🧠 Microsoft Troubleshooters & MSDT Tools

- SaRA: https://aka.ms/SaRA
- `msdt.exe /id <DiagnosticID>`
  - Examples:
    - ActivationDiagnostic
    - WindowsUpdateDiagnostic
    - PrinterDiagnostic

---

## 📝 Problem Steps Recorder (PSR)

```cmd
psr.exe /start /output "C:\Temp\steps.zip" /gui no
psr.exe /stop
```

---

## 🕒 System Clock Test & Fix

### Symptoms of Incorrect System Time:
- Can't connect to HTTPS websites
- Windows Update fails
- Microsoft 365 apps sign-in errors
- Email/calendar sync issues

### Check time:
```cmd
w32tm /query /status
w32tm /query /configuration
```

### Force sync with time server:
```cmd
w32tm /resync
```

### Set time server manually:
```cmd
w32tm /config /manualpeerlist:"time.windows.com,0x1" /syncfromflags:manual /update
net stop w32time
net start w32time
```

Use [https://time.gov](https://time.gov) to compare visually.

---

## 📋 More coming soon...


---

## ♿ Accessibility Features Triggered by Keyboard Shortcuts

Sometimes users accidentally enable these features by holding keys too long or pressing repeatedly.

| Feature | What It Does | Shortcut Key |
|----------|--------------|--------------|
| Sticky Keys | Press modifier keys (Shift, Ctrl, Alt, Windows) one at a time instead of holding | Press Shift 5 times |
| Filter Keys | Ignores brief/repeated keystrokes | Hold Right Shift for 8 seconds |
| Toggle Keys | Plays sound when Caps Lock, Num Lock, or Scroll Lock is pressed | Hold Num Lock for 5 seconds |
| High Contrast | Switches to high-contrast color scheme | Left Alt + Left Shift + Print Screen |
| Magnifier | Opens screen magnifier | Windows + Plus (+) |
| Narrator | Starts screen reader | Ctrl + Windows + Enter |
| On-Screen Keyboard | Opens virtual keyboard | Windows + Ctrl + O |
| Color Filters | Enables color filters | Windows + Ctrl + C |

> You can disable shortcut prompts in Settings → Accessibility → Keyboard.

---

---

## 🖥️ PowerShell Essentials & Common Fixes

### ✅ Running Unsigned Scripts

- Temporarily allow in session:
  ```powershell
  Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
  ```

- Allow for current user:
  ```powershell
  Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
  ```

- Check current policy:
  ```powershell
  Get-ExecutionPolicy -List
  ```

---

### ✅ Common Errors & Fixes

- **"Cannot be loaded because running scripts is disabled"** → Fix with execution policy above.
- **Module not found**:
  ```powershell
  Install-Module -Name ModuleName -Scope CurrentUser
  Import-Module ModuleName
  ```

- **Untrusted Repository Warning**:
  ```powershell
  Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
  ```

---

### ✅ Other Essential PowerShell Commands

- List running processes:
  ```powershell
  Get-Process
  ```

- Get system info:
  ```powershell
  Get-ComputerInfo
  ```

- List services:
  ```powershell
  Get-Service | Where-Object { $_.Status -eq 'Running' }
  ```

- Restart a service:
  ```powershell
  Restart-Service -Name 'wuauserv'
  ```

- Export command output to file:
  ```powershell
  Get-Process | Out-File -FilePath C:\Temp\processlist.txt
  ```

- Test network connectivity:
  ```powershell
  Test-NetConnection www.google.com
  ```

---


---

## 🖱️🖥️ Using a Computer Without a Mouse or Keyboard

### ✅ If the Mouse is Not Working

- **Keyboard Shortcuts to Navigate**:
  - `Alt + Tab`: Switch between open windows
  - `Alt + F4`: Close current window
  - `Windows + X`: Open power user menu
  - `Ctrl + Esc` or `Windows key`: Open Start Menu
  - `Tab` and `Arrow keys`: Navigate within UI
  - `Enter`: Select an item
  - `Shift + F10`: Right-click equivalent

- **Enable Mouse Keys (Control Cursor with Numpad)**:
  1. Press `Alt + Left Shift + Num Lock`
  2. Confirm prompt to turn on Mouse Keys
  3. Use the numeric keypad to move the pointer

- **On-Screen Keyboard**:
  - Launch with `Windows + Ctrl + O`
  - Navigate using arrow keys and Enter to type

---

### ✅ If the Keyboard is Not Working

- **On-Screen Keyboard (OSK)**:
  - If a mouse works, navigate to:
    - Start → Settings → Accessibility → Keyboard → Turn on On-Screen Keyboard
  - Or run:
    ```cmd
    osk.exe
    ```

- **Touchscreen Devices**:
  - Use on-screen touch keyboard if available

- **Speech Recognition**:
  - Start Speech Recognition:
    ```cmd
    control /name Microsoft.SpeechRecognition
    ```
  - Or use `Windows + H` to enable dictation

- **Remote Access Tools**:
  - Connect from another device using Remote Desktop, TeamViewer, or similar

---

### ✅ General Tips

- **BIOS/UEFI Settings**: Some systems require enabling legacy USB support for keyboards/mice.
- **Try Different USB Ports**: Prefer back panel ports for keyboards (direct chipset connection).
- **Test with Bootable USB**: Verify hardware works outside of Windows (e.g., Linux live CD).

---


---

## 🔒 SSL/TLS Protocol Mismatches – Testing & Fixing

### ✅ Common Symptoms
- "Cannot establish a secure connection"
- "ERR_SSL_VERSION_OR_CIPHER_MISMATCH" (in browsers)
- Remote Desktop, SMTP, or VPN TLS errors
- Event Viewer logs Schannel errors (Event ID 36887)

### ✅ Causes
- Client/server use incompatible TLS versions
- Older OS lacks modern protocols (TLS 1.2, TLS 1.3)
- Disabled protocols via registry or group policy
- Outdated applications with hardcoded old TLS versions

### ✅ Testing TLS Connectivity
- Use PowerShell:
  ```powershell
  Test-NetConnection example.com -Port 443
  ```

- Use OpenSSL (Linux/macOS/Windows with OpenSSL):
  ```bash
  openssl s_client -connect example.com:443 -tls1_2
  ```

### ✅ Fixes
- Enable TLS 1.2/1.3 via registry (Windows):
  ```cmd
  reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" /v Enabled /t REG_DWORD /d 1 /f
  reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" /v Enabled /t REG_DWORD /d 1 /f
  ```

- Check Group Policies:
  - Computer Configuration → Administrative Templates → Network → SSL Configuration Settings

- Update apps and libraries (e.g., curl, OpenSSL, browsers)

---


---

## 🛡️ Browser & System Certificate Issues

### ✅ Common Symptoms
- Browser shows "Your connection is not private" (NET::ERR_CERT_AUTHORITY_INVALID)
- Expired certificates cause connection failures
- Third-party root certificates silently injected (security risk)

### ✅ Viewing Certificates
- **Windows**:
  - `certmgr.msc` (Current User Certificates)
  - `mmc.exe` → Add/Remove Snap-in → Certificates (Local Computer)

- **PowerShell**:
  ```powershell
  Get-ChildItem -Path Cert:\LocalMachine\Root
  ```

- **macOS**:
  - Applications → Utilities → **Keychain Access**

- **Linux**:
  - System store: `/etc/ssl/certs/`
  - CA bundle files: `/etc/ca-certificates.conf`
  - Commands:
    ```bash
    update-ca-certificates
    openssl x509 -in cert.pem -text -noout
    ```

### ✅ Detecting Unwanted Certificates
- Compare to baseline lists:
  - Microsoft: https://aka.ms/trustedrootprogram
  - Mozilla CA List: https://ccadb-public.secure.force.com/mozilla/IncludedCACertificateReport

- Use PowerShell or OpenSSL to export and review installed root certs.

### ✅ Fixing & Resetting Trusted Certificates
- **Windows**:
  - Use Windows Update to refresh root certificates.
  - Manually delete suspicious certs in `certmgr.msc`.
  - Re-import from trusted sources if needed.

- **macOS**:
  - Delete unwanted certs in Keychain.
  - System updates refresh system CA store.

- **Linux**:
  - Update CA certificates:
    ```bash
    sudo update-ca-certificates
    ```

### ✅ Browser-Specific Certificate Stores
- **Firefox**: Uses its own certificate store (independent of OS)
  - Preferences → Privacy & Security → View Certificates
- **Chrome, Edge, Safari**: Use OS-level certificate stores

---


---

## 🆕 Bringing a Fresh Windows Install Fully Up to Date (Commands & Best Practices)

### ✅ Recommended Method: PSWindowsUpdate Module

1. Install the module:
   ```powershell
   Install-Module PSWindowsUpdate -Force -Scope CurrentUser
   Import-Module PSWindowsUpdate
   ```

2. Download and install all critical and security updates:
   ```powershell
   Get-WindowsUpdate -Install -AcceptAll -AutoReboot
   ```

- Accepts all applicable updates and reboots if required.

---

### ✅ Alternative: Built-in Windows Update Client (UsoClient)

Run the following commands in sequence:

```cmd
UsoClient StartScan
UsoClient StartDownload
UsoClient StartInstall
UsoClient RestartDevice
```

> Note: Provides limited feedback but works for simple update triggers.

---

### ✅ For Enterprises (Recommended for IT Admins)

- Windows Update for Business policies
- Microsoft Endpoint Configuration Manager (MEMCM/SCCM)
- Intune Update Rings
- WSUS (Windows Server Update Services)

---

### ✅ Optional Post-Update Cleanup

After applying all updates, run:

```cmd
DISM /Online /Cleanup-Image /StartComponentCleanup /ResetBase
```

- Reduces disk space by cleaning up superseded updates.
- Prevents rolling back removed update versions.

---

### ✅ Windows Update Assistant (GUI)

For feature updates and major cumulative rollups:
- https://www.microsoft.com/software-download/windows10
- https://www.microsoft.com/software-download/windows11

---


---

## ⚠️ Deprecated Windows Features & How to Re-enable Them

Sometimes legacy devices or applications require older protocols or features that are disabled by default in modern Windows versions.

### ✅ SMBv1 (Server Message Block v1)

**Warning**: SMBv1 is deprecated and insecure. Only enable if absolutely necessary.

- **Enable via Windows Features (GUI)**:
  - Control Panel → Programs and Features → Turn Windows features on or off
  - Check "SMB 1.0/CIFS File Sharing Support"

- **Enable via PowerShell**:
  ```powershell
  Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
  ```

- **Disable after migration**:
  ```powershell
  Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
  ```

---

### ✅ Internet Explorer Mode (for Legacy Web Apps)

- IE is deprecated, but Edge has "IE Mode" for legacy apps.
- Enable via Group Policy:
  - Computer Configuration → Administrative Templates → Microsoft Edge → Configure Internet Explorer integration → Enable

---

### ✅ Telnet Client

```powershell
Enable-WindowsOptionalFeature -Online -FeatureName TelnetClient
```

- Useful for simple TCP port tests with legacy devices.

---

### ✅ DirectPlay (Old Games Support)

```powershell
Enable-WindowsOptionalFeature -Online -FeatureName DirectPlay -NoRestart
```

---

### ✅ SNMP (Simple Network Management Protocol)

```powershell
Add-WindowsCapability -Online -Name "SNMP.Client~~~~0.0.1.0"
```

- Required by many legacy network printers and monitoring tools.

---

### ✅ Legacy Windows Photo Viewer

Re-enable registry entries to use classic Windows Photo Viewer in Windows 10/11.
- Guides available online; involves file association changes.

---

### ✅ Other Deprecated Components

- **XPS Viewer**:
  ```powershell
  Add-WindowsCapability -Online -Name "XPS.Viewer~~~~0.0.1.0"
  ```

- **Windows Media Player** (optional in some editions):
  ```powershell
  Enable-WindowsOptionalFeature -Online -FeatureName WindowsMediaPlayer
  ```

---

## 📝 Reminder:
Always disable deprecated features after use, or isolate devices needing them for security.

---
