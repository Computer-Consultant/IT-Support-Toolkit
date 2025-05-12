# IT Admin Testing Toolkit

---

### 🔎 Using Microsoft Autoruns for Deep Analysis

**Autoruns** from Microsoft Sysinternals provides a complete and categorized view of all startup-related entries:

- Logon items
- Scheduled tasks
- AppInit DLLs
- Services
- Drivers
- Explorer shell extensions

#### ✅ Launch Autoruns (GUI)

1. Download from:  
   https://learn.microsoft.com/sysinternals/downloads/autoruns

2. Extract and run:

```cmd
autoruns.exe
```

3. Filter out Microsoft entries for easier troubleshooting:
   - Uncheck **"Hide Microsoft entries"** in the toolbar

#### 🧪 Use CLI Mode (for remote or scripted use)

```cmd
autorunsc.exe -nobanner -h > autoruns_filtered.txt
```

- `-h` hides Microsoft entries
- `-nobanner` suppresses the Sysinternals intro text

---

### 💡 Live Share or Field Diagnostic Use

If troubleshooting a client PC:

- Place **Autoruns** on a network share or USB stick
- Launch directly:

```cmd
\live-share\tools\autoruns\autoruns.exe
```

Or map the share:

```cmd
net use Z: \live-share\tools
Z:\autoruns\autoruns.exe
```

This avoids leaving tools permanently on the client system.

---

---

## 🌐 Network Activity Tools – TCPView and Netstat

### 🛰️ TCPView (Sysinternals)

**TCPView** provides a real-time list of all TCP and UDP endpoints on your system:

- Shows process name, PID, local/remote addresses, ports, and connection state
- Can be sorted and filtered
- Allows killing or closing connections

#### ✅ Download:
- https://learn.microsoft.com/sysinternals/downloads/tcpview

#### ✅ Launch:

```cmd
tcpview.exe
```

Use the toolbar to:
- Refresh quickly
- Highlight new or closed connections
- Close or terminate suspicious processes

> Great for catching apps phoning home, malware, or debugging port use.

---

### 📡 Netstat (Built-In Windows Tool)

**Netstat** provides snapshot-style network info via command line.

#### ✅ Common Usage:

```cmd
netstat -ano
```

- `-a` = show all connections and listening ports
- `-n` = show addresses numerically (skip DNS lookup)
- `-o` = show the owning process ID (PID)

To match PID to process name:

```powershell
Get-Process -Id <PID>
```

#### ✅ Example:

```cmd
netstat -anob
```

- `-b` shows which executable is responsible for each connection  
  *(requires elevated CMD)*

> Use this when TCPView isn't available or for scripting.

---

---

### 💡 Tip: Run Sysinternals Tools Without Downloading

Most Sysinternals tools can be run directly over the internet or from a network share:

#### ✅ Run from Sysinternals Live Share

You can run any tool directly using:

```cmd
\live.sysinternals.com	ools\ToolName.exe
```

Examples:

```cmd
\live.sysinternals.com	oolsutoruns.exe
\live.sysinternals.com	ools\procexp.exe
\live.sysinternals.com	ools	cpview.exe
```

> No need to download manually — just run from the Start → Run dialog or elevated Command Prompt.

#### ✅ Run from Your Own Shared Tools Folder

If deploying tools from a central server, place them on a network share:

```cmd
\yourserver	oolsutoruns.exe
\fileserverdmin\sysinternals	cpview.exe
```

Or map the drive first:

```cmd
net use Z: \yourserver	ools
Z:	cpview.exe
```

---


---

## 🧭 Editing the Windows Hosts File – Protections and Workarounds

The `hosts` file in Windows is commonly used to override DNS resolution, but modern systems implement protections to prevent abuse.

### 📄 Location of the Hosts File

```plaintext
C:\Windows\System32\drivers\etc\hosts
```

---

### 🔒 Protections That May Interfere

#### 1. UAC and Admin Rights

You must edit the hosts file with elevated permissions:

```cmd
notepad C:\Windows\System32\drivers\etc\hosts
```

> Right-click Notepad → **Run as administrator** before opening the file.

---

#### 2. Windows Defender Tamper Protection

Defender may block edits to the hosts file, especially redirections to Microsoft, antivirus, or update domains.

- Disable Tamper Protection (if necessary) from:
  - **Windows Security** → **Virus & threat protection**
  - Click **Manage settings**
  - Turn off **Tamper Protection**

> 🔁 Re-enable it after testing.

---

#### 3. Controlled Folder Access or 3rd-party AV

Controlled folder access may block apps from writing to `System32`.

- Add your editor (e.g., Notepad++) to the list of allowed apps.

---

### ⚙️ PowerToys Hosts File Editor

Microsoft PowerToys includes a **Hosts File Editor** with built-in elevation and structured UI.

- Download PowerToys: [https://github.com/microsoft/PowerToys](https://github.com/microsoft/PowerToys)
- Open **PowerToys → Hosts File Editor**
- Add or edit entries with validation

> 🟢 Useful for quickly enabling/disabling entries or avoiding formatting errors.

---

### 🧪 Testing Hosts File Changes

1. Add an entry like:

   ```plaintext
   127.0.0.1 facebook.com
   ```

2. Test using:

   ```cmd
   ping facebook.com
   ```

   Expected output:
   ```
   Pinging facebook.com [127.0.0.1]
   ```

3. Or flush DNS and test:

   ```cmd
   ipconfig /flushdns
   nslookup facebook.com
   ```

---

