Active Directory Introduction and Enumeration

Active Directory Introduction

AD is a service but also a management layer, AD contains info of env, storing info of user, groups && computers, each referred to as objects

Permissions set on each on each object is the privilege that object has in the domain

config and maintaining AD is daunting for admin, given the amount of information serving as active vectors

to config a instance of AD, admin need to create a domain name such as corp.com, where corp is often the organization itself

within the corp.com domain, admin can add objects such as computers, users and group objects

To ease management, system admin organize objects into Organizational Units

OU are file system folders where they contain objects of the domain

Computer object represents actual servers and workstations
User objects represents account

all AD objects contain attributes:
user object include first name, last name, username, phone number etc

AD login:
request is sent to Domain Controller, checks whether the user is allowed to log on
one or more DC act as the hub and core of the domain, storing all OU, objects and attributes

Objects are assigned to AD groups so that admin can manage them as a single unit

Member of Domain Admin: most privileged objects

AD instance can host more than one domain in a domain tree, or multiple domain trees in a domain forest

Enterprise Admins group are grnted full control over all domain in the forest and have Admin privilege on all DC

most tool to enumerate AD uses Lightweight Directory Access Protocol


Enumeration - Defining Goals

scenario:
corp.com domain, obtained user credential for a domain user

stephanie, with rdp on win 11 , not local admin


Manuel Enumeration

AD Enumberation Using Legacy Windows Tools

first thing first we rdp into the account
given that it is a domain account:
xfreerdp3 /u:stephanie /d:corp.com /v:<ip>
note that /d: is used
with password LegmanTeamBenzoin!!

To avoid Kerberos Double Hop use RDP as much as possible, untill PEN300

start with net.exe

net user /domain
gives a list of users

net user jeffadmin /domain
shows attributes of jeffadmin user

note that admins often add serfix to usernames in a domain to ID function

net group /domain
shows a list of groups in the domain

net group "<groupname>" /domain
shows attributes of the group: group member etc



Enumberating AD with Powershell and .NET Classes

Get-ADUser: but only default on domain contollers as Remote Server Administration Tools

LDAP is uesed as the communication channel for the query

we'll use Active Directory Services Interface (built on COM) as LDAP provider

LDAP: //HostName[:PortNumber][/DistingushedName]

HostName can be computer name, IP address or a domain name, note that simply using domain name might resolve to any of the DC

we need to look for the DC that holds the most updated information: Primary Domain Controller

there is only one PDC in a domain, it is the DC with the PdcRoleOwner property

PortNumber is optional: note that non standard ports might be used so proper enumeration is important

DistinguishedName is a part of the LDAP path, name that uniquely ids an object in AD

objects in AD must be formatted according to specific naming standard

CN=Stephanie, CN=Users, DC=corp, DC=com

CN is Common Name, identifier of an object in the domain
DC is Domain Component AKA distinguished name

obtaining required hostname for PDC

in MS .NET classes: System.DirectoryServices.ActiveDirectory :: domain class

it contains a reference to the PdcRoleOwner 

in powershell:
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
returns PdcRoleOwner

([adsi]'').distinguishedName
returns DN in the LDAP path format



remember to bypass the exe policy of scripts:
powershell -ep bypass


powershell script
# Store the domain object in the $domainObj variable
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

# Store the PdcRoleOwner name to the $PDC variable
$PDC = $domainObj.PdcRoleOwner.Name

# Store the Distinguished Name variable into the $DN variable
$DN = ([adsi]'').distinguishedName

# Print the $DN variable
$DN


cleaned up:
$PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
$DN = ([adsi]'').distinguishedName 
$LDAP = "LDAP://$PDC/$DN"
$LDAP


Adding search Function to the script above

we'll use .NET:: DirectoryEntry and DirectorySearcher

DirectoryEntry: encapsulates object in AD hierachy, since we want to search from the root, we'll give it the LDAP path

DirectorySearcher: queries aginst AD with LDAP, need to specfigy AD service we want to query in SearchRoot, this is where the search will begin, note that DirectoryEntry already has the LDAP path we'll pass that

$PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
$DN = ([adsi]'').distinguishedName 
$LDAP = "LDAP://$PDC/$DN"

$direntry = New-Object System.DirectoryServices.DirectoryEntry($LDAP)

$dirsearcher = New-Object System.DirectoryServices.DirectorySearcher($direntry)
$dirsearcher.FindAll()

now we need to implement filtering, we can just filter for samAccountType

starting with 805306368 0x30000000 which is all users

$PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
$DN = ([adsi]'').distinguishedName 
$LDAP = "LDAP://$PDC/$DN"

$direntry = New-Object System.DirectoryServices.DirectoryEntry($LDAP)

$dirsearcher = New-Object System.DirectoryServices.DirectorySearcher($direntry)
$dirsearcher.filter="samAccountType=805306368"
$dirsearcher.FindAll()


final script with attributes printing of each object:

$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = $domainObj.PdcRoleOwner.Name
$DN = ([adsi]'').distinguishedName 
$LDAP = "LDAP://$PDC/$DN"

$direntry = New-Object System.DirectoryServices.DirectoryEntry($LDAP)

$dirsearcher = New-Object System.DirectoryServices.DirectorySearcher($direntry)
$dirsearcher.filter="samAccountType=805306368"
$result = $dirsearcher.FindAll()

Foreach($obj in $result)
{
    Foreach($prop in $obj.Properties)
    {
        $prop
    }

    Write-Host "-------------------------------"
}

by changing the dirsearcher.filter="name=<username>"
$prop to $prop.memberof
we can target only the user

to make the script more flexible:
we'll encapsulate into a function

function LDAPSearch {
    param (
        [string]$LDAPQuery
    )

    $PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
    $DistinguishedName = ([adsi]'').distinguishedName

    $DirectoryEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$PDC/$DistinguishedName")

    $DirectorySearcher = New-Object System.DirectoryServices.DirectorySearcher($DirectoryEntry, $LDAPQuery)

    return $DirectorySearcher.FindAll()

}

To use the function:
Import-Module .\function.ps1

and now we can use LDAPSearch, for example:
LDAPSearch -LDAPQuery "(samAccountType=805306368)"
listing all users

generally: 
LDAPSearch -LDAPQuery "(<query>)"

LDAPSearch -LDAPQuery "(objectclass=group)"
listing all groups

foreach ($group in $(LDAPSearch -LDAPQuery "(objectCategory=group)")) {
$group.properties | select {$_.cn}, {$_.member}
}
enumerate every group available in the domain and display user members

$sales = LDAPSearch -LDAPQuery "(&(objectCategory=group)(cn=Sales Department))"
$sales.properties.member
this shoves sales department into $sales and prints all members

$group = LDAPSearch -LDAPQuery "(&(objectCategory=group)(cn=Development Department*))"
$group.properties.member


AD enumeration with PowerView

PowerView PowerShell script, ADPEAS basically

in this case PowerView.ps1 is already installed on C:\Tools

Import-Module .\PowerView.ps1

https://powersploit.readthedocs.io/en/latest/Recon/
all fucntions

Get-NetDomain
basic info of domain

Get-NetUser
a lot of info so just pipe it

Get-NetUser | select cn  (slect is grep for windows)

Get-NetUser | select cn,pwdlastset,lastlogon
this shows username, last set password and last login

Get-NetGroup | select cn
shows groups 

Get-NetGroup "Sales Department" | select member
shows sales department members


Manual Enumeration

Enumerating Operating Systems

Get-NetComputer
enumerates computer objects

Get-NetComputer | select operatingsystem,dnshostname


Permissions and Logged on Users

need to build a map of the domain for attack vectors

when user logs into domain, credentials are cached in memory on the pc they logged in from

note that during an ad assessment, privileges escalation might not be needed right away

good foothold is important, we need to be able to maintain access

if we are able to compromise other users that have the same permission, we can maintain out foothold better

if the password is reset for original user, we can pivot 

don't necessarily need to escate to Domain Admin immediately, there may be other accounts that have higher privilege than a regular domain user

Service Accounts, are a good target, they might have local domain admin privelege

org's most sensitive data may be stored in locations that do not require domain admin, such as db or file server

a chain compromise is when multiple higher-level accounts to reach a goal

PowerView's Find-LocalAdminAccess
scan's network to determine if user has admin permission on any compupter 

Find-LocalAdminAccess relies on OpenServiceW function -> Service Control Manager on the target

PowerView tries to open the db with SC_MANAGER_ALL_ACCESS, which requires admin privilege

running the command with no parameter will enumerate all computer

we should try to visualize how pc and user are connected:
NetWkstaUserEnum and NetSessionEnum
admin v normal

PowerView's Get-NetSession uses both

Get-NetSession -ComputerName files04

we can try to debug output using
Get-NetSession -ComputerName files04 -Verbose

if enumeration with powerview failes we need to pivot to another tool

according to NetSessionEnum doc:
query level 0, 1, 2, 10, 502
0: name of pc
1, 2: require admin with more info
10, 502: name pc, and user

default is query 10

permissions required with NetSessionEnum are in:
SrvsvcSessionInfo:
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity

we can check with GetAcl
Get-Acl -Path HKLM:SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity\ | fl

note that:
BUILTIN, NT AUTHORITY, CREATOR OWNER, APPLICATION PACKAGE AUTHORITY are system which means no NetSessionEnum

long string at the end is capability SID

capability SID is an unforgeable token of authority that gives windows component access to resources but it will not give remote access

Get-NetComputer | select dnshostname,operatingsystem,operatingsystemversion
this gives os versions in use

other tools such as:
PsLoggedOn from SysInternals

PSloggedOn relies on Remote Registry service to scan the associated key and remote registry service is not on by default

.\PsLoggedon.exe \\files04
running it aginst files04 machine


Enumerating through service principal names

service accounts which may also be members of high-privileged groups

app exe in the context of os user -> user launch app user acoount is context

services launched by the sustem runs in service accounts

isolated app can use a set of predefined serice accounts such as:
LocalSystem
LocalService
NetworkService

app like Exchange, MS SQL, Internet Information Service are integrated into AD
Service Principal Name associates a service to service account in AD

we can obtain ip and port of app running on server by simply enumerating all SPN in the domain

info is registered in AD, it's present on the domain controller. we'll just query the DC

setspn.exe which is on windows by default

<cmd>
setspn -L iis_service

another way is to use PowerView
Get-NetUser -SPN | select samaccountname,serviceprincipalname

if we find web04,corp.com we can resolve it for ip
nslookup.exe web04.corp.com


Enumerating Object Permissions

object in AD have set of premissions applied to it with multiple Access Control Entries -> which makes up Access Control List

each Access Control List defines if access to object is allowed

user - access token -> ACL
access token > id and permission

we're just intrested in these:
GenericAll: Full permissions on object
GenericWrite: Edit certain attributes on the object
WriteOwner: Change ownership of the object
WriteDACL: Edit ACE's applied to object
AllExtendedRights: Change password, reset password, etc.
ForceChangePassword: Password change for object
Self (Self-Membership): Add ourselves to for example a group

Get-ObjectAcl -Identity stephanie
to enumerate with powerview

there's going to be output of SecurityIdentifier which represents objects in the AD

we'll need to make it human readable
Convert-SidToName <SID>

highest access permission we can have is GenericAll

Get-ObjectAcl -Identity "Management Department" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights
this filters activedirectoryrights of all in management department and finds genericall and shows sid and adr

"S-1-5-21-1987370270-658905905-1781884369-512","S-1-5-21-1987370270-658905905-1781884369-1104","S-1-5-32-548","S-1-5-18","S-1-5-21-1987370270-658905905-1781884369-519" | Convert-SidToName
to convert all the SID at once

to add a user to a group:
net group "Management Department" stephanie /add /domain

in real pentest make sure to clean up
net group "Management Department" stephanie /del /domain


Enumerating Domain Shares

PowerView:
Find-DomainShare -CheckShareAccess

-CheckShareAccess
to display shares accessable to us

an intresting share:
SYSVOL
things that resides on the domain controller itself, used for domain policies and scripts

%SystemRoot%\SYSVOL\Sysvol\domain-name
mapped by default

sys admins change local workstation passwords through Group Policy Preferences

GPP passwords are encrypted with AES-256, but private key is leaked

gpp-decrypt "<key>"


Active Directory Automated Enumeration

BloodHound

SharpHound C# uses Windows API and LDAP namespace

i have it in kali home

Get-Help Invoke-BloodHound
to get help

Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Users\stephanie\Desktop\ -OutputPrefix "corp audit"
this saves the output into desktop with corp audit prefix

to see changes in domain over a longer period of time use --Loop


Analysing Data using BloodHound

to use bloodhound we need to start Neo4j on kali

it is an open source graph database

sudo neo4j start

bloodhound
to start bloodhound

we grab the zip file from the sharphound zip

we're intrested in the Analysis button

Find all Domain Admins < Domain Information

each circle is node, we can drag them around 

we can hover over a node with mouse or toogle info by pressing control button

we can tell bloodhound how to show this information by going to settings > Node Label Display -> always display

bloodhound can find the shortest path to domain admin

in Analysis
Shortest Path > Find Shortest Paths to Domain Admins

we can rightclick on the branches to display help for more info

Owned Principle:
objects we own in the doamin
we can mark any object as owned

to obtain owned principle:
run search, right click object that shows the middle of the screen and click Mark User as Owned

we can rick-click and select Mark User as Owned

after all information is inputed we can run shortest path to domain admins from owned principals 

Username: neo4j
Password: kali

Username: admin
Password: Bl00dhound#!

Set-DomainUserPassword -Identity "robert" -AccountPassword (ConvertTo-SecureString "Summer2024!" -AsPlainText -Force)
this is how to take over a user if i have generic write