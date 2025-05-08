information gathering:

life cycle:
define scope
information gathering
vulnerability detection
initial foothold
privilege escalation
lateral movement
reporting & analysis
lessons learned remediation

scope:
which ip range, host and applications should be test subjects

passive info gathering:
OSINT -> clarifies or expands an attack surface

whois tcp: information about domain name, name server and registrar
whois <address> -h <WHOIS server ip> (-h is augment for host parameter)

or

whois <target ip> -h <WHOIS server ip>

note that whois server ip is often the vm ip offsec provides as the middle man whois service, normal usage don't neeed -h


google hacking

site:megacorpone.com site opereator limit the search to the domain
site:megacorpone.com filetype:txt limit the search to text files
(can get robot.txt this way)

site:megacorpone ext:php find indexed php page ext:xml ext:py ect

site:megacorpone -filetype:html "-" operator excludes html file type

intitle:"index of" "parent directory" index of in title and parent directory in the page



netcraft: internet service company free web portal that performs info gathering functions
https://searchdns.netcraft.com/


Open source code (github)
github search manual for small repo, for large repo use gitrob and gitleak, need access token


Shodan
search engine that crawls for devices that connects to the internet

Security headers and SSL/TLS
Security Headers: securityheaders.com
SSL Server test from qualys ssl labs: ssllabs.com/ssltest


LLM OSINT: cloud based versions not secure
???? lmao just use proper technique and do it yourself



active info gathering
DNS enumeration
NS: nameserver records contains the name of the authoritative server
A: host record ipv4 of host name
AAAA: quad a host, ipv6 hostname
MX: mail exchange record for email domain
PTR: pointer record, reverse lookup zones
CNAME: canonical name records aliases for other host records
TXT: text records

host www.megacorpone.com (returns ip) searches for A records
host -t mx megacorpone.com searches for email exchange records

bash onliner of hostname resolving:

cat list.txt (creates list.txt) 
within list:
www
ftp
mail
owa
proxy
router

bash command: 
for ip in $(cat list.txt); do host $ip.megacorpone.com; done

for <variable element> in $(source); do host <variable element>.megacorpone; done


for i in $(seq 200 254); do host 51.222.169.$i; done | grep -v "not found"

for <variable int> in $<200-254>; do host 51.222.169.<var int>; done passing grep -v "not found"

loop that scans ip 51.222.169.200-254 filtering out invalid resilts with grep -v


DNS automation:
DNSRecon: dnsrecon -d megacorpone.com -t std
dnsrecon scan on domain megacorpone.com of type standard


drawing from list.txt
dnsrecon -d megacorpone.com -D ~/list.txt -t brt
dnsrecon scan on domain megacorpone.com with direction of text being from list.txt of the current user's location with type of brute force



DNSEnum: dnsenum megacorpone.com (gobuster with dns)



From windows 
kali to windows: xfreerdp /u:username /p:password /v:ipaddress
(remember to check which ip the creditial was provided for)

nslookup mail.megacorp.com for A record of the host
nslookup -type=TXT info.megacorptwo.com 192.168.50.151 
querying 192.168.50.151 DNS server for TXT record of info.megacorptwo.com



port scanning:
very intrusive, triggering IDS/IPS
netcat (just nmap lmao)
nc -nvv -w 1 -z 192.168.50.152 3388-3390
netcat ? wait for 1 second with zero packetsize at 192.168.50.152 of port 3388-3390 with tcp packet

nc -nv -u -w 1 -z 192.168.50.152 120-123
netcat ? with udp packet wait for 1 second with zero packetsize at ip

udp is unreliable, firewall and router drop icmp packets, flase positive where icmp not reachable doesn't get back, tcp goes though the syn syn+ack ack handshake which generates a lot more noise



nmap
iptable to monitor taffic sent
sudo iptables -I INPUT 1 -s 192.168.50.149 -j ACCEPT
sudo iptables -I OUTPUT 1 -d 192.168.50.149 -j ACCEPT
sudo iptables -Z

-I to insert new rule into a given chain (INPUT & OUTPUT chain) followed by rule number
-s to specify source -d for desitination 
-j to accept traffic
-Z to zero packet and byte counter in all chains

-Pn in nmap disables host discovery and treats all targets as online, to stop blocked icmp request from terminating scan

sudo iptables -vn -L (-v for verbose, -n for numeric, -L to list rules)

nmap: -p for tcp ports specification -p 10-1222
pentest: id misconfig and sec vulnerabilities (can be loud)
redteam: real world adversrial sim (evation and stealth)

SYN (stealth scanning) (default scan option)
sudo nmap -sS ip (SYN is sent but no reply to the SYN+ACK so no information is sent to the application layer to detect)

TCP connect scanning
nmap -sT ip (doesn't need sudo because uses berkeley sockets api to craft packets)
connect scans are sometimes needed when done through proxy

UDP scanning, either icmp unreachable or snmp protocol specific packet to get response

sudo nmap -sU ip

-sn for host discovery
-oG for greppable 
nmap -v -sn 192.168.50.1-253 -oG ping-sweep.txt
grep Up ping-sweep.txt | cut -d " " -f 2

--top-ports top 20 tcp ports
-A for all (OS version, script scanning traceroute)
-O os fingerprinting
--osscan-guess to force nmap to guess os

-sV for plain service scan
--scripts to automate scanning tasks (scripts are in /usr/share/namp/scripts)

nmap --script http-headers ip 
determine supported headers of the http service on a system

nmap --script-help http-headers -h for scripts in nmap



Windows: Test-NetConnection -Port 445 ip
powershell scripting:
1..1024 | % {echo ((New-Object Net.Sockets.TcpClient).Connect("192.168.50.151", $_))"TCP port $_ is open"} 2>$null

1..1024 for(int i=1; i<=1024; ++i);
| piping
% {} for each
(New-Object Net.Sockets.TcpClient) a TcpClient class in net.sockets
.Connect("ip", $_) using the .Connect method of the class for the 1-1024 ports
echo is just printing
2>$null supresses error message

SMB enumeration port 139 and 445
server message block
NetBIOS scaner
nbtscan nbtscan -r 192.168.50.0/24
-r means 137 udp is originating port


nmap scripts fpr NSE: /usr/share/nmap/scripts

nmap -v -p 139,445 --script smb-os-discovery ip
more info compared to just -O things like domain or AD service


Windows:
net view\\dc01 /all
all shares running on dc01



SMTP enum port 25

nc -nv ip 25
netcat of trying to connect to port 25
see python3 /home/kali/Desktop/smtp.py username ip


windows 11:
Test-NetConnection -Port 25 ip

dism /online /Enable-Feature /FeatureNmae:TelnetClient
enables telnet client on windows to fully interact with smtp


SNMP enumeration
simple network management protocol

1,2 and 2c has no traffic encription replay MITM attack

SNMP MIB management information base db that contains information related to network management

sudo nmap -sU --open -p 161 ip 
--open limits to only open ports no need to grep for them

onesixtyone bruteforce attack aginst a list of ip but must have text file of community strings and ip addresses to be scanned

echo public > community
ecno private >> community
echo manager >> community
for ip in $(seq 1 254); do echo 192.168.50.$ip; done > ips
onesixtyone -c community -i ips


snmmpwalk, if we know the community string which is puublic in most cases

snmpwalk -c public -v1 -t 10 192.168.50.151
-c community string
-v snmp version number
-t timeout period
-Oa for decoding hex strings

and with the iso num string output you can ammend it at the back so
alternativly check OID on IBM site
snmpwalk -c public -v1 192.168.50.151 1.3.6.1.2.1.6.13.1.3