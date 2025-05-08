# Information Gathering Cheat Sheet

## Penetration Testing Lifecycle

1. Define Scope
2. Information Gathering
3. Vulnerability Detection
4. Initial Foothold
5. Privilege Escalation
6. Lateral Movement
7. Reporting & Analysis
8. Lessons Learned & Remediation

---

## Scope Definition

Specify:
- IP ranges
- Hosts
- Applications

---

## Passive Information Gathering

### WHOIS
```
whois <target domain or IP>
whois <target> -h <WHOIS server IP>  # For labs only
```

### Google Dorking
- `site:megacorpone.com`
- `filetype:txt`, `ext:php`, `ext:xml`, `ext:py`
- `-filetype:html`
- `intitle:"index of" "parent directory"`

### Other Sources
- **Netcraft:** https://searchdns.netcraft.com/
- **GitHub:** search manually or use `gitrob`, `gitleaks` with access tokens
- **Shodan:** Internet-connected devices search engine
- **Security Headers:** https://securityheaders.com/
- **SSL Tests:** https://ssllabs.com/ssltest

> LLM-based OSINT tools are discouraged for OPSEC reasons

---

## Active Information Gathering

### DNS Enumeration

#### Record Types
- `A`, `AAAA`, `MX`, `NS`, `PTR`, `CNAME`, `TXT`

#### Commands
```bash
host www.megacorpone.com            # A record
host -t mx megacorpone.com          # MX record

# Brute force subdomains
for ip in $(cat list.txt); do host $ip.megacorpone.com; done

# Reverse DNS sweep
for i in $(seq 200 254); do host 51.222.169.$i; done | grep -v "not found"
```

### Tools
- `dnsrecon -d megacorpone.com -t std`
- `dnsrecon -d megacorpone.com -D ~/list.txt -t brt`
- `dnsenum megacorpone.com`

### Windows DNS Queries
```powershell
nslookup mail.megacorp.com
nslookup -type=TXT info.megacorptwo.com 192.168.50.151
```

---

## Port Scanning

### Netcat (nc)
```bash
nc -nvv -w 1 -z 192.168.50.152 3388-3390   # TCP scan
nc -nv -u -w 1 -z 192.168.50.152 120-123   # UDP scan
```

### Nmap Essentials
```bash
sudo nmap -sS -p 10-1222 <ip>             # SYN scan
nmap -sT <ip>                             # TCP connect (no sudo)
sudo nmap -sU <ip>                        # UDP scan
nmap -v -sn 192.168.50.1-253 -oG sweep.txt
grep Up sweep.txt | cut -d " " -f 2
nmap --top-ports 20 -A -O --osscan-guess <ip>
nmap -sV --script http-headers <ip>
nmap --script-help http-headers
```

### IPTables Logging
```bash
sudo iptables -I INPUT 1 -s <ip> -j ACCEPT
sudo iptables -I OUTPUT 1 -d <ip> -j ACCEPT
sudo iptables -Z                          # Reset counters
sudo iptables -vnL                        # View rules
```

### PowerShell (Windows)
```powershell
Test-NetConnection -Port 445 <ip>
1..1024 | % {echo ((New-Object Net.Sockets.TcpClient).Connect("192.168.50.151", $_)) "TCP port $_ is open"} 2>$null
```

---

## SMB Enumeration (Ports 139, 445)
```bash
nbtscan -r 192.168.50.0/24
nmap -v -p 139,445 --script smb-os-discovery <ip>
net view \dc01 /all                     # Windows shares
```

---

## SMTP Enumeration (Port 25)
```bash
nc -nv <ip> 25
Test-NetConnection -Port 25 <ip>
```
Enable Telnet:
```powershell
dism /online /Enable-Feature /FeatureName:TelnetClient
```

---

## SNMP Enumeration (Port 161)

### Tools & Commands
```bash
sudo nmap -sU --open -p 161 <ip>
echo public > community && echo private >> community && echo manager >> community
for ip in $(seq 1 254); do echo 192.168.50.$ip; done > ips
onesixtyone -c community -i ips

snmpwalk -c public -v1 -t 10 192.168.50.151
snmpwalk -c public -v1 192.168.50.151 1.3.6.1.2.1.6.13.1.3
```

> `-c` = community string, `-v` = version, `-t` = timeout

---

## Disclaimer
**Perform only on systems you have explicit authorization to test. Unauthorized access is illegal.**

---

##  Nmap Flag Reference (Crafting Guide)

- `-sS` : TCP SYN scan (stealth scan)
- `-sT` : TCP Connect scan (uses system's network stack, no raw packets; works without sudo)
- `-sU` : UDP scan
- `-Pn` : Treat all hosts as online (skip ping); use if ICMP is blocked
- `-p <range>` : Specify port range (e.g., `-p 1-65535`)
- `--top-ports <N>` : Scan top N most common ports
- `-A` : Aggressive scan; includes OS detection, version detection, script scanning, and traceroute
- `-O` : OS fingerprinting
- `--osscan-guess` : Guess OS even if detection is not confident
- `-sV` : Service version detection
- `--script <name>` : Use specific NSE script (e.g., `http-headers`)
- `--script-help <script>` : Explain what a script does
- `-oG <file>` : Output in greppable format (useful with `grep`)
- `-v` : Verbose output
- `-sn` : Ping scan (host discovery only)

**Examples**:
```bash
nmap -sS -p 1-1000 -Pn <target>
nmap -A -O --osscan-guess <target>
nmap -sU --top-ports 50 --open <target>
```

---

##  IPTables Flag Reference

- `-I <CHAIN> <NUM>` : Insert rule at specific position (e.g., `-I INPUT 1`)
- `-s <ip>` : Source IP to match
- `-d <ip>` : Destination IP to match
- `-j ACCEPT` : Target action (e.g., allow traffic)
- `-Z` : Reset counters
- `-vnL` : List rules, verbose and numeric

**Examples**:
```bash
sudo iptables -I INPUT 1 -s <ip> -j ACCEPT
sudo iptables -I OUTPUT 1 -d <ip> -j ACCEPT
sudo iptables -Z
sudo iptables -vnL
```

---

##  PowerShell Port Scan Logic

```powershell
1..1024 | % {echo ((New-Object Net.Sockets.TcpClient).Connect("IP", $_)) "TCP port $_ is open"} 2>$null
```

- `1..1024` : Port range loop
- `% {}` : ForEach loop (alias)
- `New-Object Net.Sockets.TcpClient` : Creates a TCP client
- `.Connect("IP", $_)` : Attempts connection to port
- `2>$null` : Suppress error messages

---

##  Onesixtyone Usage Flags

- `-c <file>` : Community string list file (e.g., public, private)
- `-i <file>` : IP list file

**Examples**:
```bash
echo public > community && echo private >> community
for ip in $(seq 1 254); do echo 192.168.50.$ip; done > ips
onesixtyone -c community -i ips
```

---
