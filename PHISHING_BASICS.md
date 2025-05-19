Phishing 101

running malicious code or stealing login credentials

after the objective has been decided they id a comms method

email is the most traditrioal and commonly used medium

smishing, vishing and deepfacke-enhanced phishing are more common


Email Phishing

email text is crafted with a goal such as convincing target to perforrm an action that will exr code

malicious attachment in the email and persude the target to open it

PDFs, 7zip/zip shortcut files and calendar invites

embed a link that leads to an explot laden website

pharming: websites

pretext is a fake story designed to convince, success needs believable pretext

small details matter, typos, bad grammar and for atting mistakes can explose the scam

Solid social engineering skills, a strong command of the target's primary language nad details collection through OSINT, note the 7 deadly sins framework

pride, greed, wrath, envy, lust, gluttony, and sloth

email must come from a familiar source, should align other email based metadata with something the target might expect

email from unfamiliar domain is suspicous

purchaase look-alike doamins resembling the target's org, vendors or other familiar companies

if access to legitimate email account from the org or one of the cliet of the target the use of the email sugnificantly improves the chance of success

pretext must align with the expectation of a target

Whaling: a form of spear phishing that targets high level individuals

more care and attention needed, pretexts are highly customized and needs significant research or insider knowledge

generic approaches: mimicking email from a commonly used service:
Slack, Zoom, Gmail. Microsoft Teams (great for clone phishing)


Smishing, Vishing and Chatting

SMS phishing 

more personal and direct compared to emails, effectiveness depends on the target

needes pretext since the target is getting a message from a unknow number

CEO gift card scam: poses as a senior executive trying to send employee gift card (greed, pride, wrath, envy)

vishing, calls a target on the phone, relies on social engineering skills rather than technical skills

caller ID spoofing techniques, targetting VoIP

SIM swapping, call a mobile network provider and claim to be the owner of a specific mobile phone account, convince the network provider to transfer the phone number from the target's SIM to a SIM card they control.

SIM swapping used to bypass phone-based MFA 

chat messaging applications: Discord, Slack and Teams



Enhancing Phishing through Social Engineering

psychological manipulation instead of technical experties

trust is the ultimate goal of any successful phishing campaign

pretext must align with expectation and payload

details matter

approximate a impresonation attack's writing tone

Urgency: acting quickly without questioning the safty of the requested action: 
works best in organizations which have unhealthy work cultures

if target often recevies urgent requests and is expected to deliver on them without any critial thought, they are much more lickely to fall

Fear cause target to momentarily suspend judgement, Authority can amplify the urgency of the request

a good working relation and culture is a part of the security posture

see strategies must be balanced as we consider elements of trust and the benefits of creating a good rapport (pavlovian)


LLMs, Generative AI and Deepfakes

Retrieval Augmented Generation: process a laege amount of publicly available information about a target and help in crafting pretext

voice cloning AI mr crabs singing for example

deepfake video scam: needs significant computing power and is getting banned



Role on Inbound Email Filters

defenses: imbound email filters, scans all emails for markers of malicious behavior and blocks them

consider the relative reputation of an incoming email's domain, calculated as a function of the reputation block lists

scrutinize file attachments, leverage evasion techniques when delivering payload.

EXR, SCR files are often considered malicious

many orgs also explicity flag email originating from external domains with visible markers


Identifying Risks of Malicious Office Macros

Several application in the MsOffice support Visual Basic for Applications a built in scripting language that enables Office docs to execute custom macros

Ms has attempted to address malicious macros, they disabled them by default, forcing users to explicitly enable them

Mark of the Web, a file attribute set by windows when a file is downloaded from an external source

Windows applications can reference the MotW to determine whether a file should be trusted

MS introduced Protected View, presents a warning when users open office documents with the MotW set

Microsoft started blocking macros running in any documents with a MotW by default

Admins can also enforce these protections at the AD group policy level, preventing domain attached machines from exiting the protectede view or running macros at all

less common in the near future, many organization run outdated and pirated versions of MS office


Assess Threats from Malicious Files

windows based exe is statistically unlikely that these files will even reach a target's inbox

moved to SCR, HTA, JScript

given the popularity of Office documents in enterprise environments, attackers begun wusing ancillary office documents that my skrit the protections of mainstream Word, PowerPoint or Excel 

PDF viewers. Adobe Acrobat Reader is a common target for attackers

in especially advanced targeted attacks, we could even leverage a vulnerability in a piece of software which we know our target runs

short shelf life, because they are publicly known and have patches, 0-days are costly and time consuming, but microsoft stepping up macro security, so 0-days are getting more common

advanced attackers now reverse engineer security patches to find new vulnerabilities before they're patched, short but effective launch window


Recognize Malicious Links

credentual harvesting is to host a website clone of a commonly used service like:
Gmail
Zoom
Ms Login

this in conjunction with a convincing pretext in the phishing email might be enough to convice a target

password manager applications will expose these websites as frauds since they will only triifer on the proper domain

there are flaws in the password managers

LastPass browser extension trick into revealing passwords by crafting a specific URL

we can't always exploit them in a  credential phishing campaign 

might not try to extract credentials at all, link to a webpage which triggers a browser exploit which would allow for RCE -> very advanced, uncommon without access to browser exploit 0-day or N-day

web page might also try to exploit Cross-Site Request Forgery, browser might have an existing session open with a specific web service, which an attacker can makee the browser act upon

link must appear credible and enticing, the actual URL doesn't look suspicous, URL with random strings or strings which are inappropriate to the pretext 

obfuscate the embedded link using a URL shortener such as TinyURL or Bitly

homograph URLs, that replace ASCII char in a URL with char from Cyrillic, Greek or Latin alphabets, 

HTTPS required

deprecating New Technology LAN manager, we coud leverage authentication leak aginst older systems

malicious links bypass file protections by tricking users into clicking harmful URLs


Differentiate Creditial Phishing and MFA

once we have credential -> MFA

prompt bombing, which targets MFA applications that use PUSH-based authentucation prompts. bombing the target with login attempts, which trigger prompts on the phone asking them to approve, this creates MFA fatigue, where users assume the authorization requests are legitmate

another approach is to add MFA prompt directly into the credential stealing website's login flow, captres the username and password also the MFA token

browser in the middle attack, attacker proxies a real session to capture authentucation details. 
cuddlephish help automate this kind of attack, using such a tool requires access to a public IP address and cannot be step up locally

brute forcing MFA: 6 numbers 

or just social engineering


Creating a Zoom Credential Phishing Pretext

read outgoing mail

note voice and communication style along with the author and intended receipiant 

using chatgpt:
Looking at the following email:
<email>
write another email in the same style as this, and include a reminder for employees to login to Zoom. Include a hyperlink that can be clicked and directs people to the appropriate page


Cloning a Legitimate Site

replicate zoom sign in page 

internet search for zoom signin

create a ZoomSIgnin folder 

mkdir ZoomSignin
cd ZoomSignin

use wget to clone the page

-E to change the file extension to match the MIME type of the file

-k to convert all the links in the document to point to local alternatives 

-K to save the original file with a .org extension 

-p to download all necessary files for viewing the page

-e robots=off will ignore robots.txt which might prohibit downloads

-H download all files from external hosts 

-D<domain> limit tp files on the domain with

-nd to save all diles in a flat directory struct in the current working directory


Cleaning up the Clone

search files in directory for "OWASP" to find the alert text
grep "OWASP" *

we then grep the file of the warning

we then delete the line from the main page, CSRFGuard alert box should no longer display


Injecting Malicious Elements in the Clone

move phishing page to a proper web server

mv -f * /var/www/html (moves all content of the folder that we're in to the web root)

systemctl start apache2 (starts apache2 server instead of python)

cd /var/www/html (move to webroot)

back up original page so we can fall back and compare

cp -f signin.html signin_orig.html

inspect parts and id the input form

right clicking the header element and selecting the copy followed by other html

next we need to change the id of the div inside the html such that the dynamically generated code

ask chat gpt to rewrite the code

sudo echo "" > credentials.txt
sudo chmod 777 custom_login.php
sudo chmod 777 credentials.txt
give credential to the webroot to read and write