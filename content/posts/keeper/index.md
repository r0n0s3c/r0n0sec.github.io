---
layout: post
title: Keeper - HackTheBox
categories:
- HackTheBox
tags:
- Default Credentials
- Linux
- Keepass
- Putty
- Database Dump
- CVE-2023-32784
date: 2023-09-28
description: Keeper is a machine that uses a well-known ticket web application called Request Tracker with default credentials. Using the credentials we get access as root and find a ticket with information made by a user that has the SSH password in his description. Those credentials give us access to their SSH session. In there, we get a keepass dump and database. We use a vulnerability of keepass that allows us to get parts of the master key from a dump and with a quick search we get all the master key. In the database, we have a PuTTY-User-Key-File that we need to translate to an SSH private key to login in SSH as root. 
summary: Keeper is a machine that uses a well-known ticket web application called Request Tracker with default credentials. Using the credentials we get access as root and find a ticket with information made by a user that has the SSH password in his description. Those credentials give us access to their SSH session. In there, we get a keepass dump and database. We use a vulnerability of keepass that allows us to get parts of the master key from a dump and with a quick search we get all the master key. In the database, we have a PuTTY-User-Key-File that we need to translate to an SSH private key to login in SSH as root.   
cover:
  image: images/machine_img.png
---

## Recon

Scanning the target machine with nmap we get two open ports(80 and 22).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3539d439404b1f6186dd7c37bb4b989e (ECDSA)
|_  256 1ae972be8bb105d5effedd80d8efc066 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Once we access the port 80 in the browser we get: `To raise an IT support ticket, please visit tickets.keeper.htb/rt/`
We add `tickets.keeper.htb` and `keeper.htb` to hosts file.

### Website

It seems like a ticket website called "Request Tracker" in the version: `4.4.4+dfsg-2ubuntu1 (Debian)` and the company that distributes this service has a official website promoting the service outside this challenge. This means that the website may be legit but may be in a older vulnerable version.

It seems like that it does not has vulnerable versions and after running `nikto` and `gobuster` we didn't find anything.
Searching for default credentials we found the username "root" and password "password". Trying these credentials we get access to a root account.



## Foothold

It seems like we have one ticket from the user lnorgaard with the email `lnorgaard@keeper.htb`. We have another user with the email `webmaster@keeper.htb` which is attached to the ticket too. The ticket is called `Issue with Keepass Client on Windows` and has the following information:

```
Lise,

Attached to this ticket is a crash dump of the Keepass program. Do I need to update the version of the program first...?

Thanks!  
```

Then lnorgaard made a comment:

```

I have saved the file to my home directory and removed the attachment for security reasons.

Once my investigation of the crash dump is complete, I will let you know.
```

In this user profile in the tab basics we get a lot of information about the user, including a comment: `New user. Initial password set to Welcome2023!`
Using the credentials: `lnorgaard:Welcome2023!` we get access to the user ssh login and the user.txt flag.

![](/images/keeper/user.png)

We found a zip that seems like the dump from the Keepass mencioned in the ticket. Lets copy to our machine and analyze it(`scp lnorgaard@10.10.11.227:RT30000.zip . `). Inside the zip, we have two files: passcodes.kdbx which seems like the keepass database and KeePassDumpFull.dmp which seems like the dump.

## Privilege Escalation

Searching for ways to look at the keepass dump we found the CVE-2023-32784(https://nvd.nist.gov/vuln/detail/CVE-2023-32784). This CVE is related to a vulnerability in keepass that allows the recovery of some master password characters from a memory dump of a proccess, swap file (pagefile.sys), hibernation file (hiberfil.sys), or RAM dump of the entire system. There is a POC that using a dump of the keepass, we can extract the master password(https://github.com/vdohney/keepass-password-dumper).



Note: To run the POC it is required to install dotnet, just follow the following documentation if your distro is based on debian: https://learn.microsoft.com/en-us/dotnet/core/install/linux-debian

Running the exploit against the dump gives us all the characters in the master key except from the first two characters: ●{ø, Ï, ,, l, `, -, ', ], §, A, I, :, =, _, c, M}dgrød med fløde.

Searching for the master key part that we know: `dgrød med fløde`, we get a typical recipe called: rødgrød med fløde. Using it against the keepass database we get access to it. 

![](/images/keeper/keepass.png)

Trying the root password we didn't get a shell as root, however get a rsa key in the comments. Lets translate that to a file and try to login in ssh with root.

```
Group: Network, Title: keeper.htb (Ticketing Server), User Name: root, Password: ********, Creation Time: 5/19/2023 9:36:50 AM, Last Modification Time: 5/24/2023 11:48:21 AM

PuTTY-User-Key-File-3: ssh-rsa
Encryption: none
Comment: rsa-key-20230519
Public-Lines: 6
AAAAB3NzaC1yc2EAAAADAQABAAABAQCnVqse/hMswGBRQsPsC/EwyxJvc8Wpul/D
8riCZV30ZbfEF09z0PNUn4DisesKB4x1KtqH0l8vPtRRiEzsBbn+mCpBLHBQ+81T
EHTc3ChyRYxk899PKSSqKDxUTZeFJ4FBAXqIxoJdpLHIMvh7ZyJNAy34lfcFC+LM
Cj/c6tQa2IaFfqcVJ+2bnR6UrUVRB4thmJca29JAq2p9BkdDGsiH8F8eanIBA1Tu
FVbUt2CenSUPDUAw7wIL56qC28w6q/qhm2LGOxXup6+LOjxGNNtA2zJ38P1FTfZQ
LxFVTWUKT8u8junnLk0kfnM4+bJ8g7MXLqbrtsgr5ywF6Ccxs0Et
Private-Lines: 14
AAABAQCB0dgBvETt8/UFNdG/X2hnXTPZKSzQxxkicDw6VR+1ye/t/dOS2yjbnr6j
oDni1wZdo7hTpJ5ZjdmzwxVCChNIc45cb3hXK3IYHe07psTuGgyYCSZWSGn8ZCih
kmyZTZOV9eq1D6P1uB6AXSKuwc03h97zOoyf6p+xgcYXwkp44/otK4ScF2hEputY
f7n24kvL0WlBQThsiLkKcz3/Cz7BdCkn+Lvf8iyA6VF0p14cFTM9Lsd7t/plLJzT
VkCew1DZuYnYOGQxHYW6WQ4V6rCwpsMSMLD450XJ4zfGLN8aw5KO1/TccbTgWivz
UXjcCAviPpmSXB19UG8JlTpgORyhAAAAgQD2kfhSA+/ASrc04ZIVagCge1Qq8iWs
OxG8eoCMW8DhhbvL6YKAfEvj3xeahXexlVwUOcDXO7Ti0QSV2sUw7E71cvl/ExGz
in6qyp3R4yAaV7PiMtLTgBkqs4AA3rcJZpJb01AZB8TBK91QIZGOswi3/uYrIZ1r
SsGN1FbK/meH9QAAAIEArbz8aWansqPtE+6Ye8Nq3G2R1PYhp5yXpxiE89L87NIV
09ygQ7Aec+C24TOykiwyPaOBlmMe+Nyaxss/gc7o9TnHNPFJ5iRyiXagT4E2WEEa
xHhv1PDdSrE8tB9V8ox1kxBrxAvYIZgceHRFrwPrF823PeNWLC2BNwEId0G76VkA
AACAVWJoksugJOovtA27Bamd7NRPvIa4dsMaQeXckVh19/TF8oZMDuJoiGyq6faD
AF9Z7Oehlo1Qt7oqGr8cVLbOT8aLqqbcax9nSKE67n7I5zrfoGynLzYkd3cETnGy
NNkjMjrocfmxfkvuJ7smEFMg7ZywW7CBWKGozgz67tKz9Is=
Private-MAC: b0a0fd2edf4f0e557200121aa673732c9e76750739db05adc3ab65ec34c55cb0
```

Once we obtain the previous PuTTY-User-Key-File(ppk), we need a way to translate the rsa information into a private key so we can use in our ssh command in order to get a session as root. putty-tools have a binary called puttygen that can generate a private and public key from a ppk file. However not all versions of puttygen work. We started by downloading the version using the package manager apt but the version that we got was 0.74. Running th command to translate the file into a private key: `puttygen rsa.ppk -O private-openssh -o id_rsa` we get `PuTTY key format too new`. We needed to get a newer version of putty that supports the version 3 of PuTTY-User-Key-File. One article explains how to install the version 0.76, https://medium.com/@arslion/convert-ppk-version-3-to-ssh-private-public-keys-pem-on-linux-ubuntu-4bf2c8db1ef2, and how to get the private key. Using the article we finally get a private key for root user. Once we login using the private key we get a shell as root: `ssh -i id_rsa root@10.10.11.227`