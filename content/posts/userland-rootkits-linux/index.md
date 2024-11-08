---
layout: post
title: Userland Rootkit in Linux
categories:
- Information
tags:
- userland rootkit
date: 2024-01-22
description: Userland rootkit in linux
summary: Userland rootkit in linux
cover:
  image: images/machine_img.png
---  


## Introduction

Hello, in the following blog i will explain what i found about a concept i didnt know in the forensic world called rootkits and userland rootkits in linux. I made this post after finishing the suspicious threat forensics challenge in htb, I hope you like!


## Rootkits

For everyone that dont know what is a rootkit, basically a rootkit is some software that may work with some other malicious code to conceal its presence as well as any malicious activities. It can conceal the existence of files, processes, remote connections and many more stuff.

Basically rootkits hook into stuff and use shared resources to lie about a presence of a malicious threat. Example, if we want to hide a process from the task manager in windows, we hook the rootkit to the task manager and hide the process when the system admin opens the task manager process using a shared function/library.

Rootkits have two types, userland and kernel rootkits.
We will only delve into userland rootkits in this post but basically userland rootkits like the ones from [here](https://github.com/milabs/awesome-linux-rootkits) are installed in the system and use the process memory to hook into processes and other stuff. The kernel rootkits are more difficult to interact becasue they work in the core of the OS and hook to sys calls to hide the malicious threats.


For more info read:
- https://compilepeace.medium.com/memory-malware-part-0x2-writing-userland-rootkits-via-ld-preload-30121c8343d5
- https://www.malwarebytes.com/blog/news/2016/12/simple-userland-rootkit-a-case-study

## Userland Rootkits on Linux

...


For more information:
- https://neugierig.org/software/blog/2011/05/memory.html