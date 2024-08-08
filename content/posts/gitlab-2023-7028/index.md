---
layout: post
title: Gitlab CVE_2023_7028 - Vulnerability
categories:
- Vulnerability
tags:
- gitlab
date: 2024-01-19
summary: Gitlab CVE_2023_7028 vulnerability has the ability to allow unauthorized users to take over user accounts, without any interaction from the victim. The vulnerability was found by asterion04 and was assigned the severity Critical.
description: Gitlab CVE_2023_7028 vulnerability has the ability to allow unauthorized users to take over user accounts, without any interaction from the victim. The vulnerability was found by asterion04 and was assigned the severity Critical.
cover:
  image: images/post_img.png
---
Gitlab CVE_2023_7028 vulnerability has the ability to allow unauthorized users to take over user accounts, without any interaction from the victim.
The vulnerability was found by asterion04 and was assigned the severity Critical.

## Afftected Versions

- 16.1 to 16.1.5
- 16.2 to 16.2.8
- 16.3 to 16.3.6
- 16.4 to 16.4.4
- 16.5 to 16.5.5
- 16.6 to 16.6.3
- 16.7 to 16.7.1

## How it works

When a user forgets the password many web applications have a reset password functionality that in most of the times it requires only the user email.
Then the link to reset is sent to the email and everything is fine. The problem here is that the parameter sent to the server including the email of the user that wants to reset the password accepts more then one email, and the link to reset the password is sent to both email addresses, the user email and the attacker email.

All the attacker needs to know is the user email address for that gitlab.
The commit with that vulnerability was introduced in January 10, [here](https://gitlab.com/gitlab-org/gitlab-foss/-/commit/21f32835ac7ca8c7ef57a93746dac7697341acc0). 

![Alt text](/images/gitlab-2023-7028/image.png)


## POC

A POC can be found [here](https://github.com/Vozec/CVE-2023-7028/blob/main/CVE-2023-7028.py).
Essentially what it does is:
- Since the password reset has a CSRF token we need to generate an authentic one, to do this we make a request to `/users/password/new`
- Then we make a request to the vulnerable endpoint `POST /user/password` we a list containing the email of the victim and the attacker in a list.

## Detection and Mitigations

### Detection 
- Check for for **API calls** to `/users/password` with multiple email addresses.
- Inspect **email server logs** for messages from GitLab with unexpected recipients (attacker-controlled emails).
- Examine **GitLab audit logs** for entries containing a value for `meta.caller.id` as `PasswordsController#create`.
- Enable GitLab security alerts that would allow early awareness of patches.

### Mitigations
- Enable **GitLab security alerts** that would allow early awareness of patches.
- **Upgrade GitLab** to a patched version.
- Enable **two-factor authentication (2FA)** for all GitLab accounts, especially administrator accounts. Even if the attackers are able to exploit this vulnerability they can enter in the account if it is protected with 2FA.

*Source: Tryhackme room - GitLab CVE-2023-7028 *