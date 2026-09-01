---
title: "Active Directory Series : Episode 01: Setting Our Active Directory Lab for pentesting"
date: 2026-08-30 23:43:00 +0000
categories: [Red Team, Active Directory ]
tags: [active directory,  windows-pentesting,penetration-testing, Domain Controller, DC  ]
description: "building an active directory environment is an essential skill to know how active directory works and how it is configured in order to laverne our knowledge to attack it"
image:
  path: /assets/images/Active-Directory/Active-directory-series/episode01/build-lab.png
  alt: ""
---

> Hi, I'm **Zane Bilal** — a computer science student and explorer of the offensive side of cybersecurity. this is my first serie i do about active directory and i am doing it while i am started learning active directory and keep it as a note for me , i hope you will enjoy the serie and happy learning journey

In this serie of active directory will cover some basics of active directory and the some attacks that we can do in our basic lab because there is some attacks that require a complex environment that require a lot of resources and this i can not offer right now to build a complex one , but let's stick with the basics and walk through it step by step. 

# General Overview of 1st episode
in this our first episode i will cover how to build an active directory lab from scratch and how to configure it , but there is some knowledge requirement like terms definitions to fully understand how we can build it for example you need to know what is it kerberos and how it works ? what are the protocol used by it and how it works ? , what are the components of active directory ? and much more, but don't worry there is an amazing bolg series about it online you can find it here: https://niklas-heringer.com/penetration-testing/introduction-to-active-directory/   


# Lab Requirement
before starting building our lab there is some images needed to be downloaded, you need to have +70 G space in your hard disk and at least 16 G ram .
we are running our lab with three vm's, 2 windows 10  Enterprise addition machines ( play the role of client machines) and windows server 2019 (plays the role of a DC ) in addition to the attacker machine that will be kali linux machine ( in total 4 machine --> 3 for active directory lab + 1 for attacker ) in addition to visualization software like vmware or virtualbox so please download the machine from there official sites and let's begin our trip in the world od active directory

# Installation Setup

after downloading the iso images and installing the clients (basic installation with 2 G ram for each machine ), now is the part of installing windows server

## Installing The DC ( Domain Controller )
after installing the windows server 2019 and setting the login credentials , rename the machine to DC , and open the server manager , within the server manager we will install the necessary services for active directory and the main service is AD DS (active directory domain service) 

### installing AD DS 
before installing AD DS we need to understand what is it , so AD DS is a core database and management tool created by Microsoft for Windows network, It stores info on every user, computer, and printer connected to the network, and it checks IDs when people try to log in. 
to install it , within the server manager   go to manage -> add roles and features -> next -> next -> next -> select Active directory  domain service -> add feature -> next -> next -> next -> check restart the destination server automatically if required -> yes -> install .
and with that our AD DS is installed in our server.
after the installation we need to deploy the configuration ( see the yellow sigh in the top bar in the image ) 

![post deployment configuration](/assets/images/Active-Directory/Active-directory-series/episode01/post-deploy.png)

click on `remote a server to domain controler` -> `add new forest` -> set `root domain name` to cyber.local -> next -> set password for DSRM -> next -> next -> next -> next ( we dont need to change anything for the NTDS db location) -> next -> next -> install 
after the installation it will restart itself and in the login screen we can see our NetBios domain name appears , so in this stage we are secessfully installed AD DS 

to see our windows server ip run the command `ipconfig` in powershell and we can get the ip

![windows server ip address ](/assets/images/Active-Directory/Active-directory-series/episode01/win-server-ip.png)

### setting up AD DS

open the server manager and click tools --> active directory users and computers , from the screen we can see our domain is present `cyber`, but before creating users we need to create an OU (organizational unit) , right-click -> new -> organizational unit  

![creating OU ](/assets/images/Active-Directory/Active-directory-series/episode01/OU-creation.png)

then name the OU , after that a new folder is shown in the tree of our domain , from users directory , cut the users and past them in OU directory

![ transferbig users to OU ](/assets/images/Active-Directory/Active-directory-series/episode01/transfering.png)

now to create users for our domain you need to click on the person icon on the top , and add the user name and logon and the password and check the `password never expires` -> OK -> next -> finish ( for the user name use the same name used when you create the client machines )


![ setting the user name and password ](/assets/images/Active-Directory/Active-directory-series/episode01/username.png)

![ setting the user name and password ](/assets/images/Active-Directory/Active-directory-series/episode01/password.png)

create the second client user with the same steps used before (username must be unique) as we can see the both user are created secessfully 

![ setting the user name and password ](/assets/images/Active-Directory/Active-directory-series/episode01/users.png)

now we do some configuration that help us to attack this lab, within the server manager go to `file and storege services` in your left part from the screen --> select `shares` --> `tasks` --> `new share`--> select `SMB share quick` --> next --> next --> provide share name fox example `info` -> next -> next -> create 

now close the server manager and in the search bar of windows search for `groupe policy management` and follow the images below 

![  creating a GPO ](/assets/images/Active-Directory/Active-directory-series/episode01/gpo-01.png)

![  creating a GPO ](/assets/images/Active-Directory/Active-directory-series/episode01/gpo-02.png)

![  creating a GPO ](/assets/images/Active-Directory/Active-directory-series/episode01/gpo-03.png)

now we need to disable windows defender 

![ disabeling windows defender ](/assets/images/Active-Directory/Active-directory-series/episode01/dis-windefender.png)

click enable --> apply -> OK 


## setting up the client machines :

by doing the usual stuff of setting a machine in virtualbox or wmware we set up our client machines , and we select the windows 10 pro to install it, when we asked to sign in with microsoft we need to chose `join domain instead` (as in the image) rather than the usual sign in process 

![sign in to microsoft from domain ](/assets/images/Active-Directory/Active-directory-series/episode01/join-domain-instead.png)

after that provide a username and password to the first client machine and answer the 3 question you have asked , in our case we are building a testing lab so answering the question with right or wrong question is not a problem , but for a production environment we need to answer correct answers because our answers are used for kerberos authentication challenge process . then click accept --> skip --> not now . 

and now we have our first client machine running , we do the same process for the second client machine . (make sure to name the machine with unique names )


### Joining the client machines to the domain controller

before we do this , we need to do some configuration like adding the ip of the windows server as a prefered dns to the client machines , so getting the ip of the server using powershell

![getting the server ip address ](/assets/images/Active-Directory/Active-directory-series/episode01/win-server-ip.png)

![ modifying the prefered dns of the client machines ](/assets/images/Active-Directory/Active-directory-series/episode01/dns.png)

click ok for all tabs, as we can see that we are joined the domain 


![ client machine has joind the cyber domain ](/assets/images/Active-Directory/Active-directory-series/episode01/join.png)

change the username of your client machine and add the domain controller as shown in the image, -> click ok and you will get a pop up to put the username and password so the user can join the domain using this credentials 

![ configuring domain user ](/assets/images/Active-Directory/Active-directory-series/episode01/domain-user.png)

and now we officially joind the domain as we can see in the image

![ welcome box of the domain  ](/assets/images/Active-Directory/Active-directory-series/episode01/domain-welcom.png)

now restart the client machine so the changes will take effect , and do the same thing in the second client machine 

after the machine restart, sign in with the user that joined the `cyber.local` domain

#### setting a local administrator

now let's set the user-1 as a local administrator, from the sign in window add the folowing username and same password used for user-1 when created as domain user

![ making user-1 as local administrator  ](/assets/images/Active-Directory/Active-directory-series/episode01/admin-local.png)

login and check if you are administrator from the cmd by typing `whoami`

![checking for local administrator  ](/assets/images/Active-Directory/Active-directory-series/episode01/admin-local-check.png)

now we add the user-1 as an admin from the computer management, search for `computer management` in windows search and folow the steps in the image

![ computer management configuration  ](/assets/images/Active-Directory/Active-directory-series/episode01/user-1-as-admin-01.png)

![computer management configuration for user-1 as administrator  ](/assets/images/Active-Directory/Active-directory-series/episode01/user-1-as-admin-02.png)

from user one go to file explorer and click network and click for the yellow line to turn the network discovery

![turning on the network discovery  ](/assets/images/Active-Directory/Active-directory-series/episode01/net.png)

click yes, and at this point you can see a device has appeared , you do the same thing for the second client ( in order to do that you need to provide the credits of the administrator )

now create a shared folder in order smb attacks will work , go to c drive and create a folder and name it as you like , then go to property and sharing --> share --> share (all this need to be with admin credits) 


![adding share folder in the client machines  ](/assets/images/Active-Directory/Active-directory-series/episode01/share.png)


and all of that is sett now our lab is set up and i hope it is the case for you , i know this post in long a bit but this is a huge step we did to dive in the world of AD pentesting , see you in the next episode when we breach to the active directory and begin our attacks , se you sooon and bis bald



 

