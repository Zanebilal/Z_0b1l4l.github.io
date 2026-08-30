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




 

