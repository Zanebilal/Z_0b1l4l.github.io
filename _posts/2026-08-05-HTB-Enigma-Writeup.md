---
title: "Hack-The-Box : 'Enigma'  Machine writeup # Season_11"
date: 2026-08-05 13:22:00 +0000
categories: [Writeups, Linux]
tags: [Linux, penetration-testing, penetration-CTF]
description: "An easy machine from the Season 11 from hack the box"
image:
  path: /assets/images/writeups/Linux/Enigma/Enigma-logo.png
  alt: ""
---

# Machine Overview 
Enigma is an easy active machine from the HacktheBox Season 11. 


### Enumeration 
we start with a simple nmap scan on the target machine ip address and trying to identify all the opened ports 

![ all opened ports in the machine ](/assets/images/writeupsLinux/Enigma/opened-ports.png)

after we identified the opened ports we need to dig deeper in the services running for each port 


![ services running on the machine ](/assets/images/writeupsLinux/Enigma/services.png)


we can see there is a web service running in the port 80 with the domain `http://enigma.htb/`, we add this domain to our /etc/host file 

![ adding enigma.htb domain to our hosts file ](/assets/images/writeupsLinux/Enigma/adding-domain.png)

now we access this domain and we see a web page, playing around with the site we got nothing can be exploited and same case with fuzzing web content , now we move to subdomain enumeration using the powerful tool `ffuf` 

![ subdomain enumeration with ffuf ](/assets/images/writeupsLinux/Enigma/subdomains.png)

as we can see from the ffuf output there is an active subdomain `mail001` that worth investigation ,by adding this subdomain to our /etc/hosts file ( same process as the previous one ) and accessing this reveal to us a login panel of a Webmail software called roundCube,  now we need to get the credentials.

from the nmap output we know that there is `NFS` service opened for us ,we can give it a try and mount it and see what is inside 

![ showmount output ](/assets/images/writeupsLinux/Enigma/nfs-file.png)

That * means no IP restriction, anyone can mount it. now run the following commands to mount the shared network folder onto your local computer

![ mounting the NFS  ](/assets/images/writeupsLinux/Enigma/nfs-mount.png)

there is a readable pdf file and by reading it we get the credentials to use for logging to the webmail ( they don't work with ssh )

now we are inside the webmail page the first thing to do it get the version of this software and see if it has any vulnerability on it from the public exploits , but nothing there , when i was playing around i found a mail from sarah (which seems our next target) , trying to login to the webmail using username `sarah` and the default password `Enigma2024!` and it worked, we are in . 
after browsing in sarah's sendbox we can find an `admin` credentials there for another exposed subdomain  