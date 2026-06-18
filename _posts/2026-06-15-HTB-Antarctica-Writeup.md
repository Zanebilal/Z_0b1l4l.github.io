---
title: "Hack-The-Box : 'Antarctica'  Sherlock challenge writeup"
date: 2026-06-15 19:15:00 +0000
categories: [Writeups, Malware Analysis]
tags: [windows-internals, malware-dev,mutex, malware-analysis, reverse-engineering]
description: "solving a medium malware analysis challenge from hack the box"
image:
  path: /assets\images\writeups\malware/analysis/Antarctica/Antarctica-logo.png
  alt: "Sherlock challenge writeup"
---

> Hi, I'm **Zane Bilal** — a computer science student and explorer of the offensive side of cybersecurity. This is my first writeup about solving CTF challenges since i had played some ctf before but i never wrote writeups about what i played, so now i find it it is more helpful for me to document the idea's that  i encounter while playing and help others who's stuck to find their way to the end of challenges .

# Sherlock Scenario
Station 97, a classified research facility in Antarctica, is suspected to have been compromised. Investigators believe that someone outside the company was able to see activity on its internal servers. During a normal audit, a strange line of code was found in the .profile file of the facility's computers, which secretly starts an unknown process. Because the research at Station 97 is so sensitive, the whole facility is on lockdown while a full investigation is conducted. You have been brought in as part of the team that responds to incidents. Your job is to look closely at the recovered binary and figure out how it could leak sensitive information.

# Playing with the malware 

### MD5 hash of the malware?
there is a lot of ways to get the md5 has of this sample using some threat-intellegent search like virus-total, but i will stack using powershell module for that , by just running this command 
```powershell
 get-filehash <path_to_sample> -Algorithm <hash-algorithm>
```
![md5-hash of the sample](/assets\images\writeups\malware/analysis/Antarctica/mds-hash.png)


### The malware creates a lock on a file to ensure that only one instance of it is running. What is the full path of that file?
by just reading the word **lock** from the question you can get an idea about what you're looking for , we are looking for a mutex,
###### Mutex (Mutual Exclusion) 
Mutex is an object that ensure just one instance of a program is running at a time by locking it
you can see an example of how to create a mutex and others like semaphors and files in C in my github repo : /link/to/github/repo
- a good place to look for is the /temp/ directory, a common place used by malwares to writte and drop files because anyone can do things in this directory it does not require elevated privileges. 

- a second approach for this question is using some reverse-engneering skills with IDA , as shown in the screen-shot bellow
![lock-file mutex assembly code](/assets\images\writeups\malware/analysis/Antarctica/mutex-asm.png)
from the image above we can see that
1. The malware loads the path to the lock file that will be created (/tmp/file.lock) into the rax register
2. then sets up the arguments for a file creation call. 0x41 is loaded into ecx, corresponding to the O_CREAT flag, which instructs the OS to create the file if it doesn’t already exist. 0x1B6 is loaded into edi, translating to 0666 in octal — the standard Linux permission mode granting read and write access to all users. Finally, sub_4A8D00 is called as a syscall wrapper, pulling these arguments together to create the lock file on disk.

### The malware checks if a specific module is loaded as part of its anti-VM checks. What is the name of that module?
from VirusTotal we can see that the sample is a  Linux executable (Go-compiled ELF binary) , from the laoded modules we can see it is using `vboxguest` kernel driver module , and this module is highly used for anti-analysis especially when a linux system is running in virtual-box, we can confirm that by searching for the `vboxguest` in IDA and we can see it present 
![anti-VM check module](/assets\images\writeups\malware/analysis/Antarctica/anti-vm-module.png)

### The malware reads the content of files within a specific directory, searching for certain strings as part of its anti-VM checks. What is the full path of this directory?
a common location where malware targets when performing anti-VM checks is `/sys` directory , and from this directory we can get this path `/sys/class/dmi/id/` and by referencing this string path in IDA we can see that the malware loads a list of hypervisor-related strings into memory used in anti-VM routine — including virtualbox, vbox, innotek, vmware, qemu, kvm, xen, parallels, bochs, and bhyve before the `/sys/class/dmi/id/` path is loaded  (as seen in the screen-shot) which indicate that the directory is used to read form it 
![directory path when searching for certain anti-VM strings](/assets\images\writeups\malware/analysis/Antarctica/directory-path-anti-vm.png)

### What is the SSH key that the malware added?
by performing a string search for ssh in IDA then follow the reference into the disassembly
The malware is referencing the .ssh directory, the authorized_keys file, and what appears to be a truncated Base64 encoded string.Taking that Base64 encoded value into CyberChef and applying a Base64 decode operation reveals the full SSH public key

![ the added ssh key ](/assets\images\writeups\malware/analysis/Antarctica/ssh-key.png)



### What component of Linux does the malware use to watch for file changes?
A simple google search will provide us an answer
![linux component used to watch for file changes ](/assets\images\writeups\malware/analysis/Antarctica/file-changes-component.png)

### What file does the malware track for changes?
after doing some static analysis using `strings` tool , a `.bash_history` string cough my eye , then i did a string search in IDA toke me directly to subroutine sub_4FAB40, where the disassembly code reveals exactly how the malware tracks the file. since `.bash_history` stores every command a user types in the terminal, it becomes an obvious target for a malware author looking to harvest credentials, sensitive commands, or reconnaissance activity performed by the victim, so by walking in the assembly code the `sub_4FAB40` sub-routine is responsible for tracking the file changes, we can see also that `.bash_history` string is loaded into rcx alongside a %s/%s format string, indicating it is dynamically constructing the full file path at runtime ,the malware implements a manual loop, evidenced by the repeated jumps back to loc_4FAC6B, where it continuously calls sub_40EF20 to read the file, checks the result, and loops back if no change is detected. When a change is finally detected -indicated by the bit ecx, a 1 bit test passing and the jnb branch not being taken 

![ assembly code of tracking for changes ](/assets\images\writeups\malware/analysis/Antarctica/tracking-changes.png)

### What protocol does the malware use to exfiltrate data to its server? 
by doing some network base string search in IDA for example searching for `http`, `https`, `DNS` `.com` we get in the address 0x4FA99B (as seen in the screen-shot ) reveals a string referencing an invalid DNS response along side the unresolvable domain name and since this is the only domain name found  we conclude that the malware uses DNS to exfiltrate data to myserver.invalid.com server.

![ the protocol used to exfiltrate data ](/assets\images\writeups\malware/analysis/Antarctica/data-exfiltration-protocole.png)


### What is the FQDN the malware tries to connect to?
the answer is above .

