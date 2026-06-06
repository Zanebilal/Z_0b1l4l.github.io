---
title: "Swimming-inside-EDR-ousion"
date: 2025-05-25 15:07:00 +0000
categories: [Red Team, EDR]
tags: [EDR, windows-internals, malware-analysis,malware-dev,etw, ]
description: ""
---

>  hi i am  Zane Bilal , a computer science student and an adventurer in the offensive side of cybersecurity.\

> bypassing ETW --> disable etw-providers to evade detection
>bypass DLL hooking --> direct syscals , unhooking

--------------------------------

network filter --> implemented using wfp (windows filtering platform) --> edr can be blocked from wfp
                --> interact with the network stack ( kernel level )

edr drivers --> uses kernel callbacks : - process callbacks ( with its routine function) : example: get command line argument
                                        - thread callbacks  ( with its routine function) : example: get  thread context , schaduling 
                                        - image load callbacks ( with its routine function) : example: dll and driver loaded 
                                        - registry callbacks  ( with its routine function) : example: changes to sensitive registry
                                        - filesystem callbacks ( with its routine function) : example: file access , creation
                                        - object callbacks   ( with its routine function) : example: accessing kernel objects

edr processes : user-mode component that analyze the collected  telemetry 


-----------------------------------------

# General Overview:
### Definition: 
> EDR (Endpoint Detection and Response ) is a term that refers to the security solution implemented in machines and servers , it combines a set of components, layers, mini-systems and techniques that work together to detect and respond to threats in this machines

### the difference between EDR and AV (AntiVirus)
> back in the days , AV was the first created security solution, at first they were responding to threats by doing just static analysis , i mean they check the signature of malicious files, if the signature matches a know already analyzed file then it is likely the same malicious file, but over time they add dynamic analysis by dropping the files into a sandbox, but this was bypassed by malware developers easily using techniques like anti-debugging techniques .\
> and for security vendors it was just a matter of time to come with new featured product that covers what AV's cant do, so they developped more intelligent solution products like EDR, XDR, MDR .\
> so now we can say that EDR is just a more powerful and featured AV .

### EDR Software components
1. the agent : this is the actual software that you download from the official site of a vendor , it contains several folders and files that are essential or complementary to the use of the EDR agent like Executables, libraries and utilities.

2. Drivers : are kernel-mode programs ,drivers listens for events that occur and provides a function to the system, called a callback routine , which will be executed when an event of interest occurs (creation of a process or a thread, operation in files,  loading an image...etc). this matters because drivers will use techniques called API Hooking by injecting a DLL to the target process address space and then monitor the calls to Windows API functions made by that process. more info : https://learn.microsoft.com/fr-fr/windows-hardware/drivers/kernel/types-of-windows-drivers
                                 https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/callback-objects
3. Services : system processes which allow scanning the file system and RAM for suspicious activities and it manages the executables and ensure the proper functioning of the solution.
 ### what happens if a maliciouc action is present:
 > If malicious behaviors are detected, they are analyzed and the EDR can also respond using pre-configured actions (stop a process, shut down the host, isolate it on the network, etc.). How they do that, this is what comms next.


# Diving inside the EDR Architecture and Component 

