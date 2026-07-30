---
title: "Hack-The-Box : 'The Payload'  Sherlock challenge writeup"
date: 2026-06-27 13:22:00 +0000
categories: [Writeups, Malware Analysis]
tags: [windows-internals, malware-dev, malware-analysis, reverse-engineering, malware-CTF]
description: "solving a medium malware analysis challenge from hack the box"
image:
  path: /assets/images/writeups/malware-analysis/The-Payload/The-Payload-logo.png
  alt: "Sherlock challenge writeup"
---

> Hi, I'm **Zane Bilal** — a computer science student and explorer of the offensive side of cybersecurity. This blog is where I share my journey through CTF challenges, Hack The Box sherlocks, and anything that sharpens my skills, I hope my writeups help you learn something new. Happy hacking! 



# Sherlock Scenario

With the malware extracted, Holmes inspects its logic. The strain spreads silently across all HPCs. Its goal? Not destruction—but something more persistent…friends.

# Solving the challenge
We are provided with a suspicious executable `AetherDesk-v74–77.exe`, and its corresponding Program Database `AetherDesk-v74–77.exe` . after lunching our vm and reading the danger.txt file we unzip the folder that contains our malicious files  
before we begin we need to know what we are dealing with, from the unzipping process we get a PE file and .pdb file , but what is a .pdf file ??
A .pdb file most commonly stands for a Program Database file, a format developed by Microsoft to store debugging and state information for compiled software , so this file can help us avoid a lot of headache by make reverse engineering significantly easier by revealing original function and variable names 


## During execution, the malware initializes the COM library on its main thread. Based on the imported functions, which DLL is responsible for providing this functionality?

before answering the question we need to understand this new term `COM`, what does it mean and why it is used ??
So `COM` stands for Component Object Model, a Microsoft technology that lets different software programs talk and share features with each other, To use it, a program must first initialize the COM library (That contains all the necessary function to achieve the process of communication). The key functions for this are `CoInitialize` and `CoUninitialize`. By examining the executable’s import table, we can see which DLL provides these functions.
we can see all the import dll in various way using IDA or x64dbg of PeBear, but i will keep it simple and static i will use objdump as shown bellow 


![ imported dll's with their functions ](/assets/images/writeups/malware-analysis/The-Payload/objdumo-outout.png)


as seen in the image we can clearly identify that the functions used in COM like `CoInitialize` and it is under the `ole32.dll` dll name which is our correct answer 


## Which GUID is used by the binary to instantiate the object containing the data and code for execution?
for a program that needs to create a COM object , it needs to call certain function with the correct GUID or CLSID that identify that object , for example we have `CoCreateInstance` function which is a  Windows API  used to create a single, default-initialized object of a given class associated with a specific Class ID (CLSID) in Component Object Model (COM) development   , and it is defined by microsoft as follow 
```cpp
HRESULT CoCreateInstance(
  [in]  REFCLSID  rclsid,
  [in]  LPUNKNOWN pUnkOuter,
  [in]  DWORD     dwClsContext,
  [in]  REFIID    riid,
  [out] LPVOID    *ppv
);
```
by searching for this function in IDA we can extract the GUID (the first arg) used to create the object 

![ GUID-of-the-object ](/assets/images/writeups/malware-analysis/The-Payload/GUID.png)


## Which .NET framework feature is the attacker using to bridge calls between a managed .NET class and an unmanaged native binary?

