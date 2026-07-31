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
we can see all the import dll in various way using IDA or x64dbg of PeBear ,but i will keep it simple and i will use IDA import tab  as shown bellow


![ imported dll's with their functions ](/assets/images/writeups/malware-analysis/The-Payload/com-dll.png)


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

our executable is a native (unmanaged) C++ application which means it is a compiled file that is compiled directly into hardware-specific machine code (like .so or .dll files ) that runs outside the runtime requiring manual memory control unlike a managed .Net class that runs under the control of the Common Language Runtime with automatic memory management, and it is compiled into Intermediate Language (IL). so the 'bridge' technology is important feature in the windows os that make interaction and exchanging data between this two classes is possible .
In the beginning of the decompiled code below , we can see the COM calls.
``` c
v3 = 0;
CoInitialize(0);
v74[0] = 0;
Instance = CoCreateInstance(&rclsid, 0, 0x17u, &riid, (LPVOID *)pUnknown);
if ( Instance < 0 )
  goto LABEL_6;
Instance = OleRun(pUnknown[0]);
if ( Instance >= 0 )
  Instance = ((__int64 (__fastcall *)(LPUNKNOWN, void *, _QWORD *))pUnknown[0]->lpVtbl->QueryInterface)(
               pUnknown[0],
               &unk_140005AB8,
               v74);
((void (__fastcall *)(LPUNKNOWN))pUnknown[0]->lpVtbl->Release)(pUnknown[0]);

```
The call to pUnknown[0]->lpVtbl->QueryInterface indicates that calls between native and managed code are handled through COM Interop.


## Which Opcode in the disassembly is responsible for calling the first function from the managed code?

as we see before Calls to COM object methods are done via a vtable (virtual method table), which is an array of function pointers which holds a list of addresses pointing to the actual virtual functions a class can use/
The first managed call using a pointer with an offset is: 
```c
(*(void (__fastcall **)(__int64, __int64 *))(*(_QWORD *)v5 + 104LL))(v5, &v73);

```
The offset `104LL` indicates the offset in bytes from the start of the vtable. 104 in decimal is 68 in hexadecimal. we can see the opcode by clicking in the `104LL` value and synchronize it with hex view we get the opcode value `FF 50 68`


## Identify the multiplication and addition constants used by the binary's key generation algorithm for decryption
looking through the decompiled code we can see The malware is not using a static key but generating one dynamically.
 can find the key generation in this loop.
```c
if ( dword_140008098 < 6 )
 {
   do
   {
     *((_BYTE *)&pHints.ai_flags + v6) = 7 * v6 + 66;
     ++v6;
   }
   while ( v6 < 0x20 );
 }
```

The line `(uint8_t)i * 7 + 0x42` shows that each byte of the key is generated by multiplying the loop counter (i) by 7 and adding the hexadecimal value 42h.


## Which Opcode in the disassembly is responsible for calling the decryption logic from the managed code?
Similar to  previous question (question 4) we can see  another call to a COM object method 

```c

v54 = (*(__int64 (__fastcall **)(__int64, _QWORD, _QWORD, PCSTR *))(*(_QWORD *)v50 + 88LL))(
          v50,
          *(_QWORD *)v53,
          *v51,
          &pNodeName);

```
The decompiled code points to the function responsible for decryption. we see The offset here is `88LL`, 88 in decimal is 58 in hexadecimal and we follow the past approach to get the opcode by synchronizing the offset `88LL`  with hex view we get the opcode value `ff 50 58.`


## Which Win32 API is being utilized by the binary to resolve the killswitch domain name?
To check a “killswitch domain,” the malware must perform a DNS lookup. We can check the import table for networking-related functions.we take a look at the imports tab we can see there all the WinAPIs used by the binary but we are interested in networking function and those are found in  `WS2_32.dll` file. we can see the two network function `freeaddrinfo` and `getaddrinfo` are imported and with a small google search about this two function and for what are used we know now that `getaddrinfo` is our target function used resolving domain names to IP addresses.


![ Import table functions ](/assets/images/writeups/malware-analysis/The-Payload/import-table.png)


## Which network-related API does the binary use to gather details about each shared resource on a server?

again look at the import table for functions related to this. and we find two interesting functions being used from the `NETAPI32` library `NetShareEnum` and `NetApiBufferFree`and with a small google search we get the definition of the `NetShareEnum` which is a Windows API call used to retrieve information about shared resources on a local or remote compute, making it the correct answer.

## Which Opcode is responsible for running the encrypted payload?

navigate to the  `ScanAndSpread` function, we see another COM method call that is responsible for executing the main payload on a remote machine.
```c
             (*(void (__fastcall **)(__int64, __int64, _QWORD, _QWORD))(*(_QWORD *)v37 + 96LL))(
                v37,
                v50,
                *(_QWORD *)v41,
                *(_QWORD *)v40);

```
 Using the previous technique in question 4 and 6, we can get the opcode `FF 50 60`


## Identify the killswitch domain name the binary attempts to resolve.

Identify the Encrypted String: From the disassembly, we can find the Base64 encoded string that serves as the encrypted data: `KXgmYHMADxsV8uHiuPPB3w==`.
Now we have to recreate the XOR key. We found the key generation algorithm previously in Question 5. 
```c
do
{
  *((_BYTE *)&pHints.ai_flags + v6) = 7 * v6 + 66;
  ++v6;
}
while ( v6 < 0x20 );
```
we know the key is generated using this code so Converting this to Python, we get something like:

```py

seq = bytes((7 * i + 0x42) & 0xFF for i in range(32))
```

by performing a Base64 encoding the key, we get: `QklQV15lbHN6gYiPlp2kq7K5wMfO1dzj6vH4/wYNFBs=`
and now we can decrypt the domain name by XORing the newly generated key and the encoded key from the decompiled code we get the domain name that is resolved by the binary `k1v7-echosim.net`

# conclusion

at the final This challenge was a great exercise in combining different static analysis techniques and i hope you get some benefit from reading my writeup until the next time 

