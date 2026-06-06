---
title: "Processes under the telescope"
date: 2025-05-23 15:07:00 +0000
categories: [Red Team, windows internal]
tags: [process, windows-internals, malware-analysis,malware-dev]
description: ""
---

>  hi i am  Zane Bilal , a computer science student and an adventurer in the offensive side of cybersecurity.\

welcome to my portfolio , i hope you will take another round after finishing reading this blog , today we will talk about processes in windows, what are they , there properties, and there presentation in the two important mode on any system : user mode and kernel mode , before we start. here is a summery to what we will discover :
    1. User-mode Presentation:
        * definition of a process and its properties
        * the component of a process
        * the process memory
    2. kernel mode Presentation:
        * how the process in kernel mode is represented


# First : The User mode presentation of a process

## what a process means:
>in any operating system , the word process refer to an executed program (along with its component and properties) that runs in  memory , it is uniquely identified by its PID (process id ) and it main job is managing threads and memory and handles... , each process has its own memory address space allocated to it by the operating system and has also its own PEB (process environment block) and TEB (thread environment block) , a process does'nt run but a thread does
>the threads that belongs to the process are responsible for running the program and do stuffs (running code), when the first time a process is created , it contains two main threads : main thread which is responsible for running the program, if you kill it the program will be terminated. and we have the worker thread which is responsible for clean-up when a process is terminated.
> a process can be a parent process or a child process for an existing parent process , if it is a child process and its parent is dead, it will still run and unaffected with the termination event of its parent, as i said each process has its own address space , so it is isolated from other processes and does not know what happen in other processes's address space
### Process Properties 
>a process has a property called integrity level : which defined the capability of what this process can do and what it can not do 
    * low integrity: 
        the lowest integrity level, it can not do too much for example it can not open handles to other high integrity system processes but it can interact with other low integrity processes
    * Medium integrity:
        the default level of all processes like explorer , it can interact with process in the same level and bellow , It can read, write, and execute files in your personal user profile but it can not modify system files located in C drive
    * High integrity:
        each application running as an administrator is assign to this level, it can interact with process in the same level or bellow, and since it  operates with elevated administrator rights so it can perform critical system-level tasks like modify system files located in C drive 
    * System integrity:
        the highest integrity level assigned by microsoft , as the name suggest it is reserved for the operating system , it can interact with all integrity levels and it can do anything anywhere in the system.
>a process has also a protection level property, which defines who can temper with the process and who can not , in other words : what process can temper with other process, it protect processes from termination , tempering , injecting code and memory dumping ...etc 
 





 # Second : The Kernel mode presentation of a process
## what a kernel means:
> a kernel is a block of code that runs in memory  that acts like a middle-man between users application and the hardware, it translates the action triggered by application so
