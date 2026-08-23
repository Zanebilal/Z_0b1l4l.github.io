---
title: "Hack-The-Box : 'APKey' mobile challenge  "
date: 2026-08-23 13:22:00 +0000
categories: [Writeups, mobile]
tags: [jadex, smali, android-pentesting,mobile-application, CTF ]
description: "An easy mobile challenge from hack the box introducing how to patch an application in order to retrieve the flag"
image:
  path: /assets/images/writeups/mobile/APKey/APKey-logo.png
  alt: ""
---

# Solving the challenge: 
from the challenge description we get an insight about we are looking from , we are looking for an some unique key, first we install the app on our emulator and open it, and it seems like we are hanging on this login activity.
i tired some known credential like : admin:admin but all my tries are wrong. but this does not stop us here


![ login activity  ](/assets/images/writeups/mobile/APKey/login-activity.png)


## Step 01: Reversing the APKey application:

we need to reverse the apk to get the correct credentials , we open the apk file in jadex-gui to see the java source code , search for the `wrong credentials` string in jadex by pressing ctrl+f and we see it is reflected in `Onclick` method in `MainActivity` class


![ searching for the wrong credential toast ](/assets/images/writeups/mobile/APKey/toast.png)


and by reading the source code in the `OnClick`method we can see that our username input is compared to the string `admin` so the correct username is `admin` and our input password is compared to the hashed password (most likely it is md5 hash) as we see in the source code below : 

```java

    public void onClick(View view) {
            Toast makeText;
            String str;
            try {
                if (MainActivity.this.f928c.getText().toString().equals("admin")) {
                    MainActivity mainActivity = MainActivity.this;
                    b bVar = mainActivity.e;
                    String obj = mainActivity.d.getText().toString();
                    try {
                        MessageDigest messageDigest = MessageDigest.getInstance("MD5");
                        messageDigest.update(obj.getBytes());
                        byte[] digest = messageDigest.digest();
                        StringBuffer stringBuffer = new StringBuffer();
                        for (byte b2 : digest) {
                            stringBuffer.append(Integer.toHexString(b2 & 255));
                        }
                        str = stringBuffer.toString();
                    } catch (NoSuchAlgorithmException e) {
                        e.printStackTrace();
                        str = "";
                    }
                    if (str.equals("a2a3d412e92d896134d9c9126d756f")) {
                        Context applicationContext = MainActivity.this.getApplicationContext();
                        MainActivity mainActivity2 = MainActivity.this;
                        b bVar2 = mainActivity2.e;
                        g gVar = mainActivity2.f;
                        makeText = Toast.makeText(applicationContext, b.a(g.a()), 1);
                        makeText.show();
                    }
                }
                makeText = Toast.makeText(MainActivity.this.getApplicationContext(), "Wrong Credentials!", 0);
                makeText.show();
            } catch (Exception e2) {
                e2.printStackTrace();
            }
        }
    }

```

i tried to crack the md5 hash using different tool but i did not get a human readable string , so we can not retrieve the password with this way, we need to try another way which is patching the application by changing the hashed password with our own hashed password using `smali`.

## Step 02: Patching the APKey application :
in order to patch the app we need to understand what is smali code and how it is constructed.

### what is smali ??

in simple word you can see smali like assembly but for mobile application , it is the intermediate language of Android application bytecode. When Android apps are compiled from Java/Kotlin source code, they are translated into bytecode, which can then be converted into Smali code 

now we know what is smali , we can go farther to patch our app , first we need to decompile the apk file using `apktool` using this command :
```shell
    apktool d APKey.apk
```
and now we have the decompiled app in a new directory contain a numerous of directories and file because an apk is just a compressed file ( about the content of each directory , this is not our topic today but i may include a blog about the structure of an apk file)

![ decompiling the app ](/assets/images/writeups/mobile/APKey/decompalation.png)


we open the smali file of the `MainActivity` and searching where hashed password is used , now all we need is to replace this hashed password with our own md5 password, i used cyberchef to hash my password


![ smali code for the password check code  ](/assets/images/writeups/mobile/APKey/smali.png)

 i choosed to use `patched` as my password  and hash it, then replaced it with the hash in the smali code , and thats all, now the app when it does the check of the password the check passes, but we need to rebuild the app one again to apply our patch

### Step 03 : Building and Signing the app

using apktool once again to build the application 
```shell
    apktool b APKey.apk

```
and Since Android does not allow application that are not signed to run, we need to sign our application , i use two tools to do that as seen in the image below:

![ signing the application  ](/assets/images/writeups/mobile/APKey/signing.png)

all of this is set let's uninstalled the original application and installed the newly modified version.

### Step 04: Running the patched app

now let's run our patched app , provide the credentials ( make sure to pass the password you hashed and put it in the smali code) and now we bypass the authentication successfully, and the flag is retrieved 🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉


![ getting the flag ](/assets/images/writeups/mobile/APKey/flage.png)


thanks for reading and see you in the next writeup