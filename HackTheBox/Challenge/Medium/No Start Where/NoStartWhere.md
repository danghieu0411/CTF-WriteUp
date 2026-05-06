# No Start Where

## Scenario

As echoes of the Dark War lingered in UNZ's cyber-warfare HQ, a beacon blinked ominously. An analyst turned a wary eye to the screen. The alarm signal originated from the main system that controls the mining machinery! It was an attack from the Board of Arodor, aimed at crippling the mining infrastructure. Initial investigation of the network traffic revealed that the system has been compromised! Your task is to disinfect the system by uncovering the infiltration method and potential post-exploitation steps!

## Given artifact

A single packet capture file

## Solving process

Skimming through the hierarchy, TLS has quite large amount of packet, but the most of data transferred comes from the HTTP protocol:

![](1.png)

So I filter for HTTP traffic, these suspicious downloads immediately catch my eyes:

![](2.png)

I export those files for further analysis, the fake WINWORD.EXE turns out to be 7zip archive, password-protected, we cannot touch it now:

![](3.png)

The `Secutiry...` zip file contains a word document and a `.scr` executable, the word document seems to be decoy:

![](4.png)

The `.scr` file is what hinders me, I try to decomplile it, but it's too hard and long. So I take its hash and submit on VirusTotal, it seems to drop other files according to the available reports, but I still get nothing further than that. This situation leaves me no choice but to use my own VM to analyze.

Open VM and start ProcessMonitor (procmon), first I press `Ctrl E` to stop capturing (very noisy), then `Ctrl X` to clear. After that I add filter to only care about that `baseline.scr` file creating process, creating files and writing files. Finally `Ctrl E` again to start capturing, then double-click the executable file.

Immediately procmon console floods me with processes and events, some files are created, and this cmd.exe process is trggered:

![](5.png)

The folder name, also the batch file name is randomly created, each time it is run, another name it gets. So `baseline.scr` drops a structure in Temp folder, and runs it with two passed arguments, the path to itself and `/S`, which is silent mode.

The `/S` switch is the giveaway: this is the NSIS installer convention (Nullsoft Scriptable Install System). The screensaver isn't malware in the classic sense — it's a self-extracting NSIS installer that drops a batch file and runs it silently. And NSIS temp dirs are deleted after installer exit, that's why it keeps disappearing before I could copy it. I should not close this pop-up:

![](30.png)

Well, the author must definitely be Vietnamese, by the way Bún đậu mắm tôm is also my favourite dish..., oops let's stop beating around the bush. Once I leave the pop-up open and go to Temp folder, I can see the folder, copy it to Downloads folder and we can close that pop-up. When reading the batch file, I realize that it has been terribly obfuscated:

![](6.png)

Using a tool from github, I successfully recover the payload:

![](7.png)

Now everything is clear, `WINWORD.EXE` is the very `bundau.dll`, inherently the victim's machine does not have it from the beginning, so it has to download from the attacker's IP, that's why we catch it in the pcap. Now use the password to decompress the 7z file:

![](8.png)

Well, now here comes the true nightmare, that executable is very verbose, not being so familiar with reversing and machine code, I struggle for quite long before I notice this magic bytes in the POST C2 traffic, it rings a bell : havoc, cannot be wrong, `Anh trai C2` from BKSEC training revisits!:

![](31.png)

To ensure my feeling, I take its hash and submit to VirusTotal, and that's it:

![](18.png)

[Havoc](https://github.com/HavocFramework/Havoc) is an open-source C2 framework, but I am not patient enough (and not competent enough as well) to truly inspect the source code, so I revisit [this article](https://www.immersivelabs.com/resources/c7-blog/havoc-c2-framework-a-defensive-operators-guide) which helped me solve the similar challenge that I mentioned. 

By and large, the C2 framework use AES CTR with 32-byte key and 16-byte IV to encrypt traffic in both directions, after the `dead beef` magic bytes in the first POST callback, we will get the agent ID and other fields, after that is the key and IV that will be used for all subsequent traffic, this illustration is taken from that article:

![](32.png)

Apply that to our pcap, I decrypt all the POST callback here, they are just command result from the victim's machine:

![](9.png)

![](10.png)

![](11.png)

![](12.png)

![](13.png)

![](14.png)

![](15.png)

![](16.png)

![](17.png)

There are many other beaconing packets that contain nothing to display, it just checks connection to the server and ask if the attacker has any command. Now let's follow the HTTP response before each of those POST packets to see what attacker has told it to do, for the command, we need to remove the first 12 bytes from the data, and use the same key/IV as for the POST request:

![](19.png)

![](20.png)

![](21.png)

![](22.png)

![](23.png)

![](24.png)

![](25.png)

Okay, it's clear now, after the reconaissance commands, attacker uploads another executable to the victim machine. Note that I only get this clean file by dropping another 16 byte from the decryption output, because the MZ header is not at the beginning initially, it's prepended with garbage. How do I know 16 bytes ? Well you can try removing one-by-one, but I added To Hex recipe, and look for 4d 5a (MZ) and remove everything before it.

Add zip before download otherwise the browser will block the malicious file, it turns out to be .net assembly, good news, dnSpy will hand us the clean C# code:

![](28.png)

![](29.png)

We can see there are clearly 3 stages in this program, it first use hard-coded array to XOR with each other, hiding the true domain name and the address to get the next stage payload. The `check()` function performs some anti-analysis trick, and the `stage2()` function download a file from the internet, let's decrypt the array with a simple script:

![](26.png)

![](27.png)

The domain name is our flag, and the next stage is camouflaged as a fake image. In real world, it should be far worse than that.

`Flag: HTB{4_r4ns0mw4r3_4lw4ys_wr34k5_h4v0c}`