# Name Calling

## Description

I think someone called you chicken. You should do something about it

## Given artifacts

A packet capture file

## Solving process

Skimming through the hierarchy, the amount of data transferred as images stands out:

![](1.png)

Let's export HTTP objects to see what are being sent, we get a zip file that need password to unzip, and an image named chicken, based on the problem name, this image worth inspecting:

![](2.png)

Run `exiftool` on it yields a suspicious hex string:

![](3.png)

Decode it with cyberchef, this seems to be the unzipping password:

![](4.png)

Decompress the file, got the flag:

![](5.png)

`Flag: UDCTF{wh4ts_wr0ng_mcf1y}`