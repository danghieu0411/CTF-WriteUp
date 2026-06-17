# Window's Infinity Edge

## Scenario

A motivated APT group has breached our company and utilized custom tooling. We've identified the implants on compromised systems and remediated the infection using advanced AntiVirus X. However, one server seems clean but has been exhibiting suspicious traffic. Can you spot something we could have missed while cleaning this system?

## Given artifact 

A packet capture file

## Solving process

Take a look at the protocol hierarchy, HTTP packets are dominant, a typical C2 indicator

![](1.png)

Right in these first packet, I see an page used to upload file into the web, this is often the starting point for attackers to find way to upload a webshell and compromise the system:

![](2.png)

Later, I see the attacker uploads a file through that page, so I export that `.aspx` file for further investigation:

![](3.png)

That script gets executed whenever the page is loaded, acting as a webshell to handle subsequent POST requests. First I simulate the decrypting logic to attain the .NET webshell, using a python script:

```python
import struct

# Source arrays 
int_arr = [] #the huge encoded array

int_arr_r = [] # the huge 'key' array

# Output file path
output_filename = "decoded_payload.dll"

# Make sure arrays are same length
assert len(int_arr) == len(int_arr_r), "Array length mismatch!"

# Reconstruct payload bytes
decoded_bytes = bytearray()
for i in range(len(int_arr)):
    # Calculate decoded 64-bit value (replicating C# math)
    decoded_value = int_arr[i] * 345300 + int_arr_r[i]
    
    # Pack the 64-bit unsigned integer to 8 little-endian bytes.
    # '<Q' stands for little-endian ('<') unsigned 64-bit integer ('Q').
    packed_bytes = struct.pack('<Q', decoded_value)
    
    # Append the bytes to the payload buffer
    decoded_bytes.extend(packed_bytes)

# Write output assembly to disk
with open(output_filename, "wb") as f:
    f.write(decoded_bytes)
```

After gaining the `.dll` file, I decompile it using `dnSpy`, at first glance I can see that it use AES:

![](4.png)

These two functions just implement AES encryption and decryption schema, no need for further analysis, but I see the IV is also hard-coded here:

![](5.png)

Also note that the key lies in the HTTP request header, now let's convert the IV to string using cyberchef first:

![](6.png)

Got the plaintext IV, now let's analyze the `Run()` method thoroughly:

![](7.png)

In case you haven't been able to locate the 'code' and 'password', let's have a look at the next uploaded `.aspx`, and from now on, all susbequent POST request would have this form:

![](8.png)

As I already said, the decrypted 'code' should be raw C# according to how it gets launched, let's try decrypt the first command using the given key and IV in cyberchef:

![](9.png)

Succeeded! Let's open in full-screen to see what it wants to do:

![](10.png)

So the first command is only to check whether there exists the directory attackers want, they prioritize OS temp folder, then OS public directory, and if neither of them exists, they use `C:\Windows\Temp` . Let's decrypt the response:

![](11.png)

So there is not their favorite directory, now I will move to the second post:

![](12.png)

Here comes the response:

![](13.png)

Continue with the third conversation:

![](14.png)

![](15.png)

The next POST leverages Powershell encoded command to evade detection:

![](16.png)

Decode that command:

![](17.png)

Well the result does not actually make sense, so I will skip them, there are still a lot of C2 traffic. The 5-th POST uses the same policy, but they also embed a fake flag here:

![](18.png)

The 6-th POST is still reconaissance:

![](19.png)

![](20.png)

The 7-th POST creates a new directory:

![](21.png)

The 8-th POST initializes a file, delete in case that file already exists (almost impossible with that random name):

![](22.png)

The 9-th POST uploads a file in form of raw bytes:

![](23.png)

Then the file is appended in each POST (through `FileMode.Append`), ends in 14-th POST, but its content is gibberish, it's highly likely that the file itself has been encrypted. I save all of them in form of `uploaded_{i}th_raw.bin`, where i runs from 9 to 14. Then in the 15-th POST I see they create another file:

![](24.png)

And also upload it in the next POST, I saved it as `uploaded_16th_raw.bin` just like previous files. Now everything is revealed in the 17-th POST:

![](25.png)

Two files have been encrypted using XOR, the XOR key is also the AES key from the beginning, the longer file is 'module' and the shorter one is 'app_code'. Now let's decrypt them with a python script:

```python
import os

def decrypt_xor(data, key):
    dec = bytearray(len(data))
    for i in range(len(data)):
        dec[i] = data[i] ^ key[i % len(key)]
    return dec

def main():
    # Workspace path
    workspace_dir = r"C:\CTF_Workspace\BKSEC\Chall-Hard\Window's Infinity Edge"
    
    # 1. Combine modules (9th to 14th)
    module_data = bytearray()
    for chunk_num in range(9, 15):
        chunk_path = os.path.join(workspace_dir, f"uploaded_{chunk_num}th_raw.bin")
        if not os.path.exists(chunk_path):
            print(f"Error: {chunk_path} does not exist!")
            return
        with open(chunk_path, "rb") as f:
            chunk_data = f.read()
            module_data.extend(chunk_data)
            print(f"Read {len(chunk_data)} bytes from {chunk_path}")
            
    print(f"Total concatenated module size: {len(module_data)} bytes")
    
    # 2. Read app code (16th)
    app_code_path = os.path.join(workspace_dir, "uploaded_16th_raw.bin")
    if not os.path.exists(app_code_path):
        print(f"Error: {app_code_path} does not exist!")
        return
    with open(app_code_path, "rb") as f:
        app_code_data = f.read()
    print(f"Read {len(app_code_data)} bytes from {app_code_path}")
    
    # 3. Decrypt both using the key
    key = b"4d65bdbad183f00203b1e80cf96fba549663dabeab12fab153a921b346975cdd"
    
    dec_module = decrypt_xor(module_data, key)
    dec_app_code = decrypt_xor(app_code_data, key)
    
    # Try decoding as UTF-8
    try:
        dec_module_str = dec_module.decode("utf-8")
        print("Module successfully decoded as UTF-8.")
    except Exception as e:
        print(f"Module decoding failed: {e}")
        dec_module_str = dec_module.decode("utf-8", errors="replace")
        
    try:
        dec_app_code_str = dec_app_code.decode("utf-8")
        print("App code successfully decoded as UTF-8.")
    except Exception as e:
        print(f"App code decoding failed: {e}")
        dec_app_code_str = dec_app_code.decode("utf-8", errors="replace")
        
    # Write decrypted module to file
    out_module_path = os.path.join(workspace_dir, "decrypted_module.ps1")
    with open(out_module_path, "w", encoding="utf-8") as f:
        f.write(dec_module_str)
    print(f"Decrypted module saved to {out_module_path}")
    
    # Write decrypted app code to file
    out_app_path = os.path.join(workspace_dir, "decrypted_app_code.ps1")
    with open(out_app_path, "w", encoding="utf-8") as f:
        f.write(dec_app_code_str)
    print(f"Decrypted app code saved to {out_app_path}")
    
    # Write full combined script to file
    out_combined_path = os.path.join(workspace_dir, "decrypted_combined.ps1")
    with open(out_combined_path, "w", encoding="utf-8") as f:
        f.write(dec_module_str + dec_app_code_str)
    print(f"Combined script saved to {out_combined_path}")
    
    # Print the last few lines of module and the entirety of app code
    print("\n--- Decrypted App Code ---")
    print(dec_app_code_str)
    print("--------------------------")

if __name__ == "__main__":
    main()
```

Skimming through the combined script, it turns out to be the famous [PowerSploit](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) tools, specifically PowerUp module, this is a common tools for post-exploitation and privilege escalation often used by penetration testers, but attackers also use them like in this case. Let's see the result of running in the response corresponding to 17-th POST:

![](26.png)

Well so they find a way to escalate, now before inspecting 18-th POST, which is indeed performing process injection attack, let me guide you through the typical flow of injecting shellcode into process using C#

> First of all they need imports like:
> 
> ```c#
> [DllImport("kernel32.dll")]
> static extern ...
> ```
>
> This is how C# directly call Windows-native functions, normally it runs in .NET, but if it wants to perform low-level action like create process, allocate memory inside process, ... it must call Windows API
>
> The first function to run is :
>
> ```c#
> OpenProcess(
>    PROCESS_CREATE_THREAD | // allow create thread inside that process
>    PROCESS_QUERY_INFORMATION | // read process info
>    PROCESS_VM_OPERATION | // interact with process memory
>    PROCESS_VM_WRITE | // write to process
>    PROCESS_VM_READ, // read from process
>    false,
>    processId
>);
> ```
>
> This is used to open handle to a running process, if it returns 0, that means opening process failed, usaully stems from wrong PID, not enough privilege, or process protected...
>
> The second step is :
>
> ```c#
> VirtualAllocEx(
>    targetProcessHandle,  // target process
>    IntPtr.Zero, // let windows choose address itself
>    codeMemorySize, // size need to be allocated
>    MEM_COMMIT | MEM_RESERVE,
>    PAGE_EXECUTE_READWRITE // memory region that has all read-write-execute permission, suspicious!
>);
> ```
>
> It allocates memory inside other processes, not the current process.
>
> If `threadParameters` is present, the code allocates one more memory region:
>
> ```c#
> VirtualAllocEx(..., PAGE_READWRITE)
>```
>
> This rrgion only needs read-write, no need for execute as it holds data to be read into thread.
>
> The next step is:
>
> ```c#
>WriteProcessMemory(
>    targetProcessHandle, // target process
>    codeMemAddress, // address of the allocated region
>    byteArrayCode, // the shellcode
>    codeMemorySize, // its size
>    out bytesWrittenCode
>);
>```
>
> This function writes bytes into other process's memory
>
> The next step is :
>
> ```c#
>CreateRemoteThread(
>    targetProcessHandle,
>    IntPtr.Zero,
>    0,
>    codeMemAddress, // address of the shellcode
>    threadParametersMemAddress OR IntPtr.Zero,
>    0,
>    IntPtr.Zero
>);
> ```
> Meaning: create a thread inside target process, with the shellcode's address as entry point. If `threadParameters` is present, the address of memory region holding the parameters will be passed as arguments for the thread
> 
> One more function, almost equivalent to `CreateRemoteThread()` is `NTCreateThreadEx()`, if Windows version is less than 6.2 and it is attempting to inject into a running process, `NTCreateThreadEx()` is often used as an alternative, as `CreateRemoteThread()` sometimes struggles in that case.
>

Now that we know the flow, let's unpack the raw C# code from 18-th POST:

![](27.png)

![](28.png)

![](29.png)

Notice that before calling `CreateRemoteThread()` (or `NTCreateThreadEx()` as fallback), `codeMemAddress` has been offsetted, which means it only begins after the offset, what lies in the offset ?...

![](30.png)

![](31.png)

![](32.png)

Skip the whole huge base64 chunk, let's see what will be done with it:

![](33.png)

So the shellcode and the thread parameter is base64-decoded, gzip-decompressed and then injected into cmd.exe, let's se the result:

![](34.png)

Alright, it works as expected. Now we will want to know what has been injected, I copy the encoded shellcode and thread parameter into two files, then use this script to attain the original payloads:

```python
import base64
import gzip
import os

def decompress(b64_file, out_bin):
    if not os.path.exists(b64_file):
        return False
    try:
        with open(b64_file, "r", encoding="utf-8") as f:
            b64_data=f.read()

        b64_data = b64_data.strip().replace("\n", "").replace("\r", "").replace(" ", "").replace("\t", "")  # remove unexpected character in copy process
        compressed_bytes=base64.b64decode(b64_data)
        decompressed_bytes=gzip.decompress(compressed_bytes)

        with open(out_bin, "w") as out_f:
            out_f.write(decompressed_bytes)
```

After decompressing two files, I run a quick check on the thread parameter as it is quite short:

![](35.png)

Well, it adds a new user and also add him to the Administrator group, what's more, a XOR key is added to `C:\xor.k`, we may need it later.

The main shellcode is [Juicy Potato](https://github.com/ohpe/juicy-potato), a privilege escalation tool used to run command as `NT Authority/SYSTEM`, I know it as I see `Juicy` when decompiling it with ghidra, then I check with VirusTotal:

![](36.png)

![](37.png)

Looking at the 19-th POST and response, the attacker sucessfully impersonated as NT AUTHORITY/SYSTEM:

![](38.png)

![](39.png)

It seems to read from a temp file, my hypothesis is that the result of running the shellcode is stored in that file, which can also be seen in thread parameters' strings. Now let's give the 20-th POST a look:

![](40.png)

They log in as the new user, and run `whoami \all` to confirm privilege, let's see the result:

![](41.png)

Confirmed, they have the ultimate privilege. In the 21-st POST, the attacker still run command like in the previous one, but this time an encoded powershell script:

![](42.png)

![](43.png)

Here comes the result:

![](44.png)

It tries to find an instance of explorer.exe, and finds what it wants. In the 22-nd command, the attacker again inject shellcode, this time into the identified `explorer.exe`, using its PID directly, under the new user:

![](45.png)

No thread parameter is provided, let's re-use the script to get the shellcode. After running xxd on it, I see a familiar file :`C:\xor.k`, that is the XOR key we see earlier ! Let's try to XOR the subsequent chracters with that key:

![](46.png)

![](47.png)

Aha! Got the flag. But let's continue to see what is happening, here comes the result of that command:

![](48.png)

And the remaining command & result:

![](49.png)

![](50.png)

![](51.png)

![](52.png)

![](53.png)

The attacker lists the web root, timestomps the shell.aspx and deletes temporary files, that's all.

`Flag: HTB{F1n4lly_y0u_cr0ss3d_th3_edg3!}`