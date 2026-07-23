# Acknowledge the corn

## Scenario

One of our clients currently active in the banking sector, was recently targeted by a known APT group. Our endpoint protection raised some alerts about an offensive open source tool which was found in one of our client's workstation. Our incident response team managed to retrieve a dump of the malicious process and a capture of the network during the attack. Can you analyse the given samples and determine whether the malicious actors penetrated in to the network or not?

## Given artifact

A packet capture file and a memory dump of powershell process

## Solving process

Give the pcap file a look first, I immediately see two weird GET request for powershell scripts, that's not good, let's export both of them for further analysis:

![](1.png)

Hmmm..., GET for weird file followed by subsequent POST requests, that's typical malware pattern. Upon inspecting the first script, `byp.ps1`, we can see that most of its obfuscation lies in the format string and replace:

![](2.png)

Indeed, I just copy the script up to the `|iex` part and paste directly to my powershell, after removing some backticks and replace inner format string, the script looks roughly like this:

![](3.png)

With the help of LLM, the clean result is as follow:

![](4.png)

So it simply performs AMSI bypass, disable it before downloading the next script. The next script performs reflective invoke of a base64-encoded, deflated payload:

![](5.png)

Decode and decompress in cyberchef yields a C# .NET executable, now we are done with the `ps1` scripts, let's use `dnSpy` to decompile the .NET:

### Analysis of the stager

![](6.png)

The main function just initializes a new instance of GruntStager, thus detonating the malware

![](7.png)

![](8.png)

  #### 1. Setup of Connection and Headers

  • C2 Server URI: list contains the target C2 server address (`http://192.168.1.11:80`).

  • Headers/Cookies Metadata:

      • list2 contains Base64 encoded HTTP Header names:

          • VXNlci1BZ2VudA== → User-Agent

          • Q29va2ll → Cookie

      • list3 contains the corresponding values:

          • TW96aWxsYS81LjAg... → Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.
          2228.0 Safari/537.36

          • QVNQU0VTU0lPTklEPXtH... → ASPSESSIONID={GUID}; SESSIONID=1552332971750

      • list4 contains the target C2 endpoints/URI paths:

          • L2VuLXVzL2luZGV4Lmh0bWw= → /en-us/index.html

          • L2VuLXVzL2RvY3MuaHRtbA== → /en-us/docs.html

          • L2VuLXVzL3Rlc3QuaHRtbA== → /en-us/test.html



  #### 2. Key Generation & Cryptographic Operations

  • Stage Key: key is a shared AES key, decoded from Base64:

      • e+MPqFZXA52Kx1xuTPTK6M/HtJkjq/0dfBJUsSJfzQw=

  • RSA Key Generation: It initializes a new 2048-bit RSA provider (rsacryptoServiceProvider) and converts its public
  key parameters (ToXmlString(false)) into bytes.

  • Encryption & HMAC:

      • The RSA public key is encrypted using the shared AES key (key) in CBC mode with PKCS7 padding.

      • A signature (HMAC) is computed over the encrypted payload using HMACSHA256 initialized with the same shared
      AES key.

  • Initial Registration Message (s):

      • It compiles a JSON registration message using format3 containing:

          • GUID (str + text where str is 69ebf9edc5 and text is a random 10-char GUID substring).

          • Type (0, which denotes an initial staging request).

          • IV (Base64 representation of the generated AES Initialization Vector).

          • EncryptedMessage (the encrypted RSA public key).

          • HMAC (signature for verifying integrity).

![](9.png)

![](10.png)

  #### 3. Security & Certificate Pinning (Lines 89-102)

  • Sets up SSL/TLS protocols and configures a custom certificate validation callback.

  • Note that UseCertPinning and ValidateCert were initialized to false in Segment 1, so currently, all SSL
  certificates are accepted (useful for self-signed C2 certificates).

  #### 4. C2 Server Validation (Lines 104-131)

  • A custom CookieWebClient class is initialized with default system/proxy credentials to blend in with normal
  traffic.

  • It loops through the C2 servers (list) to find an active one. For each server:

      • It sets up the request headers and cookies (replacing {GUID} placeholder with an empty string).

      • It attempts a GET request (DownloadString) to a randomly selected path from list4 (e.g., /en-us/index.html).

      • If successful, the active server URI is stored in text2.


  #### 5. Sending the Registration Message (Lines 132-144)

  • Once the active C2 is found (text2), the headers and cookies are updated again, this time replacing {GUID} with
  the actual generated session GUID text.

  • The registration JSON payload s (created in previous snippet) is Base64-encoded (MessageTransform.Transform) and placed
  into format:

  `i=a19ea23062db990386a3a478cb89d52e&data={0}&session=75db-99b1-25fe4e9afbe58696-320bea73`

  • The request is sent via a POST request (UploadString) to a random endpoint from list4.

  • The server responds with HTML mimicking a benign page (as defined by format2). The stager calls the helper method
  GruntStager.Parse(..., format2)[0] to extract the payload hidden inside the HTML comment // Hello World! {0}.

  • This extracted payload is then Base64-decoded (MessageTransform.Invert) to a UTF-8 string, stored in text4.

![](11.png)

  #### 6. Validating the C2 Response (Lines 145–150)

  • The stager parses the decrypted response text4 from the C2 server using the JSON pattern format3.

  • It extracts:

      • s2 (IV)

      • s3 (Encrypted message body)

      • a (HMAC signature)

  • It verifies the HMAC of the encrypted body using the initial AES key. If the calculated HMAC matches the received
  HMAC a, it proceeds with the handshake.

  #### 7. Decrypting the Session Key (Lines 151–154)

  • The stager decrypts array2 (the body of the message) using the initial AES key in CBC mode.

  • The decrypted bytes (rgb) contain a new AES key (key2) generated by the C2, which has been encrypted with the
  stager's ephemeral RSA public key.

  • The stager uses its private RSA key (rsacryptoServiceProvider) to decrypt rgb, retrieving the new, secure,
  session-specific AES key key2.

  #### 8. Preparing the Challenge (Lines 155–174)

  • A new AES instance (aes2) is initialized with the new session key (key2).

  • The HMAC provider (hmacsha) is re-initialized with the new key.

  • The stager generates 4 random bytes (array3) as a challenge to the C2 server.

  • It encrypts this challenge with aes2 and computes its HMAC.

  • It wraps the encrypted challenge in a Type "1" message (signaling the handshake/challenge stage) and encodes it
  to Base64.

  #### 9. Sending the Challenge & Waiting for Response (Lines 175–187)

  • The stager sends the challenge via a POST request to the C2 server.

  • It receives a response, extracts the payload from the HTML comment, Base64-decodes it, and stores the result in
  text4.

![](12.png)

![](13.png)

  #### 10. Validating the C2 Challenge Response (Lines 188–202)

  • The stager parses the C2's response (text4) to its challenge (array3).

  • It decrypts the message body (src) using the new session key (aes2).

  • The decrypted buffer contains 8 bytes:

      • The first 4 bytes (array5) should match the stager's initial random challenge (array3).

      • The next 4 bytes (array6) represent a new challenge issued by the C2 to the stager.

  • If array3 matches array5, the C2's identity is verified, protecting the stager from communicating with an
  imposter/interceptor.

  #### 11. Responding to C2's Challenge (Lines 203–228)

  • To prove its own identity to the C2, the stager encrypts the C2's challenge (array6) with aes2 and a new IV.

  • It wraps the encrypted result (array7) and HMAC into a Type "2" message (the final handshake phase) and POSTs it
  back to the C2.

  • The C2 verifies the response, then returns the final payload. The stager decodes it, storing it in text4.

  #### 12. Reflective Assembly Loading (Lines 229–247)

  • The stager parses the final response, verifies the HMAC, and decrypts the payload body using aes2.

  • The decrypted payload is a compiled .NET Assembly (PE file/DLL) containing the core implant.

  • The stager uses Assembly.Load(...) to load the assembly directly into the process memory without saving it to
  disk (reflectively loading).

  • It grabs the first class/type (GetTypes()[0]), gets its first method (GetMethods()[0]), and invokes it.

  • The parameters passed to the invoked main method of the implant are:
  
      1. The target C2 URL (text2).
   
      2. The certificate hash (CovenantCertHash).
   
      3. The session GUID (text).
   
      4. The session AES crypto instance (aes2).
   
Return to the pcap file, we can easily see the exact pattern reflecting the code's logic:

![](14.png)

However, we know that the C2 server encrypts the second AES key with the client's public RSA key, we need the client's corresponding private key to decrypt it, as private key is generated on the fly in the memory, never sent on wire, we will never find it in the pcap file, that's why they give us the powershell memory dump.

To find it from the dump, we must use its pattern, the most common in modern .NET is CNG (Cryptography Next Generation):

![](15.png)

Let's construct a python script to locate the key's position in the dump:

```python
import struct

HEADER_SIG = bytes.fromhex("525341320008000003000000000100008000000080000000")

with open("powershell.dmp", "rb") as f:
    data = f.read()

idx=0
while True:
    idx=data.find(HEADER_SIG, idx)
    if idx==-1:
        break
    header=data[idx:idx+27] # header + public exponent
    magic, bitlen, cbExp, cbMod, cbP1, cbP2 = struct.unpack("<6I", header[:24])
    exp=header[24:27]

    offset=idx+27
    n= data[offset:offset+cbMod]
    p= data[offset+cbMod:offset+cbMod+cbP1]
    q= data[offset+cbMod+cbP1:offset+cbMod+cbP1+cbP2]
    print(f"Match found at offset: 0x{idx:X}")
    print(f"Exponent (hex): {exp.hex()}")
    print(f"Modulus (hex, first 16 bytes): {n[:16].hex()}")
    idx+=len(HEADER_SIG)
```

Here comes the result:

```text
lehie@MSI:/mnt/c/CTF_Workspace/BKSEC/Chall-Hard/Acknowledge the corn$ python3 find_key.py
Match found at offset: 0x45DEF20
Exponent (hex): 010001
Modulus (hex, first 16 bytes): c214c87f9f0bb1e057909d7487ea0743
Match found at offset: 0x45DF380
Exponent (hex): 010001
Modulus (hex, first 16 bytes): c214c87f9f0bb1e057909d7487ea0743
Match found at offset: 0xFF94E00
Exponent (hex): 000003
Modulus (hex, first 16 bytes): 8ff313b3add883d8822f46e15e436e38
```

There is more than 1 key, so we need to verify. Remember that the client sends its public key to the C2 server in the first POST request, encrypted using the hard-coded AES key in random IV included in the payload:

![](16.png)

Decrypt it:

![](17.png)

Decode again to obtain the modulus, so we have the matching one, it's the first two:

![](18.png)

Now that we located its position in memory, let's reconstruct the `.pem` key file using another python script:

```python
from Crypto.PublicKey import RSA    
import struct

# Offset of the correct CNG private key blob in the memory dump
offset = 0x45DEF20

with open("powershell.dmp", "rb") as f:
    f.seek(offset)
    header = f.read(24)
    # Unpack the 24-byte CNG header (BCRYPT_RSAKEY_BLOB)
    magic, bitlen, cbExp, cbMod, cbP1, cbP2 = struct.unpack("<6I", header)

    # In a BCRYPT_RSAPRIVATE_BLOB, only E, N, P, and Q are stored.
    # DP, DQ, IQ, and D are not present in this memory structure.
    exp = f.read(cbExp)  # Public Exponent (E)
    n = f.read(cbMod)    # Modulus (N)
    p = f.read(cbP1)     # Prime factor P
    q = f.read(cbP2)     # Prime factor Q

# Convert raw big-endian bytes to Python integers
E = int.from_bytes(exp, 'big')
N = int.from_bytes(n, 'big')
P = int.from_bytes(p, 'big')
Q = int.from_bytes(q, 'big')

# Mathematically calculate the private exponent D from E, P, and Q.
# D is the modular inverse of E modulo the totient phi(N).
# phi(N) = (P - 1) * (Q - 1)
phi = (P - 1) * (Q - 1)
D = pow(E, -1, phi)

# Reconstruct the RSA private key object using the calculated D
key = RSA.construct((N, E, D, P, Q))

# Export the reconstructed key to a PEM file
with open("private_key.pem", "wb") as f:
    f.write(key.export_key(format='PEM'))
```

Now that we got the private key file, we can decrypt the session key, that is the second AES key generated by the C2 server, let's copy the server's reponse for the first POST request and decode base64 to get the IV and encrypted message, I do it in cyberchef then paste to this script:

```python
import base64
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import unpad

# ----------------- STEP 1: AES DECRYPTION -----------------

# Static AES key from the stager code (Base64)
STATIC_KEY_B64 = "e+MPqFZXA52Kx1xuTPTK6M/HtJkjq/0dfBJUsSJfzQw="
static_key = base64.b64decode(STATIC_KEY_B64)

# Values extracted from the Type 0 response in the PCAP
IV_b64 = "7/1U1Qfc69DJkFQMuC7YLg=="
encrypted_msg_b64 = "8AVdSUo020zmBvJqdpXDEA9sRyotMGyUVqXOrRFk95GxGDEYotveTpqJhHUKUQ3Oduh3c7gSyyM3qVVN674P+ghJNQcdJdRS1YlUJckbg/bOEkfuxJ25JWMPh21EPS0/ptf6ytfkhnXjVJ4v3miEtdZ/+vtP4L49V8Ucl7kej8DrPfux1wi4oGjIf4TdRb2OYLQExVbcMGLb8b73mjmGwWTywqDc5+mr/m80cyv2xVQHLpQIiw1xdjFCgIH3J2FZDQMm14gr4caODgmGT+JGoOCGl8pMEPJ6q58Cv5LHTNLl/k3vtufVv8vIzn8FXHoAy+2ZHJ1vZXIqUl+OubCv2VhhSmCXz6Fg/G4AqFWb+cA="

iv = base64.b64decode(IV_b64)
encrypted_msg = base64.b64decode(encrypted_msg_b64)

# Decrypt the ciphertext to get the RSA-encrypted bytes (rgb)
aes_cipher = AES.new(static_key, AES.MODE_CBC, iv)
rgb_padded = aes_cipher.decrypt(encrypted_msg)

# Remove PKCS7 padding (reduces the 272 bytes block to the exact 256 bytes RSA ciphertext size)
rgb = unpad(rgb_padded, 16)

# ----------------- STEP 2: RSA DECRYPTION -----------------

# Load your generated private key
rsa_key = RSA.import_key(open("private_key.pem").read())
rsa_cipher = PKCS1_OAEP.new(rsa_key)

# Decrypt the RSA-encrypted block to get key2
session_key = rsa_cipher.decrypt(rgb)

print("Session Key (hex):", session_key.hex())
```

Run it:

```text
lehie@MSI:/mnt/c/CTF_Workspace/BKSEC/Chall-Hard/Acknowledge the corn$ python3 decrypt_session.py
Session Key (hex): 93a5e1e0e1044ab8cdb7292b8b8dc5ecdce3343f2d3c6093b0c5d34a2656c812
```

Got the session key! Now we can proceed to decrypt the invoked DLL, it is quite large, copy that huge b64 chunk to decode and get the IV, encrypted message as always, then use this script:

```python
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

    # ----------------- DECRYPTION SETUP -----------------

    # The session key you decrypted in the previous step (in bytes)
SESSION_KEY = bytes.fromhex("93a5e1e0e1044ab8cdb7292b8b8dc5ecdce3343f2d3c6093b0c5d34a2656c812")

    # Values extracted from the Type 2 C2 response (pasted from Wireshark)
IV_b64 = "In9qCKIr52404to1+W2O0g=="
encrypted_msg_b64="" # the huge string, cropped 
iv = base64.b64decode(IV_b64)
encrypted_msg = base64.b64decode(encrypted_msg_b64)

    # ----------------- AES DECRYPTION -----------------

aes_cipher = AES.new(SESSION_KEY, AES.MODE_CBC, iv)
decrypted_padded = aes_cipher.decrypt(encrypted_msg)

    # Strip PKCS7 padding
decrypted_assembly = unpad(decrypted_padded, 16)

    # Save the decrypted assembly to a file
output_filename = "grunt.dll"
with open(output_filename, "wb") as f:
    f.write(decrypted_assembly)

print(f"Decrypted assembly saved successfully as {output_filename}!")
```

Run that to get the third stage - the `GruntExecutor`, continue using `dnSpy` to decompile it. This thing is much more complicated than the stager:

![](20.png)

### Analysis of the executor

#### 1. Set up and environment reconaissance

![](21.png)

##### Key Variables & Configurations:

  • `Delay`: Initialized to 7 seconds. This is the sleep interval between C2 check-ins.

  • `Jitter` (num): Initialized to 10%. This adds a random variation to the check-in interval to evade detection (making the beaconing behavior look less
  predictable).

  • `ConnectAttempts` (num2): Set to 5000. The maximum number of consecutive connection failures allowed before the implant terminates itself.

  • `KillDate` (dateTime): Formatted from raw .NET ticks (`637781924050094521`), which decodes to `2022-01-19 12:33:25 UTC`. If the system time passes this
  date, the implant will exit automatically to prevent perpetual exposure.

  • `HTTP Headers & URLs`: Like the stager, the HTTP headers (User-Agent, Cookie) and URI paths (`/en-us/index.html, /en-us/docs.html, /en-us/test.html`) are
  set up using Base64-encoded templates.

##### Host Reconnaissance (Profiling):

  Before registering, the implant gathers the following details about the victim host:

  • `IP Address`: Searches for the first active IPv4 address.

  • `OS Version`: Retrieved via `Environment.OSVersion`.

  • `Process Name`: The process hosting the implant (e.g., powershell.exe).

  • `User Domain & Username`: Gathers domain and user context.

  • `Integrity Level` (num3): Calculates the privilege level of the running process:
      • 4 (SYSTEM integrity) if running as the SYSTEM user.
      • 3 (High integrity / Administrator) if the current user has administrative privileges.
      • 2 (Medium/Low integrity) for normal user privileges.


  It packages this profile into a JSON string (message2), encrypts it via the MessageCrafter (using the SessionKey we decrypted earlier), and sends it to
  the C2 via the HttpMessenger to register itself.

#### 2. The Beacon Loop

![](22.png)

  Once registered, the implant enters an infinite while (flag) loop where it continuously beacons out to the C2 server for tasks.

  ##### The Loop Lifecycle:

  1. `Sleep with Jitter`: It calculates a random sleep time (7 seconds ± up to 10% variance, which is ±0.7 seconds) and sleeps.
   
  2. `Safety Checks`: It verifies if the total consecutive network failures have exceeded 5000, or if the current time is past the `KillDate`. If either is
  true, the loop breaks and the implant exits.

  3. `Poll for Tasks`:
    `GruntTaskingMessage message = messenger.ReadTaskingMessage();`

    It performs an HTTP request to see if the C2 server has queued any tasks for it.

  4. `Command Dispatcher`:
  If a task is received, it evaluates message.Type:

      • Control Commands:

          • SetDelay / SetJitter / SetConnectAttempts / SetKillDate: Updates the internal configuration variables.

          • Exit: Gracefully shuts down the implant by breaking the loop.

          • Tasks: Lists the currently running background tasks/threads.

          • TaskKill: Aborts and suspends a background task thread by name.

      • Execution Commands:

          • If message.Token is set to true, the implant attempts to impersonate another user's security token before executing.

          • It spawns a new thread to run `Grunt.TaskExecute` to process the command, ensuring the main beaconing loop remains responsive.

  5. `Send Results`: The loop calls `messenger.WriteTaskingMessage()` to transmit any queued results back to the C2.

#### 3. The Execution Engine

![](23.png)

  This helper method executes the core payload tasking commands.

  ##### A. Running .NET Assemblies (GruntTaskingType.Assembly)

  This is [Covenant C2](https://github.com/cobbr/Covenant/tree/master)'s primary execution mechanism. Instead of running shell commands directly (which is noisy), it runs compiled .NET code reflectively
  in memory.

  1. Argument Parsing: It splits the task message by a comma ,.
      • The first part (array[0]) is the compressed, Base64-encoded .NET assembly.
      • The rest of the elements (array[1], array[2], etc.) are Base64-encoded arguments for the assembly.
  2. Decompression & Loading: It decompresses array[0] (using raw Deflate compression) and loads it into the current process using Assembly.
  Load(rawAssembly).
  3. Execution:
      • It looks for a class named Task in the loaded assembly.
      • If the Task class has a property called OutputStream, the implant sets up an anonymous pipe (`AnonymousPipeServerStream`) to redirect the
      assembly's output back to the implant. It reads the output from the pipe in 1MB chunks and sends intermediate progress reports back to the C2.
      • If there is no OutputStream property, it simply invokes the static Execute method, captures the returned string, and sends it back to the C2 as
      the final result.


  ##### B. P2P Connections (GruntTaskingType.Connect & Disconnect)

  Used in multi-hop configurations:

  • Connect: Instructs the implant to connect to another peer node (specified by IP and Port).

  • Disconnect: Closes the connection to a peer node.

Now we can return to the pcap file, every traffic from now on can be decrypted using the obtained session key as AES key, and IV from each packet. This is the initial reconaissance being sent to the C2 server:

![](24.png)

The first message from C2 server, the response to this output is empty:

![](25.png)

The second task, this time server sends an assembly to run:

![](26.png)

Split the decrypted message by a comma, take the first part, then use cyberchef's base64 decode and raw inflate yields the .NET assembly:

![](27.png)

In `dnSpy`, the `Task` class seems to just query the computer name, here is the answer:

![](28.png)

The next assembly queries running processes, here is the result:

![](29.png)

The next assembly runs Mimikatz from `Sharploit ` to dump credentials:

![](30.png)

Here is the result:

![](31.png)

The next assembly takes a screenshot of victim machine:

![](32.png)

Here is the result:

![](33.png)

The next assembly is a keylogger:

![](34.png)

Here comes the result:

![](35.png)

![](36.png)

![](37.png)

![](38.png)

![](39.png)

![](40.png)

![](41.png)

![](42.png)

Omit the `lshiftkey`, we can reconstruct the flag.

`Flag: HTB{C2s_4r3_n0t_4lw4ys_4_s4f3_c0mmun1c4t10n_ch4nn3l}`