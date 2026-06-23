# Crimewatch — A Forensics Journey Through Two Layers of Android Encryption

*A long-form writeup of how a "broken qcow2" turned into a full Android FBE + metadata-encryption teardown, the wrong turns that ate hours, and the one read that finally broke it open.*

---

## 0. The brief

The challenge shipped as `dist-Crimewatch.zip`. Inside, a tarball; inside that, three files:

```
crimewatch/a         1,394,671,616 bytes   QEMU QCOW Image (v3), virtual 6 GiB
crimewatch/b             1,114,112 bytes   QEMU QCOW Image (v3), 18 MiB, "AES-encrypted"
crimewatch/flag.py           1,776 bytes   Python
```

`flag.py` is the scoreboard. It asks four case questions and reconstructs an AES‑256‑GCM key from the answers.

---

## 1. Getting a block device at all

No `qemu-img`, no `qemu-nbd`, no `guestmount` on the box. And `sudo` wanted a password I didn't have yet.

On the host, with `sudo`:

```bash
apt-get install -y qemu-utils
modprobe nbd max_part=16          # this time the module exists → /dev/nbd0
qemu-nbd --connect=/dev/nbd0 --read-only a
```

`/dev/nbd0` appeared. Mounting solved, right? Not even close.

---

## 2. "It's encrypted" — and the number that didn't add up

```
fdisk -l /dev/nbd0   → no partition table
blkid /dev/nbd0      → nothing
xxd  /dev/nbd0       → pure noise from byte 0
```

I scanned the whole 6 GB for signatures and sampled Shannon entropy every 256 MB. Every sample came back **7.997 bits/byte**. No headers anywhere. My first instinct was *VeraCrypt/headerless dm‑crypt* — a fully random container.

But a number bugged me: the qcow2 **file** is only 1.33 GB, yet the decoded device looked like 6 GB of incompressible randomness. Random data doesn't compress, so a truly-random 6 GB disk can't live in a 1.33 GB qcow2. 

I probed specific offsets and found the truth: the low ~5.5 GB region was random; the tail read as zeros (unallocated). So it wasn't VeraCrypt — it was *a disk whose used space is uniformly encrypted with no recognizable header.* That smells like one specific thing: Android metadata encryption.

---

## 3. The partner file tells the story

I turned to `b`. `b` is a **plain qcow2**, and `strings` on it was the giveaway:

```
/metadata
u:object_r:vold_metadata_file:s0
u:object_r:password_slot_metadata_file:s0
EFI PART
```

SELinux contexts. `vold`. `password_slot`. This is **Android**. `b` is the `/metadata` partition; `a` is `/data`. The "headerless randomness" in `a` is **Android metadata encryption (`dm-default-key`)** — full-device AES with the keys stashed in `/metadata`.

Mounting `b` (after `mount -o ro,noload` because it needed journal recovery) revealed:

```
/metadata/vold/metadata_encryption/key/
    encrypted_key        (92 bytes)
    keymaster_key_blob   (182 bytes)
    secdiscardable       (16384 bytes)
    stretching           → "nopassword"
    version              → 1
```

`stretching = nopassword` means the key is **not** protected by a lockscreen PIN. No brute force needed — just unwrap it.

---

## 4. Unwrapping the metadata key

Android's `KeyStorage` wraps the disk key with a Keymaster AES‑GCM key. Since this is an **emulator** with a **software keymaster**, the wrapping key material sits in cleartext inside the blob.

The blob starts:

```
00 20 00 00 00 | db ac ce 2a … b6 d4 | 2c 00 00 00 …
^ver ^len=32     ^---- 32-byte AES key ----^   ^ auth sets
```

We treat `keymaster_key_blob[5:37]` as an AES‑256‑GCM key, split `encrypted_key` as `IV(12) ‖ ciphertext(64) ‖ tag(16)`, and decrypt. The GCM tag verified on the first try (offset 5, no AAD):

```
DATAKEY = 56c4a488…3c6c64   (64 bytes)
```

![Metadata key decryption](/mnt/c/CTF_Workspace/GreyCTF2026/Crime Watch/b_key.png)

This is the 64‑byte `dm-default-key` (AES‑256‑XTS).

---

## 5. Decrypting the metadata block layer

`dm-default-key`'s default mode is `aes-xts-plain64`. We decrypt `a.raw` at the block level using `datakey.bin` with plain `dm-crypt`, choosing a sector size of 4096 and `iv_large_sectors` tweak mapping:

| table | ext4 magic |
|-------|-----------|
| `sector_size 512` | `f99c` ✗ |
| `sector_size:4096` | `53ef` ✓ |
| `sector_size:4096 iv_large_sectors` | `53ef` ✓ |

A valid `/data` ext4 superblock structure is retrieved. We output the block-decrypted image to `a_decrypted.raw`. 

---

## 6. Transferring to Kali VM: Relieving the Pain

> [!NOTE]
> Trying to mount and manage FBE (File-Based Encryption) volumes on default WSL kernels is a dead end because WSL kernels generally lack `CONFIG_FS_ENCRYPTION` compiled in and do not support standard Linux keyrings out-of-the-box. Moving `a.raw`, `a_decrypted.raw`, the FBE keys, and scripts to a native Linux environment like a **Kali VM** immediately resolves this limitation.

Inside the Kali VM, we loop-mount the metadata-decrypted image to access the directory structure:
```bash
sudo mount -o ro,loop,noload a_decrypted.raw /mnt/data
```
The directories are accessible, but filenames are base64-encrypted (`dir_key` required).

---

## 7. FBE Keys: Adding them to the Kernel Keyring

The FBE class keys reside in:
* `/metadata/misc/vold/user_keys/de/0/` (device-encrypted)
* `/metadata/misc/vold/user_keys/ce/0/current/` (credential-encrypted)
* `/metadata/unencrypted/key/` (system / per-boot)

We unwrap these CE, DE, and system master keys using the software keymaster AES key in the exact same manner as the metadata key.

![CE Key Decryption](/mnt/c/CTF_Workspace/GreyCTF2026/Crime Watch/ce.png)
![DE Key Decryption](/mnt/c/CTF_Workspace/GreyCTF2026/Crime Watch/de.png)
![Unenc Key Decryption](/mnt/c/CTF_Workspace/GreyCTF2026/Crime Watch/unenc.png)

### The Intuition behind `add_keys_kernel`
To decrypt filenames natively through the mount, we must load our decrypted master keys (`ce_key.bin` and `de_key.bin`) into the kernel's fscrypt keyring using the `FS_IOC_ADD_ENCRYPTION_KEY` ioctl. This teaches the kernel's ext4 driver how to decrypt directories on-the-fly.

Here is our [add_keys_kernel.py](file:///mnt/c/CTF_Workspace/GreyCTF2026/Crime%20Watch/add_keys_kernel.py) script:

```python
#!/usr/bin/env python3
import fcntl
import os
import sys
import struct

# Linux kernel ioctl code for adding fscrypt encryption keys
FS_IOC_ADD_ENCRYPTION_KEY = 0xC0506617

def add_key(mount_path, key_path, name):
    if not os.path.exists(key_path):
        print(f"[-] Key file {key_path} not found.")
        return

    with open(key_path, "rb") as f:
        key_bytes = f.read()

    # struct fscrypt_add_key_arg (80 bytes prefix + raw key bytes)
    key_spec = struct.pack("<II32s", 2, 0, b"\x00" * 32)
    arg_prefix = struct.pack("<II32s", len(key_bytes), 0, b"\x00" * 32)
    arg = key_spec + arg_prefix + key_bytes

    fd = os.open(mount_path, os.O_RDONLY)
    try:
        buf = bytearray(arg)
        fcntl.ioctl(fd, FS_IOC_ADD_ENCRYPTION_KEY, buf, 1)
        
        # Parse output spec and key identifier
        returned_spec = buf[:40]
        _, _, union_val = struct.unpack("<II32s", returned_spec)
        identifier = union_val[:8].hex()
        key_id = struct.unpack("<I", buf[44:48])[0]
        
        print(f"[+] Loaded {name:<5} Key -> Kernel Key ID: {key_id:<5} | Identifier: {identifier}")
    except PermissionError:
        print(f"[-] Permission denied. Please run as root (sudo).")
    except Exception as e:
        print(f"[-] Failed to load {name} key: {e}")
    finally:
        os.close(fd)

def main():
    if len(sys.argv) < 2:
        print("Usage: sudo python3 add_keys_kernel.py <mount_point>")
        sys.exit(1)

    mount_path = sys.argv[1]
    add_key(mount_path, "ce_key.bin", "CE")
    add_key(mount_path, "de_key.bin", "DE")

if __name__ == "__main__":
    main()
```

By running this script, the kernel keyring is populated and the file path names automatically decrypt:

```bash
sudo python3 add_keys_kernel.py /mnt/data
```

![Adding keys in Kali](/mnt/c/CTF_Workspace/GreyCTF2026/Crime Watch/action_in_kali.png)

Now we can resolve filenames and identify the target inodes:
* `/mnt/data/system_ce/0/notification_history/notification_history.xml` $\rightarrow$ Inode **`49246`**
* `/mnt/data/media/0/Pictures/TeleChat/IMG_20260514_164900.png` $\rightarrow$ Inode **`303161`**
* `/mnt/data/media/0/Pictures/TeleChat/spot.jpg` $\rightarrow$ Inode **`303162`**

---

## 8. The Wall: File Contents are Garbage

Even though the filenames decrypt, attempting to read the file contents through the `/mnt/data` loop-mount yields garbage. 

This happens because the **file data extents bypass the metadata encryption layer** and are written directly as raw FBE ciphertext to `a.raw`. Reading them through `/mnt/data` makes the kernel apply `dm-crypt` decryption a second time, turning valid FBE ciphertext into double-decrypted noise.

> [!IMPORTANT]
> The correct path to extract file contents is to read their block extents directly from the raw encrypted disk image `a.raw` and FBE-decrypt them manually in user-space.

---

## 9. The Decryption Schema & Content Extraction

To decrypt a file manually, we implement the standard `fscrypt v2` decryption pipeline.

### Decryption Pipeline:
1. **FBE Key Derivation (HKDF-SHA512):**
   We extract the 16-byte nonce from bytes 24–39 (`data[24:40]`) of the inode's `c` extended attribute (the fscrypt context).
   We derive the 64-byte block decryption key via `HKDF-SHA512-Expand`:
   $$\text{PRK} = \text{HMAC-SHA512}(\text{salt}=\emptyset, \text{key}=\text{ce\_key})$$
   $$\text{File Key} = \text{HKDF-Expand}(\text{PRK}, \text{info}=\text{b"fscrypt\x00\x02"} + \text{nonce}, \text{length}=64)$$
2. **Logical Block Mapping:**
   Using `debugfs stat`, we extract the logical-to-physical block mapping (extents) for the target inode.
3. **Block-by-Block AES-XTS Decryption:**
   For each extent block, we read 4096 bytes from the raw physical block index of `a.raw` and decrypt using AES-256-XTS. The tweak (IV) is the 16-byte padded **logical** block index:
   $$\text{Tweak} = \text{logical\_block\_index (8 bytes, little-endian)} \mathbin{\Vert} \text{b"\x00"} \times 8$$
4. **Reassembly & Truncation:**
   We join the decrypted blocks together and truncate the byte stream to the exact file size.

Here is the implementation in [extract_file.py](file:///mnt/c/CTF_Workspace/GreyCTF2026/Crime%20Watch/extract_file.py):

```python
#!/usr/bin/env python3
import sys
import os
import re
import hmac
import hashlib
import subprocess
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def hkdf_expand(prk, info, length):
    t = b""
    okm = b""
    i = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha512).digest()
        okm += t
        i += 1
    return okm[:length]

def derive_file_key(master_key, nonce):
    prk = hmac.new(b"", master_key, hashlib.sha512).digest()
    info = b"fscrypt\x00\x02" + nonce
    return hkdf_expand(prk, info, 64)

def run_debugfs(cmd):
    res = subprocess.run(
        ["debugfs", "-R", cmd, "a_decrypted.raw"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    return res.stdout

def get_inode_nonce(inode):
    out = run_debugfs(f"ea_get <{inode}> c")
    if b"c (" not in out:
        return None
    try:
        hex_part = out.split(b"=")[1].strip().replace(b" ", b"")
        data = bytes.fromhex(hex_part.decode())
        return data[24:40]  # Nonce is 16 bytes starting at offset 24 for fscrypt v2
    except Exception:
        return None

def parse_stat(inode):
    out = run_debugfs(f"stat <{inode}>")
    size_match = re.search(r"Size:\s+(\d+)", out.decode('utf-8', errors='ignore'))
    if not size_match:
        raise ValueError("Could not parse file size.")
    file_size = int(size_match.group(1))

    extents_idx = out.find(b"EXTENTS:")
    if extents_idx == -1:
        raise ValueError("No block extents found.")
    extents_section = out[extents_idx:]
    
    blocks = []
    lines = extents_section.split(b"\n")
    for line in lines[1:]:
        line = line.strip()
        if not line or b":" not in line:
            continue
        parts = line.split(b":")
        log_part = parts[0].decode().strip("()")
        log_start, log_end = map(int, log_part.split("-")) if "-" in log_part else (int(log_part), int(log_part))
        phys_part = parts[1].split(b" ")[0].decode()
        phys_start, phys_end = map(int, phys_part.split("-")) if "-" in phys_part else (int(phys_part), int(phys_part))
        num_blocks = log_end - log_start + 1
        for i in range(num_blocks):
            blocks.append((log_start + i, phys_start + i))
            
    blocks.sort(key=lambda x: x[0])
    return file_size, blocks

def decrypt_file(inode, output_path):
    print(f"[*] Fetching metadata for inode {inode}...")
    with open("ce_key.bin", "rb") as f:
        ce_key = f.read()

    nonce = get_inode_nonce(inode)
    if not nonce:
        print(f"[-] Failed to get nonce for inode {inode}")
        return

    file_size, extents = parse_stat(inode)
    file_key = derive_file_key(ce_key, nonce)
    aes_algo = algorithms.AES(file_key)
    decrypted_data = bytearray()

    with open("a.raw", "rb") as f_raw:
        for logical_blk, physical_blk in extents:
            f_raw.seek(physical_blk * 4096)
            ciphertext = f_raw.read(4096)
            tweak = logical_blk.to_bytes(8, 'little') + b'\x00' * 8
            cipher = Cipher(aes_algo, modes.XTS(tweak))
            decrypted_data.extend(cipher.decryptor().update(ciphertext) + cipher.decryptor().finalize())

    with open(output_path, "wb") as f_out:
        f_out.write(decrypted_data[:file_size])
    print(f"[+] Success! Extracted and decrypted file to: {output_path}\n")

def main():
    if len(sys.argv) < 3:
        print("Usage: python3 extract_file.py <inode> <output_path>")
        sys.exit(1)
    decrypt_file(int(sys.argv[1]), sys.argv[2])

if __name__ == "__main__":
    main()
```

### Decrypting the Evidence Files
Executing the extraction script in the Kali VM successfully yields the decrypted evidence files:

```bash
python3 extract_file.py 49246 notification_history.xml
python3 extract_file.py 303161 van.png
python3 extract_file.py 303162 spot.jpg
```

![Running extraction in Kali](/mnt/c/CTF_Workspace/GreyCTF2026/Crime Watch/action_in_kali2.png)
