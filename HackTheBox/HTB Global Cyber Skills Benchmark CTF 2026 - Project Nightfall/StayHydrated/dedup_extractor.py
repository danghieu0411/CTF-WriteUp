import argparse
import os
import ctypes
import ctypes.wintypes as wt
import hashlib
import struct
import sys
import json
from dataclasses import dataclass
from typing import List, Optional, Dict, Iterable

# import first if not yet
import pytsk3
import pyewf

REC=64 #each stream record is 64 bytes
CKHR_HDR=72 #ckhr header is 72 bytes
MFT_RECSZ=1024 #MFT record size is 1024 bytes
DEDUP_TAG=0x80000013 

MAGIC = {
    ".pdf": b"%PDF-",
    ".docx": b"PK\x03\x04",
    ".xlsx": b"PK\x03\x04",
    ".pptx": b"PK\x03\x04",
    ".7z": b"\x37\x7a\xbc\xaf\x27\x1c",
    ".zip": b"PK\x03\x04",
    ".rar": b"Rar!\x1a\x07",
    ".png": b"\x89PNG",
    ".jpg": b"\xff\xd8\xff",
    ".jpeg": b"\xff\xd8\xff",
    ".gif": b"GIF8",
    ".exe": b"MZ",
    ".dll": b"MZ",
}

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def load_decompressors():
    fns = []
    try:
        from dissect.util.compression import lzxpress, lzxpress_huffman
        fns.append(lzxpress.decompress)
        fns.append(lzxpress_huffman.decompress)
    except ImportError:
        pass

    if os.name == "nt":
        try:
            ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
            rtl = ntdll.RtlDecompressBuffer
            rtl.restype = wt.DWORD
            rtl.argtypes = [wt.USHORT, ctypes.c_char_p, wt.ULONG, ctypes.c_char_p, wt.ULONG, ctypes.POINTER(wt.ULONG)]
            def win_xpress(blob: bytes) -> bytes:
                out = ctypes.create_string_buffer(max(len(blob) * 64, 64 * 1024))
                out_len = wt.ULONG(0)
                rc = rtl(0x03, out, len(out), blob, len(blob), ctypes.byref(out_len))
                if rc != 0: raise RuntimeError()
                return bytes(out[:out_len.value])
            fns.append(win_xpress)
        except Exception:
            pass
    return fns

DECOMPRESSORS = load_decompressors()

def maybe_decompress(payload, logical_size):
    if len(payload) == logical_size:
        return payload
    for decomp in DECOMPRESSORS:
        try:
            out = decomp(payload)
            if len(out) == logical_size:
                return out
        except Exception:
            continue
    return None

@dataclass
class Target:
    source: str           # "live-mft" or "deleted-mft"
    rel_path: str         # reconstructed full path within the volume
    size: int             # logical file size in bytes
    is_resident: bool     # True if $DATA was inside the MFT record (small files)
    inline_data: Optional[bytes]   # the inline bytes if resident
    mft_rec: Optional[int]         # MFT record number
    stream_name: str = ""          # ADS name, empty for default $DATA
    magic: Optional[bytes] = None  # expected file-magic for sanity check

    def output_rel_path(self) -> str:
        base, ext = os.path.splitext(self.rel_path)
        stream_suffix = f"_ADS_{self.stream_name}" if self.stream_name else ""
        return f"{base}{stream_suffix}@{self.source}-rec{self.mft_rec}-sz{self.size}{ext}"

class EWFImgInfo(pytsk3.Img_Info):
    def __init__(self, ewf_handle):
        self._ewf_handle = ewf_handle
        super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)
    def read(self, offset, size):
        self._ewf_handle.seek(offset)
        return self._ewf_handle.read(size)
    def get_size(self): return self._ewf_handle.get_media_size()

class TSKFileAdapter:
    def __init__(self, tsk_file):
        self.tsk_file = tsk_file
        self.offset = 0
        self.size = tsk_file.info.meta.size if tsk_file.info.meta else 0
    def read(self, size=-1):
        if size == -1: size = self.size - self.offset
        if size <= 0: return b""
        data = self.tsk_file.read_random(self.offset, size)
        self.offset += len(data)
        return data
    def seek(self, offset, whence=0):
        if whence == 0: self.offset = offset
        elif whence == 1: self.offset += offset
        elif whence == 2: self.offset = self.size + offset
    def __enter__(self): return self
    def __exit__(self, *args): pass

class MFTParser:
    def __init__(self, fs: pytsk3.FS_Info):
        self.fs = fs

    def parse(self) -> Dict[int, dict]:
        tsk_file = self.fs.open("/$MFT")
        with TSKFileAdapter(tsk_file) as f:
            mft = f.read()
        records = {}
        for rec_num in range(len(mft) // MFT_RECSZ):
            data = mft[rec_num * MFT_RECSZ : (rec_num + 1) * MFT_RECSZ]
            if data[:4] != b"FILE": continue
            flags = struct.unpack("<H", data[22:24])[0] #0x16 is flags, bit 0 is in-use, bit 1 is dir, bit 2 is compressed, bit 3 is encrypted, bit 4 is sparse
            entry = {
                "rec_num": rec_num,
                "in_use": bool(flags & 1),
                "is_dir": bool(flags & 2),
                "names": [],
                "streams": [],
                "has_dedup_reparse": False,
            }
            off = struct.unpack("<H", data[20:22])[0] #0x14 is offset to first attribute
            while off + 8 <= len(data):
                attr_type = struct.unpack("<I", data[off : off + 4])[0] # attr type, 0xFFFFFFFF means end of attributes
                if attr_type == 0xFFFFFFFF: break
                attr_len = struct.unpack("<I", data[off + 4 : off + 8])[0] # attr len, including header, must be > 0
                if attr_len == 0 or off + attr_len > len(data): break
                
                non_resident = data[off + 8] # 0x08 w.r.t off is non-resident flag, 0 means body inline, 1 means body is elsewhere on disk

                if attr_type == 0x30 and non_resident == 0: # type 0x30 is $FILE_NAME, non-resident=0 means resident
                    content_len, content_off = struct.unpack("<IH", data[off+16:off+22]) #0x10 wrt off is content len, 0x14 wrt off is content offset
                    fn = data[off + content_off : off + content_off + content_len] #file name
                    if len(fn) >= 66: #0x40 (wrt to attribute body) is name length, 0x42 is where name string (in utf-16-le) starts, 0x41 is namespace
                        entry["names"].append({
                            "name": fn[66 : 66 + fn[64] * 2].decode("utf-16-le", errors="replace"),
                            "parent": struct.unpack("<Q", fn[0:8])[0] & 0xFFFFFFFFFFFF, # and operator is used to keep only lower 48 bits, omitting parent sequence number (note: litte-endian)
                            "namespace": fn[65]
                        })

                elif attr_type == 0x80: # type 0x80 is $DATA, can be resident or non-resident, not trully needed in this case as all wiped file is non-resident
                    name_len = data[off+9]
                    name_off = struct.unpack("<H", data[off+10:off+12])[0]
                    s_name = data[off+name_off:off+name_off+name_len*2].decode('utf-16le') if name_len > 0 else ""
                    
                    if non_resident == 0: # resident, content is inline, read directly from attribute body
                        content_len, content_off = struct.unpack("<IH", data[off+16:off+22])
                        inline_data = data[off+content_off : off+content_off+content_len]
                        entry["streams"].append({"name": s_name, "size": content_len, "resident": True, "data": inline_data})
                    else: # non-resident, read logical size from attribute body, but actual data is elsewhere on disk, need to read runlist to get physical location
                        real_size = struct.unpack("<Q", data[off+48:off+56])[0]
                        entry["streams"].append({"name": s_name, "size": real_size, "resident": False, "data": None})

                elif attr_type == 0xC0: # type 0xC0 is reparse point, can be resident or non-resident, but in practice usually resident and small
                    if non_resident == 0:
                        content_len, content_off = struct.unpack("<IH", data[off+16:off+22])
                        rp = data[off + content_off : off + content_off + content_len]
                        if len(rp) >= 8 and struct.unpack("<I", rp[0:4])[0] == DEDUP_TAG: # first 4 bytes of reparse point is reparse tag, 0x80000013 means dedup reparse point
                            entry["has_dedup_reparse"] = True
                    else:
                        entry["has_dedup_reparse"] = True
                off += attr_len
            records[rec_num] = entry
        return records

def build_rel_path(rec_num: int, preferred: Dict[int, Optional[dict]], seen=None) -> Optional[str]:  # bulid path up to root
    if seen is None: seen = set()
    if rec_num in seen: return None
    seen.add(rec_num)
    if not preferred.get(rec_num) or not preferred[rec_num]["name"]: return None
    name, parent = preferred[rec_num]["name"], preferred[rec_num]["parent"]
    if rec_num == 5 or parent == rec_num or parent == 5: return name
    parent_path = build_rel_path(parent, preferred, seen)
    return os.path.join(parent_path, name) if parent_path else name

class DedupStore:
    def __init__(self, fs: pytsk3.FS_Info, chunk_store: str):
        self.fs = fs
        self.chunk_store = chunk_store.replace("\\", "/")
        self._stream_cache = {}
        self._candidates_by_size = {}

    def container_paths(self, cont_num: int) -> List[str]: # given container number from stream record, return all candidate paths of chunk data in the dedup store, note that each container can have multiple chunk data due to chunk sharing, and we need to check all of them to find the right one
        out = []
        data_dir = f"{self.chunk_store}/Data"
        try:
            for fobj in self.fs.open_dir(data_dir):
                fn = fobj.info.name.name.decode('utf-8', errors='ignore')
                if not fn.endswith(".ccc") or "delete" in fn:
                    continue
                parts = fn.split(".")
                try:
                    n1, n2 = int(parts[0], 16), int(parts[1], 16)
                    if n1 == cont_num or n2 == cont_num:
                        out.append(f"{data_dir}/{fn}")
                except ValueError:
                    continue
        except IOError:
            pass
        return out
    
    def find_chunk(self, cont_num: int, off: int, expected_hash: bytes) -> Optional[str]: # dis-ambiguate by comparing chunk's hash
        for cp in self.container_paths(cont_num):
            try:
                with TSKFileAdapter(self.fs.open(cp)) as f:
                    f.seek(off)
                    hdr = f.read(CKHR_HDR)
                if len(hdr) >= CKHR_HDR and hdr[:4] == b"Ckhr" and hdr[40:72] == expected_hash: # 32 bytes from 0x28 of ckhr chunk holds the sha256 hash of the chunk data, which we can use to verify if we found the right chunk, note that chunk data starts from offset 0x100 of the container file, and there can be multiple ckhr chunks in one container file, so we need to read header of each chunk to find the right one
                    return cp
            except Exception:
                continue
        return None
    
    def walk_forward(self, data: bytes, first_rec_off: int, expected_size: int): # walk each stream record forward
        records, off, prev_cum = [], first_rec_off, 0
        while off + REC <= len(data):
            rec = data[off : off + REC]
            cum = struct.unpack("<Q", rec[0:8])[0] # first 8 bytes is cummulative size up to this record
            stored_size = struct.unpack("<Q", rec[40:48])[0] # 8 bytes from 0x28 holds the acutually stored size in container
            rec_id, cont, next_off, flags = struct.unpack("<IIII", rec[48:64]) # 0x30 record id, 0x34 container number, 0x38 next chunk offset, 0x3c flags (ignore)
            if cum <= prev_cum or cum > expected_size or stored_size == 0:
                break
            records.append((cum, stored_size, rec_id, cont, next_off, flags, rec[8:40])) # also keep the expected hash of the chunk data in the record for later verification
            prev_cum = cum
            if cum == expected_size:
                return records
            off += REC
        return None
                        
    def candidates_for_size(self, target_size: int): # walk every stream container, find smap header and follow the stream records to find candidates that match the target size, note that there can be multiple candidates for the same size due to chunk sharing, and we need to check all of them to find the right one
        if target_size in self._candidates_by_size:
            return self._candidates_by_size[target_size]
        cands = []
        stream_dir = f"{self.chunk_store}/Stream"
        try:
            for fobj in self.fs.open_dir(stream_dir):
                fn = fobj.info.name.name.decode('utf-8', errors='ignore')
                if not fn.endswith(".ccc") or "delete" in fn:
                    continue
                p = f"{stream_dir}/{fn}"
                if p not in self._stream_cache:
                    with TSKFileAdapter(self.fs.open(p)) as f:
                        self._stream_cache[p] = f.read()
                data = self._stream_cache[p]
                off = 0
                while True:
                    i = data.find(b"Smap", off) # find the first index of Smap after index "off"
                    if i < 0:
                        break
                    off = i + 1 # skip the visited header to find the next one
                    if i + 24 > len(data): # nothing after header, invalid, skip
                        continue
                    fco = struct.unpack("<I", data[i+16:i+20])[0] # 0x10 from header is first chunk offset
                    fcc = struct.unpack("<I", data[i+20:i+24])[0] # 0x14 from header is first container number 
                    records = self.walk_forward(data, i+24, target_size) # walk the stream records forward to find a valid chain of records that matches the target size
                    if records:
                        cands.append((p, i, fco, fcc, records))
        except IOError:
            pass
        self._candidates_by_size[target_size] = cands
        return cands
    
    def rehydrate(self, records, fco: int, fcc: int, expected_size: int) -> Optional[bytes]: # walk the record chain, fetch each chunk data based on container number and chunk offset in the record
        cur_off, cur_cont, buf, prev_cum = fco, fcc, bytearray(), 0
        for cum, stored_size, rec_id, cont, next_off, flags, expected_hash in records:
            cp = self.find_chunk(cur_cont, cur_off, expected_hash)
            if not cp:
                return None
            try:
                with TSKFileAdapter(self.fs.open(cp)) as f:
                    f.seek(cur_off)
                    _ = f.read(CKHR_HDR + 16) # 16 bytes after the ckhr header is the start of the chunk data
                    payload = f.read(stored_size) # read based on stored_size in record
            except Exception:
                return None
            if len(payload) != stored_size:
                return None
            chunk = maybe_decompress(payload, cum - prev_cum)
            if chunk is None:
                return None
            buf.extend(chunk)
            prev_cum = cum
            cur_off, cur_cont = next_off, cont
        return bytes(buf) if len(buf) == expected_size else None
    
def discover_targets(parser: MFTParser) -> List[Target]: # filter mft record for only deduplicated files, reconstruct their relative path, and return a list of Target objects 
    records = parser.parse()
    preferred = {r: sorted(rec["names"], key=lambda n: (n["namespace"]==2, n["namespace"]))[0] if rec["names"] else None for r, rec in records.items()}
    targets = []

    for rec_num, rec in records.items():
        if rec["is_dir"]:
            continue
        
        if not rec["has_dedup_reparse"]:
            continue
            
        rel = build_rel_path(rec_num, preferred)
        if not rel or rel.lower() in ("$mft", "$logfile", "$volume", "$attrdef", "$bitmap", "$boot", "$badclus", "$secure", "$upcase", "$extend"):
            continue

        source = "live-mft" if rec["in_use"] else "deleted-mft"
        ext = os.path.splitext(rel)[1].lower()
        magic = MAGIC.get(ext)
        
        for stream in rec["streams"]:
            target = Target(
                source=source,
                rel_path=rel,
                size=stream["size"],
                is_resident=stream["resident"],
                inline_data=stream.get("data") if stream["resident"] else None,
                mft_rec=rec_num,
                stream_name=stream["name"],
                magic=magic
            )
            targets.append(target)
    return targets

def auto_find_chunkstore(fs: pytsk3.FS_Info) -> Optional[str]:
    base = "/System Volume Information/Dedup/ChunkStore"
    print(f"[*] Auto-discovering ChunkStore in: {base}")
    try:
        for fobj in fs.open_dir(base):
            name = fobj.info.name.name.decode('utf-8', errors='ignore')
            if name.startswith("{") and (name.endswith("}.ddp") or name.endswith("}")):
                print(f"[+] Found ChunkStore: {base}/{name}")
                return f"{base}/{name}"
    except IOError:
        pass
    return None

def main():
    ap = argparse.ArgumentParser(description="ProDedupExtractor Toolkit (Enhanced with magic validation)")
    ap.add_argument("-i", "--image", required=True, help="Path to E01/Raw Image")
    ap.add_argument("-c", "--chunk-store", help="Path to ChunkStore GUID (Optional, auto-detected if omitted)")
    ap.add_argument("-o", "--out", required=True, help="Output directory")
    ap.add_argument("-m", "--manifest", default="manifest.jsonl", help="Output manifest file")
    args = ap.parse_args()

    ewf_handle = pyewf.handle()
    ewf_handle.open(pyewf.glob(args.image))
    try:
        fs = pytsk3.FS_Info(EWFImgInfo(ewf_handle), offset=0)
    except IOError:
        sys.exit("[-] Cannot recognize File System.")

    chunk_store = args.chunk_store or auto_find_chunkstore(fs)
    if not chunk_store:
        sys.exit("[-] ChunkStore not found. Please provide via -c.")

    print("[*] Parsing $MFT for Dedup Reparse Points, ADS & Inline Data...")
    targets = list(discover_targets(MFTParser(fs)))
    
    unique = {}
    for t in targets:
        key = (t.rel_path.lower(), t.size, t.source, t.stream_name)
        if key not in unique:
            unique[key] = t
    targets = list(unique.values())
    
    # Sorting by files' size
    targets.sort(key=lambda t: (-t.size, t.rel_path.lower()))
    
    print(f"[+] Detected {len(targets)} targets.")
    store = DedupStore(fs, chunk_store)
    
    os.makedirs(f"{args.out}/files", exist_ok=True)
    with open(args.manifest, "w", encoding="utf-8") as mf:
        for t in targets:
            entry = {
                "path": t.rel_path,
                "ads": t.stream_name,
                "source": t.source,
                "size": t.size,
                "status": "failed",
                "sha256": None,
                "stream_candidates": 0,
                "magic_expected": t.magic.hex() if t.magic else None
            }
            if t.source == "deleted-mft":
                out_path = os.path.join(args.out, "files", "_deleted", f"rec{t.mft_rec}_sz{t.size}_{os.path.basename(t.rel_path)}")
            else:
                out_path = os.path.join(args.out, "files", t.output_rel_path())
            os.makedirs(os.path.dirname(out_path), exist_ok=True)

            if t.is_resident:
                data = t.inline_data
                if data and len(data) == t.size:
                    entry["status"] = "recovered_resident"
                    entry["sha256"] = sha256_hex(data)
                    with open(out_path, "wb") as f:
                        f.write(data)
                    print(f"[+] RECOVERED (resident) | {t.size:>10}B | {t.rel_path}" + (f" [ADS: {t.stream_name}]" if t.stream_name else ""))
                    mf.write(json.dumps(entry) + "\n")
                    continue
                else:
                    print(f"[-] FAILED (resident size mismatch) | {t.size:>10}B | {t.rel_path}")
                    mf.write(json.dumps(entry) + "\n")
                    continue

            # Non-resident: need to rehydrate from chunk store
            cands = store.candidates_for_size(t.size)
            entry["stream_candidates"] = len(cands)
            if not cands:
                print(f"[-] FAILED (no stream map) | {t.size:>10}B | {t.rel_path}")
                mf.write(json.dumps(entry) + "\n")
                continue

            data = None
            for cp, smap_pos, fco, fcc, records in cands:
                candidate = store.rehydrate(records, fco, fcc, t.size)
                if candidate is None:
                    continue
                if t.magic and not candidate.startswith(t.magic):
                    continue
                data = candidate
                break
            if data is None and not t.magic:
                for cp, smap_pos, fco, fcc, records in cands:
                    candidate = store.rehydrate(records, fco, fcc, t.size)
                    if candidate is not None:
                        data = candidate
                        break

            if data is not None:
                with open(out_path, "wb") as f:
                    f.write(data)
                entry.update({"status": "recovered", "sha256": sha256_hex(data)})
                print(f"[+] RECOVERED | {t.size:>10}B | {t.rel_path}" + (f" [ADS: {t.stream_name}]" if t.stream_name else "") + " (DEDUP)")
            else:
                print(f"[-] FAILED    | {t.size:>10}B | {t.rel_path}")
            mf.write(json.dumps(entry) + "\n")

if __name__ == "__main__":
    main()

