#!/usr/bin/env python3
"""
Decrypt + parse an Askey/Jio ODU XAPConfig .cfg file in one shot.

Requires pycryptodome:  pip3 install pycryptodome

Usage: python3 decrypt_and_parse.py engtool.cfg [more.cfg ...]
  (operates on the RAW encrypted files straight off the device/backup -
   do not pre-decrypt them yourself)
"""
import struct, sys

try:
    from Crypto.Cipher import AES
except ImportError:
    sys.exit("Missing dependency. Run:  pip3 install pycryptodome")

KEY = b"+Askey Computer+"
IV  = b"TS87" + bytes(range(4, 16))

RECLEN = 80
TAG = 0x9856

def decrypt(raw: bytes) -> bytes:
    magic = raw[0:20]
    if not magic.startswith(b"*IMQ"):
        sys.exit(f"Not a recognized XAPConfig file (bad magic: {magic!r}) - "
                  "are you sure this is the raw encrypted .cfg?")
    f1, f2, clen = struct.unpack_from('<III', raw, 20)
    body = raw[32:32+clen]
    return AES.new(KEY, AES.MODE_CBC, IV).decrypt(body)

def parse_records(data: bytes):
    n = len(data) // RECLEN
    rows = []
    for i in range(n):
        rec = data[i*RECLEN:(i+1)*RECLEN]
        idx, tag = struct.unpack_from('<HH', rec, 0)
        if tag != TAG:
            break
        name = rec[4:44].split(b'\x00')[0].decode('ascii', errors='replace')
        vtype, raw4 = struct.unpack_from('<I4s', rec, 72)
        if vtype == 2:
            val = raw4.split(b'\x00')[0].decode('ascii', errors='replace')
        else:
            val = struct.unpack('<I', raw4)[0]
        rows.append((idx, name, vtype, val))
    return rows, data[len(rows)*RECLEN:]

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    for path in sys.argv[1:]:
        raw = open(path, 'rb').read()
        pt = decrypt(raw)
        print(f"\n=== {path}  ({len(pt)} bytes decrypted) ===")
        rows, leftover = parse_records(pt)
        if not rows:
            print("  (no records parsed with the fixed 80-byte layout - "
                  "this file likely uses a different/variable record structure)")
        for idx, name, vtype, val in rows:
            print(f"  idx={idx:3d}  type={vtype:<3d}  {name:40s} = {val}")
        if leftover:
            print(f"  [{len(leftover)} bytes of variable-length data follow - not auto-parsed]")
