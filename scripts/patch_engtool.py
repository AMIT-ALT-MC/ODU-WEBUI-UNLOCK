#!/usr/bin/env python3
"""
Patch RECID_TOOL_CFG_TELNET / RECID_TOOL_CFG_SSH / RECID_CONSOLE to 1
in a raw encrypted engtool.cfg (same *IMQ format used by XAPConfig).

Requires pycryptodome:  pip3 install pycryptodome

Usage:
    python3 patch_engtool.py /data/cfg/engtool.cfg /data/cfg/engtool.cfg.new

Then on the device:
    cp /data/cfg/engtool.cfg /data/cfg/engtool.cfg.bak   # ALWAYS back up first
    cp /data/cfg/engtool.cfg.new /data/cfg/engtool.cfg
    reboot   # or restart the xap_core service if you know the right signal/command
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

# record name -> new value (1 = enabled)
TARGETS = {
    b"RECID_TOOL_CFG_TELNET": 1,
    b"RECID_TOOL_CFG_SSH":    1,
    b"RECID_CONSOLE":         1,
}

def patch(path_in, path_out):
    raw = open(path_in, 'rb').read()
    magic = raw[0:20]
    if not magic.startswith(b"*IMQ"):
        sys.exit(f"Not a recognized XAPConfig file (bad magic: {magic!r})")
    f1, f2, clen = struct.unpack_from('<III', raw, 20)
    body = raw[32:32+clen]
    pt = bytearray(AES.new(KEY, AES.MODE_CBC, IV).decrypt(body))

    n = len(pt) // RECLEN
    patched = []
    for i in range(n):
        off = i * RECLEN
        idx, tag = struct.unpack_from('<HH', pt, off)
        if tag != TAG:
            break
        name = bytes(pt[off+4:off+44]).split(b'\x00')[0]
        if name in TARGETS:
            new_val = TARGETS[name]
            struct.pack_into('<I', pt, off+76, new_val)
            patched.append(name.decode())

    missing = set(n.decode() for n in TARGETS.keys()) - set(patched)
    if missing:
        print(f"WARNING: did not find these records (not patched): {missing}", file=sys.stderr)
    if not patched:
        sys.exit("No target records found/patched - aborting, not writing output.")

    new_f1 = sum(pt) & 0xFFFFFFFF   # confirmed: header checksum = sum of plaintext bytes
    new_ct = AES.new(KEY, AES.MODE_CBC, IV).encrypt(bytes(pt))
    assert len(new_ct) == clen, "ciphertext length changed unexpectedly - aborting"

    new_header = magic + struct.pack('<III', new_f1, f2, clen)
    new_file = new_header + new_ct

    open(path_out, 'wb').write(new_file)
    print(f"Patched: {', '.join(patched)}")
    print(f"Wrote {len(new_file)} bytes to {path_out} (original was {len(raw)} bytes)")

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(1)
    patch(sys.argv[1], sys.argv[2])
