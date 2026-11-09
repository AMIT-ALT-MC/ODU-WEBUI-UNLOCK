#!/usr/bin/env python3
"""
Patch the ACS URL (RECID_TR069_CRSURL / ManagementServer URL) in a raw
encrypted tr069.cfg (same *IMQ format used throughout XAPConfig).

The ACS URL lives as a plain NUL-terminated ASCII string inside a large
(~256 byte) reserved buffer with zero padding on both sides - it is found
by searching for the CURRENT known URL string, not a fixed offset, so this
works even if the exact byte offset differs slightly on your firmware.

Does NOT touch the Connection Request URL (the device's own auto-generated
callback address with its current WAN IP) - only the outbound ACS URL.

Requires pycryptodome:  pip3 install pycryptodome

Usage:
    python3 patch_tr069.py tr069.cfg tr069.cfg.new "http://op.topvipssh.net:7547/"

    # if the current ACS URL isn't the Jio default, override what to search for:
    python3 patch_tr069.py tr069.cfg tr069.cfg.new "http://op.topvipssh.net:7547/" \
        --old "https://acs.oss.jio.com:9443/ftacs-digest/ACS"
"""
import struct, sys, argparse

try:
    from Crypto.Cipher import AES
except ImportError:
    sys.exit("Missing dependency. Run:  pip3 install pycryptodome")

KEY = b"+Askey Computer+"
IV  = b"TS87" + bytes(range(4, 16))

DEFAULT_OLD_URL = b"https://acs.oss.jio.com:9443/ftacs-digest/ACS"

def patch(path_in, path_out, new_url: bytes, old_url: bytes):
    raw = open(path_in, 'rb').read()
    magic = raw[0:20]
    if not magic.startswith(b"*IMQ"):
        sys.exit(f"Not a recognized XAPConfig file (bad magic: {magic!r})")
    f1, f2, clen = struct.unpack_from('<III', raw, 20)
    body = raw[32:32+clen]
    pt = bytearray(AES.new(KEY, AES.MODE_CBC, IV).decrypt(body))

    idx = pt.find(old_url)
    if idx == -1:
        sys.exit(f"Could not find the expected current ACS URL {old_url!r} in "
                  f"the decrypted file - pass --old with the exact current value "
                  f"(check what decrypt_and_parse.py / a plain string search shows).")

    # find the end of the reserved buffer (next non-zero byte after the old
    # string's NUL terminator) so we know how much room we actually have
    end_of_old = idx + len(old_url) + 1  # include the NUL terminator
    scan = end_of_old
    while scan < len(pt) and pt[scan] == 0:
        scan += 1
    buffer_capacity = scan - idx  # bytes available from idx up to next real data

    if len(new_url) + 1 > buffer_capacity:
        sys.exit(f"New URL ({len(new_url)} bytes + NUL) does not fit in the "
                  f"available {buffer_capacity}-byte buffer - aborting.")

    # zero the whole old region first, then write the new NUL-terminated string
    region_len = end_of_old - idx  # same length as before, safe lower bound
    # but we can safely zero up to buffer_capacity since we confirmed it's unused
    for i in range(idx, idx + buffer_capacity):
        pt[i] = 0
    pt[idx:idx+len(new_url)] = new_url
    # NUL terminator already in place from the zeroing above

    new_f1 = sum(pt) & 0xFFFFFFFF
    new_ct = AES.new(KEY, AES.MODE_CBC, IV).encrypt(bytes(pt))
    assert len(new_ct) == clen, "ciphertext length changed unexpectedly - aborting"

    new_header = magic + struct.pack('<III', new_f1, f2, clen)
    new_file = new_header + new_ct

    open(path_out, 'wb').write(new_file)
    print(f"Replaced ACS URL:\n  old: {old_url.decode()}\n  new: {new_url.decode()}")
    print(f"(buffer capacity was {buffer_capacity} bytes, used {len(new_url)+1})")
    print(f"Wrote {len(new_file)} bytes to {path_out} (original was {len(raw)} bytes)")

if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('infile')
    ap.add_argument('outfile')
    ap.add_argument('new_url')
    ap.add_argument('--old', default=None, help='override the current URL to search for')
    args = ap.parse_args()
    old = args.old.encode() if args.old else DEFAULT_OLD_URL
    patch(args.infile, args.outfile, args.new_url.encode(), old)
