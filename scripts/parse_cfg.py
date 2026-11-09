#!/usr/bin/env python3
"""
Parser for decrypted Askey/Jio ODU XAPConfig .cfg files.

Each file is a table of fixed 80-byte records:
  offset 0:  u16 LE   record index
  offset 2:  u16 LE   type tag (0x9856 for valid records; anything else = end of
                       the clean fixed-width table, rest is variable-length data)
  offset 4:  40 bytes  NUL-padded ASCII record name (RECID_...)
  offset 72: u32 LE   value type (2 = inline ASCII string stored in next 4 bytes,
                       anything else = plain little-endian integer)
  offset 76: 4 bytes  the value itself

Usage: python3 parse_cfg.py decrypted/cfg/engtool.cfg
"""
import struct, sys

RECLEN = 80
TAG = 0x9856

def parse(path):
    data = open(path, 'rb').read()
    n = len(data) // RECLEN
    rows = []
    for i in range(n):
        rec = data[i*RECLEN:(i+1)*RECLEN]
        idx, tag = struct.unpack_from('<HH', rec, 0)
        if tag != TAG:
            break  # end of clean fixed-width table
        name = rec[4:44].split(b'\x00')[0].decode('ascii', errors='replace')
        vtype, raw = struct.unpack_from('<I4s', rec, 72)
        if vtype == 2:
            val = raw.split(b'\x00')[0].decode('ascii', errors='replace')
        else:
            val = struct.unpack('<I', raw)[0]
        rows.append((idx, name, vtype, val))
    leftover = data[n_parsed_bytes(rows):] if rows else data
    return rows, data[len(rows)*RECLEN:]

def n_parsed_bytes(rows):
    return len(rows) * RECLEN

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("usage: parse_cfg.py <decrypted .cfg file> [...]")
        sys.exit(1)
    for path in sys.argv[1:]:
        print(f"\n=== {path} ===")
        rows, leftover = parse(path)
        for idx, name, vtype, val in rows:
            print(f"  idx={idx:3d}  type={vtype:<3d}  {name:40s} = {val}")
        if leftover:
            print(f"  [{len(leftover)} bytes of variable-length data follow - not auto-parsed]")
