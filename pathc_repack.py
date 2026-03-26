#!/usr/bin/env python3
"""
PATHC Repack Tool for Crimson Desert.
Handles adding and updating entries in .pathc files.
"""

from __future__ import annotations

import argparse
import bisect
import struct
import io
import os
from dataclasses import dataclass
from pathlib import Path

HASH_INITVAL = 0x000C5EDE

_DDS_BC_BLOCK_BYTES_BY_FOURCC = {
    b"DXT1": 8, b"ATI1": 8, b"BC4U": 8, b"BC4S": 8,
    b"DXT3": 16, b"DXT5": 16, b"ATI2": 16, b"BC5U": 16, b"BC5S": 16
}
_DDS_BC_BLOCK_BYTES_BY_DXGI = {
    70: 8, 71: 8, 72: 8, 73: 16, 74: 16, 75: 16, 76: 16, 77: 16, 78: 16,
    79: 8, 80: 8, 81: 8, 82: 16, 83: 16, 84: 16, 94: 16, 95: 16, 96: 16,
    97: 16, 98: 16, 99: 16
}
_DDS_DXGI_BITS_PER_PIXEL = {10: 64, 24: 32, 28: 32, 61: 8}

def get_dds_metadata(data: bytes) -> tuple[int, int, int, int]:
    if len(data) < 128 or data[:4] != b"DDS ":
        return (0, 0, 0, 0)
    
    _hsize, _flags, height, width, pitch, _depth, mips = struct.unpack_from("<7I", data, 4)
    mips = max(1, mips)
    _pf_size, pf_flags, pf_fourcc, pf_rgb_bits = struct.unpack_from("<4I", data, 76)
    fourcc = struct.pack("<I", pf_fourcc)
    
    dxgi = None
    if fourcc == b"DX10" and len(data) >= 148:
        dxgi = struct.unpack_from("<I", data, 128)[0]
    
    block_bytes = _DDS_BC_BLOCK_BYTES_BY_FOURCC.get(fourcc)
    if block_bytes is None and dxgi is not None:
        block_bytes = _DDS_BC_BLOCK_BYTES_BY_DXGI.get(dxgi)
    
    bpp = 0
    if block_bytes is None:
        if dxgi is not None: bpp = _DDS_DXGI_BITS_PER_PIXEL.get(dxgi, 0)
        if bpp == 0 and (pf_flags & 0x40): bpp = pf_rgb_bits
    
    sizes = []
    curr_w, curr_h = max(1, width), max(1, height)
    for i in range(min(4, mips)):
        if block_bytes:
            size = max(1, (curr_w + 3) // 4) * max(1, (curr_h + 3) // 4) * block_bytes
        elif bpp > 0:
            size = ((curr_w * bpp + 7) // 8) * curr_h
        elif i == 0 and pitch > 0:
            size = pitch
        else:
            size = 0
        sizes.append(size & 0xFFFFFFFF)
        curr_w, curr_h = max(1, curr_w // 2), max(1, curr_h // 2)
    
    while len(sizes) < 4: sizes.append(0)
    return tuple(sizes)

def _rot32(value: int, bits: int) -> int:
    return ((value << bits) | (value >> (32 - bits))) & 0xFFFFFFFF

def _add32(left: int, right: int) -> int:
    return (left + right) & 0xFFFFFFFF

def _sub32(left: int, right: int) -> int:
    return (left - right) & 0xFFFFFFFF

def hashlittle(data: bytes, initval: int = 0) -> int:
    length = len(data)
    remaining = length
    a = b = c = _add32(0xDEADBEEF + length, initval)
    offset = 0

    while remaining > 12:
        a = _add32(a, struct.unpack_from("<I", data, offset)[0])
        b = _add32(b, struct.unpack_from("<I", data, offset + 4)[0])
        c = _add32(c, struct.unpack_from("<I", data, offset + 8)[0])
        a = _sub32(a, c)
        a ^= _rot32(c, 4)
        c = _add32(c, b)
        b = _sub32(b, a)
        b ^= _rot32(a, 6)
        a = _add32(a, c)
        c = _sub32(c, b)
        c ^= _rot32(b, 8)
        b = _add32(b, a)
        a = _sub32(a, c)
        a ^= _rot32(c, 16)
        c = _add32(c, b)
        b = _sub32(b, a)
        b ^= _rot32(a, 19)
        a = _add32(a, c)
        c = _sub32(c, b)
        c ^= _rot32(b, 4)
        b = _add32(b, a)
        offset += 12
        remaining -= 12

    tail = data[offset:] + (b"\x00" * 12)
    if remaining >= 12:
        c = _add32(c, struct.unpack_from("<I", tail, 8)[0])
    elif remaining >= 9:
        c = _add32(c, struct.unpack_from("<I", tail, 8)[0] & (0xFFFFFFFF >> (8 * (12 - remaining))))
    if remaining >= 8:
        b = _add32(b, struct.unpack_from("<I", tail, 4)[0])
    elif remaining >= 5:
        b = _add32(b, struct.unpack_from("<I", tail, 4)[0] & (0xFFFFFFFF >> (8 * (8 - remaining))))
    if remaining >= 4:
        a = _add32(a, struct.unpack_from("<I", tail, 0)[0])
    elif remaining >= 1:
        a = _add32(a, struct.unpack_from("<I", tail, 0)[0] & (0xFFFFFFFF >> (8 * (4 - remaining))))
    elif remaining == 0:
        return c

    c ^= b
    c = _sub32(c, _rot32(b, 14))
    a ^= c
    a = _sub32(a, _rot32(c, 11))
    b ^= a
    b = _sub32(b, _rot32(a, 25))
    c ^= b
    c = _sub32(c, _rot32(b, 16))
    a ^= c
    a = _sub32(a, _rot32(c, 4))
    b ^= a
    b = _sub32(b, _rot32(a, 14))
    c ^= b
    c = _sub32(c, _rot32(b, 24))
    return c

@dataclass(slots=True)
class PathcHeader:
    unknown0: int
    unknown1: int
    dds_record_size: int
    dds_record_count: int
    hash_count: int
    collision_path_count: int
    collision_blob_size: int

@dataclass(slots=True)
class PathcMapEntry:
    selector: int
    m1: int
    m2: int
    m3: int
    m4: int

@dataclass(slots=True)
class PathcCollisionEntry:
    path_offset: int
    dds_index: int
    m1: int
    m2: int
    m3: int
    m4: int
    path: str = ""

@dataclass(slots=True)
class PathcFile:
    header: PathcHeader
    dds_records: list[bytes]
    key_hashes: list[int]
    map_entries: list[PathcMapEntry]
    collision_entries: list[PathcCollisionEntry]

def read_pathc(path: Path) -> PathcFile:
    raw = path.read_bytes()
    if len(raw) < 0x1C:
        raise ValueError(f"{path} is too small to be a valid .pathc file.")
    header = PathcHeader(*struct.unpack_from("<7I", raw, 0))
    
    dds_table_off = 0x1C
    dds_table_size = header.dds_record_size * header.dds_record_count
    hash_table_off = dds_table_off + dds_table_size
    hash_table_size = header.hash_count * 4
    map_table_off = hash_table_off + hash_table_size
    map_table_size = header.hash_count * 20
    collision_table_off = map_table_off + map_table_size
    collision_table_size = header.collision_path_count * 24
    collision_blob_off = collision_table_off + collision_table_size
    collision_blob_end = collision_blob_off + header.collision_blob_size

    dds_records = []
    for i in range(header.dds_record_count):
        off = dds_table_off + i * header.dds_record_size
        dds_records.append(raw[off : off + header.dds_record_size])

    key_hashes = list(struct.unpack_from(f"<{header.hash_count}I", raw, hash_table_off))

    map_entries = []
    for i in range(header.hash_count):
        selector, m1, m2, m3, m4 = struct.unpack_from("<IIIII", raw, map_table_off + i * 20)
        map_entries.append(PathcMapEntry(selector, m1, m2, m3, m4))

    collision_entries = []
    blob = raw[collision_blob_off:collision_blob_end]
    for i in range(header.collision_path_count):
        poff, dds_idx, m1, m2, m3, m4 = struct.unpack_from("<6I", raw, collision_table_off + i * 24)
        end = blob.find(b"\x00", poff)
        path_str = blob[poff:end].decode("utf-8", errors="replace") if end != -1 else ""
        collision_entries.append(PathcCollisionEntry(poff, dds_idx, m1, m2, m3, m4, path_str))

    return PathcFile(header, dds_records, key_hashes, map_entries, collision_entries)

def serialize_pathc(pathc: PathcFile) -> bytes:
    collision_blob = bytearray()
    collision_rows = []
    for entry in pathc.collision_entries:
        path_bytes = entry.path.encode("utf-8") + b"\x00"
        poff = len(collision_blob)
        collision_blob.extend(path_bytes)
        collision_rows.append(struct.pack("<6I", poff, entry.dds_index, entry.m1, entry.m2, entry.m3, entry.m4))
    
    pathc.header.dds_record_count = len(pathc.dds_records)
    pathc.header.hash_count = len(pathc.key_hashes)
    pathc.header.collision_path_count = len(pathc.collision_entries)
    pathc.header.collision_blob_size = len(collision_blob)

    output = io.BytesIO()
    output.write(struct.pack("<7I", 
                             pathc.header.unknown0, pathc.header.unknown1, 
                             pathc.header.dds_record_size, pathc.header.dds_record_count, 
                             pathc.header.hash_count, pathc.header.collision_path_count, 
                             pathc.header.collision_blob_size))
    
    for rec in pathc.dds_records:
        output.write(rec)
    
    if pathc.key_hashes:
        output.write(struct.pack(f"<{len(pathc.key_hashes)}I", *pathc.key_hashes))
    
    for entry in pathc.map_entries:
        output.write(struct.pack("<IIIII", entry.selector, entry.m1, entry.m2, entry.m3, entry.m4))
    
    for row in collision_rows:
        output.write(row)
    
    output.write(collision_blob)
    return output.getvalue()

def normalize_path(path_str: str) -> str:
    path = path_str.replace("\\", "/").strip().lstrip("/").strip("/")
    return "/" + path

def get_path_hash(path_str: str) -> int:
    return hashlittle(normalize_path(path_str).lower().encode("utf-8"), HASH_INITVAL)

def create_dds_record(dds_path: Path, record_size: int) -> bytes:
    data = dds_path.read_bytes()
    if not data.startswith(b"DDS "):
        raise ValueError("Not a valid DDS file")
    
    record = bytearray(record_size)
    to_copy = min(len(data), record_size)
    record[:to_copy] = data[:to_copy]
    return bytes(record)

def update_entry(pathc: PathcFile, virtual_path: str, dds_index: int, m: tuple[int, int, int, int] = (0,0,0,0)):
    target_hash = get_path_hash(virtual_path)
    idx = bisect.bisect_left(pathc.key_hashes, target_hash)
    
    selector = 0xFFFF0000 | (dds_index & 0xFFFF)
    
    if idx < len(pathc.key_hashes) and pathc.key_hashes[idx] == target_hash:
        pathc.map_entries[idx].selector = selector
        pathc.map_entries[idx].m1, pathc.map_entries[idx].m2, pathc.map_entries[idx].m3, pathc.map_entries[idx].m4 = m
    else:
        new_entry = PathcMapEntry(selector, *m)
        pathc.key_hashes.insert(idx, target_hash)
        pathc.map_entries.insert(idx, new_entry)

def add_folder_recursive(pathc: PathcFile, folder_path: Path):
    """Recursively add all .dds files from a folder, mapping them relative to the folder itself."""
    if not folder_path.is_dir():
        print(f"Error: {folder_path} is not a directory.")
        return

    count = 0
    for file_path in folder_path.rglob("*.dds"):
        rel_path = file_path.relative_to(folder_path)
        vpath = "/" + rel_path.as_posix()

        try:
            dds_data = file_path.read_bytes()
            dds_rec = create_dds_record(file_path, pathc.header.dds_record_size)
            m = get_dds_metadata(dds_data)
            
            try:
                dds_idx = pathc.dds_records.index(dds_rec)
            except ValueError:
                pathc.dds_records.append(dds_rec)
                dds_idx = len(pathc.dds_records) - 1
            
            update_entry(pathc, vpath, dds_idx, m)
            count += 1
            print(f"Processed: {vpath} (DDS index {dds_idx}, m={m})")
        except Exception as e:
            print(f"Failed to process {file_path}: {e}")
    
    print(f"Successfully processed {count} textures from {folder_path.name}.")

def main():
    parser = argparse.ArgumentParser(description="Crimson Desert .pathc Repacker")
    parser.add_argument("pathc_file", help="The .pathc file to modify (in-place)")
    parser.add_argument("folder_path", help="The folder containing .dds asset files")
    
    args = parser.parse_args()
    
    pathc_path = Path(args.pathc_file)
    folder_path = Path(args.folder_path)

    if not pathc_path.exists():
        print(f"Error: {args.pathc_file} does not exist.")
        return
    if not folder_path.exists() or not folder_path.is_dir():
        print(f"Error: {args.folder_path} is not a directory.")
        return

    print(f"Loading {pathc_path}...")
    pathc = read_pathc(pathc_path)
    
    add_folder_recursive(pathc, folder_path)

    print(f"Saving {pathc_path}...")
    output_bytes = serialize_pathc(pathc)
    pathc_path.write_bytes(output_bytes)
    print("Done.")

if __name__ == "__main__":
    main()
