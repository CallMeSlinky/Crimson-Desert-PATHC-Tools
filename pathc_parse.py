"""
PATHC parser for Crimson Desert meta/0.pathc files.
"""

from __future__ import annotations

import argparse
import bisect
import struct
from dataclasses import dataclass
from pathlib import Path


HASH_INITVAL = 0x000C5EDE


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
class DdsTemplate:
    index: int
    width: int
    height: int
    mip_count: int
    format_label: str


@dataclass(slots=True)
class MapEntry:
    key_hash: int
    selector: int
    m1: int
    m2: int
    m3: int
    m4: int

    @property
    def direct_dds_index(self) -> int | None:
        high = (self.selector >> 16) & 0xFFFF
        low = self.selector & 0xFFFF
        if high == 0xFFFF:
            return low
        return None

    @property
    def collision_range(self) -> tuple[int, int] | None:
        high = (self.selector >> 16) & 0xFFFF
        low = self.selector & 0xFFFF
        if low != 0xFFFF:
            return None
        start = high & 0xFF
        end = (high >> 8) & 0xFF
        if end < start:
            return None
        return start, end


@dataclass(slots=True)
class CollisionPath:
    path_offset: int
    dds_index: int
    m1: int
    m2: int
    m3: int
    m4: int
    path: str
    path_hash: int


@dataclass(slots=True)
class PathcFile:
    header: PathcHeader
    dds_templates: list[DdsTemplate]
    key_hashes: list[int]
    map_entries: list[MapEntry]
    collision_paths: list[CollisionPath]


def _read_c_string(data: bytes, offset: int) -> str:
    if offset < 0 or offset >= len(data):
        return ""
    end = data.find(b"\x00", offset)
    if end < 0:
        end = len(data)
    return data[offset:end].decode("utf-8", errors="replace")


def parse_pathc(pathc_path: str | Path) -> PathcFile:
    raw = Path(pathc_path).read_bytes()
    if len(raw) < 28:
        raise ValueError("File is too small to be a valid .pathc.")

    header = PathcHeader(*struct.unpack_from("<7I", raw, 0))

    dds_table_off = 0x1C
    dds_table_size = header.dds_record_size * header.dds_record_count
    hash_table_off = dds_table_off + dds_table_size
    map_table_off = hash_table_off + header.hash_count * 4
    map_table_size = header.hash_count * 20
    collision_table_off = map_table_off + map_table_size
    collision_table_size = header.collision_path_count * 24
    collision_blob_off = collision_table_off + collision_table_size
    collision_blob_end = collision_blob_off + header.collision_blob_size

    if collision_blob_end > len(raw):
        raise ValueError("Header describes a collision blob beyond file size.")

    dds_templates: list[DdsTemplate] = []
    for index in range(header.dds_record_count):
        rec_off = dds_table_off + index * header.dds_record_size
        if rec_off + header.dds_record_size > len(raw):
            raise ValueError("DDS template table is truncated.")
        if raw[rec_off : rec_off + 4] != b"DDS ":
            raise ValueError(f"DDS magic mismatch at template #{index} (0x{rec_off:X}).")
        _size, _flags, height, width, _pitch_or_linear, _depth, mip_count = struct.unpack_from("<7I", raw, rec_off + 4)
        fourcc = raw[rec_off + 84 : rec_off + 88]
        if fourcc == b"DX10":
            dxgi_format = struct.unpack_from("<I", raw, rec_off + 128)[0]
            format_label = f"DX10/{dxgi_format}"
        else:
            format_label = fourcc.decode("ascii", errors="replace").rstrip("\x00") or "UNKNOWN"
        dds_templates.append(
            DdsTemplate(
                index=index,
                width=width,
                height=height,
                mip_count=mip_count,
                format_label=format_label,
            )
        )

    key_hashes = list(struct.unpack_from(f"<{header.hash_count}I", raw, hash_table_off))

    map_entries: list[MapEntry] = []
    for i in range(header.hash_count):
        selector, m1, m2, m3, m4 = struct.unpack_from("<IIIII", raw, map_table_off + i * 20)
        map_entries.append(MapEntry(key_hash=key_hashes[i], selector=selector, m1=m1, m2=m2, m3=m3, m4=m4))

    collision_blob = raw[collision_blob_off:collision_blob_end]
    collision_paths: list[CollisionPath] = []
    for i in range(header.collision_path_count):
        path_offset, dds_index, m1, m2, m3, m4 = struct.unpack_from("<6I", raw, collision_table_off + i * 24)
        path = _read_c_string(collision_blob, path_offset)
        path_hash = hashlittle(path.lower().encode("utf-8"), HASH_INITVAL) if path else 0
        collision_paths.append(
            CollisionPath(
                path_offset=path_offset,
                dds_index=dds_index,
                m1=m1,
                m2=m2,
                m3=m3,
                m4=m4,
                path=path,
                path_hash=path_hash,
            )
        )

    return PathcFile(
        header=header,
        dds_templates=dds_templates,
        key_hashes=key_hashes,
        map_entries=map_entries,
        collision_paths=collision_paths,
    )


def find_path(pathc: PathcFile, virtual_path: str) -> tuple[int, MapEntry] | None:
    path = virtual_path.replace("\\", "/").strip().lstrip("/").strip("/").lower()
    normalized = "/" + path
    key = hashlittle(normalized.encode("utf-8"), HASH_INITVAL)
    index = bisect.bisect_left(pathc.key_hashes, key)
    if index >= len(pathc.key_hashes) or pathc.key_hashes[index] != key:
        return None
    return index, pathc.map_entries[index]


def _format_stats(pathc: PathcFile) -> str:
    direct = sum(1 for entry in pathc.map_entries if entry.direct_dds_index is not None)
    collision = sum(1 for entry in pathc.map_entries if entry.collision_range is not None)
    unknown = len(pathc.map_entries) - direct - collision
    lines = [
        f"DDS templates:       {len(pathc.dds_templates):,}",
        f"Path hash entries:   {len(pathc.key_hashes):,}",
        f"Collision paths:     {len(pathc.collision_paths):,}",
        f"Direct mappings:     {direct:,}",
        f"Collision mappings:  {collision:,}",
        f"Unknown mappings:    {unknown:,}",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Parse Crimson Desert meta/0.pathc")
    parser.add_argument("pathc", help="Path to 0.pathc")
    parser.add_argument("--lookup", action="append", default=[], help="Lookup virtual path (can be repeated)")
    args = parser.parse_args()

    parsed = parse_pathc(args.pathc)

    if not args.lookup:
        print(_format_stats(parsed))
        print("\nAll Mapping Entries (Note: Original paths are not stored for direct mappings, only hashes):")
        for i, entry in enumerate(parsed.map_entries):
            direct = entry.direct_dds_index
            if direct is not None:
                t_str = "UNKNOWN"
                if 0 <= direct < len(parsed.dds_templates):
                    t = parsed.dds_templates[direct]
                    t_str = f"{t.width}x{t.height} {t.format_label}"
                
                print(f"[{i:6d}] hash=0x{entry.key_hash:08X} dds={direct:3d} ({t_str}) m=({entry.m1:#x},{entry.m2:#x},{entry.m3:#x},{entry.m4:#x})")
            else:
                collision_range = entry.collision_range
                if collision_range:
                    start, end = collision_range
                    print(f"[{i:6d}] hash=0x{entry.key_hash:08X} collision_range=[{start}:{end}]")
                    for candidate in parsed.collision_paths[start:end]:
                        t_str = "UNKNOWN"
                        if 0 <= candidate.dds_index < len(parsed.dds_templates):
                            t = parsed.dds_templates[candidate.dds_index]
                            t_str = f"{t.width}x{t.height} {t.format_label}"
                        print(f"         - dds={candidate.dds_index:3d} ({t_str}) path={candidate.path}")
                else:
                    print(f"[{i:6d}] hash=0x{entry.key_hash:08X} selector=0x{entry.selector:08X} (unknown)")

    for lookup in args.lookup:
        print(f"\nLookup: {lookup}")
        hit = find_path(parsed, lookup)
        if hit is None:
            path = lookup.replace("\\", "/").strip().lstrip("/").strip("/").lower()
            normalized = "/" + path
            key = hashlittle(normalized.encode("utf-8"), HASH_INITVAL)
            print(f"  Not found (hash=0x{key:08X})")
            continue
        index, entry = hit
        print(f"  key_index={index} key_hash=0x{entry.key_hash:08X}")
        direct = entry.direct_dds_index
        if direct is not None:
            template = parsed.dds_templates[direct] if 0 <= direct < len(parsed.dds_templates) else None
            if template is None:
                print(f"  direct_dds_index={direct} (out of range)")
            else:
                print(
                    f"  direct_dds_index={direct} "
                    f"{template.width}x{template.height} mip={template.mip_count} fmt={template.format_label}"
                )
        else:
            collision_range = entry.collision_range
            if collision_range is None:
                print(f"  selector=0x{entry.selector:08X} (unknown mapping shape)")
            else:
                start, end = collision_range
                print(f"  collision_range=[{start}:{end}]")
                for candidate in parsed.collision_paths[start:end]:
                    template = parsed.dds_templates[candidate.dds_index] if 0 <= candidate.dds_index < len(parsed.dds_templates) else None
                    if template is None:
                        print(f"    - dds={candidate.dds_index} (out of range) path={candidate.path}")
                    else:
                        print(
                            f"    - dds={candidate.dds_index} "
                            f"{template.width}x{template.height} mip={template.mip_count} fmt={template.format_label} "
                            f"path={candidate.path}"
                        )
        print(f"  metadata m=({entry.m1:#x},{entry.m2:#x},{entry.m3:#x},{entry.m4:#x})")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
