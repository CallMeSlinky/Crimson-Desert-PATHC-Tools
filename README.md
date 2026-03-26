# Crimson Desert PATHC Tools

Guide for modifying and inspecting Crimson Desert `.pathc` files.

## PATHC Repacker (`pathc_repack.py`)

Adds a folder of `.dds` files into a `.pathc` archive.

### Usage

```bash
python pathc_repack.py 0.pathc "./custom_textures"
```

- Automatically updates or adds entries.
- Paths are built relative to your asset folder (e.g., `./custom_textures/character/texture/cd_phm_00_head_0001_macduff.dds` -> `/character/texture/cd_phm_00_head_0001_macduff.dds`).

---

## PATHC Parser (`pathc_parse.py`)

Inspects `.pathc` headers and mappings.

### Usage (List All)

Prints statistics and every mapping entry in the file.

```bash
python pathc_parse.py 0.pathc
```

### Usage (Lookup)

Finds the DDS index and metadata for a specific virtual path.

```bash
python pathc_parse.py 0.pathc --lookup "/character/texture/cd_phm_00_head_0001_macduff.dds"
```

---

## Technical Details

### Hashing Algorithm

The game uses Bob Jenkins' **`hashlittle`** (lookup3) algorithm with a custom initial value of **`0x000C5EDE`**. Virtual paths are normalized to lowercase before hashing. **Note: The file extension (e.g. `.dds`) MUST be included in the path.**

### Metadata (m1-m4)

The mapping metadata fields store the byte sizes of the first four mipmap levels of the texture. The repack tool now calculates these automatically from your DDS files to ensure they load correctly in-game.

### File Structure

1.  **DDS Templates**: Stores a table of 128-byte or 148-byte (DX10) DDS headers.
2.  **Hash Table**: An array of sorted 32-bit CRC-like hashes for binary search.
3.  **Map Entries**: Each 20-byte entry links a path hash to a DDS template index.
4.  **Collision Blob**: Stores original path strings and indices only for cases where two different paths result in the same hash.
