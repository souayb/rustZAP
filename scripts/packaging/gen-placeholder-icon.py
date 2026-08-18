#!/usr/bin/env python3
"""Generate a minimal placeholder PNG icon for packaging (no Pillow needed).

AppImage/.desktop integration requires SOME icon file to exist; this writes a
flat-color square with a simple accent so packaging isn't blocked on real
branding. Replace packaging/linux/appimage/rustzap.png with real artwork
whenever the project has one — this is explicitly a placeholder.
"""
import struct
import sys
import zlib

SIZE = 256
BG = (15, 23, 42)      # slate-900
ACCENT = (239, 68, 68)  # red-500, echoes the scanner's "critical" severity color
BORDER = 10


def pixel(x: int, y: int) -> tuple[int, int, int]:
    on_border = x < BORDER or y < BORDER or x >= SIZE - BORDER or y >= SIZE - BORDER
    return ACCENT if on_border else BG


def chunk(tag: bytes, data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data))


def main(out_path: str) -> None:
    raw = bytearray()
    for y in range(SIZE):
        raw.append(0)  # no filter
        for x in range(SIZE):
            raw.extend(pixel(x, y))
    ihdr = struct.pack(">IIBBBBB", SIZE, SIZE, 8, 2, 0, 0, 0)
    png = b"\x89PNG\r\n\x1a\n"
    png += chunk(b"IHDR", ihdr)
    png += chunk(b"IDAT", zlib.compress(bytes(raw), 9))
    png += chunk(b"IEND", b"")
    with open(out_path, "wb") as f:
        f.write(png)
    print(f"wrote {out_path} ({len(png)} bytes)")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "rustzap.png")
