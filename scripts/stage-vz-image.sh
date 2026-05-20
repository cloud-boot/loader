#!/usr/bin/env bash
# stage-vz-image.sh — copy a GPT-partitioned raw cloud image, find
# its ESP, overlay BOOTAA64.EFI + a \cmdline file, write back.
#
# Used by the vfkit-loader-* Taskfile targets to feed Apple
# Virtualization.framework an image that boots through our loader.
#
# Usage:
#   stage-vz-image.sh SRC_RAW DST_RAW LOADER_EFI CMDLINE
#
# Args:
#   SRC_RAW     — read-only path to the upstream cloud image
#   DST_RAW     — writable per-run copy (overwritten each call)
#   LOADER_EFI  — path to the freshly-built BOOTAA64.EFI
#   CMDLINE     — kernel cmdline to write at the FAT root as \cmdline
#                  (loader picks it up when CloudBootCmdline EFI var
#                  is absent — fresh vfkit varstores have no
#                  variables, so this fallback always fires).

set -euo pipefail

SRC_RAW=${1:?missing SRC_RAW}
DST_RAW=${2:?missing DST_RAW}
LOADER_EFI=${3:?missing LOADER_EFI}
CMDLINE=${4:?missing CMDLINE}

ESP_GUID='C12A7328-F81F-11D2-BA4B-00A0C93EC93B'

# Probe the GPT for the ESP partition (type-GUID match). Print
# its first/last LBA so the caller can dd-extract / dd-replace it.
read -r FIRST LAST < <(python3 - "$SRC_RAW" <<EOF
import sys, struct
with open(sys.argv[1], 'rb') as f:
    f.seek(512); hdr = f.read(512)
    assert hdr[:8] == b'EFI PART', "not GPT"
    pte_lba = struct.unpack('<Q', hdr[72:80])[0]
    pte_count = struct.unpack('<I', hdr[80:84])[0]
    pte_size = struct.unpack('<I', hdr[84:88])[0]
    f.seek(pte_lba*512)
    for _ in range(pte_count):
        e = f.read(pte_size)
        if e[:16] == b'\x00'*16: continue
        d1, d2, d3 = struct.unpack('<IHH', e[:8])
        guid = f"{d1:08X}-{d2:04X}-{d3:04X}-{e[8:10].hex().upper()}-{e[10:16].hex().upper()}"
        if guid == "$ESP_GUID":
            first = struct.unpack('<Q', e[32:40])[0]
            last = struct.unpack('<Q', e[40:48])[0]
            print(first, last)
            break
    else:
        raise SystemExit("no ESP partition found in $SRC_RAW")
EOF
)
COUNT=$((LAST - FIRST + 1))

# Fresh working copy.
cp "$SRC_RAW" "$DST_RAW"

# Extract ESP, overlay, write back.
ESP_TMP="${DST_RAW}.esp"
dd if="$DST_RAW" of="$ESP_TMP" bs=512 skip="$FIRST" count="$COUNT" status=none
mcopy -o -i "$ESP_TMP" "$LOADER_EFI" ::EFI/BOOT/BOOTAA64.EFI

CMDLINE_TMP="${DST_RAW}.cmdline"
printf '%s' "$CMDLINE" > "$CMDLINE_TMP"
mcopy -o -i "$ESP_TMP" "$CMDLINE_TMP" ::cmdline

dd if="$ESP_TMP" of="$DST_RAW" bs=512 seek="$FIRST" count="$COUNT" conv=notrunc status=none

rm -f "$ESP_TMP" "$CMDLINE_TMP"

echo "ESP overlaid at LBA ${FIRST}..${LAST} (${COUNT} sectors) in $DST_RAW"
