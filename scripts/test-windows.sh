#!/usr/bin/env bash
# test-windows.sh — smoke-test the loader's CloudBootTarget=windows
# branch against a Microsoft Edge dev VM (the free path of least
# resistance to a bootable Windows image; see
# https://developer.microsoft.com/en-us/microsoft-edge/tools/vms/).
#
# The script:
#   1. Converts the VHDX to raw (qemu-img can read VHDX directly,
#      but having a raw on disk speeds up later runs).
#   2. Assumes BOOTX64.EFI (the cloud-boot loader for amd64) is
#      already built — typically by `task -d ../ link-amd64` from
#      go-coff/stub or by `cloud-boot build --arch amd64`.
#   3. Stages a 64 MiB FAT ESP holding:
#        \EFI\BOOT\BOOTX64.EFI
#      (no NVRAM seed file — we set CloudBootTarget=windows via the
#       OVMF UEFI shell BEFORE the cloud-boot binary is auto-loaded;
#       see efivar_seed_windows.nsh below.)
#   4. Boots qemu-system-x86_64 with OVMF, the ESP, the Windows
#      disk, and a serial log file.
#   5. Greps the serial log for the markers that confirm the
#      handoff worked: "LoadImage(DevicePath) OK" (our loader
#      handed the binary over) AND either "Windows Boot Manager"
#      or "Loading kernel..." (the chained Boot Manager started).
#
# Usage:
#
#   loader/scripts/test-windows.sh \
#     --vhdx ~/Downloads/MSEdge-Win11.vhdx \
#     --efi  ./BOOTX64.EFI
#
# Output:
#   - $WORKDIR/test.log     full QEMU serial transcript
#   - $WORKDIR/raw.img      converted disk (cached for re-runs)
#   - exit 0 on both markers seen, exit 1 otherwise

set -euo pipefail

VHDX="${VHDX:-}"
EFI="${EFI:-./BOOTX64.EFI}"
WORKDIR="${WORKDIR:-$(mktemp -d -t cloud-boot-win-test-XXXXXX)}"
TIMEOUT="${TIMEOUT:-240}" # 4 min
OVMF_CODE="${OVMF_CODE:-/opt/homebrew/Cellar/qemu/*/share/qemu/edk2-x86_64-code.fd}"
OVMF_VARS_TEMPLATE="${OVMF_VARS_TEMPLATE:-/opt/homebrew/Cellar/qemu/*/share/qemu/edk2-i386-vars.fd}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --vhdx)     VHDX="$2";     shift 2 ;;
    --efi)      EFI="$2";      shift 2 ;;
    --workdir)  WORKDIR="$2";  shift 2 ;;
    --timeout)  TIMEOUT="$2";  shift 2 ;;
    -h|--help)
      sed -n '1,40p' "$0" | grep -E '^# ?' | sed -E 's/^# ?//'
      exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

[[ -n "$VHDX" ]] || { echo "--vhdx <path> is required (download from https://developer.microsoft.com/en-us/microsoft-edge/tools/vms/)" >&2; exit 2; }
[[ -f "$VHDX" ]] || { echo "VHDX not found: $VHDX" >&2; exit 2; }
[[ -f "$EFI"  ]] || { echo "EFI binary not found: $EFI (build via 'task link-amd64' in go-coff/stub or 'cloud-boot build --arch amd64')" >&2; exit 2; }

mkdir -p "$WORKDIR"
cd "$WORKDIR"
echo "→ workdir: $WORKDIR"

# -------- 1. Convert VHDX → raw (cached) -----------------------------
if [[ ! -f raw.img ]]; then
  echo "→ converting VHDX → raw (one-time, ~30 GB)..."
  qemu-img convert -p -O raw "$VHDX" raw.img
else
  echo "  raw.img already present — skipping convert"
fi

# -------- 2. Stage the loader ESP ------------------------------------
mkdir -p esp/EFI/BOOT
cp "$EFI" esp/EFI/BOOT/BOOTX64.EFI

# Write a UEFI Shell script that sets CloudBootTarget=windows and
# chain-loads our BOOTX64.EFI. Saved as startup.nsh so the OVMF
# shell auto-runs it. (The cleanest way to seed the EFI variable
# from outside the running guest — alternative would be to write
# OVMF_VARS.fd offline with virt-efivars, which is more setup.)
cat > esp/startup.nsh <<'NSH'
@echo -off
echo Seeding CloudBootTarget=windows into NVRAM
setvar CloudBootTarget =L"windows" -nv -bs
echo Chain-loading FS0:\EFI\BOOT\BOOTX64.EFI
FS0:\EFI\BOOT\BOOTX64.EFI
NSH

# -------- 3. Resolve OVMF firmware -----------------------------------
OVMF_CODE="$(echo $OVMF_CODE | tr ' ' '\n' | grep -v '\*' | head -1)"
OVMF_VARS_TEMPLATE="$(echo $OVMF_VARS_TEMPLATE | tr ' ' '\n' | grep -v '\*' | head -1)"
[[ -f "$OVMF_CODE" ]] || { echo "OVMF_CODE not found at $OVMF_CODE" >&2; exit 1; }
cp "$OVMF_VARS_TEMPLATE" ovmf-vars.fd

# -------- 4. Boot QEMU ----------------------------------------------
# - virtio-blk for both the loader ESP and the Windows disk
# - serial mon:stdio (and file:test.log for the grep step)
# - -no-reboot so we don't loop forever if the guest panics
echo "→ launching qemu-system-x86_64 (timeout ${TIMEOUT}s)..."
echo "  (Ctrl-A x to abort if you're watching live)"

# Run under a Perl alarm so we cap the runtime even if the guest
# hangs at the Windows graphics blank-screen.
perl -e 'alarm '"$TIMEOUT"'; exec @ARGV' \
  qemu-system-x86_64 \
  -machine q35 \
  -cpu max \
  -m 4096 \
  -nographic \
  -no-reboot \
  -serial file:test.log \
  -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE" \
  -drive if=pflash,format=raw,file=ovmf-vars.fd \
  -drive file=fat:rw:esp,format=raw,if=none,id=esp \
  -device virtio-blk-pci,drive=esp,bootindex=1 \
  -drive file=raw.img,format=raw,if=none,id=win \
  -device virtio-blk-pci,drive=win \
  -netdev user,id=n0 \
  -device virtio-net-pci,netdev=n0 ; true

# -------- 5. Grep markers --------------------------------------------
echo "→ inspecting test.log for handoff markers..."
HAVE_LOAD=0
HAVE_BOOT=0
if grep -q 'LoadImage(DevicePath) OK' test.log; then HAVE_LOAD=1; fi
if grep -qE 'Windows Boot Manager|Loading kernel|winload|bootmgfw' test.log; then HAVE_BOOT=1; fi

if [[ "$HAVE_LOAD" == "1" && "$HAVE_BOOT" == "1" ]]; then
  echo "✓ handoff successful — loader did LoadImage(DevicePath) and Windows Boot Manager took over."
  exit 0
fi
echo "✗ handoff incomplete:"
echo "    LoadImage(DevicePath) OK : $HAVE_LOAD"
echo "    Boot Manager marker      : $HAVE_BOOT"
echo "  last 30 lines of test.log:"
tail -30 test.log | sed 's/^/    | /'
exit 1
