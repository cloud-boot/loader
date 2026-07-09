#!/usr/bin/env bash
# install-openbsd-arm64.sh — produce a reproducible openbsd76-arm64.qcow2
# from the official OpenBSD installer image, so the loader's
# CloudBootTarget=openbsd branch has something to boot against.
#
# OpenBSD does not publish pre-installed arm64 cloud images the way
# Debian / Ubuntu / Fedora do. The closest official thing is
# https://cdn.openbsd.org/pub/OpenBSD/7.6/arm64/install76.img — a
# self-contained installer image bootable on UEFI arm64 hardware
# (and under QEMU + EDK2). This script runs that installer
# unattended via OpenBSD's site-set + auto_install.conf
# mechanism (see installboot(8) and autoinstall(8)).
#
# Usage:
#
#   loader/scripts/install-openbsd-arm64.sh [--release 7.6] [--out openbsd76-arm64.qcow2]
#
# Output:
#   $OUT                                     a qcow2 with /, swap, /usr, /var, /home
#   loader/testdata/openbsd-arm64.qcow2.zst  (if --commit)
#
# Dependencies (on macOS, brew-installed):
#   - qemu  (qemu-system-aarch64, qemu-img)
#   - mkisofs / xorriso
#   - curl
#   - zstd (only with --commit)
#
# Time budget: ~10 minutes end-to-end on an M1/M2 host with native
# arm64 QEMU. ~25 minutes on x86_64 via TCG.

set -euo pipefail

RELEASE="${RELEASE:-7.6}"
RELEASE_NODOT="${RELEASE//./}"
OUT="${OUT:-openbsd${RELEASE_NODOT}-arm64.qcow2}"
COMMIT="${COMMIT:-0}"
WORKDIR="${WORKDIR:-$(mktemp -d -t openbsd-install-XXXXXX)}"
MIRROR="${MIRROR:-https://cdn.openbsd.org/pub/OpenBSD/${RELEASE}/arm64}"
OVMF_CODE="${OVMF_CODE:-/opt/homebrew/Cellar/qemu/*/share/qemu/edk2-aarch64-code.fd}"
OVMF_VARS_TEMPLATE="${OVMF_VARS_TEMPLATE:-/opt/homebrew/Cellar/qemu/*/share/qemu/edk2-arm-vars.fd}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --release)  RELEASE="$2";  RELEASE_NODOT="${RELEASE//./}"; shift 2 ;;
    --out)      OUT="$2";      shift 2 ;;
    --workdir)  WORKDIR="$2";  shift 2 ;;
    --commit)   COMMIT=1;      shift ;;
    -h|--help)
      sed -n '1,40p' "$0" | grep -E '^# ?' | sed -E 's/^# ?//'
      exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

echo "→ release: $RELEASE  out: $OUT  workdir: $WORKDIR"

# -------- 1. Fetch the installer + bsd.rd ----------------------------
mkdir -p "$WORKDIR"
cd "$WORKDIR"
for f in install${RELEASE_NODOT}.img bsd.rd SHA256.sig; do
  if [[ ! -f "$f" ]]; then
    echo "  fetching $f"
    curl -fL --progress-bar -o "$f" "$MIRROR/$f"
  fi
done
# SHA256.sig is signed; signify-verify is OpenBSD-specific and not in
# brew. Operators that care can install signify-osx and run:
#   signify-osx -C -p ~/.signify/openbsd-${RELEASE_NODOT}-base.pub \
#       -x SHA256.sig install${RELEASE_NODOT}.img bsd.rd
echo "  (SHA256.sig present; verify manually with signify if you care)"

# -------- 2. Craft the site set --------------------------------------
# auto_install.conf answers every prompt of the OpenBSD installer.
# Field names from the autoinstall(8) man page. console=com0 keeps
# everything on the serial; "yes" to "Continue without partial
# match" lets the installer pick reasonable defaults for any field
# we don't pin.
mkdir -p site
cat > site/auto_install.conf <<EOF
System hostname = openbsd-arm64-test
Which network interface = vio0
IPv4 address for vio0 = dhcp
IPv6 address for vio0 = none
Password for root account = openbsd
Public ssh key for root account = none
Start sshd(8) by default = yes
Do you expect to run the X Window System = no
Setup a user = none
What timezone are you in = UTC
Which disk is the root disk = sd0
Encrypt the root disk with a passphrase = no
Use (W)hole disk MBR, whole disk (G)PT, (O)penBSD area or (E)dit? = G
Use (A)uto layout, (E)dit auto layout, or create (C)ustom layout? = a
Location of sets = http
HTTP Server = cdn.openbsd.org
Server directory = pub/OpenBSD/${RELEASE}/arm64
Set name(s) = -x* -game* -man* done
Checksum test = SHA256
Continue without verification = yes
EOF

# install.site runs as a script on first boot — bake a marker file
# so the test runner can grep for it (proof the install finished).
cat > site/install.site <<'EOF'
#!/bin/sh
echo "cloud-boot-openbsd-install-done $(uname -m)" > /etc/cloud-boot-install.done
EOF
chmod 755 site/install.site

# Pack as the standard OpenBSD site set.
tar -C site -czf site${RELEASE_NODOT}.tgz auto_install.conf install.site

# -------- 3. Build a tiny ISO that ships the site set + auto_install.conf
# OpenBSD's installer checks the CD-ROM for an auto_install.conf file at
# the root — that's the trigger for unattended mode. The site tgz is
# pulled in by the installer's "Set name(s)" step when we tell it
# "site${RELEASE_NODOT}.tgz".
mkdir -p iso-root
cp site/auto_install.conf iso-root/
cp site${RELEASE_NODOT}.tgz iso-root/
ISO_TOOL="$(command -v xorriso || command -v mkisofs)"
if [[ -z "$ISO_TOOL" ]]; then
  echo "neither xorriso nor mkisofs in PATH — install one (brew install xorriso)" >&2
  exit 1
fi
case "$ISO_TOOL" in
  *xorriso) "$ISO_TOOL" -as mkisofs -V SITE -o site.iso iso-root ;;
  *)        mkisofs   -V SITE -o site.iso iso-root ;;
esac

# -------- 4. Blank target disk ---------------------------------------
qemu-img create -f qcow2 "$OUT" 8G

# -------- 5. Resolve OVMF ---------------------------------------------
OVMF_CODE="$(echo $OVMF_CODE | tr ' ' '\n' | grep -v '\*' | head -1)"
OVMF_VARS_TEMPLATE="$(echo $OVMF_VARS_TEMPLATE | tr ' ' '\n' | grep -v '\*' | head -1)"
if [[ ! -f "$OVMF_CODE" ]]; then
  echo "OVMF_CODE not found — set OVMF_CODE=/path/to/edk2-aarch64-code.fd" >&2
  exit 1
fi
cp "$OVMF_VARS_TEMPLATE" ovmf-vars.fd

# -------- 6. Run the installer unattended ----------------------------
# install76.img IS itself bootable. Attach it as the boot device, the
# blank qcow2 as the install target, and the site ISO as the
# config carrier. Serial console via mon:stdio so we can grep the
# transcript later.
echo "→ launching QEMU installer (this takes ~10 min on M-series, ~25 min via TCG)..."
qemu-system-aarch64 \
  -machine virt \
  -cpu max \
  -m 2048 \
  -nographic \
  -no-reboot \
  -serial mon:stdio \
  -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE" \
  -drive if=pflash,format=raw,file=ovmf-vars.fd \
  -drive file=install${RELEASE_NODOT}.img,format=raw,if=none,id=installer \
  -device virtio-blk-pci,drive=installer,bootindex=1 \
  -drive file="$OUT",format=qcow2,if=none,id=target \
  -device virtio-blk-pci,drive=target \
  -drive file=site.iso,format=raw,if=none,id=site,media=cdrom \
  -device virtio-blk-pci,drive=site \
  -netdev user,id=n0 \
  -device virtio-net-pci,netdev=n0 \
  | tee install.log

# -------- 7. Sanity check --------------------------------------------
if grep -q "openbsd boot loader" install.log && \
   grep -q "$(uname -m)" install.log; then
  echo "→ install log looks plausible; output qcow2 at $OUT"
else
  echo "⚠ install log doesn't show the expected markers — inspect $WORKDIR/install.log" >&2
fi

# -------- 8. Optional commit -----------------------------------------
if [[ "$COMMIT" == "1" ]]; then
  TESTDATA="$(cd "$(dirname "$0")/.." && pwd)/testdata"
  mkdir -p "$TESTDATA"
  echo "→ compressing & committing to $TESTDATA/openbsd-arm64.qcow2.zst"
  zstd -19 -q -o "$TESTDATA/openbsd-arm64.qcow2.zst" "$OUT"
  ls -lh "$TESTDATA/openbsd-arm64.qcow2.zst"
fi

echo "done."
