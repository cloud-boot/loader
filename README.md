# cloud-boot/loader

Pure-UEFI variant of cloud-boot — a TinyGo PE/COFF UEFI application
that finds the distro kernel at runtime and hands off via
`BootServices.LoadImage` + `StartImage`, with NO Linux bootstrap
kernel in between. The existing `init/` + `uki/` pipeline (bootstrap
kernel + kexec) is unchanged; this lives in parallel.

A single `BOOTAA64.EFI` binary boots every major Linux distro family
end-to-end from an unmodified cloud disk image — under both QEMU/OVMF
and **real Apple Virtualization.framework** (via vfkit, the project's
original target since Apple VZ traps `kexec_file_load` on arm64).

| Family | Filesystem layout | QEMU/OVMF | Apple VZ |
| --- | --- | --- | --- |
| Debian Trixie | ext4 rootfs (/boot inside) | ✓ login prompt | ✓ login prompt + shutdown |
| Ubuntu Noble 24.04 | ext4 rootfs + gzip-compressed vmlinuz | ✓ systemd 255.4 running | — |
| Fedora 41 | ext4 /boot + btrfs / | ✓ Basic System | — |
| AlmaLinux 9 / RHEL family | xfs /boot + xfs / | ✓ systemd target | — |
| openSUSE Leap Micro 6.2 | btrfs (default-subvol snapshot) | ✓ JeOS Firstboot | — |
| Alpine Linux 3.21 | ext4 rootfs (AWS variant) | ✓ cloud-init started | ✓ cloud-init started |

amd64 cross-compiles clean (BOOTX64.EFI), untested in this round.

Each filesystem driver (ext4, xfs, btrfs) sits in its own file under
`cmd/efi-loader/`; the cascade in [`main.go`](cmd/efi-loader/main.go)
tries them in order after the FAT-volume UKI lookup misses. Inside
the btrfs path we follow the default-subvol indirection, walk
arbitrary-depth B-trees with key-range pruning, and resolve relative
symlinks (`/boot/Image-* → /usr/lib/modules/<ver>/<file>` on openSUSE).
A `CloudBootTarget=<fs>-direct` EFI var (`ext4-direct`, `xfs-direct`,
`btrfs-direct`) skips the earlier rungs when the host knows the
layout.

## Why

Apple Virtualization.framework on arm64 traps the MMU-off + EL1 jump
that Linux's `kexec_file_load` relies on, so cloud-boot's
"bootstrap kernel → fetch → kexec → distro" pipeline doesn't survive
the kexec step under Apple VZ. The pure-UEFI variant stays in
`BootServices` context throughout: fetch over UEFI HTTP, `LoadImage`
the PE-shaped Linux EFI stub of the distro kernel, `StartImage` —
the same firmware-mediated transition every distro already uses on
first boot, which Apple VZ supports natively.

Same approach also lifts the design from "Linux required" to "any
EFI-shaped binary loadable" — a riscv64 EDK2 or any future
non-Linux EFI image works the same way.

## Phasing

| Phase | Scope | Status |
| --- | --- | --- |
| 0 | Probe `EFI_HTTP_PROTOCOL` / `EFI_TCP4_PROTOCOL` availability under Apple VZ + OVMF (arm64 + amd64) | done — see [Phase 0 result](#phase-0-result) |
| 1 | TinyGo OCI v2 manifest+blob client over UEFI HTTP. Minimal JSON parse. | blocked by Phase 0 finding |
| 2 | `LoadImage(SourceBuffer = fetched bytes)` + `StartImage` of distro kernel | — |
| 3 | Dynamic `EFI_LOAD_FILE2_PROTOCOL` initrd from fetched bytes; cmdline propagation from plan | — |
| 4 | DNS-SRV via `EFI_DNS4_PROTOCOL`; multi-endpoint failover; minimal cosign | — |
| 5a | Disk-mode minimal: SFS walk, open `\EFI\Linux\cloud-boot.efi`, `LoadImage` + `StartImage` | done — see [Phase 5a result](#phase-5a-result) |
| 5b | Cmdline propagation: EFI variable (`CloudBootCmdline`) primary, `\cmdline` file fallback; `loaded-image->load_options` patched on the child | done — see [Phase 5b result](#phase-5b-result) |
| 5c | Multiple candidate UKIs, fallback order, `CloudBootTarget` selector | done |
| 5d | Boot the kernel inside an *unmodified* Linux cloud distribution image: walk BlockIO, read ext4 directly, locate `/boot/vmlinuz-*` + `/boot/initrd.img-*`, `EFI_LOAD_FILE2_PROTOCOL` for initrd, `LoadImage` + `StartImage` | done — see [Phase 5d result](#phase-5d-result) |
| 5e | xfs cloud-disk path: same handoff but reads RHEL-family layouts (xfs /boot + xfs /). Short-form + block-form directories, bit-packed `xfs_bmbt_rec` extents, v5 inode core. AlmaLinux 9. | done |
| 5f | btrfs cloud-disk path: sys_chunk_array bootstrap + chunk-tree extension; default-subvol indirection; depth-N B-tree walker with key-range pruning; INODE_ITEM mode dispatch; inline-extent symlink resolution. openSUSE Leap Micro 6.2. | done |
| 5g | Ubuntu Noble: same ext4 walker, but the cloud kernel is gzip-wrapped (`1F 8B 08 ...`). In-loader RFC 1951/1952 DEFLATE/gzip inflate into a fresh AllocatePool buffer before LoadImage. | done |
| 5h | Alpine Linux 3.21 AWS cloud image: existing ext4 walker, no code changes. Mostly a cmdline tweak (`modules=...` for the initramfs init script + `root=/dev/vda2`, since Alpine's GPT puts the ESP at partition 1). | done |
| 6 | Real Apple Virtualization.framework via vfkit (the project's actual target hypervisor): CloudBootMark non-volatile EFI variable as proof-of-execution side-channel since SimpleTextOutput goes to framebuffer only under Apple's UEFI; `\cmdline` file read in the cloud-disk paths (was previously gated on a UKI being found). Debian boots to login prompt and shuts down cleanly. | done |
| 7 | NixOS arm64: systemd-boot `/loader/entries/*.conf` parsing → kernel + initrd path lookup at content-addressed `/EFI/nixos/<hash>-{bzImage.efi,initrd}`. Code path TBD — no obvious source of prebuilt NixOS arm64 cloud disk images (Hydra builds exist but require `nix` to download; cache.nixos.org doesn't carry the AMI). | future |
| 8 | LVM2: PV label parse + text-format VG metadata + segment-table LV→physical resolver. Mostly a code addition — most cloud images use plain partitions, not LVM. Construction of a test image requires Linux-side `lvm2` tooling. | future |

## Phase 0 result

Probed under QEMU + Homebrew prebuilt OVMF (edk2-stable202408)
on both arm64 (`edk2-aarch64-code.fd`) and amd64
(`edk2-x86_64-code.fd`):

| Protocol | arm64 | amd64 |
| --- | --- | --- |
| `EFI_HTTP_SERVICE_BINDING` | **NOT FOUND** | **NOT FOUND** |
| `EFI_HTTP_PROTOCOL` | **NOT FOUND** | **NOT FOUND** |
| `EFI_TCP4_SERVICE_BINDING` | **NOT FOUND** | **NOT FOUND** |
| `EFI_UDP4_SERVICE_BINDING` | **NOT FOUND** | **NOT FOUND** |
| `EFI_DNS4_SERVICE_BINDING` | **NOT FOUND** | **NOT FOUND** |
| `EFI_DHCP4_SERVICE_BINDING` | **NOT FOUND** | **NOT FOUND** |
| `EFI_IP4_CONFIG2` | **NOT FOUND** | **NOT FOUND** |
| `EFI_MNP_SERVICE_BINDING` | **NOT FOUND** | **NOT FOUND** |
| `EFI_PXE_BASE_CODE` | **NOT FOUND** | **NOT FOUND** |
| `EFI_SIMPLE_NETWORK` | FOUND | FOUND |
| `EFI_BLOCK_IO` | FOUND | FOUND |
| `EFI_SIMPLE_FILE_SYSTEM` | FOUND | FOUND |

`ConnectController` on the SimpleNetwork handle (recursive=TRUE,
DriverImage=NULL) returns `EFI_NOT_FOUND` — no firmware-resident
driver wants to bind it. The vanilla QEMU prebuilts are stripped of
NetworkPkg, so there is no MNP / IP4 / TCP4 / HTTP layer to connect.

The original design assumed firmware-provided HTTP, mirroring the
boot manager's HTTP/PXE path. That assumption holds only on
firmwares built with NetworkPkg enabled — which the boot-manager
path itself only triggers transiently. A pure-UEFI loader that runs
under arbitrary EFI firmware (and survives even tightly-trimmed
firmwares like the QEMU prebuilts) needs one of:

1. **DIY TCP/HTTP on `EFI_SIMPLE_NETWORK`** — ARP + DHCP + IPv4 +
   TCP + HTTP/1.1 in TinyGo. Sizable but tractable; one-time cost,
   then portable to every firmware that exposes a NIC at all.
2. **Disk-mode loader (Phase 5)** — drop the network path; the OCI
   fetch is done at *provisioning* time by vzd/vzc, and the EFI
   loader just chains to a kernel found on the boot media via
   `BlockIO` + `SimpleFileSystem`. Smaller in scope, but limits the
   pure-UEFI variant to pre-baked images.

Neither path is started yet. Phase 1 in the probe binary is now
guarded by a `LocateProtocol(HTTP_SB)` check that prints a
diagnostic line and skips when the firmware lacks HTTP — so the
probe still runs cleanly on real firmware that *does* have HTTP, and
reports the situation honestly on firmware that doesn't.

## Dependencies

- [`github.com/go-coff/stub`](../../go-coff/stub) — the existing UEFI
  stub provides the PE walking + LoadImage/StartImage scaffolding we
  build on. Our extensions live in `*.go` files in this directory.
- [`github.com/go-coff/peln`](../../go-coff/peln) — PE/COFF linker
  used by the build pipeline.
- TinyGo (no GC / no scheduler).

## Phase 5a result

[`cmd/efi-loader/main.go`](cmd/efi-loader/main.go) is a TinyGo PE/COFF
binary that, on every EFI_SIMPLE_FILE_SYSTEM handle the firmware
exposes:

1. Calls `HandleProtocol(handle, SimpleFileSystem)` then `OpenVolume`
   to reach the root EFI_FILE.
2. Calls `EFI_FILE.Open("\EFI\Linux\cloud-boot.efi", READ)` and skips
   the volume on `EFI_NOT_FOUND`.
3. Sizes the file via `SetPosition(END)` + `GetPosition`, then rewinds.
4. `BootServices.AllocatePool(EfiLoaderData, size, &buf)` and reads
   the file into `buf`.
5. `BootServices.LoadImage(BootPolicy=FALSE, SourceBuffer=buf, …)`.
6. `BootServices.StartImage(childHandle, 0, 0)`.

The loop short-circuits on the first volume that yields a valid UKI.

End-to-end verification under QEMU + Homebrew OVMF (arm64,
edk2-stable202408): a 64-MiB FAT32 ESP carrying the loader at
`\EFI\BOOT\BOOTAA64.EFI` and the Phase-0 probe binary at
`\EFI\Linux\cloud-boot.efi` (used as a stand-in target EFI app —
small, with deterministic stdout) produces this transcript over
the serial port:

```text
cloud-boot/loader — disk-mode (phase 5a)
SimpleFileSystem handles: 0x0000000000000001
  trying SFS handle 0x000000007F02CB18
  found UKI, size = 0x0000000000002400      ← 9216 B probe binary
  LoadImage OK, child handle = 0x000000007F000A18
StartImage...
cloud-boot/loader probe — phase 0          ← chained probe runs
  connectAllNICs: 0x0000000000000001 handle(s)
  …
```

The chained EFI image runs cleanly — the `LoadImage`/`StartImage`
handoff path that Apple VZ supports natively (and that the existing
kexec-based bootstrap fails on under arm64) works end-to-end.

The Phase-0 probe is only a stand-in target; the real Phase 5b work
is to substitute a Linux EFI-stub kernel (the existing `uki/`
pipeline output) for the cloud-boot.efi slot, propagate
`/etc/kernel/cmdline` into the child's `loaded-image->load_options`,
and add a fallback order across multiple candidate UKIs.

## Phase 5b result

Cmdline now flows from the host into the chain-loaded kernel through
a UEFI variable, bypassing the FAT-volume rebuild that the earlier
disk-only path required.

End-to-end pipeline:

1. **Host stage**: `loader/cmd/efivar-stage` writes a
   `CloudBootCmdline` variable under the cloud-boot vendor GUID
   (`c10ddb07-83c5-4d3e-9b76-1f4c0e7a3b8e`) directly into the OVMF
   varstore *before* QEMU starts, using the host-side
   `github.com/go-filesystems/uefi` package.
2. **Loader read**: at boot the disk-mode loader's
   `readCmdlineEFIVar` calls `RuntimeServices.GetVariable` with the
   two-pass `EFI_BUFFER_TOO_SMALL` idiom, allocates pool memory, and
   widens the ASCII bytes to UTF-16LE.
3. **Disk fallback**: if no variable was staged, `readCmdline` reads
   `\cmdline` from the FAT root instead (arch-agnostic).
4. **Patch child**: after `LoadImage` returns the child handle, the
   loader calls `HandleProtocol(child, LoadedImage)` and patches the
   `LoadOptions` / `LoadOptionsSize` slots in-place, so the chain-
   loaded EFI app's stub reads the right cmdline.
5. **Chain**: `StartImage` transfers control to the child. The
   `efi-probe` test target reads its own `LoadedImage.LoadOptions`
   back to close the loop on the serial console.

Verified transcript under QEMU + Homebrew OVMF arm64
(edk2-stable202408):

```text
cloud-boot/loader — disk-mode (phase 5b)
  cmdline from EFI var CloudBootCmdline (0x2F chars): cloud-boot: hello from CloudBootCmdline EFI var
cmdline source: EFI variable
  found UKI, size = 0x2400
  LoadImage OK, child handle = 0x7F000A18
  patched child LoadOptions (0x60 bytes)
StartImage...
cloud-boot/loader probe — phase 0
  LoadOptionsSize = 0x60
  LoadOptions = cloud-boot: hello from CloudBootCmdline EFI var
```

### Mock package fixes

Getting this working surfaced four real bugs in the host-side
[`github.com/go-filesystems/uefi`](../../mock/pkg/go-filesystems/uefi)
package (which `efivar-stage` uses to write the varstore). All four
fixes landed in the mock repo alongside Phase 5b:

1. **GUID byte order** — `gEfiSystemNvDataFvGuid` constant had the
   four `Data1` bytes reversed. The canonical text form is
   `FFF12B8D-7696-4C8B-A985-2747075B4F50` (not `8D2BF1FF-…`); on-disk
   bytes encode as `8d 2b f1 ff 96 76 8b 4c a9 85 27 47 07 5b 4f 50`.
2. **Wrong format** — the legacy `Format()` produces a *raw* NvVar
   store at offset 0 with the `gEfiVariableGuid` (non-auth)
   signature. Real OVMF prebuilts (both x86_64 `edk2-i386-vars.fd`
   and arm64 `edk2-aarch64-code.fd`'s NvVar region) expect an
   `EFI_FIRMWARE_VOLUME` wrapper followed by an
   `gEfiAuthenticatedVariableGuid` store. New `FormatOVMF(path,
   size, flavor)` writes the FV-wrapped + auth layout that OVMF
   actually accepts. `OVMFAArch64` uses ArmVirtPkg's hardcoded
   geometry (`FvLength=0xC0000`, store size = `0x40000 − 72`); the
   block-map covers the entire pflash slot regardless.
3. **Auth variable header support** — `parseOneVariable` /
   `encodeVariable` learned to handle the 60-byte
   `AUTHENTICATED_VARIABLE_HEADER` layout (MonotonicCount, TimeStamp,
   PubKeyIndex all zero-filled between Attributes and NameSize).
4. **Inter-field padding** — the old encoder added a 4-byte
   `HEADER_ALIGN` pad between each record's `name` and `data`
   fields. Empirically OVMF reads `DataOffset = nameOff + nameSize`
   (no padding); the alignment is applied only when walking to the
   *next* record. Inserting padding caused `GetVariable` to return
   the pad bytes prepended to the data, visible as a `\0\0`-prefixed
   cmdline.

Regression coverage:
[`format_ovmf_test.go`](../../mock/pkg/go-filesystems/uefi/test/format_ovmf_test.go)
verifies the wire layout (FV header bytes, GUIDs, FV checksum sums to
zero, ArmVirt geometry) and round-trips a variable with a non-aligned
name size — the exact case where the old inter-field-padding code
silently corrupted reads.

## Phase 5d result

The production loader (`BOOTAA64.EFI`, single binary) now boots an
*unmodified* Linux distribution cloud disk image end-to-end. There's
no `\EFI\Linux\*.efi` staged on the FAT volume — the kernel and
initrd come straight out of the cloud image's ext4 rootfs.

Pipeline (after the FAT-volume Phase 5a-5c search returns no UKI):

1. `LocateHandleBuffer(EFI_BLOCK_IO_PROTOCOL)` walks every block
   device the firmware exposes.
2. For each logical partition: ReadBlocks 4 KiB at LBA 0, check for
   the ext4 magic `0xEF53` at offset 0x438.
3. On the first ext4 partition: parse the full superblock (block
   size, inode size, inodes-per-group, descSize, 64-bit/extents
   feature flags) and remember the BlockIO context.
4. Read inode 2 (root directory) → walk its extent tree → find
   `boot` via `ext4_dir_entry_2` records.
5. Find `vmlinuz-*` and `initrd.img-*` under `/boot` by prefix
   match.
6. `AllocatePool(EfiLoaderData)` two buffers, sized to the inode
   `s_size_lo|s_size_hi`. Run `readFile` against each: depth-0 or
   depth-1 extent walker; `ReadBlocks` straight into the pool.
7. Build a 24-byte device path (`MEDIA_VENDOR` with
   `LINUX_EFI_INITRD_MEDIA_GUID` + end terminator) and an
   `EFI_LOAD_FILE2_PROTOCOL` instance whose callback returns
   `initrdSize` bytes from our buffer. Publish both protocols on a
   fresh handle via `InstallProtocolInterface`.
8. `LoadImage(SourceBuffer = kernel buffer)` to get a child image
   handle. `patchChildCmdline` patches the EFI-var-staged cmdline
   into `LoadedImage.LoadOptions`. `StartImage`.
9. Linux EFI stub takes over — finds our LoadFile2 handle via the
   media-vendor GUID walk, copies the initrd out, calls
   `ExitBootServices`, jumps to the kernel.
10. Linux boots all the way to userspace `init`.

Verified transcript (`qemu-loader-cloud-arm64` against Debian
Trixie arm64 genericcloud raw image, ~600 MB, untouched on disk —
a fresh qcow2 overlay catches Linux's boot-time writes):

```text
cloud-boot/loader — phase 5b/5c/5d
  cmdline from EFI var CloudBootCmdline (45 chars): console=ttyAMA0 root=LABEL=cloudimg-rootfs ro
cmdline source: EFI variable
  trying UKI \EFI\Linux\cloud-boot.efi
no UKI found, falling back to cloud-disk
trying cloud-disk fallback (ext4)
  ext4 partition found, blockSize=4096
  kernel: vmlinuz-6.12.88+deb13-cloud-arm64
  initrd: initrd.img-6.12.88+deb13-cloud-arm64
  initrd protocols installed
  cloud-disk kernel LoadImage OK, child=…
  patched child LoadOptions (92 bytes)
StartImage...

EFI stub: Loaded initrd from LINUX_EFI_INITRD_MEDIA_GUID device path
EFI stub: Exiting boot services...
[    0.000000] Linux version 6.12.88+deb13-cloud-arm64 …
…
[  OK  ] Reached target multi-user.target - Multi-User System.

Debian GNU/Linux 13 debian-cloud-boot ttyAMA0
debian-cloud-boot login:
```

That's the project goal achieved: an off-the-shelf Debian Trixie
arm64 cloud image, no modification, no kexec, no GRUB — pure UEFI
hand-off all the way to the login prompt.

### Why it matters

Apple Virtualization.framework on arm64 silently traps Linux's
`kexec_file_load` (the EL1 jump after MMU-off; the kernel never
returns, the VM hangs). The existing cloud-boot `init/` pipeline
relies on that path: it boots a tiny initrd first, runs in
userspace, then kexecs into the real distro kernel — and that's
exactly what Apple VZ breaks.

Phase 5d sidesteps that entirely. The production loader stays
inside Boot Services context throughout, then hands off to the
distro kernel's *own* EFI stub via `LoadImage` + `StartImage` (the
same path every UEFI machine uses for first boot). The stub calls
`ExitBootServices` itself — a code path Apple VZ supports, since
that's what every distro installer needs.

### Code layout

Each filesystem driver is one file under
[`cmd/efi-loader/`](cmd/efi-loader/), pulling in the shared
`EFI_BLOCK_IO_PROTOCOL` / `EFI_LOAD_FILE2_PROTOCOL` /
`installInitrdProtocol` / `LoadImage` plumbing from
[`main.go`](cmd/efi-loader/main.go) and
[`ext4.go`](cmd/efi-loader/ext4.go).

- [`ext4.go`](cmd/efi-loader/ext4.go) — superblock, group descriptor,
  inode (depth-0 + depth-1 extent trees), `findInDirPrefix` over
  `ext4_dir_entry_2` records, `tryCloudDiskBoot` orchestrator.
- [`xfs.go`](cmd/efi-loader/xfs.go) — big-endian SB, v5 176-byte
  inode core, bit-packed `xfs_bmbt_rec` extents, short-form and
  block-form directory walkers, `tryXfsCloudBoot`.
- [`btrfs.go`](cmd/efi-loader/btrfs.go) — sys_chunk_array bootstrap,
  chunk-tree extension, default-subvol indirection, depth-N B-tree
  walker with key-range pruning, INODE_ITEM (size + mode),
  EXTENT_DATA reader (inline + regular), inline-extent symlink
  resolution, `tryBtrfsCloudBoot`.
- [`inflate.go`](cmd/efi-loader/inflate.go) — RFC 1951/1952
  gzip/DEFLATE inflate (fixed + dynamic Huffman, sliding-window
  folded into output buffer). Triggered by `isGzipped(kernelBufPtr)`
  on the freshly-read kernel — Ubuntu Noble arm64 needs this.

The exploratory scaffolding lives in
[`cmd/disk-probe/`](cmd/disk-probe/) — same algorithms as the
production drivers but with verbose `writeASCII` diagnostics at
every step. Useful when adding a new filesystem or distro: bring it
up under disk-probe first to see exactly which step fails, then
port the algorithm into the corresponding `cmd/efi-loader/*.go`
once it works.

## Reproduce

```sh
task -t loader/Taskfile.yaml qemu-loader-arm64
# defaults: UKI_PATH=cmd/efi-probe/BOOTAA64-probe.EFI

UKI_PATH=/path/to/uki-aa64.efi \
  task -t loader/Taskfile.yaml qemu-loader-arm64
```

The task wipes `ovmf_vars_arm64.fd` on each run — OVMF caches a
Boot0001 entry across reboots that points at the *previous* ESP and
short-circuits the removable-media fallback (`\EFI\BOOT\BOOTAA64.EFI`)
unless reset. This was the longest-running gotcha during Phase 5a
bring-up.
