# cloud-boot/loader

**Phase-0 / experimental.** Pure-UEFI variant of cloud-boot — a TinyGo
PE/COFF stub that does the plan-fetch + kernel-handoff entirely inside
UEFI Boot Services, with NO Linux bootstrap kernel in between. The
existing `init/` + `uki/` pipeline (Linux kernel + kexec) is unchanged;
this lives in parallel.

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
| 5b | Disk-mode + cmdline propagation, multiple candidate UKIs, fallback order | — |

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
