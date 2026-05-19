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
| ----- | ----- | ------ |
| 0     | Probe `EFI_HTTP_PROTOCOL` / `EFI_TCP4_PROTOCOL` availability under Apple VZ + OVMF (arm64 + amd64) | done — see [Phase 0 result](#phase-0-result) |
| 1     | TinyGo OCI v2 manifest+blob client over UEFI HTTP. Minimal JSON parse. | blocked by Phase 0 finding |
| 2     | `LoadImage(SourceBuffer = fetched bytes)` + `StartImage` of distro kernel | — |
| 3     | Dynamic `EFI_LOAD_FILE2_PROTOCOL` initrd from fetched bytes; cmdline propagation from plan | — |
| 4     | DNS-SRV via `EFI_DNS4_PROTOCOL`; multi-endpoint failover; minimal cosign | — |
| 5     | Disk-mode (`BlockIO` + `SimpleFileSystem` walk + cmdline from `/etc/kernel/cmdline`) | — |

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

## Build

(TBD — phase 0 has no build target yet; will land in
`Taskfile.yaml` once the HTTP probe stub compiles.)
