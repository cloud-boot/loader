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
| 0     | Probe `EFI_HTTP_PROTOCOL` / `EFI_TCP4_PROTOCOL` availability under Apple VZ + OVMF (arm64 + amd64) | in progress |
| 1     | TinyGo OCI v2 manifest+blob client over UEFI HTTP. Minimal JSON parse. | — |
| 2     | `LoadImage(SourceBuffer = fetched bytes)` + `StartImage` of distro kernel | — |
| 3     | Dynamic `EFI_LOAD_FILE2_PROTOCOL` initrd from fetched bytes; cmdline propagation from plan | — |
| 4     | DNS-SRV via `EFI_DNS4_PROTOCOL`; multi-endpoint failover; minimal cosign | — |
| 5     | Disk-mode (`BlockIO` + `SimpleFileSystem` walk + cmdline from `/etc/kernel/cmdline`) | — |

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
