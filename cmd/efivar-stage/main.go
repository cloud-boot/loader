// efivar-stage writes cloud-boot UEFI variables into an
// OVMF_VARS.fd / QEMU_VARS.fd binary store BEFORE QEMU is launched.
//
// Two variables are recognised:
//
//	CloudBootCmdline (-cmdline …)
//	    Kernel command line. The disk-mode loader's readCmdlineEFIVar
//	    reads it back via RuntimeServices.GetVariable and propagates
//	    it into the chained image's LoadedImage.LoadOptions.
//
//	CloudBootTarget (-target …)
//	    UKI basename under \EFI\Linux\. Selects which UKI the loader
//	    chain-loads — e.g. -target rescue → \EFI\Linux\rescue.efi.
//	    Absent → defaults to "cloud-boot" (the Phase-5a default).
//
// Goes through github.com/go-filesystems/uefi (host-side, offline
// NvVar parser/writer), so no QEMU monitor commands and no boot-time
// UEFI shell interaction is needed.
//
// Usage:
//
//	efivar-stage -store OVMF_VARS.fd \
//	    -cmdline "console=ttyAMA0 root=LABEL=…" \
//	    -target rescue
package main

import (
	"flag"
	"fmt"
	"os"

	fsuefi "github.com/go-filesystems/uefi"
)

// cloudBootGUID — namespace for cloud-boot-specific UEFI variables.
// MUST match `cloudBootGUID` in loader/cmd/efi-loader/main.go.
//
//	{c10ddb07-83c5-4d3e-9b76-1f4c0e7a3b8e}
var cloudBootGUID = fsuefi.GUID{
	0x07, 0xDB, 0x0D, 0xC1,
	0xC5, 0x83,
	0x3E, 0x4D,
	0x9B, 0x76, 0x1F, 0x4C, 0x0E, 0x7A, 0x3B, 0x8E,
}

// NV|BS|RT — non-volatile so the variable persists across reboots,
// readable from BootServices (the loader runs there), readable from
// RuntimeServices (loaded kernel could also read it if it wanted to).
// systemd-boot's LoaderEntries use the same flag combination.
const attrs = fsuefi.AttrNonVolatile |
	fsuefi.AttrBootServiceAccess |
	fsuefi.AttrRuntimeAccess

func main() {
	var (
		storePath = flag.String("store", "", "path to OVMF_VARS.fd / QEMU_VARS.fd")
		cmdline   = flag.String("cmdline", "", "kernel command line — staged as CloudBootCmdline")
		target    = flag.String("target", "", "UKI basename under \\EFI\\Linux\\ — staged as CloudBootTarget")
		delete    = flag.Bool("delete", false, "delete CloudBootCmdline + CloudBootTarget instead of writing")
		arch      = flag.String("arch", "arm64", "OVMF flavor: arm64 (ArmVirt 768 KiB FV) | amd64 (x86_64 FV=sizeBytes)")
	)
	flag.Parse()

	if *storePath == "" {
		fmt.Fprintln(os.Stderr, "efivar-stage: -store is required")
		flag.Usage()
		os.Exit(2)
	}

	// Try to open the store as-is. If it fails to parse (typical for
	// the zero-filled file created by `dd if=/dev/zero of=... bs=1M
	// count=64`), reformat it with a fresh NvVar header so subsequent
	// Set calls produce a valid varstore. Either way the resulting
	// file is one OVMF accepts at boot.
	store, err := fsuefi.Open(*storePath)
	if err != nil {
		st, ferr := os.Stat(*storePath)
		if ferr != nil {
			fmt.Fprintf(os.Stderr, "efivar-stage: stat %q: %v\n", *storePath, ferr)
			os.Exit(1)
		}
		size := st.Size()
		if size == 0 {
			size = fsuefi.VarsSizeARM64 // sensible default
		}
		// Use FormatOVMF — the FV-wrapped + authenticated layout that
		// real OVMF prebuilts use (both edk2-i386-vars.fd and the
		// aarch64 NvVar region of edk2-aarch64-code.fd). The legacy
		// fsuefi.Format produces a raw NvVar store that OVMF rejects
		// at first boot, reformats, and wipes any variable we staged.
		var flavor fsuefi.OVMFFlavor
		switch *arch {
		case "arm64", "aarch64":
			flavor = fsuefi.OVMFAArch64
		case "amd64", "x86_64", "x86-64":
			flavor = fsuefi.OVMFX86_64
		default:
			fmt.Fprintf(os.Stderr, "efivar-stage: unknown arch %q (expected arm64|amd64)\n", *arch)
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, "efivar-stage: %v — reformatting (%d bytes, OVMF %s)\n", err, size, *arch)
		store, err = fsuefi.FormatOVMF(*storePath, size, flavor)
		if err != nil {
			fmt.Fprintf(os.Stderr, "efivar-stage: format %q: %v\n", *storePath, err)
			os.Exit(1)
		}
	}
	defer store.Close()

	if *delete {
		// Delete is best-effort per variable — a missing variable is
		// not an error here; we want -delete to leave the store in a
		// known-clean state regardless of what was previously staged.
		for _, name := range []string{"CloudBootCmdline", "CloudBootTarget"} {
			if err := store.Delete(name, cloudBootGUID); err != nil {
				fmt.Fprintf(os.Stderr, "efivar-stage: delete %s: %v (continuing)\n", name, err)
			} else {
				fmt.Printf("deleted %s\n", name)
			}
		}
		return
	}

	if *cmdline == "" && *target == "" {
		fmt.Fprintln(os.Stderr, "efivar-stage: at least one of -cmdline / -target is required (or use -delete)")
		os.Exit(2)
	}

	if *cmdline != "" {
		if err := store.Set(fsuefi.Variable{
			Name:       "CloudBootCmdline",
			GUID:       cloudBootGUID,
			Attributes: attrs,
			Data:       []byte(*cmdline),
		}); err != nil {
			fmt.Fprintf(os.Stderr, "efivar-stage: set CloudBootCmdline: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("staged CloudBootCmdline (%d bytes): %s\n", len(*cmdline), *cmdline)
	}

	if *target != "" {
		if err := store.Set(fsuefi.Variable{
			Name:       "CloudBootTarget",
			GUID:       cloudBootGUID,
			Attributes: attrs,
			Data:       []byte(*target),
		}); err != nil {
			fmt.Fprintf(os.Stderr, "efivar-stage: set CloudBootTarget: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("staged CloudBootTarget (%d bytes): %s\n", len(*target), *target)
	}
}
