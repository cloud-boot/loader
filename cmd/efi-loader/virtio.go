// Phase C — Walk the virtio-net PCI capability list, locate the
// device-config capability, read the MAC address out of its BAR.
//
// virtio 1.0+ exposes its sub-pages (common cfg, notify cfg, ISR
// cfg, device cfg, PCI cfg) through a chain of Vendor-Specific (cap
// id 0x09) PCI configuration capabilities. Each cap entry tells us:
//
//   cap.cfg_type   which sub-page this is (1=COMMON, 2=NOTIFY, 3=ISR,
//                  4=DEVICE, 5=PCI). We need at least COMMON for
//                  feature negotiation + queue setup and DEVICE for
//                  reading the MAC; the others come in later phases.
//   cap.bar        which BAR (0..5) carries the sub-page
//   cap.offset     byte offset inside the BAR
//   cap.length     valid range
//
// After locating each sub-page we read it through `pciIO.Mem.Read`
// (uses BAR + offset directly — no manual BAR mapping needed).
//
// What this commit ships: the cap walk + just enough Mem.Read to
// pull the 6-byte MAC out of the device-config sub-page. Phase D
// then builds on the COMMON sub-page (queue addresses, feature bits,
// device status) once we have a virtqueue allocated.

package main

import "unsafe"

// efiPCIIOAccess mirrors EFI_PCI_IO_PROTOCOL_ACCESS — used for the
// .Mem.Read / .Mem.Write etc. function tables nested inside PCI_IO.
//
// We don't use this struct directly; instead the Mem.Read function
// pointer is at a fixed offset relative to the start of the PCI_IO
// instance. Spec layout (from EFI_PCI_IO_PROTOCOL):
//
//   pollMem, pollIO,                                  // 2 slots = 16 bytes
//   memRead, memWrite,                                // 2 slots = 16 bytes  ← mem access here
//   ioRead, ioWrite,                                  // 2 slots = 16 bytes
//   configRead, configWrite,                          // 2 slots = 16 bytes
//   ...
//
// The function table in efiPCIIO (pci.go) already exposes memRead
// at the right offset. We just need to call it.

// Width passed to memRead. Reusing pci.go's constants.
//   pciIOWidthUint8 = 0, pciIOWidthUint16 = 1, pciIOWidthUint32 = 2

// PCI configuration-space layout offsets we care about. Same for
// every PCI device.
const (
	pciCfgStatus       = 0x06 // 2 bytes — bit 4 = CAP_LIST present
	pciCfgCapPtr       = 0x34 // 1 byte  — offset of first cap entry
	pciStatusCapListOk = 0x10 // bit 4 of the status word
)

// PCI capability header.
const (
	pciCapIDVendor = 0x09 // Vendor-specific — virtio uses this
)

// virtio-1.0 cfg_type values (offset 3 in each vendor-specific cap).
const (
	virtioCfgCommon = 1
	virtioCfgNotify = 2
	virtioCfgISR    = 3
	virtioCfgDevice = 4
	virtioCfgPCI    = 5
)

// virtioCap holds the decoded fields of a virtio Vendor-Specific cap
// block. UEFI doesn't expose a typed view; we read 16 bytes from
// config space then unpack manually.
type virtioCap struct {
	capID   uint8
	capNext uint8
	capLen  uint8
	cfgType uint8
	bar     uint8
	_padA   [3]byte
	offset  uint32
	length  uint32
}

// vnetCaps holds the four sub-page locations the loader needs. Each
// is { barIndex, offset, length } — zero length means "not yet
// discovered". Package-scope per TinyGo+UEFI rules.
type vnetCap struct {
	bar    uint8
	offset uint32
	length uint32
}

var (
	vnetCommon vnetCap
	vnetNotify vnetCap
	vnetISR    vnetCap
	vnetDevice vnetCap

	// MAC read out of the virtio device-cfg sub-page at offset 0.
	// 6 bytes of station address. Stamped into CloudBootMAC when
	// Phase C succeeds.
	vnetLocalMAC [6]byte
)

// virtioCfg16 is the package-scope buffer pciConfigRead reads into.
// TinyGo escape-analysis lands a stack-local-cast-to-unsafe.Pointer
// in heap-promotion territory, so we keep it at package scope.
var (
	virtioCfgU8  uint8
	virtioCfgU16 uint16
	virtioCfgU32 uint32

	// virtioCapScratch is the 16-byte cap descriptor pciConfigRead
	// fills in during the cap-list walk. Must be package-scope —
	// declaring it as `var cap virtioCap` inside vnetInit and
	// passing `&cap` into the firmware call escapes-to-heap under
	// TinyGo+UEFI (memory:tinygo-uefi-landmines), and the firmware
	// call traps via VirtualAlloc with no diagnostic. Cost us a
	// debugging cycle on 2026-05-20.
	virtioCapScratch virtioCap
)

// vnetInit walks the virtio-net device's PCI capability list, fills
// in vnetCommon / vnetNotify / vnetISR / vnetDevice, then reads the
// MAC out of the device-cfg sub-page. Returns true iff at least the
// DEVICE_CFG cap was found AND the MAC came back non-zero.
//
// Diagnostic markers (CloudBootMark) document each branch — same
// 6-byte truncation as Phase A/B, but unique enough that the prefix
// disambiguates:
//
//	VN-NOCAP  status register reports no capability list — should
//	           never happen on virtio-1.0, would indicate a bus
//	           walk bug or a firmware that hides caps.
//	VN-NODEV  cap walk completed but no DEVICE_CFG cap found.
//	VN-MACOK  MAC read succeeded; vnetLocalMAC is valid.
func vnetInit(co *efiSimpleTextOutput) bool {
	if pciNetIO == nil {
		return false
	}
	writeASCII(co, "vnet: reading PCI capability chain\r\n")

	// Read PCI Status (2 bytes at offset 0x06), check CAP_LIST bit.
	virtioCfgU16 = 0
	if pciConfigRead(pciNetIO, pciIOWidthUint16, pciCfgStatus, 1,
		unsafe.Pointer(&virtioCfgU16)) != efiSuccess {
		writeASCII(co, "  PCI status read failed\r\n")
		bootMark("VN-NOCAP")
		return false
	}
	if virtioCfgU16&pciStatusCapListOk == 0 {
		writeASCII(co, "  CAP_LIST bit clear in PCI status\r\n")
		bootMark("VN-NOCAP")
		return false
	}

	// Read capability pointer (1 byte at offset 0x34). Walk the
	// chain: at each entry read cap_id + cap_next, dispatch on
	// cap_id, advance to cap_next.
	virtioCfgU8 = 0
	if pciConfigRead(pciNetIO, pciIOWidthUint8, pciCfgCapPtr, 1,
		unsafe.Pointer(&virtioCfgU8)) != efiSuccess {
		writeASCII(co, "  cap pointer read failed\r\n")
		bootMark("VN-NOCAP")
		return false
	}
	capPtr := virtioCfgU8

	// Reset our sub-page discovery state for idempotency.
	vnetCommon = vnetCap{}
	vnetNotify = vnetCap{}
	vnetISR = vnetCap{}
	vnetDevice = vnetCap{}

	steps := 0
	for capPtr != 0 && steps < 32 {
		steps++
		// Read 16 bytes starting at capPtr — covers id, next, len,
		// type, bar, padding, offset, length. virtioCapScratch is
		// package-scope (see comment above) so its address is safe
		// to pass to the firmware.
		if pciConfigRead(pciNetIO, pciIOWidthUint8, uint32(capPtr), 16,
			unsafe.Pointer(&virtioCapScratch)) != efiSuccess {
			writeASCII(co, "  cap entry read failed at offset 0x")
			writeHex64(co, uint64(capPtr))
			writeASCII(co, "\r\n")
			break
		}
		writeASCII(co, "  cap @0x")
		writeHex64(co, uint64(capPtr))
		writeASCII(co, " id=0x")
		writeHex64(co, uint64(virtioCapScratch.capID))
		writeASCII(co, " next=0x")
		writeHex64(co, uint64(virtioCapScratch.capNext))
		if virtioCapScratch.capID == pciCapIDVendor {
			writeASCII(co, " cfg_type=")
			writeHex64(co, uint64(virtioCapScratch.cfgType))
			writeASCII(co, " bar=")
			writeHex64(co, uint64(virtioCapScratch.bar))
			writeASCII(co, " off=0x")
			writeHex64(co, uint64(virtioCapScratch.offset))
			writeASCII(co, " len=0x")
			writeHex64(co, uint64(virtioCapScratch.length))
			switch virtioCapScratch.cfgType {
			case virtioCfgCommon:
				vnetCommon.bar = virtioCapScratch.bar
				vnetCommon.offset = virtioCapScratch.offset
				vnetCommon.length = virtioCapScratch.length
			case virtioCfgNotify:
				vnetNotify.bar = virtioCapScratch.bar
				vnetNotify.offset = virtioCapScratch.offset
				vnetNotify.length = virtioCapScratch.length
			case virtioCfgISR:
				vnetISR.bar = virtioCapScratch.bar
				vnetISR.offset = virtioCapScratch.offset
				vnetISR.length = virtioCapScratch.length
			case virtioCfgDevice:
				vnetDevice.bar = virtioCapScratch.bar
				vnetDevice.offset = virtioCapScratch.offset
				vnetDevice.length = virtioCapScratch.length
			}
		}
		writeASCII(co, "\r\n")
		capPtr = virtioCapScratch.capNext
	}

	if vnetDevice.length < 6 {
		writeASCII(co, "  no DEVICE_CFG cap found (or too short)\r\n")
		bootMark("VN-NODEV")
		return false
	}

	// Read 6 bytes of MAC from DEVICE_CFG BAR + offset.
	// virtio-net device-cfg layout (when VIRTIO_NET_F_MAC negotiated,
	// which Apple's vfkit always offers):
	//   0..6   mac[6]
	//   6..8   status
	//   8..10  max_virtqueue_pairs
	//   ...
	// The MAC is at offset 0 of device-cfg regardless of feature
	// bits, so reading it without feature negotiation is safe.
	st := efiCall6(pciNetIO.memRead,
		uintptr(unsafe.Pointer(pciNetIO)),
		pciIOWidthUint8,
		uintptr(vnetDevice.bar),
		uintptr(vnetDevice.offset),
		6, // count = 6 bytes
		uintptr(unsafe.Pointer(&vnetLocalMAC[0])))
	if st != efiSuccess {
		writeASCII(co, "  Mem.Read(device-cfg+0,6) failed: ")
		writeHex64(co, st)
		writeASCII(co, "\r\n")
		bootMark("VN-NODEV")
		return false
	}
	writeASCII(co, "  virtio-net MAC=")
	writeHexMAC(co, vnetLocalMAC)
	writeASCII(co, "\r\n")
	bootMark("VN-MACOK")
	return true
}
