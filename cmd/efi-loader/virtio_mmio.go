// Phase D1-bypass — raw MMIO access to the virtio-net BARs,
// sidestepping EFI_PCI_IO_PROTOCOL's Mem.Read/Write.
//
// Hypothesis: Apple VZ accepts our PCI_IO-mediated config-space
// writes (proven — sentinel 0xAA55BEEF round-trips through
// driver_feature_select) and accepts our reads of device_features,
// but refuses to honour FEATURES_OK from a UEFI context. The
// rejection might happen at the EFI_PCI_IO layer (Apple's wrapper
// has a denylist for certain register transitions) rather than at
// the bare-metal MMIO layer. If we read+write the same registers
// via direct *(*uint32)(...) instead, FEATURES_OK might latch.
//
// What this file does:
//   1. Discover the physical address of the BAR carrying COMMON_CFG.
//      Read BAR0..5 from PCI config space, identify 64-bit memory
//      BARs (lower nibble bits 1..2), assemble the 64-bit address.
//   2. Compute mmio_addr = BAR_phys + vnetCommon.offset.
//   3. Dump the resolved address into CloudBootVNBar (NVRAM) for
//      inspection before doing anything risky.
//
// Subsequent steps (separate commits if/when this first one shows
// the BAR address looks plausible): write status=0x0B directly via
// MMIO, re-read, see if FEATURES_OK latches.

package main

import "unsafe"

// vnetBARPhys is the resolved physical address of the BAR carrying
// virtio's common-cfg sub-page. Zero = not yet resolved.
var vnetBARPhys uint64

// vnetMMIOCommon is the physical address of the COMMON_CFG sub-page
// itself = vnetBARPhys + vnetCommon.offset. Set by vnetResolveBAR.
var vnetMMIOCommon uint64

// CloudBootVNBar — 16 bytes captured for diagnostics:
//   [0..8]   resolved BAR physical address (LE)
//   [8..16]  vnetMMIOCommon address (LE) = BAR + common-cfg offset
var vnetBarVarName = [...]uint16{
	'C', 'l', 'o', 'u', 'd', 'B', 'o', 'o', 't', 'V', 'N', 'B', 'a', 'r',
	0,
}
var vnetBarVarData [16]byte

// PCI BAR layout — config space offsets 0x10..0x28 hold 6 BARs.
//
//   bit 0 = 0  → memory BAR (vs I/O)
//   bits 1..2 = 00 → 32-bit memory
//             = 10 → 64-bit memory (uses BAR and BAR+1)
//   bit 3      = prefetchable (irrelevant here)
//   bits 4..31 = base address (mask off lower 4 bits)
//
// For 64-bit BARs the high 32 bits come from BAR[N+1] in the next
// 4-byte slot. Apple VZ's virtio devices are typically 64-bit BARs.

// vnetResolveBAR reads the BAR register vnetCommon.bar from PCI
// config space, decodes its physical base address, and computes
// vnetMMIOCommon. Returns true on success.
//
// Marker: VN-BAR  on success
//         VN-BARFAIL  if BAR read fails or returns 0 (= disabled)
func vnetResolveBAR(co *efiSimpleTextOutput) bool {
	if pciNetIO == nil || vnetCommon.length == 0 {
		return false
	}
	writeASCII(co, "vnet: resolving BAR")
	writeHex64(co, uint64(vnetCommon.bar))
	writeASCII(co, " physical address\r\n")

	// BAR is at config offset 0x10 + bar_index*4 (4 bytes each).
	bar0Offset := uint32(0x10) + uint32(vnetCommon.bar)*4
	virtioCfgU32 = 0
	if pciConfigRead(pciNetIO, pciIOWidthUint32, bar0Offset, 1,
		unsafe.Pointer(&virtioCfgU32)) != efiSuccess {
		writeASCII(co, "  BAR read failed\r\n")
		bootMark("VN-BARR")
		return false
	}
	lo := virtioCfgU32
	if lo == 0 {
		writeASCII(co, "  BAR is 0 (disabled)\r\n")
		bootMark("VN-BARZ")
		return false
	}
	// Is it a memory BAR?
	if lo&1 != 0 {
		writeASCII(co, "  BAR is an I/O BAR, not memory\r\n")
		bootMark("VN-BARI")
		return false
	}
	// 64-bit? bits 1..2 == 10 (decimal 2) means 64-bit memory.
	is64 := ((lo >> 1) & 3) == 2
	addr := uint64(lo &^ 0xF) // mask off type bits
	if is64 {
		// Read upper 32 bits from BAR[N+1].
		virtioCfgU32 = 0
		if pciConfigRead(pciNetIO, pciIOWidthUint32, bar0Offset+4, 1,
			unsafe.Pointer(&virtioCfgU32)) != efiSuccess {
			writeASCII(co, "  BAR hi read failed\r\n")
			bootMark("VN-BARH")
			return false
		}
		addr |= uint64(virtioCfgU32) << 32
	}
	vnetBARPhys = addr
	vnetMMIOCommon = addr + uint64(vnetCommon.offset)
	writeASCII(co, "  BAR phys=0x")
	writeHex64(co, addr)
	writeASCII(co, " common-cfg at 0x")
	writeHex64(co, vnetMMIOCommon)
	writeASCII(co, " (")
	if is64 {
		writeASCII(co, "64-bit")
	} else {
		writeASCII(co, "32-bit")
	}
	writeASCII(co, ")\r\n")

	// Stamp both into NVRAM.
	for i := 0; i < 8; i++ {
		vnetBarVarData[i] = byte(vnetBARPhys >> (i * 8))
		vnetBarVarData[8+i] = byte(vnetMMIOCommon >> (i * 8))
	}
	if bootMarkRT != nil && bootMarkRT.setVariable != 0 {
		efiCall5(bootMarkRT.setVariable,
			uintptr(unsafe.Pointer(&vnetBarVarName[0])),
			uintptr(unsafe.Pointer(&cloudBootGUID)),
			uintptr(0x07),
			uintptr(len(vnetBarVarData)),
			uintptr(unsafe.Pointer(&vnetBarVarData[0])))
	}
	bootMark("VN-BAR")
	return true
}

// mmioReadU8 / U32 read directly via unsafe.Pointer from the resolved
// MMIO address. Apple VZ might let bare MMIO through where PCI_IO's
// Mem.Write/Read are filtered.
//
// Calling these on an unresolved or wrong physical address is a fast
// trip to an instruction abort, so vnetResolveBAR must succeed first.
func mmioReadU8(addr uint64) uint8 {
	return *(*uint8)(unsafe.Pointer(uintptr(addr)))
}

func mmioReadU32(addr uint64) uint32 {
	return *(*uint32)(unsafe.Pointer(uintptr(addr)))
}

func mmioWriteU8(addr uint64, v uint8) {
	*(*uint8)(unsafe.Pointer(uintptr(addr))) = v
}

func mmioWriteU32(addr uint64, v uint32) {
	*(*uint32)(unsafe.Pointer(uintptr(addr))) = v
}

// vnetMmioSmokeTest reads device_status (BAR + 20) two ways:
//   1. Via PCI_IO.Mem.Read (the path we know returns 0x03)
//   2. Via direct unsafe.Pointer deref at vnetMMIOCommon + 20
// and stamps both into NVRAM. If both return the same value, the
// MMIO mapping IS accessible from us and the PCI_IO layer isn't
// adding anything beyond a wrapper. If raw returns garbage (or
// faults), Apple VZ doesn't map the BAR into our page table and
// we'd need a different escape route.
//
// CloudBootVNMMIO — 2 bytes:
//   [0] status via PCI_IO.Mem.Read
//   [1] status via raw *(*uint8)
var vnetMmioVarName = [...]uint16{
	'C', 'l', 'o', 'u', 'd', 'B', 'o', 'o', 't', 'V', 'N', 'M', 'M', 'I', 'O',
	0,
}
var vnetMmioVarData [2]byte

// vnetMmioTryFOK writes FEATURES_OK to the device_status register via
// raw MMIO (bypassing PCI_IO.Mem.Write), then re-reads the status to
// see if it latched. Stamps both pre- and post-write status into a
// new NVRAM variable. If the post-write status reads back as 0x0B
// instead of 0x03, Apple VZ's PCI_IO layer was indeed filtering the
// transition and we've cracked it open.
//
// CloudBootVNMmioFOK — 2 bytes:
//   [0] status read via raw MMIO before the write
//   [1] status read via raw MMIO after the write (after a 10 ms stall)
var vnetMmioFokVarName = [...]uint16{
	'C', 'l', 'o', 'u', 'd', 'B', 'o', 'o', 't', 'V', 'N', 'F', 'o', 'k', 'M',
	0,
}
var vnetMmioFokVarData [2]byte

func vnetMmioTryFOK(co *efiSimpleTextOutput) {
	if vnetMMIOCommon == 0 {
		return
	}
	addrStatus := vnetMMIOCommon + 20
	before := mmioReadU8(addrStatus)
	mmioWriteU8(addrStatus,
		virtioStatusAcknowledge|virtioStatusDriver|virtioStatusFeaturesOK)
	efiCall2(bsGlobal.stall, 10000, 0)
	after := mmioReadU8(addrStatus)
	vnetMmioFokVarData[0] = before
	vnetMmioFokVarData[1] = after
	if bootMarkRT != nil && bootMarkRT.setVariable != 0 {
		efiCall5(bootMarkRT.setVariable,
			uintptr(unsafe.Pointer(&vnetMmioFokVarName[0])),
			uintptr(unsafe.Pointer(&cloudBootGUID)),
			uintptr(0x07),
			uintptr(len(vnetMmioFokVarData)),
			uintptr(unsafe.Pointer(&vnetMmioFokVarData[0])))
	}
	writeASCII(co, "  MMIO status before FOK write=0x")
	writeHex64(co, uint64(before))
	writeASCII(co, " after=0x")
	writeHex64(co, uint64(after))
	writeASCII(co, "\r\n")
	if after&virtioStatusFeaturesOK != 0 {
		bootMark("VN-RAW-OK")
	} else {
		bootMark("VN-RAW-FX")
	}
}

func vnetMmioSmokeTest(co *efiSimpleTextOutput) {
	if vnetMMIOCommon == 0 {
		return
	}
	// PCI_IO path (we know this works).
	viaPCI, _ := vnetCommonReadU8(cfgDeviceStatus)
	vnetMmioVarData[0] = viaPCI
	// Direct MMIO. This will fault if the BAR isn't in our page
	// table. If we crash here, the marker stays at whatever was
	// last bootMark()-ed (VN-BAR).
	viaMMIO := mmioReadU8(vnetMMIOCommon + 20)
	vnetMmioVarData[1] = viaMMIO
	if bootMarkRT != nil && bootMarkRT.setVariable != 0 {
		efiCall5(bootMarkRT.setVariable,
			uintptr(unsafe.Pointer(&vnetMmioVarName[0])),
			uintptr(unsafe.Pointer(&cloudBootGUID)),
			uintptr(0x07),
			uintptr(len(vnetMmioVarData)),
			uintptr(unsafe.Pointer(&vnetMmioVarData[0])))
	}
	writeASCII(co, "  status via PCI_IO=0x")
	writeHex64(co, uint64(viaPCI))
	writeASCII(co, " via raw MMIO=0x")
	writeHex64(co, uint64(viaMMIO))
	writeASCII(co, "\r\n")
	bootMark("VN-MMIO")
}
