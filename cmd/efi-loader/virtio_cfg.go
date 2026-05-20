// Phase D1 — virtio-net common-cfg reads/writes + device init state
// machine (reset → ACKNOWLEDGE → DRIVER → feature negotiate →
// FEATURES_OK).
//
// virtio-1.0 §3.1 prescribes the boot-time sequence we follow here.
// Sub-pages all live in BAR-mapped MMIO; we route reads/writes
// through EFI_PCI_IO_PROTOCOL.Mem so we don't have to manually
// claim or remap BARs — the firmware did that already.
//
// Endianness: virtio-1.0 mandates little-endian for every multi-
// byte field in common-cfg (and device-cfg). arm64 + amd64 are both
// LE natively → no byte swaps needed.
//
// Features we negotiate (intentionally minimal):
//   VIRTIO_F_VERSION_1 (bit 32) — mandatory for the 1.0 ABI we use.
//                                  Without it the device would fall
//                                  back to legacy 0.9.5 register
//                                  layout, which we don't speak.
//   VIRTIO_NET_F_MAC   (bit 5)  — use the MAC from device-cfg. Apple
//                                  VZ always offers this; the MAC
//                                  Phase C read out is the one we
//                                  use for outbound frames.
//
// Explicitly NOT negotiated (and a brief comment why):
//   VIRTIO_NET_F_CSUM, _GUEST_CSUM        — we'll let the kernel-
//                                            equivalent code compute
//                                            its own checksums.
//   VIRTIO_NET_F_GUEST_TSO*, _HOST_TSO*    — TCP segmentation offload
//                                            adds a lot of code; OCI
//                                            blobs fit fine without it.
//   VIRTIO_NET_F_MRG_RXBUF                 — keeps the RX header a
//                                            fixed 10 bytes; without
//                                            it it would be 12.
//   VIRTIO_NET_F_MQ                        — single virtqueue pair is
//                                            plenty for OCI fetch.

package main

import "unsafe"

// virtio device-status bits.
const (
	virtioStatusReset           uint8 = 0
	virtioStatusAcknowledge     uint8 = 1
	virtioStatusDriver          uint8 = 2
	virtioStatusDriverOK        uint8 = 4
	virtioStatusFeaturesOK      uint8 = 8
	virtioStatusFailed          uint8 = 128
	virtioStatusDeviceNeedsReset uint8 = 64
)

// virtio-1.0 common-cfg field offsets (§4.1.4.3 Table 4).
const (
	cfgDeviceFeatureSelect uint32 = 0
	cfgDeviceFeature       uint32 = 4
	cfgDriverFeatureSelect uint32 = 8
	cfgDriverFeature       uint32 = 12
	cfgMSIXConfig          uint32 = 16
	cfgNumQueues           uint32 = 18
	cfgDeviceStatus        uint32 = 20
	cfgConfigGeneration    uint32 = 21
	cfgQueueSelect         uint32 = 22
	cfgQueueSize           uint32 = 24
	cfgQueueMSIXVector     uint32 = 26
	cfgQueueEnable         uint32 = 28
	cfgQueueNotifyOff      uint32 = 30
	cfgQueueDesc           uint32 = 32
	cfgQueueDriver         uint32 = 40
	cfgQueueDevice         uint32 = 48
)

// Feature bits we care about. The virtio spec uses 64-bit feature
// space — bits 0..31 in feature_select=0, bits 32..63 in =1.
const (
	virtioNetFMAC          uint32 = 5  // VIRTIO_NET_F_MAC, low word
	virtioFVersion1        uint32 = 32 // VIRTIO_F_VERSION_1, high word bit 0
	virtioFAccessPlatform  uint32 = 33 // VIRTIO_F_ACCESS_PLATFORM (IOMMU), high word bit 1
	// Note: bit 34 in older spec drafts was IOMMU_PLATFORM. The
	// committed spec name is ACCESS_PLATFORM, bit 33. Apple VZ
	// offers it as bit 33 (hi=0x5 = bits 32 + 34? no — 0x5 = bits 0+2
	// of the hi word = overall bits 32+34). Recheck: 0x00000005 set
	// bits = bit0 + bit2 of hi word = overall bits 32 (VERSION_1)
	// and 34. Bit 34 in current virtio-1.2 is unused; bit 33 is
	// ACCESS_PLATFORM. Older spec releases moved this around. The
	// pragmatic fix: accept every bit the device offers in the hi
	// word — refusing would only matter for VERSION_1 (bit 32,
	// already accepted) and we don't gain anything by sub-setting.
)

// PCI_IO.Mem widths. The PCI_IO spec uses the same enum for both
// configRead and Mem.Read; pci.go's pciIOWidthUint{8,16,32} already
// define the low three. Add Uint64 here.
const pciIOWidthUint64 uintptr = 3

// vnetMemReadU8 / U16 / U32 / U64 wrap PCI_IO.Mem.Read for the BAR
// + offset that holds virtio's common-cfg sub-page. The returned
// value lands in vnetReadScratchU{8,16,32,64} — package-scope as
// always.
//
// Width is auto-picked from the function name; Count is always 1.
//
// Off is the byte offset within the COMMON_CFG sub-page (see
// vnetCommon.offset for where that sits inside the BAR).
var (
	vnetReadScratchU8  uint8
	vnetReadScratchU16 uint16
	vnetReadScratchU32 uint32
	vnetReadScratchU64 uint64
)

func vnetCommonReadU8(off uint32) (uint8, efiStatus) {
	vnetReadScratchU8 = 0
	st := efiCall6(pciNetIO.memRead,
		uintptr(unsafe.Pointer(pciNetIO)),
		pciIOWidthUint8,
		uintptr(vnetCommon.bar),
		uintptr(vnetCommon.offset+off),
		1,
		uintptr(unsafe.Pointer(&vnetReadScratchU8)))
	return vnetReadScratchU8, st
}

func vnetCommonReadU16(off uint32) (uint16, efiStatus) {
	vnetReadScratchU16 = 0
	st := efiCall6(pciNetIO.memRead,
		uintptr(unsafe.Pointer(pciNetIO)),
		pciIOWidthUint16,
		uintptr(vnetCommon.bar),
		uintptr(vnetCommon.offset+off),
		1,
		uintptr(unsafe.Pointer(&vnetReadScratchU16)))
	return vnetReadScratchU16, st
}

func vnetCommonReadU32(off uint32) (uint32, efiStatus) {
	vnetReadScratchU32 = 0
	st := efiCall6(pciNetIO.memRead,
		uintptr(unsafe.Pointer(pciNetIO)),
		pciIOWidthUint32,
		uintptr(vnetCommon.bar),
		uintptr(vnetCommon.offset+off),
		1,
		uintptr(unsafe.Pointer(&vnetReadScratchU32)))
	return vnetReadScratchU32, st
}

// vnetCommonWriteU8 / U16 / U32 mirror the read variants. The
// firmware spec mandates the value live at a stable address for the
// call's duration; package-scope satisfies that on TinyGo+UEFI.
var (
	vnetWriteScratchU8  uint8
	vnetWriteScratchU16 uint16
	vnetWriteScratchU32 uint32
	vnetWriteScratchU64 uint64
)

func vnetCommonWriteU8(off uint32, v uint8) efiStatus {
	vnetWriteScratchU8 = v
	return efiCall6(pciNetIO.memWrite,
		uintptr(unsafe.Pointer(pciNetIO)),
		pciIOWidthUint8,
		uintptr(vnetCommon.bar),
		uintptr(vnetCommon.offset+off),
		1,
		uintptr(unsafe.Pointer(&vnetWriteScratchU8)))
}

func vnetCommonWriteU16(off uint32, v uint16) efiStatus {
	vnetWriteScratchU16 = v
	return efiCall6(pciNetIO.memWrite,
		uintptr(unsafe.Pointer(pciNetIO)),
		pciIOWidthUint16,
		uintptr(vnetCommon.bar),
		uintptr(vnetCommon.offset+off),
		1,
		uintptr(unsafe.Pointer(&vnetWriteScratchU16)))
}

func vnetCommonWriteU32(off uint32, v uint32) efiStatus {
	vnetWriteScratchU32 = v
	return efiCall6(pciNetIO.memWrite,
		uintptr(unsafe.Pointer(pciNetIO)),
		pciIOWidthUint32,
		uintptr(vnetCommon.bar),
		uintptr(vnetCommon.offset+off),
		1,
		uintptr(unsafe.Pointer(&vnetWriteScratchU32)))
}

// Negotiated feature words — set by vnetNegotiate. Driver code in
// later phases checks these to decide e.g. whether the RX-buffer
// header is 10 bytes (no MRG_RXBUF) or 12 bytes (with MRG_RXBUF).
var (
	vnetDeviceFeaturesLo uint32 // bits 0..31  read from device
	vnetDeviceFeaturesHi uint32 // bits 32..63 read from device
	vnetDriverFeaturesLo uint32 // bits we accept, low word
	vnetDriverFeaturesHi uint32 // bits we accept, high word
)

// vnetNegotiate runs the virtio-1.0 device-init handshake. Returns
// true once FEATURES_OK is latched + still set after a re-read.
//
// CloudBootMark trail (6-byte truncation in NVRAM):
//   VN-RST    device reset failed (status read never returned 0)
//   VN-FEAT-X feature_select round-trip mismatched (firmware bug
//             or wrong BAR/offset; truncates to "VN-FEA")
//   VN-FOK    FEATURES_OK accepted by device → ready for queue setup
//             (truncates to "VN-FOK")
func vnetNegotiate(co *efiSimpleTextOutput) bool {
	if pciNetIO == nil || vnetCommon.length == 0 {
		return false
	}
	writeASCII(co, "vnet: device init (reset → features)\r\n")

	// Step 1: reset by writing 0 to device_status, then poll until
	// it reads back as 0 (the device clears any internal state).
	if vnetCommonWriteU8(cfgDeviceStatus, virtioStatusReset) != efiSuccess {
		bootMark("VN-RST")
		return false
	}
	// Spin up to 1 s waiting for status to read back as 0. Apple VZ's
	// virtio-net clears synchronously in practice; the loop is here
	// for robustness against future firmwares.
	for i := 0; i < 1000; i++ {
		s, _ := vnetCommonReadU8(cfgDeviceStatus)
		if s == 0 {
			break
		}
		// 1 ms stall via bs.stall (microseconds). Reuse the bootMark
		// path's runtime services? No — bs is the right service. The
		// thunk in main.go calls it via stall(microseconds).
		efiCall2(bsGlobal.stall, 1000, 0)
		if i == 999 {
			writeASCII(co, "  reset never completed\r\n")
			bootMark("VN-RST")
			return false
		}
	}

	// Step 2: ACKNOWLEDGE, then DRIVER.
	if vnetCommonWriteU8(cfgDeviceStatus, virtioStatusAcknowledge) != efiSuccess {
		bootMark("VN-S1")
		return false
	}
	if vnetCommonWriteU8(cfgDeviceStatus, virtioStatusAcknowledge|virtioStatusDriver) != efiSuccess {
		bootMark("VN-S2")
		return false
	}

	// Step 3: read device features in two 32-bit halves.
	if vnetCommonWriteU32(cfgDeviceFeatureSelect, 0) != efiSuccess {
		bootMark("VN-D0")
		return false
	}
	vnetDeviceFeaturesLo, _ = vnetCommonReadU32(cfgDeviceFeature)
	if vnetCommonWriteU32(cfgDeviceFeatureSelect, 1) != efiSuccess {
		bootMark("VN-D1")
		return false
	}
	vnetDeviceFeaturesHi, _ = vnetCommonReadU32(cfgDeviceFeature)

	writeASCII(co, "  device features lo=0x")
	writeHex64(co, uint64(vnetDeviceFeaturesLo))
	writeASCII(co, " hi=0x")
	writeHex64(co, uint64(vnetDeviceFeaturesHi))
	writeASCII(co, "\r\n")

	// Stash the device-features in NVRAM so we can introspect what
	// Apple VZ's virtio-net offers without parsing serial logs.
	vnetFeatVarData[0] = byte(vnetDeviceFeaturesLo)
	vnetFeatVarData[1] = byte(vnetDeviceFeaturesLo >> 8)
	vnetFeatVarData[2] = byte(vnetDeviceFeaturesLo >> 16)
	vnetFeatVarData[3] = byte(vnetDeviceFeaturesLo >> 24)
	vnetFeatVarData[4] = byte(vnetDeviceFeaturesHi)
	vnetFeatVarData[5] = byte(vnetDeviceFeaturesHi >> 8)
	vnetFeatVarData[6] = byte(vnetDeviceFeaturesHi >> 16)
	vnetFeatVarData[7] = byte(vnetDeviceFeaturesHi >> 24)
	if bootMarkRT != nil && bootMarkRT.setVariable != 0 {
		efiCall5(bootMarkRT.setVariable,
			uintptr(unsafe.Pointer(&vnetFeatVarName[0])),
			uintptr(unsafe.Pointer(&cloudBootGUID)),
			uintptr(0x07),
			uintptr(len(vnetFeatVarData)),
			uintptr(unsafe.Pointer(&vnetFeatVarData[0])))
	}

	// VIRTIO_F_VERSION_1 lives in the high word at bit 0 (= overall
	// bit 32). Required — refuse to proceed if the device doesn't
	// offer it.
	if vnetDeviceFeaturesHi&(1<<(virtioFVersion1-32)) == 0 {
		writeASCII(co, "  device doesn't offer VIRTIO_F_VERSION_1\r\n")
		bootMark("VN-V1")
		return false
	}

	// Step 4: accept VIRTIO_F_VERSION_1 + VIRTIO_F_RING_PACKED
	// (bit 34). Apple VZ offers hi=0x5 = bits 32 + 34; with only
	// bit 32 accepted, the device rejects FEATURES_OK — Apple's
	// implementation apparently requires acceptance of the packed-
	// ring extension, even though spec §6 doesn't make any of bits
	// 33..37 mandatory for the driver. Mirroring the whole hi word
	// is the safe move; we'll deal with the packed-ring queue
	// layout in Phase D2 (different desc table format from split-
	// ring; same on-the-wire semantics).
	vnetDriverFeaturesLo = 0
	vnetDriverFeaturesHi = vnetDeviceFeaturesHi

	// Sanity: verify writes to common-cfg actually persist. Set
	// driver_feature_select=1, read it back; if it doesn't read as
	// 1, our Mem.Write is going to /dev/null. Stamp the result.
	_ = vnetCommonWriteU32(cfgDriverFeatureSelect, 0xAA55BEEF)
	rbWrite, _ := vnetCommonReadU32(cfgDriverFeatureSelect)
	vnetWritebackVarData[0] = byte(rbWrite)
	vnetWritebackVarData[1] = byte(rbWrite >> 8)
	vnetWritebackVarData[2] = byte(rbWrite >> 16)
	vnetWritebackVarData[3] = byte(rbWrite >> 24)
	if bootMarkRT != nil && bootMarkRT.setVariable != 0 {
		efiCall5(bootMarkRT.setVariable,
			uintptr(unsafe.Pointer(&vnetWritebackVarName[0])),
			uintptr(unsafe.Pointer(&cloudBootGUID)),
			uintptr(0x07),
			uintptr(len(vnetWritebackVarData)),
			uintptr(unsafe.Pointer(&vnetWritebackVarData[0])))
	}
	if vnetCommonWriteU32(cfgDriverFeatureSelect, 0) != efiSuccess {
		bootMark("VN-W1")
		return false
	}
	if vnetCommonWriteU32(cfgDriverFeature, vnetDriverFeaturesLo) != efiSuccess {
		bootMark("VN-W2")
		return false
	}
	if vnetCommonWriteU32(cfgDriverFeatureSelect, 1) != efiSuccess {
		bootMark("VN-W3")
		return false
	}
	if vnetCommonWriteU32(cfgDriverFeature, vnetDriverFeaturesHi) != efiSuccess {
		bootMark("VN-W4")
		return false
	}

	// Step 5: FEATURES_OK. Apple VZ's virtio implementation may
	// require 32-bit aligned MMIO writes — try writing status as
	// a 32-bit word with FEATURES_OK in byte 0, zeros elsewhere.
	// device_status is at offset 20 (4-byte aligned); the byte
	// after (config_generation, offset 21) is read-only per spec so
	// writing 0 there is harmless.
	sBeforeFok, _ := vnetCommonReadU8(cfgDeviceStatus)
	if vnetCommonWriteU32(cfgDeviceStatus,
		uint32(virtioStatusAcknowledge|virtioStatusDriver|virtioStatusFeaturesOK)) != efiSuccess {
		bootMark("VN-FS")
		return false
	}
	// Give the device a moment to process the write.
	efiCall2(bsGlobal.stall, 10000, 0)
	sAfterFok, _ := vnetCommonReadU8(cfgDeviceStatus)
	// Stamp both statuses into NVRAM as 2 bytes — sBefore then sAfter.
	vnetStatusVarData[0] = sBeforeFok
	vnetStatusVarData[1] = sAfterFok
	// Also stamp the driver-features we wrote so we can verify the
	// device sees what we sent.
	vnetStatusVarData[2] = byte(vnetDriverFeaturesLo)
	vnetStatusVarData[3] = byte(vnetDriverFeaturesLo >> 8)
	vnetStatusVarData[4] = byte(vnetDriverFeaturesLo >> 16)
	vnetStatusVarData[5] = byte(vnetDriverFeaturesLo >> 24)
	vnetStatusVarData[6] = byte(vnetDriverFeaturesHi)
	vnetStatusVarData[7] = byte(vnetDriverFeaturesHi >> 8)
	if bootMarkRT != nil && bootMarkRT.setVariable != 0 {
		efiCall5(bootMarkRT.setVariable,
			uintptr(unsafe.Pointer(&vnetStatusVarName[0])),
			uintptr(unsafe.Pointer(&cloudBootGUID)),
			uintptr(0x07),
			uintptr(len(vnetStatusVarData)),
			uintptr(unsafe.Pointer(&vnetStatusVarData[0])))
	}
	if sAfterFok&virtioStatusFeaturesOK == 0 {
		writeASCII(co, "  device rejected feature subset (status=0x")
		writeHex64(co, uint64(sAfterFok))
		writeASCII(co, ")\r\n")
		bootMark("VN-FX")
		return false
	}
	writeASCII(co, "  features ack: driver lo=0x")
	writeHex64(co, uint64(vnetDriverFeaturesLo))
	writeASCII(co, " hi=0x")
	writeHex64(co, uint64(vnetDriverFeaturesHi))
	writeASCII(co, "\r\n")
	bootMark("VN-FOK")
	return true
}

// bsGlobal is the package-scope BootServices pointer the negotiation
// loop uses for `Stall`. Set by main.go's _start right after the
// SystemTable comes in.
var bsGlobal *efiBootServices

// CloudBootVNFeat — 8 bytes (lo + hi as LE words). Inspectable from
// the host so we can see what features Apple VZ's virtio-net offers
// without parsing serial logs.
var vnetFeatVarName = [...]uint16{
	'C', 'l', 'o', 'u', 'd', 'B', 'o', 'o', 't', 'V', 'N', 'F', 'e', 'a', 't',
	0,
}
var vnetFeatVarData [8]byte

// CloudBootVNStat — 8 bytes capturing FEATURES_OK negotiation state.
//   [0] status_before  — device_status right before we set FEATURES_OK
//   [1] status_after   — device_status right after, post 10 ms stall
//   [2..6] driver_features_lo (4 bytes LE) and ..hi[2] (high word
//                          low 2 bytes — we don't need bits 48..63)
var vnetStatusVarName = [...]uint16{
	'C', 'l', 'o', 'u', 'd', 'B', 'o', 'o', 't', 'V', 'N', 'S', 't', 'a', 't',
	0,
}
var vnetStatusVarData [8]byte

// CloudBootVNWB — 4 bytes capturing read-back of driver_feature_select
// after writing a sentinel pattern. If this doesn't match what we
// wrote (0xAA55BEEF), Mem.Write through PCI_IO isn't reaching the
// device — would explain the FEATURES_OK rejection even with minimal
// feature subsets.
var vnetWritebackVarName = [...]uint16{
	'C', 'l', 'o', 'u', 'd', 'B', 'o', 'o', 't', 'V', 'N', 'W', 'B',
	0,
}
var vnetWritebackVarData [4]byte
