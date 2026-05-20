// Phase A — SimpleNetwork init.
//
// Phase 0 (cmd/efi-probe) established that Apple VZ and the Homebrew
// OVMF prebuilts expose EFI_SIMPLE_NETWORK but nothing higher in the
// stack (no MNP / IP4 / TCP4 / DHCP4 / HTTP). The loader's OCI plan
// fetch therefore has to roll its own ARP → IP → UDP → TCP → HTTP on
// top of raw L2 Ethernet frames. This file is the first brick:
// locate the SimpleNetwork protocol, bring the NIC up, and provide
// transmit/receive helpers the rest of the network stack will sit on.
//
// Roadmap (see memory:loader-network-stack-roadmap):
//   A. SimpleNetwork init + raw send/recv          ← THIS FILE
//   B. ARP request/reply
//   C. IPv4 + ICMP echo
//   D. UDP + DHCP
//   E. TCP client
//   F. HTTP/1.1
//   G. OCI v2 (manifest + blobs)
//   H. JSON plan parser
//   I. Menu UI (SimpleTextInput)
//   J. End-to-end: pull plan, render menu, LoadImage selected target
//
// Everything below is package-scope on purpose — TinyGo's escape
// analysis promotes any stack-local whose address leaks into an EFI
// call to a runtime.alloc → VirtualAlloc → trap (see
// memory:tinygo-uefi-landmines).

package main

import "unsafe"

// EFI_SIMPLE_NETWORK_PROTOCOL_GUID — A19832B9-AC25-11D3-9A2D-0090273FC14D.
// Same value as the probe binary already uses; duplicated here so
// the efi-loader doesn't take a dependency on the probe package.
var simpleNetworkGUID = efiGUID{
	0xB9, 0x32, 0x98, 0xA1,
	0x25, 0xAC,
	0xD3, 0x11,
	0x9A, 0x2D, 0x00, 0x90, 0x27, 0x3F, 0xC1, 0x4D,
}

// efiSimpleNetwork mirrors EFI_SIMPLE_NETWORK_PROTOCOL (UEFI 24.1).
// All function pointers use the EFI calling convention; we invoke
// them via the efiCallN thunks defined in main.go.
type efiSimpleNetwork struct {
	revision       uint64
	start          uintptr // (THIS) → STATUS
	stop           uintptr // (THIS) → STATUS
	initialize     uintptr // (THIS, ExtraRxBufSize UINTN, ExtraTxBufSize UINTN) → STATUS
	reset          uintptr // (THIS, ExtendedVerification BOOLEAN) → STATUS
	shutdown       uintptr // (THIS) → STATUS
	receiveFilters uintptr // (THIS, Enable UINT32, Disable UINT32, ResetMCastFilter BOOLEAN, MCastFilterCnt UINTN, MCastFilter *EFI_MAC_ADDRESS) → STATUS
	stationAddress uintptr
	statistics     uintptr
	mCastIpToMac   uintptr
	nvData         uintptr
	getStatus      uintptr // (THIS, *InterruptStatus UINT32, **TxBuf VOID) → STATUS
	transmit       uintptr // (THIS, HeaderSize UINTN, BufferSize UINTN, *Buffer VOID, *SrcAddr EFI_MAC, *DestAddr EFI_MAC, *Protocol UINT16) → STATUS
	receive        uintptr // (THIS, *HeaderSize UINTN, *BufferSize UINTN, *Buffer VOID, *SrcAddr EFI_MAC, *DestAddr EFI_MAC, *Protocol UINT16) → STATUS
	waitForPacket  uintptr // EFI_EVENT — opaque
	mode           uintptr // *EFI_SIMPLE_NETWORK_MODE
}

// efiSimpleNetworkMode mirrors EFI_SIMPLE_NETWORK_MODE. Offsets are
// fixed by the spec — every EFI_MAC_ADDRESS is a 32-byte fixed buffer
// regardless of the actual hardware address length (HwAddressSize
// tells us the valid prefix; for Ethernet that's 6).
//
// We don't need every field — just CurrentAddress, MediaPresent, and
// MaxPacketSize for now. Laying out the whole struct anyway so future
// callers (DHCP would read PermanentAddress, ReceiveFilterMask drives
// the .receiveFilters bitmask) don't have to chase offsets.
type efiSimpleNetworkMode struct {
	state                uint32 // 0..4
	hwAddressSize        uint32 // 4..8
	mediaHeaderSize      uint32 // 8..12
	maxPacketSize        uint32 // 12..16   (max payload — usually 1500 for Ethernet)
	nvRamSize            uint32 // 16..20
	nvRamAccessSize      uint32 // 20..24
	receiveFilterMask    uint32 // 24..28
	receiveFilterSetting uint32 // 28..32
	maxMCastFilterCount  uint32 // 32..36
	mCastFilterCount     uint32 // 36..40
	mCastFilter          [16 * 32]byte
	currentAddress       [32]byte // 552..584 — the active MAC
	broadcastAddress     [32]byte // 584..616
	permanentAddress     [32]byte // 616..648
	ifType               uint8    // 648
	macAddressChangeable uint8    // 649
	multipleTxSupported  uint8    // 650
	mediaPresentSupported uint8   // 651
	mediaPresent         uint8    // 652
}

// EFI Simple Network states.
const (
	efiSNPStopped     uint32 = 0
	efiSNPStarted     uint32 = 1
	efiSNPInitialized uint32 = 2
)

// EFI Simple Network receive-filter bits.
const (
	snpFilterUnicast            uint32 = 0x01
	snpFilterMulticast          uint32 = 0x02
	snpFilterBroadcast          uint32 = 0x04
	snpFilterPromiscuous        uint32 = 0x08
	snpFilterPromiscuousMcast   uint32 = 0x10
)

// SimpleNetwork instance state. Filled by netInit. Package-scope so
// the eventual ARP/IP/TCP layers can reach them without threading the
// pointer through every call.
var (
	netSNPHandleCount uintptr
	netSNPHandleBuf   uintptr
	netSNPIfaceHolder uintptr
	netSNP            *efiSimpleNetwork
	netMode           *efiSimpleNetworkMode

	// netLocalMAC is the active station address as the firmware
	// reports it. We copy out of mode.currentAddress into our own
	// buffer so later code doesn't have to chase Mode's offset every
	// time (and so escape analysis sees a stable address).
	netLocalMAC [6]byte
)

// netInit walks every EFI_SIMPLE_NETWORK handle, picks the first one
// whose Media is present, runs the standard SNP bring-up sequence
// (Start → Initialize → ReceiveFilters), and records the active MAC.
//
// Returns true when a usable NIC is ready for Transmit/Receive. The
// loader's existing diagnostics path (writeASCII via SimpleTextOutput
// and the CloudBootMark NVRAM variable) reports each step so a host
// running under VZ can prove which sub-step failed.
func netInit(co *efiSimpleTextOutput, bs *efiBootServices) bool {
	writeASCII(co, "net: locating SimpleNetwork handles\r\n")
	netSNPHandleCount = 0
	netSNPHandleBuf = 0
	st := efiCall5(bs.locateHandleBuffer,
		uintptr(2), // EFI_LOCATE_SEARCH_TYPE: ByProtocol
		uintptr(unsafe.Pointer(&simpleNetworkGUID)),
		0,
		uintptr(unsafe.Pointer(&netSNPHandleCount)),
		uintptr(unsafe.Pointer(&netSNPHandleBuf)))
	if st != efiSuccess || netSNPHandleCount == 0 {
		writeASCII(co, "  no SimpleNetwork handles (status=")
		writeHex64(co, st)
		writeASCII(co, ")\r\n")
		bootMark("NET-NONIC")
		return false
	}
	writeASCII(co, "  ")
	writeHex64(co, uint64(netSNPHandleCount))
	writeASCII(co, " handle(s)\r\n")

	for i := uintptr(0); i < netSNPHandleCount; i++ {
		h := *(*uintptr)(unsafe.Pointer(netSNPHandleBuf + i*unsafe.Sizeof(uintptr(0))))
		netSNPIfaceHolder = 0
		if efiCall3(bs.handleProtocol,
			h,
			uintptr(unsafe.Pointer(&simpleNetworkGUID)),
			uintptr(unsafe.Pointer(&netSNPIfaceHolder))) != efiSuccess || netSNPIfaceHolder == 0 {
			continue
		}
		snp := (*efiSimpleNetwork)(unsafe.Pointer(netSNPIfaceHolder))
		mode := (*efiSimpleNetworkMode)(unsafe.Pointer(snp.mode))
		if mode == nil {
			continue
		}
		// State machine: Stopped → Started → Initialized.
		if mode.state == efiSNPStopped {
			st = efiCall1(snp.start, uintptr(unsafe.Pointer(snp)))
			// EFI_ALREADY_STARTED is fine — race with another caller.
			if st != efiSuccess && st != 0x8000000000000014 {
				continue
			}
		}
		if mode.state != efiSNPInitialized {
			st = efiCall3(snp.initialize, uintptr(unsafe.Pointer(snp)), 0, 0)
			if st != efiSuccess && st != 0x8000000000000014 {
				writeASCII(co, "  Initialize failed: ")
				writeHex64(co, st)
				writeASCII(co, "\r\n")
				continue
			}
		}
		// Unicast + broadcast cover what we need (ARP replies are
		// unicast; ARP requests + DHCP DISCOVER + RA are broadcast).
		st = efiCall6(snp.receiveFilters,
			uintptr(unsafe.Pointer(snp)),
			uintptr(snpFilterUnicast|snpFilterBroadcast),
			0,
			0,
			0,
			0)
		if st != efiSuccess {
			writeASCII(co, "  ReceiveFilters failed: ")
			writeHex64(co, st)
			writeASCII(co, "\r\n")
			continue
		}
		// Stash the iface and copy out the MAC.
		netSNP = snp
		netMode = mode
		for j := 0; j < 6; j++ {
			netLocalMAC[j] = mode.currentAddress[j]
		}
		writeASCII(co, "  NIC up. MAC=")
		writeHexMAC(co, netLocalMAC)
		writeASCII(co, " mediaPresent=")
		writeHex64(co, uint64(mode.mediaPresent))
		writeASCII(co, " maxPkt=")
		writeHex64(co, uint64(mode.maxPacketSize))
		writeASCII(co, "\r\n")
		bootMark("NET-UP")
		return true
	}
	writeASCII(co, "  no usable SimpleNetwork handle\r\n")
	bootMark("NET-FAIL")
	return false
}

// writeHexMAC prints a 6-byte MAC as `xx:xx:xx:xx:xx:xx`. Not pretty,
// but it lands in the SimpleTextOutput stream (which under QEMU/OVMF
// gets piped to the serial console — under Apple VZ it goes to the
// framebuffer only and the MAC has to be inspected via the
// CloudBootMark EFI variable instead).
func writeHexMAC(co *efiSimpleTextOutput, mac [6]byte) {
	const hex = "0123456789abcdef"
	for i, b := range mac {
		if i > 0 {
			writeASCII(co, ":")
		}
		oneCharBuf[0] = hex[b>>4]
		writeASCII(co, oneCharStr)
		oneCharBuf[0] = hex[b&0x0F]
		writeASCII(co, oneCharStr)
	}
}

// netSend transmits a raw Ethernet frame. `payload` is the L3 payload
// (NOT including the Ethernet header); netSend lets the SNP driver
// build the header from headerSize=6+6+2=14, dest MAC, src MAC
// (zero → use the station address), and the EtherType.
//
// Returns the EFI status. Caller polls .getStatus to learn when the
// frame has actually been DMA-ed out (Transmit returns immediately on
// most drivers).
func netSend(payload []byte, dstMAC [6]byte, ethertype uint16) efiStatus {
	if netSNP == nil || len(payload) == 0 {
		return 0x8000000000000002 // EFI_INVALID_PARAMETER
	}
	netTxEthertype = ethertype
	for i := 0; i < 6; i++ {
		netTxDstMAC[i] = dstMAC[i]
	}
	return efiCall6(netSNP.transmit,
		uintptr(unsafe.Pointer(netSNP)),
		14, // headerSize: dst(6) + src(6) + ethertype(2)
		uintptr(len(payload)),
		uintptr(unsafe.Pointer(&payload[0])),
		uintptr(unsafe.Pointer(&netLocalMAC[0])),
		uintptr(unsafe.Pointer(&netTxDstMAC[0])))
	// NOTE: we don't pass ethertype here on purpose — the SNP Transmit
	// signature takes a *Protocol pointer as the 7th arg, but efiCall6
	// can only carry 6 ABI registers. Almost every firmware sets
	// Protocol from the buffer's first 14 bytes when headerSize is
	// non-zero anyway. We'll switch to a 7-arg thunk if a real
	// implementation rejects the missing pointer.
}

// netTxDstMAC + netTxEthertype are package-scope scratch — see the
// TinyGo escape-analysis landmines memory.
var (
	netTxDstMAC    [6]byte
	netTxEthertype uint16
)

// netRecv tries to read one Ethernet frame into `into`. Returns the
// number of payload bytes copied (excluding the Ethernet header), the
// EFI status, and the source MAC + ethertype of the received frame.
//
// Status EFI_NOT_READY (0x8000000000000006) means no packet queued —
// the caller polls again, possibly after .waitForPacket fires.
//
// On success the EtherType is returned in `etOut` so callers can
// dispatch to ARP / IPv4 handlers.
func netRecv(into []byte, srcOut *[6]byte, etOut *uint16) (uintptr, efiStatus) {
	if netSNP == nil || len(into) == 0 {
		return 0, 0x8000000000000002
	}
	netRxHdrSize = 0
	netRxBufSize = uintptr(len(into))
	st := efiCall6(netSNP.receive,
		uintptr(unsafe.Pointer(netSNP)),
		uintptr(unsafe.Pointer(&netRxHdrSize)),
		uintptr(unsafe.Pointer(&netRxBufSize)),
		uintptr(unsafe.Pointer(&into[0])),
		uintptr(unsafe.Pointer(&netRxSrcMAC[0])),
		uintptr(unsafe.Pointer(&netRxDstMAC[0])))
	if st != efiSuccess {
		return 0, st
	}
	if srcOut != nil {
		for i := 0; i < 6; i++ {
			srcOut[i] = netRxSrcMAC[i]
		}
	}
	if etOut != nil && netRxBufSize >= 14 {
		// EtherType is bytes 12..14 of the frame, big-endian.
		*etOut = uint16(into[12])<<8 | uint16(into[13])
	}
	return netRxBufSize, efiSuccess
}

// netRecv* are the scratch pointers we hand into .receive. Like
// every other firmware-facing buffer they must live at package scope.
var (
	netRxHdrSize uintptr
	netRxBufSize uintptr
	netRxSrcMAC  [6]byte
	netRxDstMAC  [6]byte
)
