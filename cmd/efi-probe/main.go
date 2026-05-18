// Phase-0 probe — minimal UEFI app that calls LocateProtocol for the
// protocols we'll need for the pure-UEFI cloud-boot variant, and
// reports which ones the firmware exposes.
//
// Every buffer is package-scope to avoid any heap allocation —
// TinyGo's `gc: leaking` runtime would otherwise call VirtualAlloc,
// which is unresolved under UEFI and crashes on first dereference.
package main

import (
	"unsafe"
)

// ----- EFI primitive types -----

type efiStatus = uint64

const efiSuccess efiStatus = 0

type efiGUID [16]byte

type efiTableHeader struct {
	signature  uint64
	revision   uint32
	headerSize uint32
	crc32      uint32
	_reserved  uint32
}

type efiSimpleTextOutput struct {
	reset        uintptr
	outputString uintptr
}

type efiBootServices struct {
	hdr efiTableHeader

	raiseTPL   uintptr
	restoreTPL uintptr

	allocatePages uintptr
	freePages     uintptr
	getMemoryMap  uintptr
	allocatePool  uintptr
	freePool      uintptr

	createEvent  uintptr
	setTimer     uintptr
	waitForEvent uintptr
	signalEvent  uintptr
	closeEvent   uintptr
	checkEvent   uintptr

	installProtocolInterface   uintptr
	reinstallProtocolInterface uintptr
	uninstallProtocolInterface uintptr
	handleProtocol             uintptr
	_reserved                  uintptr
	registerProtocolNotify     uintptr
	locateHandle               uintptr
	locateDevicePath           uintptr
	installConfigurationTable  uintptr

	loadImage   uintptr
	startImage  uintptr
	exit        uintptr
	unloadImage uintptr

	exitBootServices uintptr

	getNextMonotonicCount uintptr
	stall                 uintptr
	setWatchdogTimer      uintptr

	connectController    uintptr
	disconnectController uintptr

	openProtocol            uintptr
	closeProtocol           uintptr
	openProtocolInformation uintptr

	protocolsPerHandle uintptr
	locateHandleBuffer uintptr
	locateProtocol     uintptr // 0x140 ← what we need
}

type efiSystemTable struct {
	hdr               efiTableHeader
	firmwareVendor    uintptr
	firmwareRevision  uint32
	consoleInHandle   uintptr
	conIn             uintptr
	consoleOutHandle  uintptr
	conOut            *efiSimpleTextOutput
	standardErrHandle uintptr
	stdErr            uintptr
	runtimeServices   uintptr
	bootServices      *efiBootServices
}

// ----- asm thunks (defined in thunk-arm64.S / thunk-amd64.S) -----

//go:linkname efiCall2 efiCall2
func efiCall2(fn, a, b uintptr) uint64

//go:linkname efiCall3 efiCall3
func efiCall3(fn, a, b, c uintptr) uint64

//go:linkname efiCall5 efiCall5
func efiCall5(fn, a, b, c, d, e uintptr) uint64

// ----- protocol GUIDs (package-scope, no heap) -----

var (
	httpServiceBindingGUID = efiGUID{
		0xAF, 0xE6, 0xC8, 0xBD,
		0xBC, 0xD9,
		0x79, 0x43,
		0xA7, 0x2A, 0xE0, 0xC4, 0xE7, 0x5D, 0xAE, 0x1C,
	}
	httpProtocolGUID = efiGUID{
		0x9B, 0xB2, 0x59, 0x7A,
		0x0B, 0x91,
		0x71, 0x41,
		0x82, 0x42, 0xA8, 0x5A, 0x0D, 0xF2, 0x5B, 0x5B,
	}
	tcp4ServiceBindingGUID = efiGUID{
		0x65, 0x06, 0x72, 0x00,
		0xEB, 0x67,
		0x99, 0x4A,
		0xBA, 0xF7, 0xD3, 0xC3, 0x3A, 0x1C, 0x7C, 0xC9,
	}
	dns4ServiceBindingGUID = efiGUID{
		0x86, 0xB1, 0x25, 0xB6,
		0x63, 0xE0,
		0xF7, 0x44,
		0x89, 0x05, 0x6A, 0x74, 0xDC, 0x6F, 0x52, 0xB4,
	}
	dhcp4ServiceBindingGUID = efiGUID{
		0xD8, 0x39, 0x9A, 0x9D,
		0x42, 0xBD,
		0x73, 0x4A,
		0xA4, 0xD5, 0x8E, 0xE9, 0x4B, 0xE1, 0x13, 0x80,
	}
	ip4Config2GUID = efiGUID{
		0xD1, 0x6E, 0x44, 0x5B,
		0x0B, 0xE3,
		0xAA, 0x4F,
		0x87, 0x1A, 0x36, 0x54, 0xEC, 0xA3, 0x60, 0x80,
	}
	blockIOGUID = efiGUID{
		0x21, 0x5B, 0x4E, 0x96,
		0x59, 0x64,
		0xD2, 0x11,
		0x8E, 0x39, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B,
	}
	simpleFileSystemGUID = efiGUID{
		0x22, 0x5B, 0x4E, 0x96,
		0x59, 0x64,
		0xD2, 0x11,
		0x8E, 0x39, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B,
	}
	// EFI_SIMPLE_NETWORK_PROTOCOL_GUID — A19832B9-AC25-11D3-9A2D-0090273FC14D
	// L2 packet I/O — what PXE-style firmwares always expose. If this
	// is present we can roll our own DHCP+ARP+IP+TCP+HTTP in TinyGo.
	simpleNetworkGUID = efiGUID{
		0xB9, 0x32, 0x98, 0xA1,
		0x25, 0xAC,
		0xD3, 0x11,
		0x9A, 0x2D, 0x00, 0x90, 0x27, 0x3F, 0xC1, 0x4D,
	}
	// EFI_PXE_BASE_CODE_PROTOCOL_GUID — 03c4e603-ac28-11d3-9a2d-0090273fc14d
	pxeBCGUID = efiGUID{
		0x03, 0xE6, 0xC4, 0x03,
		0x28, 0xAC,
		0xD3, 0x11,
		0x9A, 0x2D, 0x00, 0x90, 0x27, 0x3F, 0xC1, 0x4D,
	}
	// EFI_UDP4_SERVICE_BINDING_PROTOCOL_GUID — 83f01464-99bd-45e5-b383-af6305d8e9e6
	udp4ServiceBindingGUID = efiGUID{
		0x64, 0x14, 0xF0, 0x83,
		0xBD, 0x99,
		0xE5, 0x45,
		0xB3, 0x83, 0xAF, 0x63, 0x05, 0xD8, 0xE9, 0xE6,
	}
	// EFI_MANAGED_NETWORK_SERVICE_BINDING_PROTOCOL_GUID
	//   — f36ff770-a7e1-42cf-9ed2-56f0f271f44c
	mnpServiceBindingGUID = efiGUID{
		0x70, 0xF7, 0x6F, 0xF3,
		0xE1, 0xA7,
		0xCF, 0x42,
		0x9E, 0xD2, 0x56, 0xF0, 0xF2, 0x71, 0xF4, 0x4C,
	}
)

// Single package-scope output buffer reused by every writeASCII call.
// 256 UTF-16 chars is plenty for our diagnostic lines and keeps us
// off the heap (which doesn't exist in UEFI without VirtualAlloc).
var outBuf [256]uint16

// reportBuf accumulates a parallel ASCII copy of every line we print
// via writeASCII. On firmwares whose SimpleTextOutput is rendered to
// VGA but not to virtio-console (Apple Virtualization.framework
// being the canonical case), the probe result is invisible at run
// time — so we ALSO write `reportBuf` to a fixed disk sector via
// `EFI_BLOCK_IO_PROTOCOL.WriteBlocks` and let the host read it back
// with a plain `xxd -s offset` after the VM shuts down.
//
// 512 bytes = one LBA. The probe's full output fits comfortably.
var reportBuf [512]byte
var reportLen int

func reportAppendASCII(s string) {
	for i := 0; i < len(s) && reportLen < len(reportBuf); i++ {
		reportBuf[reportLen] = s[i]
		reportLen++
	}
}

func reportAppendHex64(n uint64) {
	const hex = "0123456789ABCDEF"
	if reportLen+18 > len(reportBuf) {
		return
	}
	reportBuf[reportLen] = '0'
	reportBuf[reportLen+1] = 'x'
	for i := 0; i < 16; i++ {
		reportBuf[reportLen+2+i] = hex[(n>>uint(60-4*i))&0xF]
	}
	reportLen += 18
}

func writeASCII(co *efiSimpleTextOutput, s string) {
	reportAppendASCII(s)
	n := 0
	for i := 0; i < len(s) && n < len(outBuf)-1; i++ {
		c := s[i]
		if c == '\n' {
			outBuf[n] = '\r'
			n++
			if n >= len(outBuf)-1 {
				break
			}
		}
		outBuf[n] = uint16(c)
		n++
	}
	outBuf[n] = 0
	efiCall2(co.outputString,
		uintptr(unsafe.Pointer(co)),
		uintptr(unsafe.Pointer(&outBuf[0])))
}

func writeHex64(co *efiSimpleTextOutput, n uint64) {
	reportAppendHex64(n)
	const hex = "0123456789ABCDEF"
	outBuf[0] = '0'
	outBuf[1] = 'x'
	for i := 0; i < 16; i++ {
		outBuf[2+i] = uint16(hex[(n>>uint(60-4*i))&0xF])
	}
	outBuf[18] = 0
	efiCall2(co.outputString,
		uintptr(unsafe.Pointer(co)),
		uintptr(unsafe.Pointer(&outBuf[0])))
}

// efiBlockIOProtocol — first three slots only. Media descriptor at
// +0x08 carries BlockSize / LastBlock, but we hard-code LBA at the
// call site so we don't need to dereference it.
type efiBlockIOProtocol struct {
	revision    uint64  // 0x00
	media       uintptr // 0x08 → EFI_BLOCK_IO_MEDIA
	reset       uintptr // 0x10
	readBlocks  uintptr // 0x18
	writeBlocks uintptr // 0x20 — WriteBlocks(this, mediaId, lba, size, buf)
	flushBlocks uintptr // 0x28
}

// efiBlockIOMedia — only the fields we read: MediaId (0x00) and
// LastBlock (0x18) on PE32+/aligned struct layout.
type efiBlockIOMedia struct {
	mediaId         uint32  // 0x00
	removableMedia  uint8   // 0x04
	mediaPresent    uint8   // 0x05
	logicalPartition uint8  // 0x06
	readOnly        uint8   // 0x07
	writeCaching    uint8   // 0x08
	_pad            [3]byte // 0x09..0x0B
	blockSize       uint32  // 0x0C
	ioAlign         uint32  // 0x10
	_pad2           uint32  // 0x14
	lastBlock       uint64  // 0x18
}

// writeReportToDisk dumps reportBuf to LBA `lastBlock` of every
// BlockIO handle that's not a logical partition. The duplication
// is intentional — under Apple VZ we don't know in advance which
// handle is "our" boot disk vs the cidata ISO vs another, and
// writing to all of them with a leading "cb-probe " marker lets
// the host trivially find the right one.
func writeReportToDisk(bs *efiBootServices) uint64 {
	// Prepend an unambiguous marker so the host can grep.
	marker := "cb-probe\x00"
	// Shift report right by 9 bytes.
	if reportLen > len(reportBuf)-len(marker) {
		reportLen = len(reportBuf) - len(marker)
	}
	for i := reportLen - 1; i >= 0; i-- {
		reportBuf[i+len(marker)] = reportBuf[i]
	}
	for i := 0; i < len(marker); i++ {
		reportBuf[i] = marker[i]
	}
	reportLen += len(marker)

	// LocateHandleBuffer-style enumeration via LocateProtocol is too
	// rich for our needs — LocateProtocol picks the first handle
	// supporting the GUID, which is usually the whole disk. That's
	// what we want for the boot media.
	var blockIO uintptr
	st := efiCall3(bs.locateProtocol,
		uintptr(unsafe.Pointer(&blockIOGUID)),
		0,
		uintptr(unsafe.Pointer(&blockIO)))
	if st != efiSuccess {
		return st
	}
	bio := (*efiBlockIOProtocol)(unsafe.Pointer(blockIO))
	media := (*efiBlockIOMedia)(unsafe.Pointer(bio.media))
	// Write 1 LBA at the disk's last block. 512-byte FAT16 means
	// lastBlock = 8191 for our 4 MiB probe disk.
	return efiCall5(bio.writeBlocks,
		blockIO,
		uintptr(media.mediaId),
		uintptr(media.lastBlock),
		uintptr(media.blockSize),
		uintptr(unsafe.Pointer(&reportBuf[0])))
}

// Holder for LocateProtocol's out pointer. Single instance, reused.
var ifaceHolder uintptr

func probe(co *efiSimpleTextOutput, bs *efiBootServices, name string, guid *efiGUID) {
	ifaceHolder = 0
	st := efiCall3(bs.locateProtocol,
		uintptr(unsafe.Pointer(guid)),
		0,
		uintptr(unsafe.Pointer(&ifaceHolder)))
	writeASCII(co, "  ")
	writeASCII(co, name)
	writeASCII(co, ": ")
	if st == efiSuccess {
		writeASCII(co, "FOUND iface=")
		writeHex64(co, uint64(ifaceHolder))
		writeASCII(co, "\r\n")
	} else {
		writeASCII(co, "NOT FOUND status=")
		writeHex64(co, st)
		writeASCII(co, "\r\n")
	}
}

//go:export _start
func _start(imageHandle uintptr, st *efiSystemTable) efiStatus {
	co := st.conOut
	bs := st.bootServices

	writeASCII(co, "cloud-boot/loader probe — phase 0\r\n")

	probe(co, bs, "EFI_HTTP_SERVICE_BINDING ", &httpServiceBindingGUID)
	probe(co, bs, "EFI_HTTP_PROTOCOL        ", &httpProtocolGUID)
	probe(co, bs, "EFI_TCP4_SERVICE_BINDING ", &tcp4ServiceBindingGUID)
	probe(co, bs, "EFI_UDP4_SERVICE_BINDING ", &udp4ServiceBindingGUID)
	probe(co, bs, "EFI_DNS4_SERVICE_BINDING ", &dns4ServiceBindingGUID)
	probe(co, bs, "EFI_DHCP4_SERVICE_BINDING", &dhcp4ServiceBindingGUID)
	probe(co, bs, "EFI_IP4_CONFIG2          ", &ip4Config2GUID)
	probe(co, bs, "EFI_MNP_SERVICE_BINDING  ", &mnpServiceBindingGUID)
	probe(co, bs, "EFI_PXE_BASE_CODE        ", &pxeBCGUID)
	probe(co, bs, "EFI_SIMPLE_NETWORK       ", &simpleNetworkGUID)
	probe(co, bs, "EFI_BLOCK_IO             ", &blockIOGUID)
	probe(co, bs, "EFI_SIMPLE_FILE_SYSTEM   ", &simpleFileSystemGUID)

	writeASCII(co, "PROBE-DONE\r\n")

	// Persisting the report to disk via BlockIO.WriteBlocks proved
	// fragile under Apple VZ (EDK2 strict memory protection bites the
	// callback path). Until we have a robust capture mechanism, only
	// firmwares that route SimpleTextOutput to a host-readable serial
	// (QEMU + OVMF, hardware EFI consoles) can read the result.
	_ = bs
	_ = writeReportToDisk
	for {
	}
}

func main() {}
