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

//go:linkname efiCall1 efiCall1
func efiCall1(fn, a uintptr) uint64

//go:linkname efiCall2 efiCall2
func efiCall2(fn, a, b uintptr) uint64

//go:linkname efiCall3 efiCall3
func efiCall3(fn, a, b, c uintptr) uint64

//go:linkname efiCall4 efiCall4
func efiCall4(fn, a, b, c, d uintptr) uint64

//go:linkname efiCall5 efiCall5
func efiCall5(fn, a, b, c, d, e uintptr) uint64

//go:linkname efiCall6 efiCall6
func efiCall6(fn, a, b, c, d, e, f uintptr) uint64

// ----- EFI service binding protocol (UEFI 2.10 §10.1) -----
//
// The "service binding" pattern: the SB protocol creates per-instance
// child handles that themselves carry the actual service protocol.
// HTTP / TCP4 / DNS4 / DHCP4 all follow this — LocateProtocol on the
// SB GUID returns the binding, then CreateChild gives us a fresh
// handle with the real protocol installed on it.
type efiServiceBinding struct {
	createChild  uintptr // 0x00 — EFI_STATUS (*)(SB *this, EFI_HANDLE *outChild)
	destroyChild uintptr // 0x08 — EFI_STATUS (*)(SB *this, EFI_HANDLE child)
}

// ----- EFI HTTP protocol (UEFI 2.10 §29.4) -----

// efiHTTPProtocol — function table installed on the child handle by
// the service binding. All five non-poll calls are 2-arg.
type efiHTTPProtocol struct {
	getModeData uintptr // 0x00 — EFI_STATUS (*)(HTTP *, HTTP_CONFIG_DATA *)
	configure   uintptr // 0x08 — EFI_STATUS (*)(HTTP *, HTTP_CONFIG_DATA *or NULL)
	request     uintptr // 0x10 — EFI_STATUS (*)(HTTP *, HTTP_TOKEN *)
	cancel      uintptr // 0x18 — EFI_STATUS (*)(HTTP *, HTTP_TOKEN *)
	response    uintptr // 0x20 — EFI_STATUS (*)(HTTP *, HTTP_TOKEN *)
	poll        uintptr // 0x28 — EFI_STATUS (*)(HTTP *)
}

// efiHTTPConfigData mirrors the C layout exactly. CGo would compute
// these offsets automatically; here we lay them out by hand. Keep the
// padding bytes explicit so a structural change shows up as a Go diff
// rather than a silent firmware fault.
//
//	UINT32 HttpVersion          // 0x00 enum: 0=HTTP/1.0, 1=HTTP/1.1
//	UINT32 TimeOutMillisec      // 0x04
//	BOOLEAN LocalAddressIsIPv6  // 0x08 (1 byte + 7-byte pad to align ptr)
//	VOID *AccessPoint           // 0x10 → *efiHTTPv4AccessPoint
type efiHTTPConfigData struct {
	httpVersion        uint32
	timeOutMillisec    uint32
	localAddressIsIPv6 uint8
	_pad               [7]byte
	accessPoint        uintptr
}

// efiHTTPv4AccessPoint:
//
//	BOOLEAN UseDefaultAddress  // 0x00 + 3-byte pad
//	UINT8 LocalAddress[4]      // 0x04
//	UINT8 LocalSubnet[4]       // 0x08
//	UINT16 LocalPort           // 0x0C + 2-byte pad
type efiHTTPv4AccessPoint struct {
	useDefaultAddress uint8
	_pad              [3]byte
	localAddress      [4]byte
	localSubnet       [4]byte
	localPort         uint16
	_pad2             [2]byte
}

// efiHTTPRequestData — passed via efiHTTPMessage.data for outgoing
// requests:
//
//	EFI_HTTP_METHOD Method   // UINT32 enum: 0=GET, 1=POST, 5=HEAD …
//	CHAR16 *Url              // null-terminated UTF-16 URL
type efiHTTPRequestData struct {
	method uint32
	_pad   uint32
	url    uintptr // CHAR16 *
}

// efiHTTPResponseData — incoming responses:
//
//	EFI_HTTP_STATUS_CODE StatusCode  // UINT32 enum
type efiHTTPResponseData struct {
	statusCode uint32
}

// efiHTTPHeader:
//
//	CHAR8 *FieldName
//	CHAR8 *FieldValue
type efiHTTPHeader struct {
	fieldName  uintptr
	fieldValue uintptr
}

// efiHTTPMessage — message body shared by Request and Response:
//
//	union { Request *, Response * } Data  // 8 bytes
//	UINTN HeaderCount                     // 8 bytes
//	EFI_HTTP_HEADER *Headers              // 8 bytes
//	UINTN BodyLength                      // 8 bytes (in/out: caller's
//	                                      // buffer cap on input,
//	                                      // bytes-written on output)
//	VOID *Body                            // 8 bytes (caller-allocated)
type efiHTTPMessage struct {
	data        uintptr // points at request or response struct
	headerCount uintptr
	headers     uintptr
	bodyLength  uintptr
	body        uintptr
}

// efiHTTPToken — the async handshake unit:
//
//	EFI_EVENT Event       // 8 bytes (firmware-allocated handle)
//	EFI_STATUS Status     // 8 bytes
//	EFI_HTTP_MESSAGE *Msg // 8 bytes
type efiHTTPToken struct {
	event   uintptr
	status  uintptr // EFI_STATUS is UINTN
	message uintptr
}

// ----- EFI IP4 config 2 protocol (UEFI 2.10 §28.4) -----
//
// HTTP's "UseDefaultAddress=TRUE" tells the stack to pull its IP
// from EFI_IP4_CONFIG2 — but the IP4 stack only initiates DHCP
// when its policy is explicitly set. OVMF doesn't auto-DHCP for
// arbitrary EFI apps; we have to do it ourselves.
type efiIP4Config2Protocol struct {
	setData              uintptr // 0x00 — EFI_STATUS (*)(this, DataType, DataSize, Data)
	getData              uintptr // 0x08 — EFI_STATUS (*)(this, DataType, &DataSize, Data)
	registerDataNotify   uintptr // 0x10
	unregisterDataNotify uintptr // 0x18
}

const (
	ip4Config2DataTypePolicy = 0 // EFI_IP4_CONFIG2_DATA_TYPE: Ip4Config2DataTypePolicy
	ip4Config2PolicyDhcp     = 1 // EFI_IP4_CONFIG2_POLICY:    Ip4Config2PolicyDhcp
)

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
	mediaId          uint32  // 0x00
	removableMedia   uint8   // 0x04
	mediaPresent     uint8   // 0x05
	logicalPartition uint8   // 0x06
	readOnly         uint8   // 0x07
	writeCaching     uint8   // 0x08
	_pad             [3]byte // 0x09..0x0B
	blockSize        uint32  // 0x0C
	ioAlign          uint32  // 0x10
	_pad2            uint32  // 0x14
	lastBlock        uint64  // 0x18
}

// All EFI out-pointers — kept package-scope. Stack-local vars whose
// address is handed to firmware via unsafe.Pointer trigger TinyGo's
// escape analysis to heap-allocate them, which under UEFI ends in
// runtime.alloc → VirtualAlloc (unresolved) → instruction abort.
var (
	httpChildHandle    uintptr
	httpProtocolHolder uintptr
	httpSBHolder       uintptr
	httpConfig         efiHTTPConfigData
	httpV4AP           efiHTTPv4AccessPoint

	// Request/response state — all package-scope per the
	// "no-heap-under-UEFI" rule.
	reqEvent  uintptr
	respEvent uintptr

	reqToken  efiHTTPToken
	respToken efiHTTPToken

	reqMessage  efiHTTPMessage
	respMessage efiHTTPMessage

	reqData  efiHTTPRequestData
	respData efiHTTPResponseData

	// One Host header is enough for HTTP/1.1.
	reqHeaders [1]efiHTTPHeader

	// CHAR8 header field name/value buffers.
	hdrHost      = [...]byte{'H', 'o', 's', 't', 0}
	hdrHostValue = [...]byte{'1', '0', '.', '0', '.', '2', '.', '2', ':', '5', '0', '0', '0', 0}

	// Target URL — UTF-16LE, null-terminated. Pre-encoded so we
	// don't need a runtime ASCII→UTF-16 conversion. The probe hits
	// the OCI catalog endpoint which any registry:2 instance
	// answers with `{"repositories":[…]}`.
	reqURL = [...]uint16{
		'h', 't', 't', 'p', ':', '/', '/',
		'1', '0', '.', '0', '.', '2', '.', '2', ':', '5', '0', '0', '0',
		'/', 'v', '2', '/', 0,
	}

	// 4 KiB caller-allocated body buffer for the response.
	respBody [4096]byte

	// IP4 config policy buffer + holder for the IP4Config2 protocol.
	ip4Config2Holder uintptr
	ip4PolicyDhcp    uint32 = ip4Config2PolicyDhcp

	// LocateHandleBuffer out-params for the NIC walk.
	nicHandleCount uintptr
	nicHandleBuf   uintptr

	// HandleProtocol out-pointer used in the per-NIC IP4Config2
	// loop. Must be package-scope — stack-local + & under TinyGo
	// trips escape-to-heap (runtime.alloc → VirtualAlloc → fault).
	nicIfaceHolder uintptr
)

// connectAllNICs walks every EFI_SIMPLE_NETWORK handle in the system
// and recursively ConnectController's it. This drives the firmware's
// DriverBinding machinery up the network protocol stack (SNP → MNP →
// IP4 → TCP4 → HTTP), which OVMF does not do on its own when an EFI
// app is loaded directly from a FAT volume rather than via the boot
// manager's HTTP/PXE path. The enumeration result (nicHandleCount,
// nicHandleBuf) is left in place for later passes that need to walk
// the NIC handles again (e.g. per-NIC IP4Config2 lookup).
func connectAllNICs(co *efiSimpleTextOutput, bs *efiBootServices) {
	nicHandleCount = 0
	nicHandleBuf = 0
	st := efiCall5(bs.locateHandleBuffer,
		uintptr(2), // EFI_LOCATE_SEARCH_TYPE: ByProtocol
		uintptr(unsafe.Pointer(&simpleNetworkGUID)),
		0,
		uintptr(unsafe.Pointer(&nicHandleCount)),
		uintptr(unsafe.Pointer(&nicHandleBuf)))
	if st != efiSuccess || nicHandleCount == 0 {
		writeASCII(co, "  connectAllNICs: no SimpleNetwork handles (status=")
		writeHex64(co, st)
		writeASCII(co, ")\r\n")
		return
	}
	writeASCII(co, "  connectAllNICs: ")
	writeHex64(co, uint64(nicHandleCount))
	writeASCII(co, " handle(s)\r\n")
	for i := uintptr(0); i < nicHandleCount; i++ {
		h := *(*uintptr)(unsafe.Pointer(nicHandleBuf + i*unsafe.Sizeof(uintptr(0))))
		cst := efiCall4(bs.connectController,
			h, 0, 0, 1, // DriverImageHandle=NULL, RemainingDP=NULL, Recursive=TRUE
		)
		writeASCII(co, "    ConnectController h=")
		writeHex64(co, uint64(h))
		writeASCII(co, " → ")
		writeHex64(co, cst)
		writeASCII(co, "\r\n")
	}
	// Stall briefly so any driver-initiated DHCP can get under way.
	efiCall2(bs.stall, 500_000, 0)
}

func probeHTTPChild(co *efiSimpleTextOutput, bs *efiBootServices, imageHandle uintptr) {
	// Step 1: LocateProtocol(EFI_HTTP_SERVICE_BINDING).
	httpSBHolder = 0
	st := efiCall3(bs.locateProtocol,
		uintptr(unsafe.Pointer(&httpServiceBindingGUID)),
		0,
		uintptr(unsafe.Pointer(&httpSBHolder)))
	if st != efiSuccess {
		writeASCII(co, "  LocateProtocol(HTTP_SB) failed: ")
		writeHex64(co, st)
		writeASCII(co, "\r\n")
		return
	}
	bind := (*efiServiceBinding)(unsafe.Pointer(httpSBHolder))

	// Step 2: CreateChild — allocates a new handle with EFI_HTTP_PROTOCOL
	// installed on it. ChildHandle out-pointer must point at an
	// initially-NULL handle; firmware writes the new handle into it.
	httpChildHandle = 0
	st = efiCall2(bind.createChild,
		uintptr(unsafe.Pointer(bind)),
		uintptr(unsafe.Pointer(&httpChildHandle)))
	if st != efiSuccess {
		writeASCII(co, "  CreateChild failed: ")
		writeHex64(co, st)
		writeASCII(co, "\r\n")
		return
	}
	writeASCII(co, "  CreateChild OK, childHandle=")
	writeHex64(co, uint64(httpChildHandle))
	writeASCII(co, "\r\n")

	// Step 3: HandleProtocol(childHandle, HTTP_PROTOCOL) — fetch the
	// per-instance HTTP function table. Service-binding pattern
	// guarantees the protocol is installed on the freshly-created
	// child handle, so HandleProtocol is the cheapest way to read it.
	httpProtocolHolder = 0
	st = efiCall3(bs.handleProtocol,
		httpChildHandle,
		uintptr(unsafe.Pointer(&httpProtocolGUID)),
		uintptr(unsafe.Pointer(&httpProtocolHolder)))
	if st != efiSuccess {
		writeASCII(co, "  HandleProtocol(HTTP) failed: ")
		writeHex64(co, st)
		writeASCII(co, "\r\n")
		return
	}
	writeASCII(co, "  HandleProtocol(HTTP) OK, iface=")
	writeHex64(co, uint64(httpProtocolHolder))
	writeASCII(co, "\r\n")
	writeASCII(co, "  HTTP-CHILD-READY\r\n")
	_ = imageHandle // reserved for OpenProtocol when we switch to the
	// fully-controlled BY_DRIVER attribute later in phase 1.

	// Step 4: Configure HTTP — let the firmware-managed IP4 stack
	// pick our address (it should have just DHCP'd after the
	// ConnectController cascade above). HTTP/1.1, 5-second timeout.
	httpV4AP.useDefaultAddress = 1
	httpV4AP.localPort = 0 // ephemeral

	httpConfig.httpVersion = 1 // HTTP/1.1
	httpConfig.timeOutMillisec = 5000
	httpConfig.localAddressIsIPv6 = 0
	httpConfig.accessPoint = uintptr(unsafe.Pointer(&httpV4AP))

	// Step 3a: bootstrap the IP4 stack into DHCP mode. Without this
	// the underlying TCP4 instance has no IP and HTTP.Request returns
	// EFI_NO_MAPPING with "HttpConfigureTcp4 - No mapping".
	//
	// LocateProtocol(IP4_CONFIG2) returns a global instance whose
	// SetData rejects our calls; the per-NIC instance lives on the
	// NIC handle and must be fetched via HandleProtocol. Walk the
	// connected NIC handles from the SimpleNetwork enumeration and
	// take the first IP4Config2 we find.
	ip4Config2Holder = 0
	if nicHandleCount > 0 && nicHandleBuf != 0 {
		for i := uintptr(0); i < nicHandleCount; i++ {
			h := *(*uintptr)(unsafe.Pointer(nicHandleBuf + i*unsafe.Sizeof(uintptr(0))))
			nicIfaceHolder = 0
			cst := efiCall3(bs.handleProtocol,
				h,
				uintptr(unsafe.Pointer(&ip4Config2GUID)),
				uintptr(unsafe.Pointer(&nicIfaceHolder)))
			if cst == efiSuccess && nicIfaceHolder != 0 {
				ip4Config2Holder = nicIfaceHolder
				writeASCII(co, "  IP4Config2 on NIC handle ")
				writeHex64(co, uint64(h))
				writeASCII(co, ", iface=")
				writeHex64(co, uint64(nicIfaceHolder))
				writeASCII(co, "\r\n")
				break
			}
		}
	}
	if ip4Config2Holder == 0 {
		// Fall back to the global protocol — better than nothing.
		st = efiCall3(bs.locateProtocol,
			uintptr(unsafe.Pointer(&ip4Config2GUID)),
			0,
			uintptr(unsafe.Pointer(&ip4Config2Holder)))
		if st != efiSuccess {
			writeASCII(co, "  no IP4Config2 instance found\r\n")
			return
		}
		writeASCII(co, "  IP4Config2 (global), iface=")
		writeHex64(co, uint64(ip4Config2Holder))
		writeASCII(co, "\r\n")
	}
	ip4 := (*efiIP4Config2Protocol)(unsafe.Pointer(ip4Config2Holder))
	// Re-set the policy byte at runtime — TinyGo's package init
	// with `scheduler: none` is touchy about late writes to BSS,
	// and the firmware will reject a Data pointer that resolves
	// to a zero (= PolicyStatic) when we asked for DHCP.
	ip4PolicyDhcp = ip4Config2PolicyDhcp
	st = efiCall4(ip4.setData,
		ip4Config2Holder,
		uintptr(ip4Config2DataTypePolicy),
		uintptr(4),
		uintptr(unsafe.Pointer(&ip4PolicyDhcp)))
	switch st {
	case efiSuccess:
		writeASCII(co, "  IP4Config2.SetData(Dhcp): OK\r\n")
	case efiAlreadyStarted:
		writeASCII(co, "  IP4Config2.SetData(Dhcp): already DHCP — OK\r\n")
	default:
		// Don't bail — OVMF may have already DHCP'd via its PXE
		// boot-manager scan, in which case the IP4 stack is up but
		// SetData rejects our redundant call.
		writeASCII(co, "  IP4Config2.SetData(Dhcp) returned ")
		writeHex64(co, st)
		writeASCII(co, " — proceeding\r\n")
	}

	// Give the firmware time to actually DHCP. 3 seconds at most.
	// (Stall takes microseconds; 3_000_000 µs = 3 s.)
	efiCall2(bs.stall, 3_000_000, 0)

	http := (*efiHTTPProtocol)(unsafe.Pointer(httpProtocolHolder))
	st = efiCall2(http.configure,
		httpProtocolHolder,
		uintptr(unsafe.Pointer(&httpConfig)))
	writeASCII(co, "  Configure: ")
	if st != efiSuccess {
		writeASCII(co, "FAILED status=")
		writeHex64(co, st)
		writeASCII(co, "\r\n")
		return
	}
	writeASCII(co, "OK\r\n  HTTP-CONFIGURED\r\n")

	// Step 5: CreateEvent for the request and response tokens.
	// Type=0 (basic, signalable) means we can leave NotifyFunction
	// NULL and just CheckEvent in a poll loop — no callback thunks
	// to maintain. UEFI 2.10 §7.1.2 explicitly allows this:
	// "If Type doesn't have NOTIFY_WAIT or NOTIFY_SIGNAL, the
	//  NotifyTpl/NotifyFunction/NotifyContext args are ignored."
	reqEvent = 0
	st = efiCall5(bs.createEvent, 0, 0, 0, 0, uintptr(unsafe.Pointer(&reqEvent)))
	if st != efiSuccess {
		writeASCII(co, "  CreateEvent(req) failed: ")
		writeHex64(co, st)
		writeASCII(co, "\r\n")
		return
	}
	respEvent = 0
	st = efiCall5(bs.createEvent, 0, 0, 0, 0, uintptr(unsafe.Pointer(&respEvent)))
	if st != efiSuccess {
		writeASCII(co, "  CreateEvent(resp) failed: ")
		writeHex64(co, st)
		writeASCII(co, "\r\n")
		return
	}

	// Step 6: wire the request token.
	reqData.method = 0 // HttpMethodGet
	reqData.url = uintptr(unsafe.Pointer(&reqURL[0]))

	reqHeaders[0].fieldName = uintptr(unsafe.Pointer(&hdrHost[0]))
	reqHeaders[0].fieldValue = uintptr(unsafe.Pointer(&hdrHostValue[0]))

	reqMessage.data = uintptr(unsafe.Pointer(&reqData))
	reqMessage.headerCount = uintptr(len(reqHeaders))
	reqMessage.headers = uintptr(unsafe.Pointer(&reqHeaders[0]))
	reqMessage.bodyLength = 0
	reqMessage.body = 0

	reqToken.event = reqEvent
	reqToken.status = 0
	reqToken.message = uintptr(unsafe.Pointer(&reqMessage))

	writeASCII(co, "  Request: ")
	st = efiCall2(http.request, httpProtocolHolder, uintptr(unsafe.Pointer(&reqToken)))
	if st != efiSuccess {
		writeASCII(co, "FAILED status=")
		writeHex64(co, st)
		writeASCII(co, "\r\n")
		return
	}
	writeASCII(co, "submitted\r\n")

	// Step 7: poll until reqToken.Event is signaled. HTTP.Poll
	// drives the stack's internal state machine — must be called
	// regularly or progress stalls. Cap the loop with a hard
	// iteration ceiling so we don't spin forever if the firmware
	// fumbles the token.
	if !waitToken(co, bs, http, reqEvent, "  Request") {
		return
	}

	// Step 8: send the Response token. Body buffer is caller-
	// allocated; the HTTP stack fills as much as fits and updates
	// BodyLength to the actual byte count.
	respData.statusCode = 0
	respMessage.data = uintptr(unsafe.Pointer(&respData))
	respMessage.headerCount = 0
	respMessage.headers = 0
	respMessage.bodyLength = uintptr(len(respBody))
	respMessage.body = uintptr(unsafe.Pointer(&respBody[0]))

	respToken.event = respEvent
	respToken.status = 0
	respToken.message = uintptr(unsafe.Pointer(&respMessage))

	writeASCII(co, "  Response: ")
	st = efiCall2(http.response, httpProtocolHolder, uintptr(unsafe.Pointer(&respToken)))
	if st != efiSuccess {
		writeASCII(co, "FAILED status=")
		writeHex64(co, st)
		writeASCII(co, "\r\n")
		return
	}
	writeASCII(co, "submitted\r\n")
	if !waitToken(co, bs, http, respEvent, "  Response") {
		return
	}

	// Step 9: report.
	writeASCII(co, "  HTTP status code (enum) = ")
	writeHex64(co, uint64(respData.statusCode))
	writeASCII(co, "\r\n  bodyLength = ")
	writeHex64(co, uint64(respMessage.bodyLength))
	writeASCII(co, "\r\n  body first bytes: ")
	n := int(respMessage.bodyLength)
	if n > 80 {
		n = 80
	}
	for i := 0; i < n; i++ {
		b := respBody[i]
		// Mangle non-printable so SimpleTextOutput can't choke.
		if b < 0x20 || b > 0x7E {
			b = '.'
		}
		// writeASCII expects a string — use a one-char scratch buffer.
		oneCharBuf[0] = b
		writeASCII(co, oneCharStr)
	}
	writeASCII(co, "\r\n  HTTP-FETCH-DONE\r\n")
}

// oneCharBuf + oneCharStr is a 1-byte "string view" reusing the same
// underlying byte. Lets writeASCII walk the response body without
// constructing a fresh Go string per character (which TinyGo would
// pin to runtime.alloc).
var oneCharBuf [1]byte
var oneCharStr = unsafe.String(&oneCharBuf[0], 1)

// waitToken polls HTTP.Poll until the token's event is signaled by
// the firmware, or up to ~maxIter iterations have passed. Returns
// true on signal, false on timeout. Each Poll call advances the
// internal state machine one step — without it the HTTP stack
// would stall waiting for time-driven progress that the firmware
// can't give us here.
func waitToken(co *efiSimpleTextOutput, bs *efiBootServices, http *efiHTTPProtocol, ev uintptr, label string) bool {
	const maxIter = 1_000_000 // soft cap; firmwares usually settle in <100 K
	for i := 0; i < maxIter; i++ {
		efiCall1(http.poll, httpProtocolHolder)
		// CheckEvent returns EFI_SUCCESS (0) when signaled,
		// EFI_NOT_READY (0x80000000_00000006) when still pending,
		// or an actual error.
		st := efiCall1(bs.checkEvent, ev)
		if st == efiSuccess {
			return true
		}
		if st != efiNotReady {
			writeASCII(co, label)
			writeASCII(co, ": CheckEvent failed: ")
			writeHex64(co, st)
			writeASCII(co, "\r\n")
			return false
		}
	}
	writeASCII(co, label)
	writeASCII(co, ": Poll timeout\r\n")
	return false
}

const (
	efiNotReady       efiStatus = 0x8000000000000006
	efiAlreadyStarted efiStatus = 0x8000000000000014
)

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

// efiLoadedImageProtocol — only the LoadOptions slot+size matter here.
// Layout per UEFI 2.10 §9.1; see loader/cmd/efi-loader/main.go for the
// full picture.
type efiLoadedImageProtocol struct {
	revision        uint32
	_pad            uint32
	parentHandle    uintptr
	systemTable     uintptr
	deviceHandle    uintptr
	filePath        uintptr
	_reserved       uintptr
	loadOptionsSize uint32
	_pad2           uint32
	loadOptions     uintptr
	// rest unused
}

// EFI_LOADED_IMAGE_PROTOCOL_GUID — 5b1b31a1-9562-11d2-8e3f-00a0c969723b
var loadedImageGUID = efiGUID{
	0xA1, 0x31, 0x1B, 0x5B,
	0x62, 0x95,
	0xD2, 0x11,
	0x8E, 0x3F, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B,
}

var probeLIPHolder uintptr

//go:export _start
func _start(imageHandle uintptr, st *efiSystemTable) efiStatus {
	co := st.conOut
	bs := st.bootServices

	writeASCII(co, "cloud-boot/loader probe — phase 0\r\n")

	// Echo the LoadOptions we received from whatever loaded us. When
	// this probe is chain-loaded by the disk-mode loader, the loader's
	// patchChildCmdline path will have stuffed the staged
	// CloudBootCmdline value into our LoadedImage.LoadOptions; echoing
	// it back closes the end-to-end loop.
	probeLIPHolder = 0
	if efiCall3(bs.handleProtocol, imageHandle,
		uintptr(unsafe.Pointer(&loadedImageGUID)),
		uintptr(unsafe.Pointer(&probeLIPHolder))) == efiSuccess && probeLIPHolder != 0 {
		lip := (*efiLoadedImageProtocol)(unsafe.Pointer(probeLIPHolder))
		writeASCII(co, "  LoadOptionsSize = ")
		writeHex64(co, uint64(lip.loadOptionsSize))
		writeASCII(co, "\r\n  LoadOptions = ")
		// Walk the UTF-16LE buffer back into ASCII for display.
		// Stop at NUL or after loadOptionsSize/2 chars.
		if lip.loadOptionsSize > 0 && lip.loadOptions != 0 {
			limit := lip.loadOptionsSize / 2
			for i := uint32(0); i < limit; i++ {
				c := *(*uint16)(unsafe.Pointer(lip.loadOptions + uintptr(i)*2))
				if c == 0 {
					break
				}
				b := byte(c)
				if b < 0x20 || b > 0x7E {
					b = '.'
				}
				oneCharBuf[0] = b
				writeASCII(co, oneCharStr)
			}
		}
		writeASCII(co, "\r\n")
	}

	// Bind the network driver stack. OVMF auto-connects the network
	// protocol layers (SNP → MNP → ARP → IP4 → TCP4/UDP4 → HTTP/DNS)
	// only when the boot manager initiates a PXE/HTTP boot. Loading
	// us directly from a FAT volume short-circuits that, so we have
	// to drive the binding ourselves before LocateProtocol can find
	// anything but raw SimpleNetwork. One recursive ConnectController
	// call per NIC handle is enough — the firmware's DriverBinding
	// machinery walks the stack up to the highest layer.
	connectAllNICs(co, bs)

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

	// ----- Phase 1 step 1: validate the service-binding pattern -----
	//
	// Only attempt the HTTP service-binding pattern if the firmware
	// actually exposes EFI_HTTP_SERVICE_BINDING. Vanilla Homebrew
	// QEMU prebuilts (both edk2-aarch64-code.fd and edk2-x86_64-code.fd
	// as of 2026-05) ship without NetworkPkg drivers — only
	// SimpleNetwork / BlockIO / SimpleFileSystem are exposed. In that
	// environment the HTTP-firmware design cannot work and Phase 1
	// would just crash on a NULL function-table dereference. Real
	// hardware EFI firmwares vary in whether they include NetworkPkg;
	// production cloud-boot needs to detect this and fall back to a
	// TinyGo TCP+HTTP stack over SimpleNetwork (or pivot to disk-mode).
	ifaceHolder = 0
	hasHTTP := efiCall3(bs.locateProtocol,
		uintptr(unsafe.Pointer(&httpServiceBindingGUID)),
		0,
		uintptr(unsafe.Pointer(&ifaceHolder))) == efiSuccess
	if hasHTTP {
		writeASCII(co, "\r\nPhase 1 step 1 — HTTP service binding\r\n")
		probeHTTPChild(co, bs, imageHandle)
	} else {
		writeASCII(co, "\r\nPhase 1 step 1 SKIPPED — firmware lacks HTTP_SB\r\n")
		writeASCII(co, "  → loader needs DIY TCP/HTTP on SimpleNetwork,\r\n")
		writeASCII(co, "    or pivot to disk-mode (BlockIO + SimpleFS).\r\n")
	}

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
