// efi-loader — Phase-5a disk-mode pure-UEFI loader.
//
// Walks every EFI_SIMPLE_FILE_SYSTEM handle in the system looking for a
// kernel image at the canonical UKI path `\EFI\Linux\cloud-boot.efi`,
// reads it into Boot Services pool memory, then chain-loads it via
// LoadImage + StartImage. On Apple Virtualization.framework arm64 this
// is the path that the Linux kexec-based bootstrap can't take (the EL1
// jump traps silently); LoadImage stays inside Boot Services context
// and is the same firmware-mediated handoff every distro uses at first
// boot, which Apple VZ supports.
//
// Every buffer is package-scope. TinyGo with `gc: leaking` +
// `scheduler: none` will heap-allocate any stack-local whose address
// escapes via unsafe.Pointer, and the heap allocator under UEFI ends
// at runtime.alloc → VirtualAlloc, which is unresolved here.
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
	allocatePool  uintptr // +0x40 on arm64 / amd64 (after the 5 prior pointers + hdr)
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
	locateProtocol     uintptr
}

type efiSystemTable struct {
	hdr               efiTableHeader
	firmwareVendor    uintptr
	firmwareRevision  uint32
	_pad              uint32
	consoleInHandle   uintptr
	conIn             uintptr
	consoleOutHandle  uintptr
	conOut            *efiSimpleTextOutput
	standardErrHandle uintptr
	stdErr            uintptr
	runtimeServices   *efiRuntimeServices
	bootServices      *efiBootServices
}

// efiRuntimeServices — laid out in UEFI 2.10 §4.5 order. We only call
// GetVariable, but keep the upstream fields so the offset matches.
type efiRuntimeServices struct {
	hdr efiTableHeader

	getTime       uintptr
	setTime       uintptr
	getWakeupTime uintptr
	setWakeupTime uintptr

	setVirtualAddressMap uintptr
	convertPointer       uintptr

	getVariable          uintptr // 5 args
	getNextVariableName  uintptr
	setVariable          uintptr

	getNextHighMonotonicCount uintptr
	resetSystem               uintptr
}

// EFI_BUFFER_TOO_SMALL — returned by GetVariable when the supplied
// buffer is too small; the call writes the required size back into
// `DataSize`. The standard two-pass GetVariable idiom relies on this.
const efiBufferTooSmall efiStatus = 0x8000000000000005

// EFI_SIMPLE_FILE_SYSTEM_PROTOCOL — only the OpenVolume slot matters.
//
//	UINT64                  Revision;          // 0x00
//	EFI_FILE_OPEN_VOLUME    OpenVolume;        // 0x08
//	    EFI_STATUS (*)(SFS *this, EFI_FILE_PROTOCOL **root)
type efiSimpleFileSystem struct {
	revision   uint64
	openVolume uintptr
}

// EFI_LOADED_IMAGE_PROTOCOL — what the firmware installs on every
// handle returned by LoadImage. We only patch two fields after
// LoadImage and before StartImage: LoadOptions (UTF-16LE buffer) and
// LoadOptionsSize (BYTES, sized for that buffer). Linux's EFI stub
// reads its kernel command line from those slots.
//
// Layout (UEFI 2.10 §9.1):
//
//	UINT32             Revision;            // 0x00
//	EFI_HANDLE         ParentHandle;        // 0x08
//	EFI_SYSTEM_TABLE  *SystemTable;         // 0x10
//	EFI_HANDLE         DeviceHandle;        // 0x18
//	EFI_DEVICE_PATH   *FilePath;            // 0x20
//	VOID              *Reserved;            // 0x28
//	UINT32             LoadOptionsSize;     // 0x30  ← bytes
//	VOID              *LoadOptions;         // 0x38  ← UTF-16LE
//	VOID              *ImageBase;           // 0x40
//	UINT64             ImageSize;           // 0x48
//	EFI_MEMORY_TYPE    ImageCodeType;       // 0x50
//	EFI_MEMORY_TYPE    ImageDataType;       // 0x54
//	EFI_IMAGE_UNLOAD   Unload;              // 0x58
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
	imageBase       uintptr
	imageSize       uint64
	imageCodeType   uint32
	imageDataType   uint32
	unload          uintptr
}

// EFI_FILE_PROTOCOL — fields we actually call. Rev1 layout is enough.
//
//	UINT64               Revision;
//	EFI_FILE_OPEN        Open;        // 0x08 — 5 args
//	EFI_FILE_CLOSE       Close;       // 0x10 — 1 arg
//	EFI_FILE_DELETE      Delete;      // 0x18
//	EFI_FILE_READ        Read;        // 0x20 — 3 args (this, *size, *buf)
//	EFI_FILE_WRITE       Write;       // 0x28
//	EFI_FILE_GET_POSITION GetPosition;// 0x30 — 2 args (this, *pos)
//	EFI_FILE_SET_POSITION SetPosition;// 0x38 — 2 args (this, pos)
type efiFile struct {
	revision    uint64
	open        uintptr
	close       uintptr
	delete      uintptr
	read        uintptr
	write       uintptr
	getPosition uintptr
	setPosition uintptr
	// getInfo / setInfo / flush / Rev2 entries not needed here.
}

const (
	efiFileModeRead uint64 = 0x0000000000000001

	// SetPosition(file, POSITION_END_OF_FILE) seeks to EOF.
	efiFilePositionEnd uint64 = 0xFFFFFFFFFFFFFFFF

	// AllocatePool memory types.
	efiLoaderData uintptr = 2
)

// Protocol GUIDs.
var (
	// EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID — 964e5b22-6459-11d2-8e39-00a0c969723b
	simpleFileSystemGUID = efiGUID{
		0x22, 0x5B, 0x4E, 0x96,
		0x59, 0x64,
		0xD2, 0x11,
		0x8E, 0x39, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B,
	}
	// EFI_LOADED_IMAGE_PROTOCOL_GUID — 5b1b31a1-9562-11d2-8e3f-00a0c969723b
	loadedImageGUID = efiGUID{
		0xA1, 0x31, 0x1B, 0x5B,
		0x62, 0x95,
		0xD2, 0x11,
		0x8E, 0x3F, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B,
	}

	// cloud-boot vendor GUID — namespace for cloud-boot-specific UEFI
	// variables ("CloudBootCmdline", future "CloudBootTarget", …).
	//
	//   {c10ddb07-83c5-4d3e-9b76-1f4c0e7a3b8e}
	//
	// Generated once, stable across releases. Host-side
	// `loader/cmd/efivar-stage` writes variables under this GUID; the
	// loader's GetVariable calls pass the same GUID.
	cloudBootGUID = efiGUID{
		0x07, 0xDB, 0x0D, 0xC1,
		0xC5, 0x83,
		0x3E, 0x4D,
		0x9B, 0x76, 0x1F, 0x4C, 0x0E, 0x7A, 0x3B, 0x8E,
	}
)

// "CloudBootMark" — Apple-VZ diagnostic. The loader writes this
// non-volatile EFI variable as its very first action; if the variable
// appears in vfkit's variable-store file after the VM stops, we know
// our BOOTAA64.EFI executed on Apple Virtualization.framework (where
// SimpleTextOutput goes to the framebuffer only).
var bootMarkVarName = [...]uint16{
	'C', 'l', 'o', 'u', 'd', 'B', 'o', 'o', 't', 'M', 'a', 'r', 'k',
	0,
}
var bootMarkVarData = [...]byte{'C', 'B', '-', 'R', 'A', 'N'}

// "CloudBootMAC" — set by the net-init shortcut after netInit
// succeeds; holds the 6-byte MAC address the firmware reports for
// the active SimpleNetwork interface. Phase-A proof that the loader
// can talk to a NIC at all; subsequent phases (ARP/IP/TCP) build on
// the same instance.
var netMacVarName = [...]uint16{
	'C', 'l', 'o', 'u', 'd', 'B', 'o', 'o', 't', 'M', 'A', 'C',
	0,
}
var netMarkVarData [6]byte

// bootMarkRT is the package-scope runtime services pointer + marker
// helper so any cascade point can update CloudBootMark without
// threading rt + co through every function. Set once in _start.
var bootMarkRT *efiRuntimeServices

func bootMark(tag string) {
	if bootMarkRT == nil || bootMarkRT.setVariable == 0 {
		return
	}
	if len(tag) > len(bootMarkVarData) {
		tag = tag[:len(bootMarkVarData)]
	}
	for i := 0; i < len(bootMarkVarData); i++ {
		bootMarkVarData[i] = ' '
	}
	for i := 0; i < len(tag); i++ {
		bootMarkVarData[i] = tag[i]
	}
	efiCall5(bootMarkRT.setVariable,
		uintptr(unsafe.Pointer(&bootMarkVarName[0])),
		uintptr(unsafe.Pointer(&cloudBootGUID)),
		uintptr(0x07),
		uintptr(len(bootMarkVarData)),
		uintptr(unsafe.Pointer(&bootMarkVarData[0])))
}

// "CloudBootCmdline" — UTF-16LE, NUL-terminated. Pre-encoded so we
// don't allocate at runtime.
var cmdlineVarName = [...]uint16{
	'C', 'l', 'o', 'u', 'd', 'B', 'o', 'o', 't', 'C', 'm', 'd', 'l', 'i', 'n', 'e',
	0,
}

// "CloudBootTarget" — UTF-16LE, NUL-terminated. Picks which UKI under
// \EFI\Linux\ the loader chain-loads; e.g. CloudBootTarget="rescue"
// → \EFI\Linux\rescue.efi. Falls back to "cloud-boot" (= the
// historical Phase-5a default) when the variable is missing or
// references a non-existent file on every volume.
var targetVarName = [...]uint16{
	'C', 'l', 'o', 'u', 'd', 'B', 'o', 'o', 't', 'T', 'a', 'r', 'g', 'e', 't',
	0,
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

// ----- text output -----

// outBuf reused by every writeASCII call. 256 chars is enough for
// any single diagnostic line; longer lines split across calls.
var outBuf [256]uint16

func writeASCII(co *efiSimpleTextOutput, s string) {
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

// ----- package-scope EFI out-pointers and buffers -----
//
// Stack-local vars whose address is handed to firmware via
// unsafe.Pointer trigger TinyGo's escape analysis to allocate them on
// the heap, which under UEFI ends in runtime.alloc → VirtualAlloc
// (unresolved) → instruction abort. Keep every firmware-facing
// pointer here in BSS.

var (
	// LocateHandleBuffer out-params.
	sfsHandleCount uintptr
	sfsHandleBuf   uintptr

	// HandleProtocol(handle, SFS_GUID, &sfsHolder) result.
	sfsHolder uintptr

	// OpenVolume → root EFI_FILE.
	rootFileHolder uintptr

	// Open("\EFI\Linux\cloud-boot.efi") → kernel EFI_FILE.
	kernelFileHolder uintptr

	// GetPosition / SetPosition slot.
	filePos uint64

	// AllocatePool → kernel image bytes.
	kernelBuffer uintptr
	kernelSize   uintptr // also used as the in/out byte count for Read

	// LoadImage → child handle.
	childImageHandle uintptr

	// UKI path buffer. Built at boot time from "\EFI\Linux\" +
	// CloudBootTarget (or "cloud-boot" default) + ".efi" + NUL. UEFI
	// requires backslash separators and UTF-16LE encoding.
	//
	// Sized for a 64-char target name; total = 11 prefix chars + 64
	// target chars + 4 suffix chars + NUL = 80 — round up to 128 for
	// headroom.
	ukiPath [128]uint16

	// Target name buffer (ASCII, NUL-terminated). Populated by
	// readTargetEFIVar from `CloudBootTarget` UEFI variable, or left
	// as "cloud-boot" default.
	targetRaw     [64]byte
	targetRawLen  uintptr
	defaultTarget = [...]byte{'c', 'l', 'o', 'u', 'd', '-', 'b', 'o', 'o', 't'}

	// Cmdline source path. ASCII bytes, one line, trailing newline
	// tolerated. "\cmdline" at the FAT root — same convention
	// systemd-boot's loader.conf uses, with the simplification of
	// not requiring a [config] header.
	//
	// "\cmdline"
	cmdlinePath = [...]uint16{
		'\\', 'c', 'm', 'd', 'l', 'i', 'n', 'e',
		0,
	}

	// Holder for Open("\cmdline").
	cmdlineFileHolder uintptr

	// AllocatePool buffer for the raw ASCII bytes.
	cmdlineRawBuf uintptr
	cmdlineRawLen uintptr
	cmdlinePos    uint64

	// UTF-16 buffer used to back the child kernel's LoadOptions. Sized
	// for a hefty cmdline (4096 chars = 8 KiB) and kept in BSS so its
	// address survives ExitBootServices the same way every other
	// firmware-facing pointer here does.
	cmdlineUTF16 [4096]uint16
	cmdlineChars uint32 // number of UTF-16 code units written (excl. NUL)

	// Loaded-image lookup for the chain-loaded child — used by the
	// cmdline patch.
	childLIPHolder uintptr

	// Scratch byte-count slot for GetVariable / EFI_FILE.Read. Lives in
	// BSS so its address can be handed to firmware via unsafe.Pointer
	// without triggering TinyGo's escape-to-heap path — which would
	// reach runtime.alloc → VirtualAlloc and crash here.
	scratchSize uintptr

	// CloudBootTarget shortcut tags. When the staged value matches
	// one of these, _start skips ahead in the cascade.
	ext4DirectTag  = [...]byte{'e', 'x', 't', '4', '-', 'd', 'i', 'r', 'e', 'c', 't'}
	xfsDirectTag   = [...]byte{'x', 'f', 's', '-', 'd', 'i', 'r', 'e', 'c', 't'}
	btrfsDirectTag = [...]byte{'b', 't', 'r', 'f', 's', '-', 'd', 'i', 'r', 'e', 'c', 't'}
)

// bytesMatchTarget returns true if `tag` equals the CloudBootTarget
// value most-recently read by readTargetEFIVar (i.e. targetRaw[:
// targetRawLen]). Closure-free per the no-heap convention.
func bytesMatchTarget(tag []byte) bool {
	if int(targetRawLen) != len(tag) {
		return false
	}
	for i := 0; i < len(tag); i++ {
		if targetRaw[i] != tag[i] {
			return false
		}
	}
	return true
}

// readTargetEFIVar fetches the host-staged UKI target name from the
// `CloudBootTarget` UEFI variable. The value is plain ASCII (no NUL
// terminator required) naming the UKI under `\EFI\Linux\<target>.efi`.
// Returns true if a non-empty target was read; populates targetRaw /
// targetRawLen. On any failure the caller falls back to the
// `cloud-boot` default.
func readTargetEFIVar(co *efiSimpleTextOutput, rt *efiRuntimeServices) bool {
	if rt == nil || rt.getVariable == 0 {
		return false
	}
	scratchSize = uintptr(len(targetRaw))
	st := efiCall5(rt.getVariable,
		uintptr(unsafe.Pointer(&targetVarName[0])),
		uintptr(unsafe.Pointer(&cloudBootGUID)),
		0,
		uintptr(unsafe.Pointer(&scratchSize)),
		uintptr(unsafe.Pointer(&targetRaw[0])))
	if st != efiSuccess || scratchSize == 0 {
		return false
	}
	// Trim trailing whitespace / NUL / CR / LF.
	for scratchSize > 0 {
		b := targetRaw[scratchSize-1]
		if b != '\r' && b != '\n' && b != ' ' && b != '\t' && b != 0 {
			break
		}
		scratchSize--
	}
	if scratchSize == 0 {
		return false
	}
	targetRawLen = scratchSize
	writeASCII(co, "  target from EFI var CloudBootTarget: ")
	for i := uintptr(0); i < targetRawLen; i++ {
		oneCharBuf[0] = targetRaw[i]
		writeASCII(co, oneCharStr)
	}
	writeASCII(co, "\r\n")
	return true
}

// buildUKIPath constructs the UTF-16LE path "\EFI\Linux\<target>.efi"
// in `ukiPath`, NUL-terminated. If targetRawLen is zero, "cloud-boot"
// is used as the target name (Phase-5a default).
func buildUKIPath() {
	const prefix = "\\EFI\\Linux\\"
	const suffix = ".efi"

	off := 0
	for i := 0; i < len(prefix); i++ {
		ukiPath[off] = uint16(prefix[i])
		off++
	}
	if targetRawLen == 0 {
		for i := 0; i < len(defaultTarget); i++ {
			ukiPath[off] = uint16(defaultTarget[i])
			off++
		}
	} else {
		for i := uintptr(0); i < targetRawLen && off < len(ukiPath)-len(suffix)-1; i++ {
			ukiPath[off] = uint16(targetRaw[i])
			off++
		}
	}
	for i := 0; i < len(suffix); i++ {
		ukiPath[off] = uint16(suffix[i])
		off++
	}
	ukiPath[off] = 0
}

// readCmdlineEFIVar fetches the host-staged cmdline from the
// `CloudBootCmdline` UEFI variable under the cloud-boot vendor GUID.
// This is the primary cmdline source — the host pre-populates the
// variable via `loader/cmd/efivar-stage` (which uses the host-side
// github.com/go-filesystems/uefi package to write into OVMF_VARS.fd
// before QEMU launches). Returns true on success; falls through to
// the disk-file fallback otherwise.
//
// EFI's GetVariable uses the classic two-call idiom: first probe with
// DataSize=0 → EFI_BUFFER_TOO_SMALL (and the actual size written
// back), then allocate + read.
func readCmdlineEFIVar(co *efiSimpleTextOutput, bs *efiBootServices, rt *efiRuntimeServices) bool {
	if rt == nil || rt.getVariable == 0 {
		return false
	}

	// Probe pass — DataSize=0, Data=NULL.
	cmdlineRawLen = 0
	st := efiCall5(rt.getVariable,
		uintptr(unsafe.Pointer(&cmdlineVarName[0])),
		uintptr(unsafe.Pointer(&cloudBootGUID)),
		0, // Attributes (optional)
		uintptr(unsafe.Pointer(&cmdlineRawLen)),
		0)
	if st != efiBufferTooSmall {
		// EFI_NOT_FOUND etc. — the host didn't stage a variable.
		return false
	}
	if cmdlineRawLen == 0 {
		return false
	}

	// Reserve one slot for the NUL terminator in cmdlineUTF16. The
	// data we read is ASCII (1 byte per char), so the resulting
	// UTF-16 widening uses the same character count.
	maxRaw := uintptr(len(cmdlineUTF16) - 1)
	if cmdlineRawLen > maxRaw {
		cmdlineRawLen = maxRaw
	}

	cmdlineRawBuf = 0
	st = efiCall3(bs.allocatePool,
		efiLoaderData,
		cmdlineRawLen,
		uintptr(unsafe.Pointer(&cmdlineRawBuf)))
	if st != efiSuccess {
		return false
	}

	scratchSize = cmdlineRawLen
	st = efiCall5(rt.getVariable,
		uintptr(unsafe.Pointer(&cmdlineVarName[0])),
		uintptr(unsafe.Pointer(&cloudBootGUID)),
		0,
		uintptr(unsafe.Pointer(&scratchSize)),
		cmdlineRawBuf)
	if st != efiSuccess || scratchSize == 0 {
		efiCall1(bs.freePool, cmdlineRawBuf)
		return false
	}

	// Trim trailing CR / LF / whitespace.
	for scratchSize > 0 {
		b := *(*byte)(unsafe.Pointer(cmdlineRawBuf + scratchSize - 1))
		if b != '\r' && b != '\n' && b != ' ' && b != '\t' && b != 0 {
			break
		}
		scratchSize--
	}
	if scratchSize == 0 {
		efiCall1(bs.freePool, cmdlineRawBuf)
		return false
	}

	for i := uintptr(0); i < scratchSize; i++ {
		cmdlineUTF16[i] = uint16(*(*byte)(unsafe.Pointer(cmdlineRawBuf + i)))
	}
	cmdlineUTF16[scratchSize] = 0
	cmdlineChars = uint32(scratchSize)

	efiCall1(bs.freePool, cmdlineRawBuf)

	writeASCII(co, "  cmdline from EFI var CloudBootCmdline (")
	writeHex64(co, uint64(cmdlineChars))
	writeASCII(co, " chars): ")
	for i := uint32(0); i < cmdlineChars; i++ {
		oneCharBuf[0] = byte(cmdlineUTF16[i])
		writeASCII(co, oneCharStr)
	}
	writeASCII(co, "\r\n")
	return true
}

// readCmdline opens `\cmdline` at the volume root, reads up to the
// cmdlineUTF16 capacity, and widens the ASCII bytes to UTF-16LE in
// cmdlineUTF16. Trailing CR/LF/whitespace is stripped; the buffer is
// NUL-terminated. Sets cmdlineChars to the code-unit count (excl. NUL).
// Returns true if a non-empty cmdline was loaded.
//
// This is the disk-file fallback used only when no `CloudBootCmdline`
// EFI variable was staged. On any error or missing file, returns false
// — the caller falls back to LoadImage with the firmware's default
// cmdline (= empty).
func readCmdline(co *efiSimpleTextOutput, bs *efiBootServices, root *efiFile) bool {
	cmdlineFileHolder = 0
	st := efiCall5(root.open,
		uintptr(unsafe.Pointer(root)),
		uintptr(unsafe.Pointer(&cmdlineFileHolder)),
		uintptr(unsafe.Pointer(&cmdlinePath[0])),
		uintptr(efiFileModeRead),
		0)
	if st != efiSuccess {
		return false
	}
	cf := (*efiFile)(unsafe.Pointer(cmdlineFileHolder))

	// Size the file.
	cmdlinePos = 0
	st = efiCall2(cf.setPosition, cmdlineFileHolder, uintptr(efiFilePositionEnd))
	if st != efiSuccess {
		efiCall1(cf.close, cmdlineFileHolder)
		return false
	}
	st = efiCall2(cf.getPosition, cmdlineFileHolder, uintptr(unsafe.Pointer(&cmdlinePos)))
	if st != efiSuccess || cmdlinePos == 0 {
		efiCall1(cf.close, cmdlineFileHolder)
		return false
	}
	// Reserve one slot for the NUL terminator.
	maxRaw := uint64(len(cmdlineUTF16) - 1)
	if cmdlinePos > maxRaw {
		cmdlinePos = maxRaw
	}
	cmdlineRawLen = uintptr(cmdlinePos)

	st = efiCall2(cf.setPosition, cmdlineFileHolder, 0)
	if st != efiSuccess {
		efiCall1(cf.close, cmdlineFileHolder)
		return false
	}

	// Allocate a scratch buffer for the raw ASCII bytes — we widen
	// out of it into cmdlineUTF16 below.
	cmdlineRawBuf = 0
	st = efiCall3(bs.allocatePool,
		efiLoaderData,
		cmdlineRawLen,
		uintptr(unsafe.Pointer(&cmdlineRawBuf)))
	if st != efiSuccess {
		efiCall1(cf.close, cmdlineFileHolder)
		return false
	}

	scratchSize = cmdlineRawLen
	st = efiCall3(cf.read,
		cmdlineFileHolder,
		uintptr(unsafe.Pointer(&scratchSize)),
		cmdlineRawBuf)
	efiCall1(cf.close, cmdlineFileHolder)
	if st != efiSuccess || scratchSize == 0 {
		efiCall1(bs.freePool, cmdlineRawBuf)
		return false
	}

	// Trim trailing CR / LF / space — cmdline files often have a
	// gratuitous newline from `echo ... > \cmdline`.
	for scratchSize > 0 {
		b := *(*byte)(unsafe.Pointer(cmdlineRawBuf + scratchSize - 1))
		if b != '\r' && b != '\n' && b != ' ' && b != '\t' {
			break
		}
		scratchSize--
	}
	if scratchSize == 0 {
		efiCall1(bs.freePool, cmdlineRawBuf)
		return false
	}

	// Widen ASCII → UTF-16LE.
	for i := uintptr(0); i < scratchSize; i++ {
		cmdlineUTF16[i] = uint16(*(*byte)(unsafe.Pointer(cmdlineRawBuf + i)))
	}
	cmdlineUTF16[scratchSize] = 0
	cmdlineChars = uint32(scratchSize)

	efiCall1(bs.freePool, cmdlineRawBuf)

	writeASCII(co, "  cmdline (")
	writeHex64(co, uint64(cmdlineChars))
	writeASCII(co, " chars): ")
	// Echo the ASCII (already validated as non-empty).
	for i := uint32(0); i < cmdlineChars; i++ {
		oneCharBuf[0] = byte(cmdlineUTF16[i])
		writeASCII(co, oneCharStr)
	}
	writeASCII(co, "\r\n")
	return true
}

// One-byte scratch "string" used to print ASCII chars through writeASCII
// without allocating a fresh Go string per character.
var oneCharBuf [1]byte
var oneCharStr = unsafe.String(&oneCharBuf[0], 1)

// patchChildCmdline installs cmdlineUTF16 on the chain-loaded image's
// LoadedImage protocol so its EFI stub reads the right cmdline. Soft-
// fails (logs + returns) when the protocol can't be fetched — the
// kernel will boot with an empty cmdline, which is still useful for
// triage. Mirrors the corresponding logic in go-coff/stub Phase 3c.
func patchChildCmdline(co *efiSimpleTextOutput, bs *efiBootServices, childHandle uintptr) {
	if cmdlineChars == 0 {
		return
	}
	childLIPHolder = 0
	st := efiCall3(bs.handleProtocol,
		childHandle,
		uintptr(unsafe.Pointer(&loadedImageGUID)),
		uintptr(unsafe.Pointer(&childLIPHolder)))
	if st != efiSuccess {
		writeASCII(co, "  child HandleProtocol(LoadedImage) failed: ")
		writeHex64(co, st)
		writeASCII(co, " — booting with default cmdline\r\n")
		return
	}
	childLip := (*efiLoadedImageProtocol)(unsafe.Pointer(childLIPHolder))
	childLip.loadOptions = uintptr(unsafe.Pointer(&cmdlineUTF16[0]))
	// Linux's EFI stub accepts either form (NUL-included or NUL-
	// excluded). systemd-stub convention is bytes-with-NUL — match that.
	childLip.loadOptionsSize = (cmdlineChars + 1) * 2
	writeASCII(co, "  patched child LoadOptions (")
	writeHex64(co, uint64(childLip.loadOptionsSize))
	writeASCII(co, " bytes)\r\n")
}

// tryAllHandles walks every SimpleFileSystem handle in sfsHandleBuf
// and tries to load the UKI currently encoded in ukiPath from each
// one. Returns true on the first successful LoadImage. The caller is
// responsible for StartImage; this helper just locates and prepares
// the child image.
func tryAllHandles(co *efiSimpleTextOutput, bs *efiBootServices, imageHandle uintptr) bool {
	writeASCII(co, "  trying UKI ")
	for i := 0; ukiPath[i] != 0 && i < len(ukiPath); i++ {
		oneCharBuf[0] = byte(ukiPath[i])
		writeASCII(co, oneCharStr)
	}
	writeASCII(co, "\r\n")
	for i := uintptr(0); i < sfsHandleCount; i++ {
		h := *(*uintptr)(unsafe.Pointer(sfsHandleBuf + i*unsafe.Sizeof(uintptr(0))))
		if tryLoadFromHandle(co, bs, imageHandle, h) {
			return true
		}
	}
	return false
}

// tryLoadFromHandle attempts to chain-load the UKI named by ukiPath
// from the SimpleFileSystem on `sfsHandle`. Returns true if LoadImage
// succeeded — the caller must then StartImage. False means the file
// wasn't found here (try the next handle) or an error occurred. All
// errors are logged before returning so the caller doesn't need to.
func tryLoadFromHandle(co *efiSimpleTextOutput, bs *efiBootServices, imageHandle, sfsHandle uintptr) bool {
	// Step 1: HandleProtocol(sfsHandle, SFS) → SimpleFileSystem instance.
	sfsHolder = 0
	st := efiCall3(bs.handleProtocol,
		sfsHandle,
		uintptr(unsafe.Pointer(&simpleFileSystemGUID)),
		uintptr(unsafe.Pointer(&sfsHolder)))
	if st != efiSuccess {
		return false
	}
	sfs := (*efiSimpleFileSystem)(unsafe.Pointer(sfsHolder))

	// Step 2: OpenVolume → root EFI_FILE.
	rootFileHolder = 0
	st = efiCall2(sfs.openVolume,
		sfsHolder,
		uintptr(unsafe.Pointer(&rootFileHolder)))
	if st != efiSuccess {
		return false
	}
	root := (*efiFile)(unsafe.Pointer(rootFileHolder))

	// Step 2a: opportunistically read \cmdline from this volume BEFORE
	// trying to open the UKI. Reading-before-UKI means the cmdline is
	// still picked up when the UKI doesn't exist on the volume and we
	// later fall through to the cloud-disk cascade. Only do this if
	// readCmdlineEFIVar didn't already populate one — the EFI variable
	// wins over disk files since the host can re-stage it without
	// rebuilding the FAT image.
	if cmdlineChars == 0 {
		if readCmdline(co, bs, root) {
			writeASCII(co, "cmdline source: \\cmdline file\r\n")
		}
	}

	// Step 3: Open the kernel image. Mode = READ, no attributes.
	kernelFileHolder = 0
	st = efiCall5(root.open,
		rootFileHolder,
		uintptr(unsafe.Pointer(&kernelFileHolder)),
		uintptr(unsafe.Pointer(&ukiPath[0])),
		uintptr(efiFileModeRead),
		0)
	if st != efiSuccess {
		// EFI_NOT_FOUND is the normal "this volume doesn't have our
		// UKI" path; don't log it noisily. Close root before bailing.
		efiCall1(root.close, rootFileHolder)
		return false
	}
	kf := (*efiFile)(unsafe.Pointer(kernelFileHolder))
	// Now done with root.
	efiCall1(root.close, rootFileHolder)

	// Step 4: find the file size via SetPosition(END) → GetPosition.
	st = efiCall2(kf.setPosition, kernelFileHolder, uintptr(efiFilePositionEnd))
	if st != efiSuccess {
		writeASCII(co, "  SetPosition(END) failed: ")
		writeHex64(co, st)
		writeASCII(co, "\r\n")
		efiCall1(kf.close, kernelFileHolder)
		return false
	}
	filePos = 0
	st = efiCall2(kf.getPosition, kernelFileHolder, uintptr(unsafe.Pointer(&filePos)))
	if st != efiSuccess {
		writeASCII(co, "  GetPosition failed: ")
		writeHex64(co, st)
		writeASCII(co, "\r\n")
		efiCall1(kf.close, kernelFileHolder)
		return false
	}
	if filePos == 0 {
		writeASCII(co, "  kernel file is empty\r\n")
		efiCall1(kf.close, kernelFileHolder)
		return false
	}
	kernelSize = uintptr(filePos)
	writeASCII(co, "  found UKI, size = ")
	writeHex64(co, uint64(kernelSize))
	writeASCII(co, "\r\n")

	// Step 5: rewind for the Read.
	st = efiCall2(kf.setPosition, kernelFileHolder, 0)
	if st != efiSuccess {
		writeASCII(co, "  SetPosition(0) failed: ")
		writeHex64(co, st)
		writeASCII(co, "\r\n")
		efiCall1(kf.close, kernelFileHolder)
		return false
	}

	// Step 6: AllocatePool a fresh buffer.
	kernelBuffer = 0
	st = efiCall3(bs.allocatePool,
		efiLoaderData,
		kernelSize,
		uintptr(unsafe.Pointer(&kernelBuffer)))
	if st != efiSuccess {
		writeASCII(co, "  AllocatePool failed: ")
		writeHex64(co, st)
		writeASCII(co, "\r\n")
		efiCall1(kf.close, kernelFileHolder)
		return false
	}

	// Step 7: Read kernel bytes. Read mutates kernelSize in place —
	// keep a copy in `filePos` so we can detect short reads.
	filePos = uint64(kernelSize)
	st = efiCall3(kf.read,
		kernelFileHolder,
		uintptr(unsafe.Pointer(&kernelSize)),
		kernelBuffer)
	// Close the file regardless.
	efiCall1(kf.close, kernelFileHolder)
	if st != efiSuccess {
		writeASCII(co, "  Read failed: ")
		writeHex64(co, st)
		writeASCII(co, "\r\n")
		return false
	}
	if uint64(kernelSize) != filePos {
		writeASCII(co, "  short read: ")
		writeHex64(co, uint64(kernelSize))
		writeASCII(co, " of ")
		writeHex64(co, filePos)
		writeASCII(co, "\r\n")
		return false
	}

	// Step 8: LoadImage from the in-memory buffer.
	childImageHandle = 0
	st = efiCall6(bs.loadImage,
		0,                                            // BootPolicy = FALSE: SourceBuffer holds the image
		imageHandle,                                  // ParentImageHandle
		0,                                            // DevicePath = NULL
		kernelBuffer,                                 // SourceBuffer
		kernelSize,                                   // SourceSize
		uintptr(unsafe.Pointer(&childImageHandle)),   // OUT: ImageHandle
	)
	if st != efiSuccess {
		writeASCII(co, "  LoadImage failed: ")
		writeHex64(co, st)
		writeASCII(co, "\r\n")
		return false
	}
	writeASCII(co, "  LoadImage OK, child handle = ")
	writeHex64(co, uint64(childImageHandle))
	writeASCII(co, "\r\n")

	// Step 9: propagate the cmdline (if any) into the child's
	// LoadedImage protocol. Soft-fails — see patchChildCmdline.
	patchChildCmdline(co, bs, childImageHandle)
	return true
}

//go:export _start
func _start(imageHandle uintptr, st *efiSystemTable) efiStatus {
	co := st.conOut
	bs := st.bootServices
	rt := st.runtimeServices

	// Apple-VZ diagnostic: SimpleTextOutput on Apple's UEFI under
	// vfkit goes to framebuffer only — there's no serial pipe to
	// macOS hosting. Stamp a non-volatile EFI variable as the very
	// first action so the host can detect via vfkit's varstore file
	// that the loader executed at all.
	bootMarkRT = rt
	bootMark("CB-RAN")

	// Phase-A passive probe: bring the EFI_SIMPLE_NETWORK interface
	// up (LocateHandleBuffer → HandleProtocol → Start → Initialize
	// → ReceiveFilters) and stash the active MAC in the non-volatile
	// `CloudBootMAC` EFI variable. Non-fatal — if no NIC handle is
	// exposed (e.g. firmware without an SNP driver for the connected
	// device), we just continue with the existing FAT-UKI / cloud-disk
	// cascade. CloudBootMAC absent from the post-run varstore = SNP
	// not reachable.
	//
	// This is the foundation the loader's eventual OCI plan fetch
	// sits on (see memory:loader-network-stack-roadmap). Keeping it
	// non-fatal lets the loader continue to boot the existing 6
	// distros without depending on network — the OCI path is opt-in.
	if netInit(co, bs) {
		for i := 0; i < 6; i++ {
			netMarkVarData[i] = netLocalMAC[i]
		}
		if rt != nil && rt.setVariable != 0 {
			efiCall5(rt.setVariable,
				uintptr(unsafe.Pointer(&netMacVarName[0])),
				uintptr(unsafe.Pointer(&cloudBootGUID)),
				uintptr(0x07), // NV|BS|RT
				uintptr(len(netMarkVarData)),
				uintptr(unsafe.Pointer(&netMarkVarData[0])))
		}
	} else {
		// SNP wasn't available (typical on Apple VZ). Phase B
		// fallback: enumerate PCI directly and look for virtio-net.
		// This sets up the foundation for the DIY virtio-net stack
		// that the eventual OCI plan fetch will sit on
		// (memory:loader-network-stack-roadmap, option 1 of the
		// VZ-pivot question). Result lands in CloudBootMark =
		// PCI-NETOK / PCI-NONET / PCI-NONE.
		if pciInit(co, bs) {
			// Phase C: walk the virtio capability chain on the
			// found PCI device, locate the DEVICE_CFG sub-page,
			// read the MAC out of it. CloudBootMark = VN-MACOK
			// on success.
			if vnetInit(co) {
				for i := 0; i < 6; i++ {
					netMarkVarData[i] = vnetLocalMAC[i]
				}
				if rt != nil && rt.setVariable != 0 {
					efiCall5(rt.setVariable,
						uintptr(unsafe.Pointer(&netMacVarName[0])),
						uintptr(unsafe.Pointer(&cloudBootGUID)),
						uintptr(0x07),
						uintptr(len(netMarkVarData)),
						uintptr(unsafe.Pointer(&netMarkVarData[0])))
				}
				// Phase D1: virtio device-init handshake. Resets
				// the device, runs feature negotiation, latches
				// FEATURES_OK. Required before any virtqueue work
				// (Phase D2) can program queue addresses. Marker:
				// VN-FOK on success.
				bsGlobal = bs
				vnetNegotiate(co)
			}
		}
	}

	writeASCII(co, "cloud-boot/loader — phase 5b/5c/5d\r\n")

	// Try the EFI-variable cmdline first. If the host staged
	// `CloudBootCmdline` under cloudBootGUID via efivar-stage, it
	// wins — no disk dependency for boot configuration. The disk
	// `\cmdline` fallback still works for media that doesn't have
	// host-side access to the OVMF varstore.
	cmdlineChars = 0
	if readCmdlineEFIVar(co, bs, rt) {
		writeASCII(co, "cmdline source: EFI variable\r\n")
	}

	// Resolve target UKI from CloudBootTarget (or fall back to the
	// "cloud-boot" default). Builds the full \EFI\Linux\<target>.efi
	// path in ukiPath.
	targetRawLen = 0
	readTargetEFIVar(co, rt)
	buildUKIPath()

	// CloudBootTarget shortcuts. The variable normally names a UKI
	// under \EFI\Linux\<target>.efi, but three special values let
	// the host force a specific cascade entry:
	//
	//   "ext4-direct"  — skip FAT entirely, go straight to ext4
	//                     cloud-disk fallback.
	//   "xfs-direct"   — skip FAT and ext4, go straight to xfs
	//                     cloud-disk fallback.
	//   "btrfs-direct" — skip FAT/ext4/xfs, go straight to btrfs
	//                     cloud-disk fallback.
	//   anything else  — normal FAT-volume UKI lookup, with
	//                     cloud-disk fallback if nothing matches.
	skipFAT := bytesMatchTarget(ext4DirectTag[:]) ||
		bytesMatchTarget(xfsDirectTag[:]) ||
		bytesMatchTarget(btrfsDirectTag[:])
	skipExt4 := bytesMatchTarget(xfsDirectTag[:]) ||
		bytesMatchTarget(btrfsDirectTag[:])
	skipXfs := bytesMatchTarget(btrfsDirectTag[:])

	loaded := false
	if !skipFAT && !skipExt4 {
		// Step 1: enumerate every SimpleFileSystem handle.
		sfsHandleCount = 0
		sfsHandleBuf = 0
		status := efiCall5(bs.locateHandleBuffer,
			uintptr(2),
			uintptr(unsafe.Pointer(&simpleFileSystemGUID)),
			0,
			uintptr(unsafe.Pointer(&sfsHandleCount)),
			uintptr(unsafe.Pointer(&sfsHandleBuf)))
		if status == efiSuccess && sfsHandleCount > 0 {
			writeASCII(co, "SimpleFileSystem handles: ")
			writeHex64(co, uint64(sfsHandleCount))
			writeASCII(co, "\r\n")
			// Step 2: try each volume for the resolved target.
			loaded = tryAllHandles(co, bs, imageHandle)
			if !loaded && targetRawLen > 0 {
				writeASCII(co, "  target UKI not found, falling back to cloud-boot.efi\r\n")
				targetRawLen = 0
				buildUKIPath()
				loaded = tryAllHandles(co, bs, imageHandle)
			}
		} else {
			writeASCII(co, "no SimpleFileSystem handles, going to cloud-disk\r\n")
		}
	} else {
		writeASCII(co, "CloudBootTarget shortcut: skipping FAT UKI lookup\r\n")
	}

	if !loaded {
		// Phase 5d fallback: walk BlockIO handles for an ext4
		// partition whose /boot has vmlinuz-* + initrd.img-*. This
		// is the cloud-disk path that boots a stock Linux
		// distribution image (Debian / Ubuntu / Fedora …) without
		// modification — same handoff as the FAT path (LoadImage +
		// patchChildCmdline + StartImage) so the rest of _start
		// runs unchanged.
		writeASCII(co, "no UKI found, falling back to cloud-disk\r\n")
		// ext4 first (Debian / Ubuntu / Alpine — /boot inside rootfs).
		// xfs second (RHEL / AlmaLinux / Rocky — separate /boot
		// partition). btrfs third (openSUSE MicroOS / Leap Micro,
		// snapshot-based rootfs). The CloudBootTarget=<fs>-direct
		// shortcuts (skipExt4 / skipXfs) skip earlier rungs when the
		// host knows which filesystem the cloud image uses, mostly
		// for diagnostic isolation.
		cdOK := false
		if !skipExt4 {
			cdOK = tryCloudDiskBoot(co, bs, imageHandle)
		}
		if !cdOK && !skipXfs {
			cdOK = tryXfsCloudBoot(co, bs, imageHandle)
		}
		if !cdOK {
			cdOK = tryBtrfsCloudBoot(co, bs, imageHandle)
		}
		if !cdOK {
			writeASCII(co, "cloud-disk fallback failed\r\n")
			for {
			}
		}
		patchChildCmdline(co, bs, childImageHandle)
	}

	// Step 3: StartImage. On the happy path it never returns — the
	// kernel's EFI stub takes over, calls ExitBootServices itself,
	// and runs Linux. On failure (a non-EFI image, a stub that exits
	// without ExitBootServices, etc.) we land back here.
	writeASCII(co, "StartImage...\r\n")
	rc := efiCall3(bs.startImage, childImageHandle, 0, 0)
	writeASCII(co, "StartImage returned: ")
	writeHex64(co, rc)
	writeASCII(co, "\r\n")
	for {
	}
}

func main() {}
