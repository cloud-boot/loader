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
	consoleInHandle   uintptr
	conIn             uintptr
	consoleOutHandle  uintptr
	conOut            *efiSimpleTextOutput
	standardErrHandle uintptr
	stdErr            uintptr
	runtimeServices   uintptr
	bootServices      *efiBootServices
}

// EFI_SIMPLE_FILE_SYSTEM_PROTOCOL — only the OpenVolume slot matters.
//
//	UINT64                  Revision;          // 0x00
//	EFI_FILE_OPEN_VOLUME    OpenVolume;        // 0x08
//	    EFI_STATUS (*)(SFS *this, EFI_FILE_PROTOCOL **root)
type efiSimpleFileSystem struct {
	revision   uint64
	openVolume uintptr
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
)

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

	// Canonical UKI path. UEFI requires backslash separators and
	// UTF-16LE. Pre-encoded so we don't allocate at runtime.
	//
	// "\EFI\Linux\cloud-boot.efi"
	ukiPath = [...]uint16{
		'\\', 'E', 'F', 'I',
		'\\', 'L', 'i', 'n', 'u', 'x',
		'\\', 'c', 'l', 'o', 'u', 'd', '-', 'b', 'o', 'o', 't', '.', 'e', 'f', 'i',
		0,
	}
)

// tryLoadFromHandle attempts to chain-load `\EFI\Linux\cloud-boot.efi`
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

	// Step 3: Open the kernel image. Mode = READ, no attributes.
	kernelFileHolder = 0
	st = efiCall5(root.open,
		rootFileHolder,
		uintptr(unsafe.Pointer(&kernelFileHolder)),
		uintptr(unsafe.Pointer(&ukiPath[0])),
		uintptr(efiFileModeRead),
		0)
	// Close root regardless — we're done with it.
	efiCall1(root.close, rootFileHolder)
	if st != efiSuccess {
		// EFI_NOT_FOUND is the normal "this volume doesn't have our
		// UKI" path; don't log it noisily.
		return false
	}
	kf := (*efiFile)(unsafe.Pointer(kernelFileHolder))

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
	return true
}

//go:export _start
func _start(imageHandle uintptr, st *efiSystemTable) efiStatus {
	co := st.conOut
	bs := st.bootServices

	writeASCII(co, "cloud-boot/loader — disk-mode (phase 5a)\r\n")

	// Step 1: enumerate every SimpleFileSystem handle. ByProtocol
	// search (SearchType=2) plus the EFI_SIMPLE_FILE_SYSTEM GUID
	// gives us every FAT/exfat/iso9660 volume the firmware exposes,
	// which is what holds our UKI.
	sfsHandleCount = 0
	sfsHandleBuf = 0
	status := efiCall5(bs.locateHandleBuffer,
		uintptr(2),
		uintptr(unsafe.Pointer(&simpleFileSystemGUID)),
		0,
		uintptr(unsafe.Pointer(&sfsHandleCount)),
		uintptr(unsafe.Pointer(&sfsHandleBuf)))
	if status != efiSuccess || sfsHandleCount == 0 {
		writeASCII(co, "no SimpleFileSystem handles (status=")
		writeHex64(co, status)
		writeASCII(co, ")\r\n")
		for {
		}
	}
	writeASCII(co, "SimpleFileSystem handles: ")
	writeHex64(co, uint64(sfsHandleCount))
	writeASCII(co, "\r\n")

	// Step 2: try each volume until one yields the UKI. First hit wins.
	loaded := false
	for i := uintptr(0); i < sfsHandleCount; i++ {
		h := *(*uintptr)(unsafe.Pointer(sfsHandleBuf + i*unsafe.Sizeof(uintptr(0))))
		writeASCII(co, "  trying SFS handle ")
		writeHex64(co, uint64(h))
		writeASCII(co, "\r\n")
		if tryLoadFromHandle(co, bs, imageHandle, h) {
			loaded = true
			break
		}
	}
	if !loaded {
		writeASCII(co, "no UKI found at \\EFI\\Linux\\cloud-boot.efi on any volume\r\n")
		for {
		}
	}

	// Step 3: StartImage. On the happy path it never returns — the
	// kernel's EFI stub takes over, calls ExitBootServices itself,
	// and runs Linux. On failure (a non-EFI image, a stub that exits
	// without ExitBootServices, etc.) we land back here.
	writeASCII(co, "StartImage...\r\n")
	status = efiCall3(bs.startImage, childImageHandle, 0, 0)
	writeASCII(co, "StartImage returned: ")
	writeHex64(co, status)
	writeASCII(co, "\r\n")
	for {
	}
}

func main() {}
