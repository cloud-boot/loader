// disk-probe — pure-UEFI disk inspection helper. Walks every
// EFI_BLOCK_IO handle the firmware exposes and reports:
//
//   - LBA size, last block (gives total size)
//   - Whether the handle is a logical partition or a whole disk
//   - GPT header magic (if present at LBA 1) and partition count
//   - For each child partition: filesystem signature detection
//     (ext4 magic at offset 0x438, FAT BPB heuristics, …)
//
// This is the scaffolding for Phase 5d's ext4 driver: by the time we
// can read all the right bytes from the cloud image's root partition,
// most of the BlockIO plumbing is already validated here.
//
// Every buffer is package-scope per the loader's no-heap-under-UEFI
// convention.
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
	runtimeServices   uintptr
	bootServices      *efiBootServices
}

// EFI_BLOCK_IO_PROTOCOL — first three callable slots; the rest we
// don't touch.
type efiBlockIO struct {
	revision    uint64
	media       uintptr // → efiBlockIOMedia
	reset       uintptr
	readBlocks  uintptr // 5 args: (this, mediaId, lba, size, buf)
	writeBlocks uintptr
	flushBlocks uintptr
}

// EFI_BLOCK_IO_MEDIA, laid out per UEFI 2.10 §13.9. We read MediaId,
// MediaPresent, LogicalPartition, BlockSize and LastBlock.
type efiBlockIOMedia struct {
	mediaId          uint32
	removableMedia   uint8
	mediaPresent     uint8
	logicalPartition uint8
	readOnly         uint8
	writeCaching     uint8
	_pad             [3]byte
	blockSize        uint32
	ioAlign          uint32
	_pad2            uint32
	lastBlock        uint64
	// further fields (LowestAlignedLba, …) unused.
}

// ----- protocol GUIDs -----

var (
	// EFI_BLOCK_IO_PROTOCOL_GUID — 964e5b21-6459-11d2-8e39-00a0c969723b
	blockIOGUID = efiGUID{
		0x21, 0x5B, 0x4E, 0x96,
		0x59, 0x64,
		0xD2, 0x11,
		0x8E, 0x39, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B,
	}
)

// ----- asm thunks -----

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

// ----- text output (package-scope buffer, no heap) -----

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

func writeDec(co *efiSimpleTextOutput, n uint64) {
	// Worst-case 20 digits for uint64.
	var digits [21]byte
	i := len(digits)
	if n == 0 {
		i--
		digits[i] = '0'
	}
	for n > 0 {
		i--
		digits[i] = '0' + byte(n%10)
		n /= 10
	}
	// Copy into outBuf.
	j := 0
	for k := i; k < len(digits) && j < len(outBuf)-1; k++ {
		outBuf[j] = uint16(digits[k])
		j++
	}
	outBuf[j] = 0
	efiCall2(co.outputString,
		uintptr(unsafe.Pointer(co)),
		uintptr(unsafe.Pointer(&outBuf[0])))
}

var oneCharBuf [1]byte
var oneCharStr = unsafe.String(&oneCharBuf[0], 1)

// ----- package-scope EFI out-pointers -----

var (
	bioHandleCount uintptr
	bioHandleBuf   uintptr
	bioHolder      uintptr

	// Probe read buffer — 4 KiB, big enough to inspect the first
	// block of any partition we care about. ext4 superblock lives at
	// offset 1024; FAT BPB at 0; GPT header at LBA 1. All comfortably
	// inside 4 KiB.
	probeBuf [4096]byte
)

// readBlocks calls EFI_BLOCK_IO.ReadBlocks(this, MediaId, LBA, Size, Buffer).
func readBlocks(bio uintptr, mediaId uint32, lba uint64, size uintptr, buf uintptr) efiStatus {
	bp := (*efiBlockIO)(unsafe.Pointer(bio))
	return efiCall5(bp.readBlocks,
		bio,
		uintptr(mediaId),
		uintptr(lba),
		size,
		buf)
}

// detectFilesystem reads the first 4 KiB of a partition and reports
// what it looks like. Heuristics:
//
//   - ext2/3/4: magic 0xEF53 at offset 0x438 (relative to the start
//     of the partition, i.e. byte offset 1024 + 0x38 inside the
//     superblock).
//   - FAT12/16/32: OEM string at offset 3 is ASCII; FAT32 BPB has
//     "FAT32   " at offset 0x52, FAT16 has "FAT16   " at 0x36.
//   - GPT: at LBA 1, signature "EFI PART".
//   - Otherwise: unknown.
//
// `data` must be ≥ 4 KiB.
func detectFilesystem(co *efiSimpleTextOutput, data []byte) {
	// GPT header at offset 0x200 (block 1, 512-byte blocks).
	if len(data) >= 0x208 &&
		data[0x200] == 'E' && data[0x201] == 'F' &&
		data[0x202] == 'I' && data[0x203] == ' ' &&
		data[0x204] == 'P' && data[0x205] == 'A' &&
		data[0x206] == 'R' && data[0x207] == 'T' {
		writeASCII(co, "    layout: GPT")
		// Number of entries at offset 0x200 + 0x50.
		if len(data) >= 0x254 {
			nentries := uint32(data[0x250]) |
				uint32(data[0x251])<<8 |
				uint32(data[0x252])<<16 |
				uint32(data[0x253])<<24
			writeASCII(co, ", entries=")
			writeDec(co, uint64(nentries))
		}
		writeASCII(co, "\r\n")
		return
	}

	// ext4 magic at offset 0x438.
	if len(data) >= 0x43A {
		magic := uint16(data[0x438]) | uint16(data[0x439])<<8
		if magic == 0xEF53 {
			writeASCII(co, "    fs: ext2/3/4")
			// s_rev_level at 0x44C (bytes 0x44C-0x44F). v0 = ext2-ish,
			// v1 = ext3/4 with dynamic-size features.
			if len(data) >= 0x450 {
				rev := uint32(data[0x44C]) |
					uint32(data[0x44D])<<8 |
					uint32(data[0x44E])<<16 |
					uint32(data[0x44F])<<24
				writeASCII(co, " rev=")
				writeDec(co, uint64(rev))
			}
			// s_log_block_size at offset 0x418 — log2(blockSize) - 10.
			if len(data) >= 0x41C {
				logBs := uint32(data[0x418]) |
					uint32(data[0x419])<<8 |
					uint32(data[0x41A])<<16 |
					uint32(data[0x41B])<<24
				bs := uint64(1) << (10 + logBs)
				writeASCII(co, " blkSize=")
				writeDec(co, bs)
			}
			// s_volume_name at offset 0x478 (16 ASCII bytes).
			writeASCII(co, " label=\"")
			if len(data) >= 0x488 {
				for i := 0x478; i < 0x488; i++ {
					if data[i] == 0 {
						break
					}
					oneCharBuf[0] = data[i]
					writeASCII(co, oneCharStr)
				}
			}
			writeASCII(co, "\"\r\n")
			return
		}
	}

	// FAT detection — VBR signature 0xAA55 at offset 0x1FE, then look
	// for "FAT" in either of the two well-known BPB slots.
	if len(data) >= 0x200 && data[0x1FE] == 0x55 && data[0x1FF] == 0xAA {
		if len(data) >= 0x46 && data[0x36] == 'F' && data[0x37] == 'A' && data[0x38] == 'T' {
			writeASCII(co, "    fs: FAT12/16 (")
			for i := 0x36; i < 0x3E; i++ {
				if data[i] == 0 || data[i] == ' ' {
					break
				}
				oneCharBuf[0] = data[i]
				writeASCII(co, oneCharStr)
			}
			writeASCII(co, ")\r\n")
			return
		}
		if len(data) >= 0x5A && data[0x52] == 'F' && data[0x53] == 'A' && data[0x54] == 'T' {
			writeASCII(co, "    fs: FAT32 (")
			for i := 0x52; i < 0x5A; i++ {
				if data[i] == 0 || data[i] == ' ' {
					break
				}
				oneCharBuf[0] = data[i]
				writeASCII(co, oneCharStr)
			}
			writeASCII(co, ")\r\n")
			return
		}
	}

	writeASCII(co, "    fs: unknown (first 8 bytes = ")
	if len(data) >= 8 {
		for i := 0; i < 8; i++ {
			writeHex64(co, uint64(data[i]))
			writeASCII(co, " ")
		}
	}
	writeASCII(co, ")\r\n")
}

//go:export _start
func _start(imageHandle uintptr, st *efiSystemTable) efiStatus {
	co := st.conOut
	bs := st.bootServices

	writeASCII(co, "cloud-boot/loader disk-probe (phase 5d step 1)\r\n")

	// Enumerate every BlockIO handle.
	bioHandleCount = 0
	bioHandleBuf = 0
	status := efiCall5(bs.locateHandleBuffer,
		uintptr(2), // ByProtocol
		uintptr(unsafe.Pointer(&blockIOGUID)),
		0,
		uintptr(unsafe.Pointer(&bioHandleCount)),
		uintptr(unsafe.Pointer(&bioHandleBuf)))
	if status != efiSuccess || bioHandleCount == 0 {
		writeASCII(co, "no BlockIO handles (status=")
		writeHex64(co, status)
		writeASCII(co, ")\r\n")
		for {
		}
	}
	writeASCII(co, "BlockIO handles: ")
	writeDec(co, uint64(bioHandleCount))
	writeASCII(co, "\r\n")

	for i := uintptr(0); i < bioHandleCount; i++ {
		h := *(*uintptr)(unsafe.Pointer(bioHandleBuf + i*unsafe.Sizeof(uintptr(0))))

		bioHolder = 0
		st := efiCall3(bs.handleProtocol,
			h,
			uintptr(unsafe.Pointer(&blockIOGUID)),
			uintptr(unsafe.Pointer(&bioHolder)))
		if st != efiSuccess || bioHolder == 0 {
			continue
		}
		bp := (*efiBlockIO)(unsafe.Pointer(bioHolder))
		media := (*efiBlockIOMedia)(unsafe.Pointer(bp.media))

		writeASCII(co, "  [")
		writeDec(co, uint64(i))
		writeASCII(co, "] handle=")
		writeHex64(co, uint64(h))
		writeASCII(co, " mediaId=")
		writeHex64(co, uint64(media.mediaId))
		writeASCII(co, " blkSize=")
		writeDec(co, uint64(media.blockSize))
		writeASCII(co, " lastLba=")
		writeDec(co, media.lastBlock)
		writeASCII(co, " sizeMiB=")
		// Total bytes = blockSize * (lastBlock + 1); print in MiB.
		totalMiB := (uint64(media.blockSize) * (media.lastBlock + 1)) >> 20
		writeDec(co, totalMiB)
		if media.logicalPartition != 0 {
			writeASCII(co, " [partition]\r\n")
		} else {
			writeASCII(co, " [whole disk]\r\n")
		}

		// Read first 4 KiB for fs / GPT detection. Need (4096 /
		// blockSize) blocks; round up.
		blocks := uintptr(4096) / uintptr(media.blockSize)
		if uintptr(4096)%uintptr(media.blockSize) != 0 {
			blocks++
		}
		readSize := blocks * uintptr(media.blockSize)
		if uint64(blocks) > media.lastBlock+1 {
			writeASCII(co, "    (too small to read 4 KiB)\r\n")
			continue
		}
		// Clear the buffer between handles.
		for k := 0; k < len(probeBuf); k++ {
			probeBuf[k] = 0
		}
		rst := readBlocks(bioHolder, media.mediaId, 0,
			readSize, uintptr(unsafe.Pointer(&probeBuf[0])))
		if rst != efiSuccess {
			writeASCII(co, "    ReadBlocks failed: ")
			writeHex64(co, rst)
			writeASCII(co, "\r\n")
			continue
		}
		detectFilesystem(co, probeBuf[:])
	}

	writeASCII(co, "DISK-PROBE-DONE\r\n")
	_ = imageHandle
	for {
	}
}

func main() {}
