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

	// Latest parsed ext4 superblock. Populated by parseExt4SB when
	// detectFilesystem classifies a handle as ext4. Step 3+ will use
	// it together with the BlockIO handle to read inode tables.
	lastSB      ext4SB
	lastSBValid bool

	// Remember the BlockIO context that produced lastSB so the GDT
	// follow-up read uses the right handle/media/blksize without
	// passing parameters through detectFilesystem.
	lastBIO       uintptr
	lastMediaId   uint32
	lastDevBlkSz  uint32
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

// ----- ext4 superblock parsing -----
//
// The superblock starts at byte offset 1024 of the filesystem
// (independently of the underlying block size). It's 1024 bytes long.
// We only mirror the fields we need to walk inode tables; everything
// else gets accessed by raw offset.

type ext4SB struct {
	inodesCount      uint32 // 0x00
	blocksCountLo    uint32 // 0x04
	rsvdBlocksLo     uint32 // 0x08
	freeBlocksLo     uint32 // 0x0C
	freeInodesCount  uint32 // 0x10
	firstDataBlock   uint32 // 0x14
	logBlockSize     uint32 // 0x18 — block size = 1 << (10 + this)
	blocksPerGroup   uint32 // 0x20
	inodesPerGroup   uint32 // 0x28
	magic            uint16 // 0x38
	revLevel         uint32 // 0x4C  (0 = ext2-classic; 1 = dynamic)
	firstIno         uint32 // 0x54  (usually 11; root is ALWAYS inode 2)
	inodeSize        uint16 // 0x58  (128 or 256)
	featureCompat    uint32 // 0x5C
	featureIncompat  uint32 // 0x60
	featureROCompat  uint32 // 0x64
	descSize         uint16 // 0xFE  (64 if 64bit feature, 32 otherwise)
	blocksCountHi    uint32 // 0x150 (with 64bit feature)
	logGroupsPerFlex uint8  // 0x174 (flex_bg)

	// Derived.
	blockSize  uint64
	is64bit    bool
	totalBlks  uint64
	totalGroups uint64
}

const (
	ext4FeatureIncompat64Bit  uint32 = 0x80
	ext4FeatureIncompatExtent uint32 = 0x40
	ext4FeatureCompatExtNames uint32 = 0x4 // dir_index
)

// parseExt4SB fills `sb` from `data` (must contain at least 2048
// bytes — the partition's first 2 blocks of 1024). Returns true if
// the magic checks out.
func parseExt4SB(data []byte, sb *ext4SB) bool {
	if len(data) < 0x500 {
		return false
	}
	const o = 1024 // superblock offset
	sb.inodesCount = le32(data[o+0x00:])
	sb.blocksCountLo = le32(data[o+0x04:])
	sb.rsvdBlocksLo = le32(data[o+0x08:])
	sb.freeBlocksLo = le32(data[o+0x0C:])
	sb.freeInodesCount = le32(data[o+0x10:])
	sb.firstDataBlock = le32(data[o+0x14:])
	sb.logBlockSize = le32(data[o+0x18:])
	sb.blocksPerGroup = le32(data[o+0x20:])
	sb.inodesPerGroup = le32(data[o+0x28:])
	sb.magic = le16(data[o+0x38:])
	if sb.magic != 0xEF53 {
		return false
	}
	sb.revLevel = le32(data[o+0x4C:])
	sb.firstIno = le32(data[o+0x54:])
	sb.inodeSize = le16(data[o+0x58:])
	sb.featureCompat = le32(data[o+0x5C:])
	sb.featureIncompat = le32(data[o+0x60:])
	sb.featureROCompat = le32(data[o+0x64:])
	sb.descSize = le16(data[o+0xFE:])
	sb.blocksCountHi = le32(data[o+0x150:])
	sb.logGroupsPerFlex = data[o+0x174]

	// Inode size defaults to 128 for ext2 (revLevel=0).
	if sb.inodeSize == 0 {
		sb.inodeSize = 128
	}
	// desc_size defaults to 32 unless the 64bit feature is on AND a
	// non-zero value is recorded.
	sb.is64bit = sb.featureIncompat&ext4FeatureIncompat64Bit != 0
	if sb.descSize == 0 {
		sb.descSize = 32
	} else if !sb.is64bit && sb.descSize < 32 {
		sb.descSize = 32
	}

	sb.blockSize = uint64(1) << (10 + sb.logBlockSize)
	sb.totalBlks = uint64(sb.blocksCountLo)
	if sb.is64bit {
		sb.totalBlks |= uint64(sb.blocksCountHi) << 32
	}
	if sb.blocksPerGroup > 0 {
		sb.totalGroups = (sb.totalBlks + uint64(sb.blocksPerGroup) - 1) /
			uint64(sb.blocksPerGroup)
	}
	return true
}

func le16(b []byte) uint16 {
	return uint16(b[0]) | uint16(b[1])<<8
}
func le32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

// printExt4SB dumps the parsed fields for diagnostic.
func printExt4SB(co *efiSimpleTextOutput, sb *ext4SB) {
	writeASCII(co, "    ext4 SB: blockSize=")
	writeDec(co, sb.blockSize)
	writeASCII(co, " inodeSize=")
	writeDec(co, uint64(sb.inodeSize))
	writeASCII(co, " inodesPerGroup=")
	writeDec(co, uint64(sb.inodesPerGroup))
	writeASCII(co, " blocksPerGroup=")
	writeDec(co, uint64(sb.blocksPerGroup))
	writeASCII(co, "\r\n    rev=")
	writeDec(co, uint64(sb.revLevel))
	writeASCII(co, " firstIno=")
	writeDec(co, uint64(sb.firstIno))
	writeASCII(co, " totalBlocks=")
	writeDec(co, sb.totalBlks)
	writeASCII(co, " totalGroups=")
	writeDec(co, sb.totalGroups)
	writeASCII(co, " descSize=")
	writeDec(co, uint64(sb.descSize))
	writeASCII(co, "\r\n    feat: ")
	if sb.is64bit {
		writeASCII(co, "64bit ")
	}
	if sb.featureIncompat&ext4FeatureIncompatExtent != 0 {
		writeASCII(co, "extents ")
	}
	if sb.featureIncompat&0x200 != 0 {
		writeASCII(co, "flex_bg ")
	}
	if sb.featureCompat&ext4FeatureCompatExtNames != 0 {
		writeASCII(co, "dir_index ")
	}
	writeASCII(co, "(incompat=")
	writeHex64(co, uint64(sb.featureIncompat))
	writeASCII(co, " compat=")
	writeHex64(co, uint64(sb.featureCompat))
	writeASCII(co, ")\r\n")
}

// ----- ext4 inode + extent tree -----
//
// Modern ext4 (with EXT4_FEATURE_INCOMPAT_EXTENTS, which the Debian
// cloud image uses) addresses data blocks through an in-inode extent
// tree. The 60-byte i_block area at inode offset 0x28 holds:
//
//   ext4_extent_header { magic(2)=0xF30A, entries(2), max(2),
//                        depth(2), generation(4) }       // 12 bytes
//   followed by `entries` extent entries (12 B each):
//     depth == 0 — leaf:
//       ee_block(4)  first logical block in this extent
//       ee_len(2)    block count (clamped to 32768 if "uninitialised")
//       ee_start_hi(2) | ee_start_lo(4)  physical block
//     depth >  0 — index node:
//       ei_block(4)  first logical block covered by this child
//       ei_leaf_lo(4) | ei_leaf_hi(2) | ei_unused(2)  child block ptr
//
// 60 / 12 = 5 → header + 4 inline extents per inode. Larger files
// chain through index nodes living in separate blocks.

const (
	extentHeaderMagic uint16 = 0xF30A
	inodeBlockOff     uint32 = 0x28 // start of i_block within an inode
	inodeBlockSize    uint32 = 60   // size of i_block

	// inode flag bits we care about.
	inodeFlagExtents uint32 = 0x80000
)

type ext4Inode struct {
	mode       uint16 // 0x00
	sizeLo     uint32 // 0x04
	flags      uint32 // 0x20
	sizeHi     uint32 // 0x6C
	// i_block (60 bytes) starts at offset 0x28 in the raw inode data.
}

// extentHeader is what sits at offset 0 of i_block (or at offset 0 of
// any extent-index node's body).
type extentHeader struct {
	magic      uint16
	entries    uint16
	maxEntries uint16
	depth      uint16
	generation uint32
}

func parseInode(raw []byte, ino *ext4Inode) bool {
	if len(raw) < 0x80 {
		return false
	}
	ino.mode = le16(raw[0x00:])
	ino.sizeLo = le32(raw[0x04:])
	ino.flags = le32(raw[0x20:])
	ino.sizeHi = le32(raw[0x6C:]) // i_size_high (for files; reserved on dirs)
	return true
}

func parseExtentHeader(raw []byte, eh *extentHeader) bool {
	if len(raw) < 12 {
		return false
	}
	eh.magic = le16(raw[0:])
	eh.entries = le16(raw[2:])
	eh.maxEntries = le16(raw[4:])
	eh.depth = le16(raw[6:])
	eh.generation = le32(raw[8:])
	return eh.magic == extentHeaderMagic
}

// readInode reads inode `inoNum` from the partition into rawInodeBuf
// at offset (inodeSize bytes starting at index 0). Returns true on
// success; the caller can then `parseInode(rawInodeBuf[:inodeSize])`
// and pull the extent header out of rawInodeBuf[0x28:].
func readInode(co *efiSimpleTextOutput, bio uintptr, mediaId, devBlkSz uint32, sb *ext4SB, inoNum uint32) bool {
	if inoNum == 0 || sb.inodesPerGroup == 0 || sb.blockSize == 0 {
		return false
	}
	group := (inoNum - 1) / sb.inodesPerGroup
	idxInGroup := (inoNum - 1) % sb.inodesPerGroup
	if uint64(group) >= sb.totalGroups {
		writeASCII(co, "    readInode: group out of range\r\n")
		return false
	}
	// Find the inode table for this group via the GDT. GDT byte
	// offset = blockSize (for blockSize > 1024). Entry `group` starts
	// at gdtByte + group*descSize.
	gdtByte := sb.blockSize
	if sb.blockSize == 1024 {
		gdtByte = 2 * 1024
	}
	entryByte := gdtByte + uint64(group)*uint64(sb.descSize)
	// Read the block containing the GDT entry.
	gdtBlkLBA := entryByte / uint64(devBlkSz)
	gdtBlkOff := entryByte % uint64(devBlkSz)
	// Need descSize bytes starting at gdtBlkOff. Read one device
	// sector — descSize ≤ 64 ≤ 512 so it can't straddle.
	for k := 0; k < len(probeBuf); k++ {
		probeBuf[k] = 0
	}
	if rst := readBlocks(bio, mediaId, gdtBlkLBA, uintptr(devBlkSz),
		uintptr(unsafe.Pointer(&probeBuf[0]))); rst != efiSuccess {
		writeASCII(co, "    readInode GDT read failed: ")
		writeHex64(co, rst)
		writeASCII(co, "\r\n")
		return false
	}
	itLo := le32(probeBuf[gdtBlkOff+0x08:])
	var inodeTableBlk uint64
	if sb.is64bit && sb.descSize >= 64 {
		itHi := le32(probeBuf[gdtBlkOff+0x28:])
		inodeTableBlk = (uint64(itHi) << 32) | uint64(itLo)
	} else {
		inodeTableBlk = uint64(itLo)
	}
	// Inode's byte offset in the partition.
	inoByte := inodeTableBlk*sb.blockSize + uint64(idxInGroup)*uint64(sb.inodeSize)
	inoLBA := inoByte / uint64(devBlkSz)
	inoOff := inoByte % uint64(devBlkSz)
	// Read one block (4 KiB) covering the inode. Inode size ≤ 256 so
	// it fits even if inoOff is near the end of a 512-byte sector.
	for k := 0; k < len(probeBuf); k++ {
		probeBuf[k] = 0
	}
	if rst := readBlocks(bio, mediaId, inoLBA, uintptr(sb.blockSize),
		uintptr(unsafe.Pointer(&probeBuf[0]))); rst != efiSuccess {
		writeASCII(co, "    readInode inode read failed: ")
		writeHex64(co, rst)
		writeASCII(co, "\r\n")
		return false
	}
	// Copy the inode bytes to the front of rawInodeBuf so the parsers
	// don't have to know about the in-block offset.
	for k := uint32(0); k < uint32(sb.inodeSize); k++ {
		rawInodeBuf[k] = probeBuf[uint32(inoOff)+k]
	}
	return true
}

// rawInodeBuf is the working area for the most-recently-read inode.
// Sized for 256 (= ext4 default); 128-byte ext2 inodes fit too.
var rawInodeBuf [256]byte

// dirBuf is a separate 4-KiB scratch for reading directory data
// blocks. Kept distinct from probeBuf (used by readInode internally)
// so directory traversal can keep multiple buffers live at once.
var dirBuf [4096]byte

// inodeExtents caches the parsed extent tree of the most-recently-
// read inode (depth-0 leaves only — caps at 4 inline extents). The
// caller copies into here right after readInode, then can issue more
// readInode/readDataBlock calls without clobbering the extent info.
type ext4Extent struct {
	logical  uint32
	length   uint16
	physical uint64
}

var (
	inodeExtents     [4]ext4Extent
	inodeExtentCount int
	inodeExtentDepth uint16
	inodeSizeBytes   uint64
)

// snapshotInodeExtents must be called immediately after readInode
// (while rawInodeBuf still holds the just-read inode). It populates
// inodeExtents / inodeExtentCount / inodeExtentDepth / inodeSizeBytes
// from rawInodeBuf so the caller can issue further inode/data reads
// safely.
func snapshotInodeExtents() bool {
	var ino ext4Inode
	if !parseInode(rawInodeBuf[:], &ino) {
		return false
	}
	inodeSizeBytes = (uint64(ino.sizeHi) << 32) | uint64(ino.sizeLo)
	iblock := rawInodeBuf[inodeBlockOff : inodeBlockOff+inodeBlockSize]
	var eh extentHeader
	if !parseExtentHeader(iblock, &eh) {
		return false
	}
	inodeExtentDepth = eh.depth
	inodeExtentCount = 0
	// Only inline leaves for now (depth == 0). Index nodes get
	// walked in a later step.
	if eh.depth != 0 {
		return true
	}
	for i := uint16(0); i < eh.entries && int(i) < len(inodeExtents); i++ {
		off := 12 + int(i)*12
		inodeExtents[i].logical = le32(iblock[off+0:])
		inodeExtents[i].length = le16(iblock[off+4:])
		startHi := le16(iblock[off+6:])
		startLo := le32(iblock[off+8:])
		inodeExtents[i].physical = (uint64(startHi) << 32) | uint64(startLo)
		inodeExtentCount++
	}
	return true
}

// readDataBlock reads one filesystem-block of an inode's data into
// `out`. logicalBlock is the file-relative block index (0 = first
// block of the file). Returns false if the logical block isn't
// mapped (sparse hole) or extents are too complex for this step.
func readDataBlock(co *efiSimpleTextOutput, bio uintptr, mediaId, devBlkSz uint32,
	sb *ext4SB, logicalBlock uint32, out *[4096]byte) bool {
	if inodeExtentDepth != 0 {
		writeASCII(co, "    readDataBlock: depth>0 not implemented yet\r\n")
		return false
	}
	for i := 0; i < inodeExtentCount; i++ {
		e := &inodeExtents[i]
		if logicalBlock >= e.logical && logicalBlock < e.logical+uint32(e.length) {
			physBlk := e.physical + uint64(logicalBlock-e.logical)
			lba := physBlk * sb.blockSize / uint64(devBlkSz)
			for k := 0; k < len(out); k++ {
				out[k] = 0
			}
			rst := readBlocks(bio, mediaId, lba, uintptr(sb.blockSize),
				uintptr(unsafe.Pointer(&out[0])))
			return rst == efiSuccess
		}
	}
	return false
}

// findInDir reads dirIno's data blocks and looks for an entry whose
// name matches `name`. Returns the child inode number and file type
// (1=regular, 2=directory, …) on success.
//
// Caps at scanning the first INODE_DIR_MAX_BLOCKS blocks of the dir,
// which is more than enough for /boot/ on a stock cloud image.
const inodeDirMaxBlocks = 64

func findInDir(co *efiSimpleTextOutput, bio uintptr, mediaId, devBlkSz uint32,
	sb *ext4SB, dirIno uint32, name []byte,
) (childIno uint32, fileType uint8, found bool) {
	if !readInode(co, bio, mediaId, devBlkSz, sb, dirIno) ||
		!snapshotInodeExtents() {
		return 0, 0, false
	}
	maxBlocks := uint32(inodeSizeBytes / sb.blockSize)
	if uint64(maxBlocks)*sb.blockSize < inodeSizeBytes {
		maxBlocks++
	}
	if maxBlocks > inodeDirMaxBlocks {
		maxBlocks = inodeDirMaxBlocks
	}
	for b := uint32(0); b < maxBlocks; b++ {
		if !readDataBlock(co, bio, mediaId, devBlkSz, sb, b, &dirBuf) {
			continue
		}
		// Walk ext4_dir_entry_2 records.
		off := uint32(0)
		for off+8 <= uint32(sb.blockSize) {
			ent := le32(dirBuf[off:])
			recLen := uint32(le16(dirBuf[off+4:]))
			nameLen := uint32(dirBuf[off+6])
			ft := dirBuf[off+7]
			if recLen == 0 || recLen < 8 || off+recLen > uint32(sb.blockSize) {
				break
			}
			if ent != 0 && nameLen > 0 && uint32(len(name)) == nameLen {
				if bytesEqual(dirBuf[off+8:off+8+nameLen], name) {
					return ent, ft, true
				}
			}
			off += recLen
		}
	}
	return 0, 0, false
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// resolvePath walks an absolute path "/a/b/c" component-by-component
// starting from inode 2 (root). Returns the final inode number and
// file type. Components are passed as a single string with '/' as
// separator; leading/trailing slashes tolerated.
func resolvePath(co *efiSimpleTextOutput, bio uintptr, mediaId, devBlkSz uint32,
	sb *ext4SB, path string,
) (uint32, uint8, bool) {
	cur := uint32(2) // root
	curFT := uint8(2) // directory
	i := 0
	for i < len(path) {
		// Skip slashes.
		for i < len(path) && path[i] == '/' {
			i++
		}
		if i >= len(path) {
			break
		}
		// Locate next slash.
		j := i
		for j < len(path) && path[j] != '/' {
			j++
		}
		name := path[i:j]
		// findInDir doesn't accept strings (no heap → []byte). Reuse a
		// fixed name buffer.
		for k := 0; k < len(nameScratch); k++ {
			nameScratch[k] = 0
		}
		if len(name) > len(nameScratch) {
			return 0, 0, false
		}
		copy(nameScratch[:], name)
		ino, ft, ok := findInDir(co, bio, mediaId, devBlkSz, sb, cur, nameScratch[:len(name)])
		if !ok {
			return 0, 0, false
		}
		cur = ino
		curFT = ft
		i = j
	}
	return cur, curFT, true
}

var nameScratch [255]byte

// Hard-coded name buffers for the bring-up path. Keeps us away from
// any string-handling code while we're proving the inode/dir reader
// works against a real cloud image.
var bootNameBuf = [...]byte{'b', 'o', 'o', 't'}

// vmlinuzPrefix is the byte-for-byte prefix every Linux distribution
// uses for its EFI-stubbed kernel under /boot. The "-" terminator
// avoids matching shadow files like "vmlinuz.old" or "vmlinuz.tmp".
var vmlinuzPrefix = [...]byte{'v', 'm', 'l', 'i', 'n', 'u', 'z', '-'}

// kernelName is filled by findInDirPrefix when a vmlinuz-* match is
// found; the full filename is read out so the rest of the loader can
// reference / log it. 255 = max ext4 dir_entry name length.
var (
	kernelName    [255]byte
	kernelNameLen int

	// AllocatePool holder for the kernel image buffer.
	kernelBufPtr uintptr
)

// findInDirPrefix scans `dirIno` for the first entry whose name
// starts with `prefix`. Useful for the kernel/initrd lookup since
// the version suffix changes between distro images.
func findInDirPrefix(co *efiSimpleTextOutput, bio uintptr, mediaId, devBlkSz uint32,
	sb *ext4SB, dirIno uint32, prefix []byte,
	outNameBuf *[255]byte, outNameLen *int,
) (childIno uint32, fileType uint8, found bool) {
	if !readInode(co, bio, mediaId, devBlkSz, sb, dirIno) ||
		!snapshotInodeExtents() {
		return 0, 0, false
	}
	maxBlocks := uint32(inodeSizeBytes / sb.blockSize)
	if uint64(maxBlocks)*sb.blockSize < inodeSizeBytes {
		maxBlocks++
	}
	if maxBlocks > inodeDirMaxBlocks {
		maxBlocks = inodeDirMaxBlocks
	}
	for b := uint32(0); b < maxBlocks; b++ {
		if !readDataBlock(co, bio, mediaId, devBlkSz, sb, b, &dirBuf) {
			continue
		}
		off := uint32(0)
		for off+8 <= uint32(sb.blockSize) {
			ent := le32(dirBuf[off:])
			recLen := uint32(le16(dirBuf[off+4:]))
			nameLen := uint32(dirBuf[off+6])
			ft := dirBuf[off+7]
			if recLen == 0 || recLen < 8 || off+recLen > uint32(sb.blockSize) {
				break
			}
			if ent != 0 && nameLen >= uint32(len(prefix)) {
				match := true
				for i := 0; i < len(prefix); i++ {
					if dirBuf[off+8+uint32(i)] != prefix[i] {
						match = false
						break
					}
				}
				if match {
					// Copy the full name out for the caller.
					n := int(nameLen)
					if n > len(outNameBuf) {
						n = len(outNameBuf)
					}
					for i := 0; i < n; i++ {
						outNameBuf[i] = dirBuf[off+8+uint32(i)]
					}
					*outNameLen = n
					return ent, ft, true
				}
			}
			off += recLen
		}
	}
	return 0, 0, false
}

// ----- extent tree walking for file reads -----
//
// readFile handles depth-0 (inline leaves in i_block) and depth-1
// (i_block has extent-index entries pointing at leaf blocks) trees.
// That covers any file up to ~5 GiB even on 4-KiB blocks
// (4 inline idx × 340 leaves/block × 32 768 blocks/leaf × 4 KiB).
//
// For each leaf extent we ReadBlocks `len` blocks straight into
// out + logical*blockSize. The destination buffer must be at least
// the inode's data size.

// extentLeafBuf is the scratch for one extent-tree leaf block when
// walking depth-1 trees. Separate from dirBuf so an outer caller can
// keep dirBuf live across this call (not needed today, but cheap).
var extentLeafBuf [4096]byte

// readFile reads the entire content of inode `inoNum` into the
// caller-allocated buffer at `outAddr` (size = `outCap`). Returns
// the number of bytes written.
func readFile(co *efiSimpleTextOutput, bio uintptr, mediaId, devBlkSz uint32,
	sb *ext4SB, inoNum uint32, outAddr uintptr, outCap uint64,
) uint64 {
	if !readInode(co, bio, mediaId, devBlkSz, sb, inoNum) {
		writeASCII(co, "    readFile: read inode failed\r\n")
		return 0
	}
	var ino ext4Inode
	if !parseInode(rawInodeBuf[:], &ino) {
		return 0
	}
	fileSize := (uint64(ino.sizeHi) << 32) | uint64(ino.sizeLo)
	if fileSize > outCap {
		writeASCII(co, "    readFile: file too big for buffer\r\n")
		return 0
	}
	iblock := rawInodeBuf[inodeBlockOff : inodeBlockOff+inodeBlockSize]
	var eh extentHeader
	if !parseExtentHeader(iblock, &eh) {
		writeASCII(co, "    readFile: bad extent header\r\n")
		return 0
	}
	switch eh.depth {
	case 0:
		// Inline leaves — same shape snapshotInodeExtents handles.
		for i := uint16(0); i < eh.entries; i++ {
			off := 12 + int(i)*12
			eeBlock := le32(iblock[off+0:])
			eeLen := le16(iblock[off+4:])
			eeStartHi := le16(iblock[off+6:])
			eeStartLo := le32(iblock[off+8:])
			physStart := (uint64(eeStartHi) << 32) | uint64(eeStartLo)
			if !readExtentRange(co, bio, mediaId, devBlkSz, sb,
				physStart, uint64(eeLen),
				outAddr+uintptr(eeBlock)*uintptr(sb.blockSize)) {
				return 0
			}
		}
	case 1:
		// i_block holds up to 4 extent_idx entries. Each leaf block
		// is one filesystem block (4 KiB), itself an extent_header
		// followed by depth-0 leaves.
		for i := uint16(0); i < eh.entries; i++ {
			off := 12 + int(i)*12
			eiLeafLo := le32(iblock[off+4:])
			eiLeafHi := le16(iblock[off+8:])
			eiLeaf := (uint64(eiLeafHi) << 32) | uint64(eiLeafLo)
			leafLBA := eiLeaf * sb.blockSize / uint64(devBlkSz)
			for k := 0; k < len(extentLeafBuf); k++ {
				extentLeafBuf[k] = 0
			}
			if rst := readBlocks(bio, mediaId, leafLBA, uintptr(sb.blockSize),
				uintptr(unsafe.Pointer(&extentLeafBuf[0]))); rst != efiSuccess {
				writeASCII(co, "    readFile: leaf read failed\r\n")
				return 0
			}
			var leafEh extentHeader
			if !parseExtentHeader(extentLeafBuf[:], &leafEh) {
				writeASCII(co, "    readFile: bad leaf magic\r\n")
				return 0
			}
			if leafEh.depth != 0 {
				writeASCII(co, "    readFile: depth>1 not implemented\r\n")
				return 0
			}
			for j := uint16(0); j < leafEh.entries; j++ {
				eoff := 12 + int(j)*12
				eeBlock := le32(extentLeafBuf[eoff+0:])
				eeLen := le16(extentLeafBuf[eoff+4:])
				eeStartHi := le16(extentLeafBuf[eoff+6:])
				eeStartLo := le32(extentLeafBuf[eoff+8:])
				physStart := (uint64(eeStartHi) << 32) | uint64(eeStartLo)
				if !readExtentRange(co, bio, mediaId, devBlkSz, sb,
					physStart, uint64(eeLen),
					outAddr+uintptr(eeBlock)*uintptr(sb.blockSize)) {
					return 0
				}
			}
		}
	default:
		writeASCII(co, "    readFile: depth>1 not supported yet\r\n")
		return 0
	}
	return fileSize
}

// efiLoadedImageProtocol — only the LoadOptions slots matter; we
// patch them post-LoadImage so the chained kernel sees our cmdline.
// Layout per UEFI 2.10 §9.1 (mirrors loader/cmd/efi-loader's copy).
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

// EFI_LOADED_IMAGE_PROTOCOL_GUID — 5b1b31a1-9562-11d2-8e3f-00a0c969723b
var loadedImageGUID = efiGUID{
	0xA1, 0x31, 0x1B, 0x5B,
	0x62, 0x95,
	0xD2, 0x11,
	0x8E, 0x3F, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B,
}

// EFI_DEVICE_PATH_PROTOCOL_GUID — 09576e91-6d3f-11d2-8e39-00a0c969723b
var devicePathGUID = efiGUID{
	0x91, 0x6E, 0x57, 0x09,
	0x3F, 0x6D,
	0xD2, 0x11,
	0x8E, 0x39, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B,
}

// EFI_LOAD_FILE2_PROTOCOL_GUID — 4006c0c1-fcb3-403e-996d-4a6c8724e06d
var loadFile2GUID = efiGUID{
	0xC1, 0xC0, 0x06, 0x40,
	0xB3, 0xFC,
	0x3E, 0x40,
	0x99, 0x6D, 0x4A, 0x6C, 0x87, 0x24, 0xE0, 0x6D,
}

// LINUX_EFI_INITRD_MEDIA_GUID — 5568e427-68fc-4f3d-ac74-ca555231cc68
//
// This is the vendor GUID Linux's EFI stub looks for: it scans every
// handle in the system for one whose device path is a MEDIA_VENDOR
// node carrying this GUID, then calls LoadFile2 on it to fetch the
// initrd. See efi/libstub/efi-stub-helper.c and
// efi/libstub/file.c in the kernel tree.
var linuxInitrdGUID = efiGUID{
	0x27, 0xE4, 0x68, 0x55,
	0xFC, 0x68,
	0x3D, 0x4F,
	0xAC, 0x74, 0xCA, 0x55, 0x52, 0x31, 0xCC, 0x68,
}

// EFI_LOAD_FILE2_PROTOCOL is a single-method protocol whose
// instance pointer the firmware (well, the Linux EFI stub here)
// dereferences to find the LoadFile callback. The callback runs
// in AAPCS64 — same convention every other firmware call uses on
// arm64 — so we install a raw asm trampoline (loadFile2 in
// thunk-arm64.S) that tail-calls our Go implementation
// goLoadFile2.
type efiLoadFile2Protocol struct {
	loadFile uintptr
}

// loadFile2Ptr is defined in thunk-arm64.S — returns the runtime
// address of the asm `loadFile2` entry symbol.
//go:linkname loadFile2Ptr loadFile2Ptr
func loadFile2Ptr() uintptr

// EFI status codes the LoadFile2 callback needs.
const (
	efiInvalidParameter efiStatus = 0x8000000000000002
	efiBufferTooSmall   efiStatus = 0x8000000000000005
)

// Hard-coded bring-up cmdline: serial console + label-based root.
// Once the loader proper inherits this code path, the cmdline comes
// from the CloudBootCmdline UEFI variable (Phase 5b).
//
// "console=ttyAMA0 root=LABEL=cloudimg-rootfs ro\0" as UTF-16LE.
var cmdlineUTF16 = [...]uint16{
	'c', 'o', 'n', 's', 'o', 'l', 'e', '=', 't', 't', 'y', 'A', 'M', 'A', '0', ' ',
	'r', 'o', 'o', 't', '=', 'L', 'A', 'B', 'E', 'L', '=',
	'c', 'l', 'o', 'u', 'd', 'i', 'm', 'g', '-', 'r', 'o', 'o', 't', 'f', 's', ' ',
	'r', 'o',
	0,
}

var (
	kernelImageHandle uintptr
	kernelLIPHolder   uintptr

	// Filled by readKernel right after a successful readFile so the
	// caller (here: _start) can pass the exact byte count to LoadImage
	// without re-parsing the inode.
	loadedKernelSize uint64

	// Initrd state. initrdDataPtr+initrdSize describe the in-memory
	// initrd buffer; the goLoadFile2 callback uses them to answer the
	// kernel's LoadFile2 request.
	initrdHandle   uintptr
	initrdDataPtr  uintptr
	initrdSize     uint64
	initrdName     [255]byte
	initrdNameLen  int
	initrdProtocol efiLoadFile2Protocol

	// Device path published on initrdHandle: MEDIA_VENDOR node with
	// LINUX_EFI_INITRD_MEDIA_GUID + end-of-path terminator.
	vendorMediaInitrdPath [24]byte
)

// "initrd.img-" — Debian / Ubuntu / Alpine all use this prefix.
// RHEL/Fedora use "initramfs-" instead; the loader can scan for both
// once we generalise. For Phase-5d bring-up against the Debian image
// the single prefix is enough.
var initrdPrefix = [...]byte{'i', 'n', 'i', 't', 'r', 'd', '.', 'i', 'm', 'g', '-'}

// goLoadFile2 — the EFI_LOAD_FILE2_PROTOCOL.LoadFile callback the
// Linux EFI stub invokes when it walks the system for an initrd
// provider. Signature (UEFI 2.10 §13.4):
//
//	EFI_STATUS LoadFile(
//	  EFI_LOAD_FILE2_PROTOCOL *This,
//	  EFI_DEVICE_PATH_PROTOCOL *FilePath,
//	  BOOLEAN BootPolicy,
//	  UINTN *BufferSize,
//	  VOID *Buffer);
//
// Two-pass protocol: kernel calls with Buffer=NULL to learn the
// size (we return EFI_BUFFER_TOO_SMALL and write our size to
// *BufferSize), then again with a buffer of that size.
//
//go:export goLoadFile2
func goLoadFile2(self, devPath, bootPolicy uintptr, bufSizePtr *uint64, buf uintptr) uint64 {
	if bufSizePtr == nil {
		return uint64(efiInvalidParameter)
	}
	if buf == 0 || *bufSizePtr < initrdSize {
		*bufSizePtr = initrdSize
		return uint64(efiBufferTooSmall)
	}
	*bufSizePtr = initrdSize
	// Byte-by-byte copy. With initrdSize ~30 MiB this takes ~tens of
	// milliseconds on real hardware; acceptable for a one-shot.
	for i := uint64(0); i < initrdSize; i++ {
		*(*byte)(unsafe.Pointer(buf + uintptr(i))) =
			*(*byte)(unsafe.Pointer(initrdDataPtr + uintptr(i)))
	}
	return uint64(efiSuccess)
}

// readInitrd locates /boot/initrd.img-* via prefix match, reads the
// whole file into a fresh AllocatePool buffer, and stores it in
// initrdDataPtr / initrdSize for the LoadFile2 callback.
func readInitrd(co *efiSimpleTextOutput, bs *efiBootServices,
	bio uintptr, mediaId, devBlkSz uint32, sb *ext4SB, bootIno uint32,
) bool {
	iIno, _, ok := findInDirPrefix(co, bio, mediaId, devBlkSz, sb, bootIno,
		initrdPrefix[:], &initrdName, &initrdNameLen)
	if !ok {
		writeASCII(co, "    no initrd.img-* in /boot\r\n")
		return false
	}
	writeASCII(co, "    initrd: ")
	for i := 0; i < initrdNameLen; i++ {
		oneCharBuf[0] = initrdName[i]
		writeASCII(co, oneCharStr)
	}
	writeASCII(co, " (inode=")
	writeDec(co, uint64(iIno))
	writeASCII(co, ")\r\n")

	if !readInode(co, bio, mediaId, devBlkSz, sb, iIno) {
		return false
	}
	var ino ext4Inode
	if !parseInode(rawInodeBuf[:], &ino) {
		return false
	}
	fileSize := (uint64(ino.sizeHi) << 32) | uint64(ino.sizeLo)
	writeASCII(co, "    initrd size = ")
	writeDec(co, fileSize)
	writeASCII(co, " bytes\r\n")

	initrdDataPtr = 0
	st := efiCall3(bs.allocatePool,
		efiLoaderData,
		uintptr(fileSize),
		uintptr(unsafe.Pointer(&initrdDataPtr)))
	if st != efiSuccess || initrdDataPtr == 0 {
		writeASCII(co, "    AllocatePool(initrd) failed: ")
		writeHex64(co, st)
		writeASCII(co, "\r\n")
		return false
	}
	got := readFile(co, bio, mediaId, devBlkSz, sb, iIno, initrdDataPtr, fileSize)
	if got == 0 {
		return false
	}
	initrdSize = got
	writeASCII(co, "    readFile(initrd) OK, ")
	writeDec(co, got)
	writeASCII(co, " bytes\r\n")
	return true
}

// installInitrdProtocol builds the MEDIA_VENDOR device-path node
// (LINUX_EFI_INITRD_MEDIA_GUID) + end terminator, then publishes
// DevicePath + LoadFile2 on a fresh handle. The two
// InstallProtocolInterface calls follow go-coff/stub's Phase-3b
// pattern exactly:
//
//   - First call's *initrdHandle == 0 → firmware creates a new
//     handle and writes it back. DevicePath gets attached.
//   - Second call uses the same handle to add LoadFile2 on top.
//
// After this returns, the Linux EFI stub will find our protocol
// when it walks for the LINUX_EFI_INITRD_MEDIA_GUID device path.
func installInitrdProtocol(co *efiSimpleTextOutput, bs *efiBootServices) bool {
	// MEDIA_DEVICE_PATH (Type=0x04) / MEDIA_VENDOR (SubType=0x03),
	// length 20 (4-byte header + 16-byte GUID).
	vendorMediaInitrdPath[0] = 0x04
	vendorMediaInitrdPath[1] = 0x03
	vendorMediaInitrdPath[2] = 20
	vendorMediaInitrdPath[3] = 0
	for i := 0; i < 16; i++ {
		vendorMediaInitrdPath[4+i] = linuxInitrdGUID[i]
	}
	// End-of-hardware-device-path: Type=0x7F, SubType=0xFF, Length=4.
	vendorMediaInitrdPath[20] = 0x7F
	vendorMediaInitrdPath[21] = 0xFF
	vendorMediaInitrdPath[22] = 4
	vendorMediaInitrdPath[23] = 0

	initrdProtocol.loadFile = loadFile2Ptr()
	writeASCII(co, "    LoadFile2 callback addr = ")
	writeHex64(co, uint64(initrdProtocol.loadFile))
	writeASCII(co, "\r\n")

	const efiNativeInterface = 0
	initrdHandle = 0
	st := efiCall4(bs.installProtocolInterface,
		uintptr(unsafe.Pointer(&initrdHandle)),
		uintptr(unsafe.Pointer(&devicePathGUID)),
		efiNativeInterface,
		uintptr(unsafe.Pointer(&vendorMediaInitrdPath[0])))
	if st != efiSuccess {
		writeASCII(co, "    InstallProtocol(DevicePath) failed: ")
		writeHex64(co, st)
		writeASCII(co, "\r\n")
		return false
	}
	st = efiCall4(bs.installProtocolInterface,
		uintptr(unsafe.Pointer(&initrdHandle)),
		uintptr(unsafe.Pointer(&loadFile2GUID)),
		efiNativeInterface,
		uintptr(unsafe.Pointer(&initrdProtocol)))
	if st != efiSuccess {
		writeASCII(co, "    InstallProtocol(LoadFile2) failed: ")
		writeHex64(co, st)
		writeASCII(co, "\r\n")
		return false
	}
	writeASCII(co, "    initrd protocols installed on handle ")
	writeHex64(co, uint64(initrdHandle))
	writeASCII(co, "\r\n")
	return true
}

// chainKernel LoadImages the kernel buffer, patches LoadOptions,
// then StartImages it. On the happy path control never returns; on
// failure we report the status and idle.
func chainKernel(co *efiSimpleTextOutput, bs *efiBootServices, imageHandle uintptr, size uint64) {
	kernelImageHandle = 0
	st := efiCall6(bs.loadImage,
		0,                                              // BootPolicy = FALSE
		imageHandle,                                    // ParentImageHandle
		0,                                              // DevicePath = NULL
		kernelBufPtr,                                   // SourceBuffer
		uintptr(size),                                  // SourceSize
		uintptr(unsafe.Pointer(&kernelImageHandle)))
	if st != efiSuccess {
		writeASCII(co, "    LoadImage failed: ")
		writeHex64(co, st)
		writeASCII(co, "\r\n")
		return
	}
	writeASCII(co, "    LoadImage OK, child=")
	writeHex64(co, uint64(kernelImageHandle))
	writeASCII(co, "\r\n")

	kernelLIPHolder = 0
	st = efiCall3(bs.handleProtocol,
		kernelImageHandle,
		uintptr(unsafe.Pointer(&loadedImageGUID)),
		uintptr(unsafe.Pointer(&kernelLIPHolder)))
	if st != efiSuccess {
		writeASCII(co, "    HandleProtocol(LoadedImage) failed: ")
		writeHex64(co, st)
		writeASCII(co, "\r\n")
	} else {
		lip := (*efiLoadedImageProtocol)(unsafe.Pointer(kernelLIPHolder))
		// Count UTF-16 chars excl. NUL.
		n := uint32(0)
		for cmdlineUTF16[n] != 0 && int(n) < len(cmdlineUTF16) {
			n++
		}
		lip.loadOptions = uintptr(unsafe.Pointer(&cmdlineUTF16[0]))
		lip.loadOptionsSize = (n + 1) * 2
		writeASCII(co, "    patched LoadOptions (")
		writeDec(co, uint64(lip.loadOptionsSize))
		writeASCII(co, " bytes)\r\n")
	}

	writeASCII(co, "    StartImage...\r\n")
	st = efiCall3(bs.startImage, kernelImageHandle, 0, 0)
	writeASCII(co, "    StartImage returned: ")
	writeHex64(co, st)
	writeASCII(co, "\r\n")
}

// readKernel resolves the kernel inode, AllocatePool's a buffer of
// the right size from EfiLoaderData, reads every data block through
// the extent walker, then sanity-checks the result by looking for
// "MZ" at offset 0 (the PE/COFF stub at the head of every Linux
// EFI-stubbed kernel) and the canonical Linux 0x40 "PE\0\0" pointer.
const (
	efiLoaderData uintptr = 2
)

func readKernel(co *efiSimpleTextOutput, bs *efiBootServices,
	bio uintptr, mediaId, devBlkSz uint32, sb *ext4SB, inoNum uint32,
) {
	// Need the size first — read the inode just to extract it.
	if !readInode(co, bio, mediaId, devBlkSz, sb, inoNum) {
		writeASCII(co, "    readKernel: read inode failed\r\n")
		return
	}
	var ino ext4Inode
	if !parseInode(rawInodeBuf[:], &ino) {
		return
	}
	fileSize := (uint64(ino.sizeHi) << 32) | uint64(ino.sizeLo)
	writeASCII(co, "    kernel size = ")
	writeDec(co, fileSize)
	writeASCII(co, " bytes\r\n")

	// AllocatePool(EfiLoaderData, fileSize, &kernelBufPtr).
	kernelBufPtr = 0
	st := efiCall3(bs.allocatePool,
		efiLoaderData,
		uintptr(fileSize),
		uintptr(unsafe.Pointer(&kernelBufPtr)))
	if st != efiSuccess || kernelBufPtr == 0 {
		writeASCII(co, "    AllocatePool failed: ")
		writeHex64(co, st)
		writeASCII(co, "\r\n")
		return
	}
	writeASCII(co, "    AllocatePool OK, buf=")
	writeHex64(co, uint64(kernelBufPtr))
	writeASCII(co, "\r\n")

	got := readFile(co, bio, mediaId, devBlkSz, sb, inoNum,
		kernelBufPtr, fileSize)
	if got == 0 {
		writeASCII(co, "    readFile returned 0 bytes\r\n")
		return
	}
	writeASCII(co, "    readFile OK, ")
	writeDec(co, got)
	writeASCII(co, " bytes\r\n")

	// Remember the size for chainKernel.
	loadedKernelSize = got

	// PE/COFF sanity check: first two bytes must be "MZ"; the LE u32
	// at offset 0x3C points at the "PE\0\0" signature.
	b0 := *(*byte)(unsafe.Pointer(kernelBufPtr))
	b1 := *(*byte)(unsafe.Pointer(kernelBufPtr + 1))
	writeASCII(co, "    bytes[0..2] = ")
	writeHex64(co, uint64(b0))
	writeASCII(co, " ")
	writeHex64(co, uint64(b1))
	if b0 == 'M' && b1 == 'Z' {
		writeASCII(co, " (MZ ✓)")
	}
	writeASCII(co, "\r\n")
	peOff := uint32(*(*byte)(unsafe.Pointer(kernelBufPtr + 0x3C))) |
		uint32(*(*byte)(unsafe.Pointer(kernelBufPtr + 0x3D)))<<8 |
		uint32(*(*byte)(unsafe.Pointer(kernelBufPtr + 0x3E)))<<16 |
		uint32(*(*byte)(unsafe.Pointer(kernelBufPtr + 0x3F)))<<24
	writeASCII(co, "    PE offset = ")
	writeHex64(co, uint64(peOff))
	if peOff < uint32(fileSize)-4 {
		pe0 := *(*byte)(unsafe.Pointer(kernelBufPtr + uintptr(peOff)))
		pe1 := *(*byte)(unsafe.Pointer(kernelBufPtr + uintptr(peOff) + 1))
		pe2 := *(*byte)(unsafe.Pointer(kernelBufPtr + uintptr(peOff) + 2))
		pe3 := *(*byte)(unsafe.Pointer(kernelBufPtr + uintptr(peOff) + 3))
		writeASCII(co, " sig=")
		writeHex64(co, uint64(pe0))
		writeASCII(co, " ")
		writeHex64(co, uint64(pe1))
		writeASCII(co, " ")
		writeHex64(co, uint64(pe2))
		writeASCII(co, " ")
		writeHex64(co, uint64(pe3))
		if pe0 == 'P' && pe1 == 'E' && pe2 == 0 && pe3 == 0 {
			writeASCII(co, " (PE\\0\\0 ✓)")
		}
	}
	writeASCII(co, "\r\n")
}

// readExtentRange ReadBlocks `numBlocks` filesystem blocks starting
// at physical block `physStart` into `dst`. Chunks the call as
// needed since some firmwares cap a single ReadBlocks at the device
// block-window size — but BLOCK_IO has no documented max.
func readExtentRange(co *efiSimpleTextOutput, bio uintptr, mediaId, devBlkSz uint32,
	sb *ext4SB, physStart, numBlocks uint64, dst uintptr,
) bool {
	if numBlocks == 0 {
		return true
	}
	lba := physStart * sb.blockSize / uint64(devBlkSz)
	bytes := numBlocks * sb.blockSize
	rst := readBlocks(bio, mediaId, lba, uintptr(bytes), dst)
	if rst != efiSuccess {
		writeASCII(co, "    readExtentRange: ReadBlocks failed: ")
		writeHex64(co, rst)
		writeASCII(co, "\r\n")
		return false
	}
	return true
}

// listDir prints every name in `dirIno`. Diagnostic helper — Step 5
// will replace this with a name-matching pass that locates a kernel
// like "vmlinuz-6.1.0-cloud-arm64".
func listDir(co *efiSimpleTextOutput, bio uintptr, mediaId, devBlkSz uint32,
	sb *ext4SB, dirIno uint32,
) {
	if !readInode(co, bio, mediaId, devBlkSz, sb, dirIno) ||
		!snapshotInodeExtents() {
		writeASCII(co, "    listDir: read/parse failed\r\n")
		return
	}
	maxBlocks := uint32(inodeSizeBytes / sb.blockSize)
	if uint64(maxBlocks)*sb.blockSize < inodeSizeBytes {
		maxBlocks++
	}
	if maxBlocks > inodeDirMaxBlocks {
		maxBlocks = inodeDirMaxBlocks
	}
	for b := uint32(0); b < maxBlocks; b++ {
		if !readDataBlock(co, bio, mediaId, devBlkSz, sb, b, &dirBuf) {
			continue
		}
		off := uint32(0)
		for off+8 <= uint32(sb.blockSize) {
			ent := le32(dirBuf[off:])
			recLen := uint32(le16(dirBuf[off+4:]))
			nameLen := uint32(dirBuf[off+6])
			ft := dirBuf[off+7]
			if recLen == 0 || recLen < 8 || off+recLen > uint32(sb.blockSize) {
				break
			}
			if ent != 0 && nameLen > 0 {
				writeASCII(co, "      [")
				writeDec(co, uint64(ent))
				writeASCII(co, "/")
				writeDec(co, uint64(ft))
				writeASCII(co, "] ")
				for i := uint32(0); i < nameLen; i++ {
					oneCharBuf[0] = dirBuf[off+8+i]
					writeASCII(co, oneCharStr)
				}
				writeASCII(co, "\r\n")
			}
			off += recLen
		}
	}
}

// dumpExtentTree prints the extent header + entries from a raw 60-byte
// i_block area. Index nodes are reported but not followed (the
// follow-the-pointer path comes in step 4 / 5 once we need it for
// reading directory blocks).
func dumpExtentTree(co *efiSimpleTextOutput, iblock []byte) {
	var eh extentHeader
	if !parseExtentHeader(iblock, &eh) {
		writeASCII(co, "    extent header: bad magic ")
		writeHex64(co, uint64(le16(iblock[0:])))
		writeASCII(co, "\r\n")
		return
	}
	writeASCII(co, "    extent header: entries=")
	writeDec(co, uint64(eh.entries))
	writeASCII(co, " max=")
	writeDec(co, uint64(eh.maxEntries))
	writeASCII(co, " depth=")
	writeDec(co, uint64(eh.depth))
	writeASCII(co, "\r\n")
	for i := uint16(0); i < eh.entries && (12+int(i)*12+12) <= len(iblock); i++ {
		off := 12 + int(i)*12
		if eh.depth == 0 {
			// Leaf — extent.
			eeBlock := le32(iblock[off+0:])
			eeLen := le16(iblock[off+4:])
			eeStartHi := le16(iblock[off+6:])
			eeStartLo := le32(iblock[off+8:])
			eeStart := (uint64(eeStartHi) << 32) | uint64(eeStartLo)
			writeASCII(co, "      ext[")
			writeDec(co, uint64(i))
			writeASCII(co, "]: logical=")
			writeDec(co, uint64(eeBlock))
			writeASCII(co, " len=")
			writeDec(co, uint64(eeLen))
			writeASCII(co, " physical=")
			writeHex64(co, eeStart)
			writeASCII(co, "\r\n")
		} else {
			// Index node.
			eiBlock := le32(iblock[off+0:])
			eiLeafLo := le32(iblock[off+4:])
			eiLeafHi := le16(iblock[off+8:])
			eiLeaf := (uint64(eiLeafHi) << 32) | uint64(eiLeafLo)
			writeASCII(co, "      idx[")
			writeDec(co, uint64(i))
			writeASCII(co, "]: logical=")
			writeDec(co, uint64(eiBlock))
			writeASCII(co, " leaf=")
			writeHex64(co, eiLeaf)
			writeASCII(co, "\r\n")
		}
	}
}

// ext4InspectGroupDesc reads the group-descriptor at index 0 from the
// GDT (always at byte offset blockSize, for blockSize >= 2048) and
// prints the inode table block address for that group. This validates
// the descSize math + that BlockIO can read past the first 4 KiB.
func ext4InspectGroupDesc(co *efiSimpleTextOutput, bio uintptr, mediaId, blkSize uint32, sb *ext4SB) {
	// GDT lives at: byte offset = blockSize if blockSize > 1024,
	//                 else byte offset = 2 * blockSize.
	gdtByte := sb.blockSize
	if sb.blockSize == 1024 {
		gdtByte = 2 * 1024
	}
	// Read one block starting from gdtByte. The underlying device
	// uses blkSize-byte sectors; convert byte offset to LBA.
	lba := uint64(gdtByte) / uint64(blkSize)
	// Need at least descSize bytes; pull a whole sector.
	for k := 0; k < len(probeBuf); k++ {
		probeBuf[k] = 0
	}
	if rst := readBlocks(bio, mediaId, lba, uintptr(blkSize),
		uintptr(unsafe.Pointer(&probeBuf[0]))); rst != efiSuccess {
		writeASCII(co, "    GDT read failed: ")
		writeHex64(co, rst)
		writeASCII(co, "\r\n")
		return
	}
	// Group descriptor 0 layout (32B or 64B):
	//   uint32 bg_block_bitmap_lo     // 0x00
	//   uint32 bg_inode_bitmap_lo     // 0x04
	//   uint32 bg_inode_table_lo      // 0x08
	//   uint16 bg_free_blocks_count_lo
	//   uint16 bg_free_inodes_count_lo
	//   uint16 bg_used_dirs_count_lo
	//   uint16 bg_flags
	//   …
	//   (descSize == 64): bg_block_bitmap_hi / bg_inode_bitmap_hi /
	//   bg_inode_table_hi at offsets 0x20 / 0x24 / 0x28.
	inodeTblLo := le32(probeBuf[0x08:])
	writeASCII(co, "    GDT[0]: inodeTbl=")
	if sb.is64bit && sb.descSize >= 64 {
		inodeTblHi := le32(probeBuf[0x28:])
		writeHex64(co, (uint64(inodeTblHi)<<32)|uint64(inodeTblLo))
	} else {
		writeHex64(co, uint64(inodeTblLo))
	}
	writeASCII(co, "\r\n")
}

// ----- xfs superblock parsing -----
//
// The xfs SB lives at byte 0 of the partition. All on-disk integers
// are BIG-endian (the opposite of ext4). Only the fields we need to
// reach an inode and walk extents are pulled out here; everything
// else is reachable by raw offset.
//
// Format reference: xfs/libxfs/xfs_format.h in the kernel.

type xfsSB struct {
	magic       uint32 // 0x00 "XFSB" = 0x58465342
	blockSize   uint32 // 0x04
	dblocks     uint64 // 0x08  total data blocks
	rblocks     uint64 // 0x10
	rextents    uint64 // 0x18
	uuid        [16]byte
	logstart    uint64
	rootIno     uint64 // 0x38  root inode number
	rbmino      uint64
	rsumino     uint64
	rextsize    uint32
	agblocks    uint32 // 0x54  blocks per AG
	agcount     uint32 // 0x58  number of AGs
	rbmblocks   uint32
	logblocks   uint32
	versionnum  uint16 // 0x64  v4 = 4 | features; v5 = 5
	sectsize    uint16
	inodesize   uint16 // 0x68
	inopblock   uint16 // 0x6A  inodes per block
	// then 12 bytes fsname[12]
	blocklog    uint8 // 0x78  log2(blockSize)
	sectlog     uint8
	inodelog    uint8 // 0x7A  log2(inodesize)
	inopblog    uint8 // 0x7B  log2(inopblock)
	agblklog    uint8 // 0x7C  log2(agblocks rounded up)
	// rest skipped
}

const xfsMagic uint32 = 0x58465342 // "XFSB"

func be16(b []byte) uint16 { return uint16(b[1]) | uint16(b[0])<<8 }
func be32(b []byte) uint32 {
	return uint32(b[3]) | uint32(b[2])<<8 | uint32(b[1])<<16 | uint32(b[0])<<24
}
func be64(b []byte) uint64 {
	return uint64(b[7]) | uint64(b[6])<<8 | uint64(b[5])<<16 | uint64(b[4])<<24 |
		uint64(b[3])<<32 | uint64(b[2])<<40 | uint64(b[1])<<48 | uint64(b[0])<<56
}

func parseXfsSB(data []byte, sb *xfsSB) bool {
	if len(data) < 0x80 {
		return false
	}
	sb.magic = be32(data[0x00:])
	if sb.magic != xfsMagic {
		return false
	}
	sb.blockSize = be32(data[0x04:])
	sb.dblocks = be64(data[0x08:])
	sb.rootIno = be64(data[0x38:])
	sb.agblocks = be32(data[0x54:])
	sb.agcount = be32(data[0x58:])
	sb.versionnum = be16(data[0x64:])
	sb.sectsize = be16(data[0x66:])
	sb.inodesize = be16(data[0x68:])
	sb.inopblock = be16(data[0x6A:])
	sb.blocklog = data[0x78]
	sb.sectlog = data[0x79]
	sb.inodelog = data[0x7A]
	sb.inopblog = data[0x7B]
	sb.agblklog = data[0x7C]
	return true
}

func printXfsSB(co *efiSimpleTextOutput, sb *xfsSB) {
	writeASCII(co, "    xfs SB: blockSize=")
	writeDec(co, uint64(sb.blockSize))
	writeASCII(co, " inodeSize=")
	writeDec(co, uint64(sb.inodesize))
	writeASCII(co, " inopblock=")
	writeDec(co, uint64(sb.inopblock))
	writeASCII(co, "\r\n    agblocks=")
	writeDec(co, uint64(sb.agblocks))
	writeASCII(co, " agcount=")
	writeDec(co, uint64(sb.agcount))
	writeASCII(co, " rootIno=")
	writeDec(co, sb.rootIno)
	writeASCII(co, "\r\n    version=")
	writeHex64(co, uint64(sb.versionnum))
	writeASCII(co, " inopblog=")
	writeDec(co, uint64(sb.inopblog))
	writeASCII(co, " agblklog=")
	writeDec(co, uint64(sb.agblklog))
	writeASCII(co, "\r\n")
}

var (
	lastXfsSB      xfsSB
	lastXfsSBValid bool

	// Working area for the most-recently-read xfs inode. xfs inode
	// size is 256 (legacy) or 512 (v5 default); 512 covers both.
	xfsInodeBuf [512]byte

	// Set by tryXfsCloudBoot once a kernel has been LoadImage'd —
	// stops the BlockIO-handle loop from trying a second xfs
	// partition after the first one wins.
	xfsBooted bool

	// Diagnostic toggle: when true, tryXfsCloudBoot skips the
	// initrd lookup + LoadFile2 install. Useful for isolating
	// crashes in InstallProtocolInterface from the LoadImage path.
	xfsSkipInitrd = false

	// 4-KiB scratch for the btrfs superblock probe at LBA 128
	// (byte 65536 of the partition).
	btrfsSBBuf [4096]byte
)

// ----- btrfs superblock probe -----
//
// btrfs places its primary superblock at byte offset 65536 (64 KiB)
// of the device, with mirror copies at 64 MiB / 256 GiB / 1 PiB. The
// magic "_BHRfS_M" is at offset 64 of the SB itself.
//
// SB structure (little-endian, packed) — relevant fields:
//
//   0..32   csum
//   32..48  fsid
//   48..56  bytenr (physical addr of this SB)
//   64..72  magic = "_BHRfS_M"  (= 0x4D5F53665248425F as LE u64)
//   72..80  generation
//   80..88  root            (root tree, LOGICAL addr)
//   88..96  chunk_root      (chunk tree, LOGICAL addr)
//  136..144 num_devices
//  144..148 sectorsize
//  148..152 nodesize
//  160..164 sys_chunk_array_size
//  199     chunk_root_level
//  299..555 label[256]
//  811..811+sys_chunk_array_size  inline chunk records (the bootstrap)
//
// `sys_chunk_array` carries enough chunk-record information to map
// the chunk tree's own root from logical → physical. From there we
// can walk the chunk tree for the rest of the chunks.

const btrfsSBMagic uint64 = 0x4D5F53665248425F // "_BHRfS_M"

type btrfsSB struct {
	magic             uint64
	generation        uint64
	rootLogical       uint64 // root-tree root
	chunkRootLogical  uint64
	totalBytes        uint64
	sectorsize        uint32
	nodesize          uint32
	sysChunkArraySize uint32
	rootLevel         uint8
	chunkRootLevel    uint8
	label             [256]byte
}

func parseBtrfsSB(data []byte, sb *btrfsSB) bool {
	if len(data) < 0x500 {
		return false
	}
	sb.magic = le64(data[64:])
	if sb.magic != btrfsSBMagic {
		return false
	}
	sb.generation = le64(data[72:])
	sb.rootLogical = le64(data[80:])
	sb.chunkRootLogical = le64(data[88:])
	sb.totalBytes = le64(data[112:])
	sb.sectorsize = le32(data[144:])
	sb.nodesize = le32(data[148:])
	sb.sysChunkArraySize = le32(data[160:])
	sb.rootLevel = data[198]
	sb.chunkRootLevel = data[199]
	for i := 0; i < 256; i++ {
		sb.label[i] = data[299+i]
	}
	return true
}

func le64(b []byte) uint64 {
	return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
}

func printBtrfsSB(co *efiSimpleTextOutput, sb *btrfsSB) {
	writeASCII(co, "    btrfs SB: sectorsize=")
	writeDec(co, uint64(sb.sectorsize))
	writeASCII(co, " nodesize=")
	writeDec(co, uint64(sb.nodesize))
	writeASCII(co, " totalBytes=")
	writeDec(co, sb.totalBytes)
	writeASCII(co, "\r\n    generation=")
	writeDec(co, sb.generation)
	writeASCII(co, " rootLogical=")
	writeHex64(co, sb.rootLogical)
	writeASCII(co, " (level=")
	writeDec(co, uint64(sb.rootLevel))
	writeASCII(co, ")\r\n    chunkRootLogical=")
	writeHex64(co, sb.chunkRootLogical)
	writeASCII(co, " (level=")
	writeDec(co, uint64(sb.chunkRootLevel))
	writeASCII(co, ") sysChunkArraySize=")
	writeDec(co, uint64(sb.sysChunkArraySize))
	writeASCII(co, "\r\n    label=\"")
	for i := 0; i < 256; i++ {
		if sb.label[i] == 0 {
			break
		}
		oneCharBuf[0] = sb.label[i]
		writeASCII(co, oneCharStr)
	}
	writeASCII(co, "\"\r\n")
}

// lastBtrfsSB is package-scope so its address never escapes to the
// TinyGo heap promoter — a stack-local + & through a function call
// would trip runtime.alloc → VirtualAlloc → trap.
var (
	lastBtrfsSB      btrfsSB
	lastBtrfsSBValid bool
)

// ----- btrfs chunk map (logical → physical) -----
//
// The chunk map is the address-translation layer between
// btrfs' "logical" addresses (used in tree node pointers, file
// extent records, root pointers, etc.) and physical bytes on the
// device. The sys_chunk_array inside the superblock bootstraps a
// minimal map covering at least the chunk-tree's own range; the
// rest of the chunks live as items in the chunk tree itself, which
// we walk once the bootstrap is in place.
//
// Each chunk record is:
//   key (17 bytes):
//     objectid (u64)   = BTRFS_FIRST_CHUNK_TREE_OBJECTID (256)
//     type     (u8)    = BTRFS_CHUNK_ITEM_KEY (228 = 0xE4)
//     offset   (u64)   = logical address of the chunk's first byte
//   chunk header (48 bytes):
//     length, owner, stripe_len, type,
//     io_align, io_width, sector_size,
//     num_stripes (u16), sub_stripes (u16)
//   stripe[num_stripes]: 32 bytes each
//     devid (u64), offset (u64), dev_uuid[16]
//
// For single-disk filesystems we use the first stripe's offset as
// the physical address (and ignore DUP/RAID extras).

const (
	btrfsKeySize          = 17
	btrfsChunkItemKey     = 0xE4 // BTRFS_CHUNK_ITEM_KEY
	btrfsFirstChunkObjID  = 256  // BTRFS_FIRST_CHUNK_TREE_OBJECTID
)

type btrfsChunk struct {
	logical    uint64
	length     uint64
	physical   uint64 // first stripe's physical offset
	numStripes uint16
}

// chunkMap is the cumulative logical → physical translation. We cap
// at 256 chunks for cloud-image use (typical: handful for system,
// few dozen for metadata + data). Beyond that we'd need a dynamic
// container — out of scope for the no-heap loader.
const maxChunks = 256

var (
	chunkMap      [maxChunks]btrfsChunk
	chunkMapCount int
)

// parseSysChunkArray walks the sys_chunk_array bytes (which start
// at SB offset 811 and run for sysChunkArraySize bytes) and appends
// each chunk record to chunkMap.
func parseSysChunkArray(sbData []byte, sysSize uint32, dst *[maxChunks]btrfsChunk, n *int) bool {
	const off0 = 811
	if uint32(len(sbData)) < off0+sysSize {
		return false
	}
	off := uint32(off0)
	end := off0 + sysSize
	for off+btrfsKeySize+48 <= end {
		// key: objectid(8) | type(1) | offset(8)
		// objectid := le64(sbData[off:])
		ktype := sbData[off+8]
		koff := le64(sbData[off+9:])
		off += btrfsKeySize
		if ktype != btrfsChunkItemKey {
			// Unknown bootstrap record — bail.
			return false
		}
		if uint32(*n) >= uint32(len(dst)) {
			return false
		}
		// chunk header
		length := le64(sbData[off:])
		// owner := le64(sbData[off+8:])
		// stripe_len := le64(sbData[off+16:])
		// type := le64(sbData[off+24:])
		// io_align := le32(sbData[off+32:])
		// io_width := le32(sbData[off+36:])
		// sector_size := le32(sbData[off+40:])
		numStripes := le16(sbData[off+44:])
		// sub_stripes := le16(sbData[off+46:])
		off += 48
		if numStripes == 0 || off+uint32(numStripes)*32 > end {
			return false
		}
		// First stripe: devid(8) | offset(8) | dev_uuid[16]
		// devid := le64(sbData[off:])
		physical := le64(sbData[off+8:])
		dst[*n].logical = koff
		dst[*n].length = length
		dst[*n].physical = physical
		dst[*n].numStripes = numStripes
		*n++
		off += uint32(numStripes) * 32
	}
	return true
}

// btrfsLogicalToPhys translates a logical address using chunkMap.
// Returns 0,false if no chunk covers the address.
func btrfsLogicalToPhys(logical uint64) (uint64, bool) {
	for i := 0; i < chunkMapCount; i++ {
		c := &chunkMap[i]
		if logical >= c.logical && logical < c.logical+c.length {
			return c.physical + (logical - c.logical), true
		}
	}
	return 0, false
}

// ----- btrfs tree node layout -----
//
// Every tree block (leaf or interior node) starts with a 101-byte
// btrfs_header:
//
//   0..32     csum
//   32..48    fsid
//   48..56    bytenr      (logical addr of this block — sanity check)
//   56..64    flags
//   64..80    chunk_tree_uuid
//   80..88    generation
//   88..96    owner       (tree id)
//   96..100   nritems     (u32; items if leaf, key_ptrs if node)
//   100       level       (0 = leaf, >0 = internal node)
//
// Leaf payload — array of btrfs_item (25 bytes each):
//   key (17)  | offset (u32) | size (u32)
//   The item's data sits at  blockStart + sizeof(header) + offset.
//   "offset" is measured from the START of the LEAF DATA AREA,
//   which begins right after the header (so item-data starts at
//   blockStart + 101 + offset). [verified empirically against real
//   btrfs nodes]
//
// Internal node payload — array of btrfs_key_ptr (33 bytes each):
//   key (17) | blockptr (u64, logical) | generation (u64)

const (
	btrfsHeaderSize = 101
	btrfsItemSize   = 25
	btrfsKeyPtrSize = 33
)

// btrfsTreeBuf holds the most-recently-read tree block. 16 KiB
// covers default nodesize (sb.nodesize) on cloud images.
var btrfsTreeBuf [16384]byte

// readBtrfsBlock reads `size` bytes from `physical` into out.
// Wraps ReadBlocks with the partition's LBA arithmetic.
func readBtrfsBlock(bio uintptr, mediaId, devBlkSz uint32, physical uint64, size uint32, out unsafe.Pointer) bool {
	lba := physical / uint64(devBlkSz)
	if physical%uint64(devBlkSz) != 0 {
		return false
	}
	return readBlocks(bio, mediaId, lba, uintptr(size), uintptr(out)) == efiSuccess
}

// btrfsItem extracted from a leaf's item array.
type btrfsItem struct {
	objectid uint64
	keyType  uint8
	keyOff   uint64
	dataOff  uint32 // relative to start of leaf-data area (= header end)
	dataSize uint32
}

func parseBtrfsItem(b []byte, it *btrfsItem) bool {
	if len(b) < btrfsItemSize {
		return false
	}
	it.objectid = le64(b[0:])
	it.keyType = b[8]
	it.keyOff = le64(b[9:])
	it.dataOff = le32(b[17:])
	it.dataSize = le32(b[21:])
	return true
}

// ----- btrfs FS_TREE walker -----
//
// FS_TREE is the per-subvolume directory hierarchy. Its leaves
// carry one or more record types per (objectid, name) pair:
//
//   INODE_ITEM_KEY  (0x01): inode metadata for `objectid`
//   INODE_REF_KEY   (0x0C): reverse name lookup
//   DIR_ITEM_KEY    (0x60): forward-lookup-by-hash entry
//   DIR_INDEX_KEY   (0x61): sequential directory entries
//   EXTENT_DATA_KEY (0x6C): file data extent (in regular files)
//   XATTR_ITEM_KEY  (0x18): xattr
//
// Each DIR_ITEM_KEY or DIR_INDEX_KEY item's data is a
// btrfs_dir_item record:
//
//   0..17    location (btrfs_disk_key — key of the target object)
//   17..25   transid
//   25..27   data_len  (xattr value length; 0 for plain dir entries)
//   27..29   name_len
//   29       type      (BTRFS_FT_*: 1=REG, 2=DIR, 7=SYMLINK …)
//   30..     name[name_len]
//   then     data[data_len] (xattr value or 0 bytes)
//
// The "location" field gives the child inode number / tree id; for
// in-tree children that's (location.objectid, INODE_ITEM_KEY, 0).
//
// The root directory of an FS_TREE has objectid = 256
// (BTRFS_FIRST_FREE_OBJECTID).

const (
	btrfsDirItemKey         = 0x60
	btrfsDirIndexKey        = 0x61
	btrfsInodeItemKey       = 0x01
	btrfsExtentDataKey      = 0x6C
	btrfsFirstFreeObjectID  = 256
)

// findInBtrfsDirPrefix walks the FS_TREE leaf for entries under
// parentDirInode whose name starts with `prefix`. Returns the
// matching child object id (file/dir inode number).
//
// Only handles level-0 FS_TREEs (single leaf node) for now —
// follow-on commit adds B-tree descent for multi-node FS trees.
func findInBtrfsDirPrefix(co *efiSimpleTextOutput, bio uintptr, mediaId, devBlkSz uint32,
	fsTreeLogical uint64, fsTreeLevel uint8, nodesize uint32,
	parentDirInode uint64, prefix []byte,
	outNameBuf *[255]byte, outNameLen *int,
) (uint64, bool) {
	if fsTreeLevel != 0 {
		writeASCII(co, "    FS_TREE level>0 not yet supported\r\n")
		return 0, false
	}
	phys, ok := btrfsLogicalToPhys(fsTreeLogical)
	if !ok {
		return 0, false
	}
	if !readBtrfsBlock(bio, mediaId, devBlkSz, phys, nodesize,
		unsafe.Pointer(&btrfsTreeBuf[0])) {
		return 0, false
	}
	nritems := le32(btrfsTreeBuf[96:])
	for i := uint32(0); i < nritems; i++ {
		off := uint32(btrfsHeaderSize) + i*btrfsItemSize
		if off+btrfsItemSize > nodesize {
			break
		}
		var it btrfsItem
		if !parseBtrfsItem(btrfsTreeBuf[off:off+btrfsItemSize], &it) {
			break
		}
		if it.objectid != parentDirInode {
			continue
		}
		// Accept both DIR_INDEX_KEY (0x61, sequential-index) and
		// DIR_ITEM_KEY (0x60, name-hash-keyed) — both carry a
		// btrfs_dir_item record. Some distros (openSUSE MicroOS)
		// store FS_TREE dir entries only as DIR_ITEM_KEY.
		if it.keyType != btrfsDirIndexKey && it.keyType != btrfsDirItemKey {
			continue
		}
		dataPos := uint32(btrfsHeaderSize) + it.dataOff
		if dataPos+30 > nodesize {
			break
		}
		// location is at dataPos+0; we want (objectid, type, offset)
		locObjID := le64(btrfsTreeBuf[dataPos:])
		// locType := btrfsTreeBuf[dataPos+8]
		// locOff := le64(btrfsTreeBuf[dataPos+9:])
		nameLen := le16(btrfsTreeBuf[dataPos+27:])
		// ftype := btrfsTreeBuf[dataPos+29]
		if uint32(nameLen) >= uint32(len(prefix)) &&
			dataPos+30+uint32(nameLen) <= nodesize {
			match := true
			for j := 0; j < len(prefix); j++ {
				if btrfsTreeBuf[dataPos+30+uint32(j)] != prefix[j] {
					match = false
					break
				}
			}
			if match {
				n := int(nameLen)
				if n > len(outNameBuf) {
					n = len(outNameBuf)
				}
				for j := 0; j < n; j++ {
					outNameBuf[j] = btrfsTreeBuf[dataPos+30+uint32(j)]
				}
				*outNameLen = n
				return locObjID, true
			}
		}
	}
	_ = co
	return 0, false
}

// dumpBtrfsLeafAll prints every (objectid, type, offset) tuple in the
// given tree-leaf block. Diagnostic for cases where the structure
// doesn't match expectations (snapshot subvols, mostly).
func dumpBtrfsLeafAll(co *efiSimpleTextOutput, bio uintptr, mediaId, devBlkSz uint32,
	logical uint64, nodesize uint32, label string,
) {
	phys, ok := btrfsLogicalToPhys(logical)
	if !ok {
		return
	}
	if !readBtrfsBlock(bio, mediaId, devBlkSz, phys, nodesize,
		unsafe.Pointer(&btrfsTreeBuf[0])) {
		return
	}
	if btrfsTreeBuf[100] != 0 {
		return
	}
	nritems := le32(btrfsTreeBuf[96:])
	writeASCII(co, "    ")
	writeASCII(co, label)
	writeASCII(co, " (")
	writeDec(co, uint64(nritems))
	writeASCII(co, " items):\r\n")
	for i := uint32(0); i < nritems; i++ {
		off := uint32(btrfsHeaderSize) + i*btrfsItemSize
		if off+btrfsItemSize > nodesize {
			break
		}
		var it btrfsItem
		if !parseBtrfsItem(btrfsTreeBuf[off:off+btrfsItemSize], &it) {
			break
		}
		writeASCII(co, "      obj=")
		writeDec(co, it.objectid)
		writeASCII(co, " type=0x")
		writeHex64(co, uint64(it.keyType))
		writeASCII(co, " keyOff=")
		writeHex64(co, it.keyOff)
		writeASCII(co, " dataOff=")
		writeDec(co, uint64(it.dataOff))
		writeASCII(co, " size=")
		writeDec(co, uint64(it.dataSize))
		writeASCII(co, "\r\n")
	}
}

// listBtrfsDir dumps every DIR_INDEX_KEY entry under `parentDirInode`
// in the FS_TREE leaf. Diagnostic only — used to figure out what's
// actually present at a given inode level (snapshot subvolume names,
// "@", etc. on distributions that don't put the user-visible root
// directly under inode 256).
func listBtrfsDir(co *efiSimpleTextOutput, bio uintptr, mediaId, devBlkSz uint32,
	fsTreeLogical uint64, fsTreeLevel uint8, nodesize uint32,
	parentDirInode uint64,
) {
	if fsTreeLevel != 0 {
		return
	}
	phys, ok := btrfsLogicalToPhys(fsTreeLogical)
	if !ok {
		return
	}
	if !readBtrfsBlock(bio, mediaId, devBlkSz, phys, nodesize,
		unsafe.Pointer(&btrfsTreeBuf[0])) {
		return
	}
	nritems := le32(btrfsTreeBuf[96:])
	writeASCII(co, "    contents of inode ")
	writeDec(co, parentDirInode)
	writeASCII(co, ":\r\n")
	for i := uint32(0); i < nritems; i++ {
		off := uint32(btrfsHeaderSize) + i*btrfsItemSize
		if off+btrfsItemSize > nodesize {
			break
		}
		var it btrfsItem
		if !parseBtrfsItem(btrfsTreeBuf[off:off+btrfsItemSize], &it) {
			break
		}
		if it.objectid != parentDirInode || it.keyType != btrfsDirIndexKey {
			continue
		}
		dataPos := uint32(btrfsHeaderSize) + it.dataOff
		if dataPos+30 > nodesize {
			break
		}
		locObjID := le64(btrfsTreeBuf[dataPos:])
		locType := btrfsTreeBuf[dataPos+8]
		nameLen := le16(btrfsTreeBuf[dataPos+27:])
		ftype := btrfsTreeBuf[dataPos+29]
		if dataPos+30+uint32(nameLen) > nodesize {
			break
		}
		writeASCII(co, "      [child=")
		writeDec(co, locObjID)
		writeASCII(co, "/loc.type=")
		writeHex64(co, uint64(locType))
		writeASCII(co, "/ft=")
		writeDec(co, uint64(ftype))
		writeASCII(co, "] ")
		for j := uint16(0); j < nameLen; j++ {
			oneCharBuf[0] = btrfsTreeBuf[dataPos+30+uint32(j)]
			writeASCII(co, oneCharStr)
		}
		writeASCII(co, "\r\n")
	}
}

// ----- btrfs root tree walker -----
//
// The root tree (logical address = sb.root) is a B-tree whose
// leaves carry ROOT_ITEM_KEY records (one per subvolume tree).
// We look for objectid = BTRFS_FS_TREE_OBJECTID (5) to find the
// default subvolume's tree root.
//
// btrfs_root_item layout (post-inode_item, total 160 + remaining):
//
//   0..160     btrfs_inode_item (we skip)
//   160..168   generation
//   168..176   root_dirid
//   176..184   bytenr          ← logical addr of subvol tree root
//   184..192   byte_limit
//   192..200   bytes_used
//   200..208   last_snapshot
//   208..216   flags
//   216..220   refs
//   220..237   drop_progress (btrfs_disk_key)
//   237        drop_level
//   238        level           ← level of subvol tree root

const (
	btrfsRootItemKey         = 0x84 // BTRFS_ROOT_ITEM_KEY (132)
	btrfsFsTreeObjectID      = 5    // BTRFS_FS_TREE_OBJECTID
	btrfsRootTreeDirObjectID = 6    // BTRFS_ROOT_TREE_DIR_OBJECTID
	btrfsRootItemBytenrOff   = 176
	btrfsRootItemLevelOff    = 238
)

// btrfsActiveSubvolRootID holds the root_id of the default subvolume
// (resolved via DIR_ITEM "default" under ROOT_TREE_DIR_OBJECTID=6).
// Zero means "no override, use FS_TREE objectid=5".
var btrfsActiveSubvolRootID uint64

// walkRootTreeForDefaultSubvol scans the root-tree leaf for a
// DIR_ITEM_KEY entry under ROOT_TREE_DIR_OBJECTID (6) whose name is
// "default" and pulls out the subvolume's root_id from the
// embedded btrfs_dir_item's location key. That's the
// snapshot-subvolume indirection that distributions like openSUSE
// MicroOS use to point at the active snapshot.
//
// Returns true if a default was found; sets
// btrfsActiveSubvolRootID. Returns false on a "vanilla" btrfs
// where the default IS FS_TREE — the caller should fall back to
// FS_TREE objectid=5.
func walkRootTreeForDefaultSubvol(co *efiSimpleTextOutput, bio uintptr, mediaId, devBlkSz uint32,
	rootLogical uint64, nodesize uint32,
) bool {
	rootPhys, ok := btrfsLogicalToPhys(rootLogical)
	if !ok {
		return false
	}
	if !readBtrfsBlock(bio, mediaId, devBlkSz, rootPhys, nodesize,
		unsafe.Pointer(&btrfsTreeBuf[0])) {
		return false
	}
	if btrfsTreeBuf[100] != 0 {
		// Internal node — multi-level walk not implemented.
		return false
	}
	nritems := le32(btrfsTreeBuf[96:])
	for i := uint32(0); i < nritems; i++ {
		off := uint32(btrfsHeaderSize) + i*btrfsItemSize
		if off+btrfsItemSize > nodesize {
			break
		}
		var it btrfsItem
		if !parseBtrfsItem(btrfsTreeBuf[off:off+btrfsItemSize], &it) {
			break
		}
		if it.objectid != btrfsRootTreeDirObjectID || it.keyType != btrfsDirItemKey {
			continue
		}
		dataPos := uint32(btrfsHeaderSize) + it.dataOff
		if dataPos+30 > nodesize {
			break
		}
		locObjID := le64(btrfsTreeBuf[dataPos:])
		nameLen := le16(btrfsTreeBuf[dataPos+27:])
		if nameLen == 7 && dataPos+30+7 <= nodesize {
			n := btrfsTreeBuf[dataPos+30 : dataPos+37]
			if n[0] == 'd' && n[1] == 'e' && n[2] == 'f' && n[3] == 'a' &&
				n[4] == 'u' && n[5] == 'l' && n[6] == 't' {
				btrfsActiveSubvolRootID = locObjID
				writeASCII(co, "    btrfs default subvol root_id=")
				writeDec(co, locObjID)
				writeASCII(co, "\r\n")
				return true
			}
		}
	}
	return false
}

// walkRootTreeForSubvolRoot looks up the ROOT_ITEM_KEY whose
// objectid matches `rootID`, and extracts the subvolume tree's
// root-node bytenr + level. Same leaf, just a different filter from
// walkRootTreeForFSTree.
func walkRootTreeForSubvolRoot(co *efiSimpleTextOutput, bio uintptr, mediaId, devBlkSz uint32,
	rootLogical uint64, nodesize uint32, rootID uint64,
	outBytenr *uint64, outLevel *uint8,
) bool {
	rootPhys, ok := btrfsLogicalToPhys(rootLogical)
	if !ok {
		return false
	}
	if !readBtrfsBlock(bio, mediaId, devBlkSz, rootPhys, nodesize,
		unsafe.Pointer(&btrfsTreeBuf[0])) {
		return false
	}
	if btrfsTreeBuf[100] != 0 {
		return false
	}
	nritems := le32(btrfsTreeBuf[96:])
	for i := uint32(0); i < nritems; i++ {
		off := uint32(btrfsHeaderSize) + i*btrfsItemSize
		if off+btrfsItemSize > nodesize {
			break
		}
		var it btrfsItem
		if !parseBtrfsItem(btrfsTreeBuf[off:off+btrfsItemSize], &it) {
			break
		}
		if it.objectid != rootID || it.keyType != btrfsRootItemKey {
			continue
		}
		dataPos := uint32(btrfsHeaderSize) + it.dataOff
		if dataPos+239 > nodesize {
			break
		}
		*outBytenr = le64(btrfsTreeBuf[dataPos+btrfsRootItemBytenrOff:])
		*outLevel = btrfsTreeBuf[dataPos+btrfsRootItemLevelOff]
		writeASCII(co, "    subvol root_id=")
		writeDec(co, rootID)
		writeASCII(co, " bytenr=")
		writeHex64(co, *outBytenr)
		writeASCII(co, " level=")
		writeDec(co, uint64(*outLevel))
		writeASCII(co, "\r\n")
		_ = co
		return true
	}
	return false
}

// btrfsFsTreeRootLogical is the resolved logical address of the
// FS_TREE root node, found by walkRootTreeForFSTree. btrfsFsTreeLevel
// is its tree depth.
var (
	btrfsFsTreeRootLogical uint64
	btrfsFsTreeLevel       uint8
)

func walkRootTreeForFSTree(co *efiSimpleTextOutput, bio uintptr, mediaId, devBlkSz uint32,
	rootLogical uint64, nodesize uint32,
) bool {
	rootPhys, ok := btrfsLogicalToPhys(rootLogical)
	if !ok {
		writeASCII(co, "    root_logical not covered by chunkMap\r\n")
		return false
	}
	writeASCII(co, "    rootPhys=")
	writeHex64(co, rootPhys)
	writeASCII(co, "\r\n")
	if !readBtrfsBlock(bio, mediaId, devBlkSz, rootPhys, nodesize,
		unsafe.Pointer(&btrfsTreeBuf[0])) {
		writeASCII(co, "    root-tree read failed\r\n")
		return false
	}
	level := btrfsTreeBuf[100]
	nritems := le32(btrfsTreeBuf[96:])
	if level != 0 {
		writeASCII(co, "    root-tree root is internal node (level=")
		writeDec(co, uint64(level))
		writeASCII(co, ") — multi-level walk not implemented yet\r\n")
		return false
	}
	writeASCII(co, "    root-tree leaf: ")
	writeDec(co, uint64(nritems))
	writeASCII(co, " items, looking for FS_TREE (objectid=5)\r\n")
	for i := uint32(0); i < nritems; i++ {
		off := uint32(btrfsHeaderSize) + i*btrfsItemSize
		if off+btrfsItemSize > nodesize {
			break
		}
		var it btrfsItem
		if !parseBtrfsItem(btrfsTreeBuf[off:off+btrfsItemSize], &it) {
			break
		}
		if it.objectid != btrfsFsTreeObjectID || it.keyType != btrfsRootItemKey {
			continue
		}
		dataPos := uint32(btrfsHeaderSize) + it.dataOff
		if dataPos+239 > nodesize {
			break
		}
		btrfsFsTreeRootLogical = le64(btrfsTreeBuf[dataPos+btrfsRootItemBytenrOff:])
		btrfsFsTreeLevel = btrfsTreeBuf[dataPos+btrfsRootItemLevelOff]
		writeASCII(co, "    found FS_TREE: bytenr=")
		writeHex64(co, btrfsFsTreeRootLogical)
		writeASCII(co, " level=")
		writeDec(co, uint64(btrfsFsTreeLevel))
		writeASCII(co, "\r\n")
		return true
	}
	writeASCII(co, "    FS_TREE not found in root tree\r\n")
	return false
}

// walkChunkTreeLeaf reads the leaf at `phys` and appends every
// CHUNK_ITEM_KEY (objectid=256, type=228) record to chunkMap.
// Only handles the level-0 case (chunk_root_level=0) — sufficient
// for cloud images with one chunk-tree node.
func walkChunkTreeLeaf(co *efiSimpleTextOutput, bio uintptr, mediaId, devBlkSz uint32,
	phys uint64, nodesize uint32,
) bool {
	if !readBtrfsBlock(bio, mediaId, devBlkSz, phys, nodesize,
		unsafe.Pointer(&btrfsTreeBuf[0])) {
		writeASCII(co, "    chunk-tree leaf read failed\r\n")
		return false
	}
	// Sanity: bytenr at offset 48 should equal logical of the block.
	// Skip strict check — we just want to walk items.
	level := btrfsTreeBuf[100]
	nritems := le32(btrfsTreeBuf[96:])
	if level != 0 {
		writeASCII(co, "    chunk-tree root is internal node (level=")
		writeDec(co, uint64(level))
		writeASCII(co, ") — multi-level walk not implemented yet\r\n")
		return false
	}
	writeASCII(co, "    chunk-tree leaf: ")
	writeDec(co, uint64(nritems))
	writeASCII(co, " items\r\n")
	for i := uint32(0); i < nritems; i++ {
		off := uint32(btrfsHeaderSize) + i*btrfsItemSize
		if off+btrfsItemSize > nodesize {
			break
		}
		var it btrfsItem
		if !parseBtrfsItem(btrfsTreeBuf[off:off+btrfsItemSize], &it) {
			break
		}
		if it.keyType != btrfsChunkItemKey {
			continue
		}
		// Item data sits at btrfsHeaderSize + dataOff.
		dataPos := uint32(btrfsHeaderSize) + it.dataOff
		if dataPos+48 > nodesize {
			break
		}
		length := le64(btrfsTreeBuf[dataPos:])
		numStripes := le16(btrfsTreeBuf[dataPos+44:])
		if numStripes == 0 || dataPos+48+uint32(numStripes)*32 > nodesize {
			break
		}
		physical := le64(btrfsTreeBuf[dataPos+48+8:]) // stripe[0].offset
		if chunkMapCount >= maxChunks {
			writeASCII(co, "    chunkMap full, dropping later records\r\n")
			break
		}
		chunkMap[chunkMapCount].logical = it.keyOff
		chunkMap[chunkMapCount].length = length
		chunkMap[chunkMapCount].physical = physical
		chunkMap[chunkMapCount].numStripes = numStripes
		chunkMapCount++
	}
	return true
}

// probeBtrfsPartition reads bytes 64 KiB..68 KiB of the partition,
// checks for the btrfs magic at offset 64, and dumps the SB if found.
func probeBtrfsPartition(co *efiSimpleTextOutput, bio uintptr, mediaId, devBlkSz uint32) {
	// LBA = 65536 / devBlkSz. For devBlkSz=512 → LBA 128.
	lba := uint64(65536) / uint64(devBlkSz)
	for k := 0; k < len(btrfsSBBuf); k++ {
		btrfsSBBuf[k] = 0
	}
	// Read enough to cover offset 64 (magic) + 4 KiB.
	if readBlocks(bio, mediaId, lba, uintptr(len(btrfsSBBuf)),
		uintptr(unsafe.Pointer(&btrfsSBBuf[0]))) != efiSuccess {
		return
	}
	if le64(btrfsSBBuf[64:]) != btrfsSBMagic {
		return
	}
	writeASCII(co, "    fs: btrfs\r\n")
	if !parseBtrfsSB(btrfsSBBuf[:], &lastBtrfsSB) {
		return
	}
	lastBtrfsSBValid = true
	printBtrfsSB(co, &lastBtrfsSB)

	// Bootstrap chunk map from sys_chunk_array.
	chunkMapCount = 0
	if !parseSysChunkArray(btrfsSBBuf[:], lastBtrfsSB.sysChunkArraySize, &chunkMap, &chunkMapCount) {
		writeASCII(co, "    sys_chunk_array parse failed\r\n")
		return
	}
	writeASCII(co, "    sys_chunk_array: ")
	writeDec(co, uint64(chunkMapCount))
	writeASCII(co, " chunk record(s)\r\n")
	for i := 0; i < chunkMapCount; i++ {
		c := &chunkMap[i]
		writeASCII(co, "      [")
		writeDec(co, uint64(i))
		writeASCII(co, "] logical=")
		writeHex64(co, c.logical)
		writeASCII(co, " length=")
		writeHex64(co, c.length)
		writeASCII(co, " phys=")
		writeHex64(co, c.physical)
		writeASCII(co, " stripes=")
		writeDec(co, uint64(c.numStripes))
		writeASCII(co, "\r\n")
	}

	// Translate chunk_root_logical → physical and read the node.
	chunkRootPhys, ok := btrfsLogicalToPhys(lastBtrfsSB.chunkRootLogical)
	if !ok {
		writeASCII(co, "    chunk_root not covered by bootstrap map\r\n")
		return
	}
	writeASCII(co, "    chunkRootPhys=")
	writeHex64(co, chunkRootPhys)
	writeASCII(co, "\r\n")
	// Walk the chunk tree's root leaf — extends chunkMap with every
	// chunk record the filesystem owns.
	walkChunkTreeLeaf(co, lastBIO, lastMediaId, lastDevBlkSz,
		chunkRootPhys, lastBtrfsSB.nodesize)
	writeASCII(co, "    chunkMap (full): ")
	writeDec(co, uint64(chunkMapCount))
	writeASCII(co, " chunks\r\n")
	for i := 0; i < chunkMapCount; i++ {
		c := &chunkMap[i]
		writeASCII(co, "      [")
		writeDec(co, uint64(i))
		writeASCII(co, "] log=")
		writeHex64(co, c.logical)
		writeASCII(co, " len=")
		writeHex64(co, c.length)
		writeASCII(co, " phys=")
		writeHex64(co, c.physical)
		writeASCII(co, "\r\n")
	}

	// First try the default-subvolume indirection: look up
	// (objectid=6, type=DIR_ITEM_KEY, name="default") in the root
	// tree → its location key gives the active subvol's root_id →
	// look up that root_id's ROOT_ITEM_KEY → use its bytenr/level
	// as the tree root we walk for /boot. Distros like openSUSE
	// MicroOS use this snapshot indirection.
	btrfsActiveSubvolRootID = 0
	if walkRootTreeForDefaultSubvol(co, lastBIO, lastMediaId, lastDevBlkSz,
		lastBtrfsSB.rootLogical, lastBtrfsSB.nodesize) {
		var bytenr uint64
		var level uint8
		if walkRootTreeForSubvolRoot(co, lastBIO, lastMediaId, lastDevBlkSz,
			lastBtrfsSB.rootLogical, lastBtrfsSB.nodesize,
			btrfsActiveSubvolRootID, &bytenr, &level) {
			btrfsFsTreeRootLogical = bytenr
			btrfsFsTreeLevel = level
		} else {
			writeASCII(co, "    subvol root_item lookup failed; falling back to FS_TREE\r\n")
			btrfsActiveSubvolRootID = 0
		}
	}
	// Fall back to FS_TREE objectid=5 if default-subvol absent /
	// unresolved.
	if btrfsActiveSubvolRootID == 0 {
		if !walkRootTreeForFSTree(co, lastBIO, lastMediaId, lastDevBlkSz,
			lastBtrfsSB.rootLogical, lastBtrfsSB.nodesize) {
			return
		}
	}
	// Dump what's under FS_TREE root (inode 256) for diagnostic —
	// MicroOS uses snapshot subvolumes so "/" isn't where we
	// initially expect.
	listBtrfsDir(co, lastBIO, lastMediaId, lastDevBlkSz,
		btrfsFsTreeRootLogical, btrfsFsTreeLevel, lastBtrfsSB.nodesize,
		btrfsFirstFreeObjectID)
	// Also dump every item in the FS_TREE leaf to see what kind of
	// keys are present (in case inode 256 isn't where the user-
	// visible root directory lives).
	dumpBtrfsLeafAll(co, lastBIO, lastMediaId, lastDevBlkSz,
		btrfsFsTreeRootLogical, lastBtrfsSB.nodesize, "FS_TREE leaf items")
	// And dump every item in the ROOT tree so we can see all
	// available subvolumes (their objectids match
	// ROOT_ITEM_KEYs).
	dumpBtrfsLeafAll(co, lastBIO, lastMediaId, lastDevBlkSz,
		lastBtrfsSB.rootLogical, lastBtrfsSB.nodesize, "root tree items")

	// FS_TREE → find /boot under root inode 256.
	bootInode, ok2 := findInBtrfsDirPrefix(co, lastBIO, lastMediaId, lastDevBlkSz,
		btrfsFsTreeRootLogical, btrfsFsTreeLevel, lastBtrfsSB.nodesize,
		btrfsFirstFreeObjectID, btrfsBootName[:],
		&btrfsScanName, &btrfsScanNameLen)
	if !ok2 {
		writeASCII(co, "    /boot not found under FS_TREE root\r\n")
		return
	}
	writeASCII(co, "    /boot inode = ")
	writeDec(co, bootInode)
	writeASCII(co, "\r\n")
	// /boot → find vmlinuz-* under it.
	kIno, ok3 := findInBtrfsDirPrefix(co, lastBIO, lastMediaId, lastDevBlkSz,
		btrfsFsTreeRootLogical, btrfsFsTreeLevel, lastBtrfsSB.nodesize,
		bootInode, vmlinuzPrefix[:],
		&btrfsScanName, &btrfsScanNameLen)
	if !ok3 {
		writeASCII(co, "    no vmlinuz-* under /boot\r\n")
		return
	}
	writeASCII(co, "    kernel: ")
	for i := 0; i < btrfsScanNameLen; i++ {
		oneCharBuf[0] = btrfsScanName[i]
		writeASCII(co, oneCharStr)
	}
	writeASCII(co, " (inode=")
	writeDec(co, kIno)
	writeASCII(co, ")\r\n")
}

// Hardcoded prefix buffers for the btrfs dir search.
var (
	btrfsBootName    = [...]byte{'b', 'o', 'o', 't'}
	btrfsScanName    [255]byte
	btrfsScanNameLen int
)

// ----- xfs inode -----
//
// xfs_dinode core is 96 bytes (v4) or 176 bytes (v5, with CRC +
// changecount + lsn + flags2 + crtime + ino + uuid).
//
// Layout (BE on disk):
//   0   di_magic (u16)   "IN" = 0x494E
//   2   di_mode  (u16)
//   4   di_version (u8)  1|2|3   (3 = v5 inode with CRC)
//   5   di_format  (u8)  1=local, 2=extents, 3=btree
//  …
//  56   di_size (u64)
//  76   di_nextents (u32) — count of records in the data extent list
//
// Data fork starts at:
//   v4 (di_version <= 2): offset 96
//   v5 (di_version == 3): offset 176
//
// For our cloud-boot use we only need format=2 (extents) on files
// and format=1 (local) or 2 (extents) on directories.

const (
	xfsDinodeMagic uint16 = 0x494E // "IN"
	xfsCoreV4             = 96
	xfsCoreV5             = 176

	xfsFormatLocal   uint8 = 1
	xfsFormatExtents uint8 = 2
	xfsFormatBtree   uint8 = 3
)

type xfsInode struct {
	magic    uint16
	mode     uint16
	version  uint8
	format   uint8
	size     uint64
	nextents uint32
}

func parseXfsInode(raw []byte, ino *xfsInode) bool {
	if len(raw) < 80 {
		return false
	}
	ino.magic = be16(raw[0:])
	if ino.magic != xfsDinodeMagic {
		return false
	}
	ino.mode = be16(raw[2:])
	ino.version = raw[4]
	ino.format = raw[5]
	ino.size = be64(raw[56:])
	ino.nextents = be32(raw[76:])
	return true
}

// xfsDataForkOffset returns the byte offset of the data fork within
// the raw inode bytes.
func xfsDataForkOffset(version uint8) uint32 {
	if version >= 3 {
		return xfsCoreV5
	}
	return xfsCoreV4
}

// readXfsInode reads inode `inoNum` from the partition into
// xfsInodeBuf. Returns true on success.
//
// XFS inode numbers encode (agno, agbno, offset) bit-shifted:
//   inopblog       = log2(inopblock)
//   agblklog       = log2(agblocks rounded up)
//   agino_log      = inopblog + agblklog
//   agno           = ino >> agino_log
//   agino          = ino & ((1<<agino_log) - 1)
//   agbno          = agino >> inopblog
//   offsetInBlock  = agino & ((1<<inopblog) - 1)
//
// Physical position = agno*agblocks*blockSize + agbno*blockSize +
//                     offsetInBlock*inodeSize.
func readXfsInode(co *efiSimpleTextOutput, bio uintptr, mediaId, devBlkSz uint32, sb *xfsSB, inoNum uint64) bool {
	if sb.inopblock == 0 || sb.blockSize == 0 {
		return false
	}
	aginoLog := uint64(sb.inopblog) + uint64(sb.agblklog)
	agno := inoNum >> aginoLog
	agino := inoNum & ((1 << aginoLog) - 1)
	agbno := agino >> uint64(sb.inopblog)
	off := agino & ((1 << uint64(sb.inopblog)) - 1)
	if uint64(agno) >= uint64(sb.agcount) {
		writeASCII(co, "    readXfsInode: agno out of range\r\n")
		return false
	}
	byteOff := agno*uint64(sb.agblocks)*uint64(sb.blockSize) +
		agbno*uint64(sb.blockSize) +
		off*uint64(sb.inodesize)
	// Underlying device sectors are devBlkSz bytes; align down to a
	// sector and pull one fs-block (4 KiB) to comfortably cover the
	// inode regardless of in-block offset.
	lba := byteOff / uint64(devBlkSz)
	inSec := byteOff % uint64(devBlkSz)
	if inSec+uint64(sb.inodesize) > uint64(sb.blockSize) {
		writeASCII(co, "    readXfsInode: inode straddles fs-block — unexpected\r\n")
		return false
	}
	for k := 0; k < len(probeBuf); k++ {
		probeBuf[k] = 0
	}
	if readBlocks(bio, mediaId, lba, uintptr(sb.blockSize),
		uintptr(unsafe.Pointer(&probeBuf[0]))) != efiSuccess {
		return false
	}
	// Copy inodeSize bytes starting at inSec into xfsInodeBuf.
	for k := uint32(0); k < uint32(sb.inodesize); k++ {
		xfsInodeBuf[k] = probeBuf[uint32(inSec)+k]
	}
	return true
}

// ----- xfs extent decoding -----
//
// Each extent in an inode's data fork is a 128-bit BE bit-packed
// record (xfs_bmbt_rec):
//
//   bit 0         flag (1 = unwritten extent)
//   bits 1..54    startoff   (54-bit logical-block offset in the file)
//   bits 55..106  startblock (52-bit FSB address — composite of
//                              AG number + AG block number)
//   bits 107..127 blockcount (21-bit)
//
// FSB encoding (XFS_FSB_TO_AGNO / AGBNO):
//   agno  = startblock >> sb_agblklog
//   agbno = startblock & ((1 << sb_agblklog) - 1)
//   physicalBlock = agno*agblocks + agbno
//   byteOff       = physicalBlock * blockSize

type xfsExtent struct {
	startoff   uint64
	startblock uint64
	count      uint32
}

func parseXfsExtent(raw []byte, e *xfsExtent) bool {
	if len(raw) < 16 {
		return false
	}
	w0 := be64(raw[0:])
	w1 := be64(raw[8:])
	// flag = (w0 >> 63) & 1 — we ignore it (unwritten extents in
	// /boot files don't happen on cloud images).
	e.startoff = (w0 >> 9) & ((uint64(1) << 54) - 1)
	startblockHi := w0 & ((uint64(1) << 9) - 1)
	startblockLo := w1 >> 21
	e.startblock = (startblockHi << 43) | startblockLo
	e.count = uint32(w1 & ((uint64(1) << 21) - 1))
	return true
}

func fsbToByteOff(fsb uint64, sb *xfsSB) uint64 {
	agno := fsb >> uint64(sb.agblklog)
	agbno := fsb & ((uint64(1) << uint64(sb.agblklog)) - 1)
	physBlk := agno*uint64(sb.agblocks) + agbno
	return physBlk * uint64(sb.blockSize)
}

// ----- xfs short-form directory parser -----
//
// xfs_dir2_sf_hdr:
//   1 byte  count        (# entries)
//   1 byte  i8count      (# entries with 8-byte inumbers; >0 means
//                          ALL entries — and parent — use 8-byte)
//   N bytes parent       (4 or 8)
//
// xfs_dir2_sf_entry:
//   1 byte  namelen
//   2 bytes offset (tag, ignored)
//   N bytes name (namelen)
//   1 byte  ftype        (v5 only)
//   N bytes inumber      (4 or 8 depending on i8count)

func walkXfsDirShortForm(co *efiSimpleTextOutput, sfData []byte, isV5 bool,
	callback func(name []byte, inumber uint64, ftype uint8) bool,
) {
	if len(sfData) < 2 {
		return
	}
	count := uint32(sfData[0])
	i8count := uint32(sfData[1])
	use8 := i8count > 0
	inumLen := uint32(4)
	if use8 {
		inumLen = 8
	}
	off := uint32(2 + inumLen) // skip hdr + parent
	for i := uint32(0); i < count; i++ {
		if uint32(len(sfData)) < off+3 {
			break
		}
		namelen := uint32(sfData[off])
		off++
		off += 2 // skip tag
		if uint32(len(sfData)) < off+namelen+inumLen {
			break
		}
		name := sfData[off : off+namelen]
		off += namelen
		var ftype uint8
		if isV5 {
			ftype = sfData[off]
			off++
		}
		var inumber uint64
		if use8 {
			inumber = be64(sfData[off:])
		} else {
			inumber = uint64(be32(sfData[off:]))
		}
		off += inumLen
		if !callback(name, inumber, ftype) {
			return
		}
	}
	_ = co
}

// ----- xfs block-form directory parser -----
//
// One-block dir (xfs_dir2_block). Layout at offset 0 of the block:
//
//   xfs_dir3_data_hdr (v5) — 64 bytes:
//     magic   = "XDB3" (0x58444233) — single-block dir
//     crc, blkno, lsn, uuid, owner   (48 bytes blk_hdr)
//     best_free[3]                    (12 bytes)
//     pad                             (4 bytes)
//
//   Data entries (variable length, 8-byte aligned)
//
//   Leaf entries (xfs_dir2_leaf_entry, 8 B each: hash + offset)
//
//   xfs_dir2_block_tail (8 B at end):
//     count, stale
//
// Walking: from data-header-end up to (blockSize - 8 - count*8),
// each record is either an entry (8-byte inumber + 1-byte namelen
// + name + 1-byte ftype + 2-byte tag) or unused (2-byte 0xFFFF +
// 2-byte length + 2-byte tag). All entry lengths rounded to 8.

const (
	xfsDir3BlockMagic uint32 = 0x58444233 // "XDB3"
	xfsDir3DataMagic  uint32 = 0x58444433 // "XDD3"
	xfsDir2BlockMagic uint32 = 0x58443242 // "XD2B"
	xfsDir2DataMagic  uint32 = 0x58443244 // "XD2D"
	xfsDir3HdrSize           = 64
	xfsDir2HdrSize           = 16
)

func walkXfsDirBlockForm(co *efiSimpleTextOutput, block []byte, blockSize uint32, isV5 bool,
	callback func(name []byte, inumber uint64, ftype uint8) bool,
) {
	if uint32(len(block)) < blockSize {
		return
	}
	magic := be32(block[0:])
	if magic != xfsDir3BlockMagic && magic != xfsDir2BlockMagic {
		writeASCII(co, "    walkXfsDirBlockForm: bad magic ")
		writeHex64(co, uint64(magic))
		writeASCII(co, "\r\n")
		return
	}
	hdrSize := uint32(xfsDir3HdrSize)
	if !isV5 || magic == xfsDir2BlockMagic {
		hdrSize = xfsDir2HdrSize
	}
	// Tail at end of block.
	tailOff := blockSize - 8
	leafCount := be32(block[tailOff:])
	leafStart := tailOff - leafCount*8

	off := hdrSize
	for off+8 < leafStart {
		first2 := be16(block[off:])
		if first2 == 0xFFFF {
			// xfs_dir2_data_unused: 2-byte freetag + 2-byte length + 2-byte tag
			length := uint32(be16(block[off+2:]))
			if length < 6 {
				break
			}
			off += length
			continue
		}
		// xfs_dir2_data_entry.
		inumber := be64(block[off:])
		namelen := uint32(block[off+8])
		if namelen == 0 || off+9+namelen > leafStart {
			break
		}
		name := block[off+9 : off+9+namelen]
		var ftype uint8
		var recLen uint32
		if isV5 {
			ftype = block[off+9+namelen]
			recLen = 8 + 1 + namelen + 1 + 2 // inumber+namelen+name+ftype+tag
		} else {
			recLen = 8 + 1 + namelen + 2
		}
		// Round up to 8-byte alignment.
		recLen = (recLen + 7) &^ 7
		if !callback(name, inumber, ftype) {
			return
		}
		off += recLen
	}
}

// ----- xfs file read via extents -----
//
// readXfsFile pulls the entire file into `outAddr`. Only handles the
// in-line extent format (di_format = 2) with nextents records sitting
// right after the inode core. Btree-format files (di_format = 3) are
// out of scope for the bring-up; kernels + initrds on cloud images
// fit comfortably under the few-hundred-extent ceiling.

func readXfsFile(co *efiSimpleTextOutput, bio uintptr, mediaId, devBlkSz uint32,
	sb *xfsSB, inoNum uint64, outAddr uintptr, outCap uint64,
) uint64 {
	if !readXfsInode(co, bio, mediaId, devBlkSz, sb, inoNum) {
		return 0
	}
	var ino xfsInode
	if !parseXfsInode(xfsInodeBuf[:], &ino) {
		return 0
	}
	if ino.format != xfsFormatExtents {
		writeASCII(co, "    readXfsFile: unsupported format\r\n")
		return 0
	}
	if ino.size > outCap {
		writeASCII(co, "    readXfsFile: file too big for buffer\r\n")
		return 0
	}
	dfo := xfsDataForkOffset(ino.version)
	for i := uint32(0); i < ino.nextents; i++ {
		off := dfo + i*16
		if uint32(len(xfsInodeBuf)) < off+16 {
			writeASCII(co, "    readXfsFile: extent past inode\r\n")
			return 0
		}
		var e xfsExtent
		if !parseXfsExtent(xfsInodeBuf[off:off+16], &e) {
			return 0
		}
		byteOff := fsbToByteOff(e.startblock, sb)
		bytes := uint64(e.count) * uint64(sb.blockSize)
		dst := outAddr + uintptr(e.startoff)*uintptr(sb.blockSize)
		lba := byteOff / uint64(devBlkSz)
		if readBlocks(bio, mediaId, lba, uintptr(bytes), dst) != efiSuccess {
			writeASCII(co, "    readXfsFile: ReadBlocks failed\r\n")
			return 0
		}
	}
	return ino.size
}

// tryXfsCloudBoot is the xfs counterpart to readKernel + readInitrd
// + chainKernel for ext4: walk the partition's root dir for
// vmlinuz-* and initramfs-* (or initrd-*), AllocatePool the right
// sizes, read both files via readXfsFile, install LoadFile2 for the
// initrd, then LoadImage the kernel.
//
// Returns true if a kernel was loaded and StartImage'd. Sets
// xfsBooted so the outer BlockIO loop stops trying further
// partitions.
//
// AlmaLinux/RHEL put kernel+initrd at the *root* of a dedicated
// /boot xfs partition. So unlike the Debian case there's no
// "/boot/" prefix here — we scan the partition's root directly.
func tryXfsCloudBoot(co *efiSimpleTextOutput, bs *efiBootServices, imageHandle,
	bio uintptr, mediaId, devBlkSz uint32, sb *xfsSB,
) bool {
	writeASCII(co, "  tryXfsCloudBoot: bio=")
	writeHex64(co, uint64(bio))
	writeASCII(co, " rootIno=")
	writeDec(co, sb.rootIno)
	writeASCII(co, "\r\n")
	// Find vmlinuz-* in the root.
	kIno, kOK := findInXfsDirPrefix(co, bio, mediaId, devBlkSz, sb,
		sb.rootIno, vmlinuzPrefix[:], &kernelName, &kernelNameLen)
	writeASCII(co, "  findInXfsDirPrefix returned, kOK=")
	if kOK {
		writeASCII(co, "true\r\n")
	} else {
		writeASCII(co, "false\r\n")
	}
	if !kOK {
		// Not a /boot partition (no vmlinuz at its root) — skip.
		return false
	}
	writeASCII(co, "  xfs kernel: ")
	for i := 0; i < kernelNameLen; i++ {
		oneCharBuf[0] = kernelName[i]
		writeASCII(co, oneCharStr)
	}
	writeASCII(co, " (inode=")
	writeDec(co, kIno)
	writeASCII(co, ")\r\n")

	// Read kernel inode to learn its size.
	if !readXfsInode(co, bio, mediaId, devBlkSz, sb, kIno) {
		return false
	}
	var ino xfsInode
	if !parseXfsInode(xfsInodeBuf[:], &ino) {
		return false
	}
	writeASCII(co, "    kernel size = ")
	writeDec(co, ino.size)
	writeASCII(co, " bytes (nextents=")
	writeDec(co, uint64(ino.nextents))
	writeASCII(co, ")\r\n")

	kernelBufPtr = 0
	if efiCall3(bs.allocatePool, efiLoaderData, uintptr(ino.size),
		uintptr(unsafe.Pointer(&kernelBufPtr))) != efiSuccess || kernelBufPtr == 0 {
		writeASCII(co, "    AllocatePool(kernel) failed\r\n")
		return false
	}
	writeASCII(co, "    kernelBufPtr=")
	writeHex64(co, uint64(kernelBufPtr))
	writeASCII(co, "\r\n")
	got := readXfsFile(co, bio, mediaId, devBlkSz, sb, kIno, kernelBufPtr, ino.size)
	if got != ino.size {
		writeASCII(co, "    short kernel read\r\n")
		return false
	}
	loadedKernelSize = got
	writeASCII(co, "    readXfsFile(kernel) OK, ")
	writeDec(co, got)
	writeASCII(co, " bytes\r\n")

	// Find an initrd. RHEL ships initramfs-*; Debian uses
	// initrd.img-*. Try the RHEL convention first; fall back to the
	// Debian one — same disk-probe binary works for both
	// distributions.
	var iIno uint64
	var iOK bool
	if !xfsSkipInitrd {
		iIno, iOK = findInXfsDirPrefix(co, bio, mediaId, devBlkSz, sb,
			sb.rootIno, initramfsPrefix[:], &initrdName, &initrdNameLen)
		if !iOK {
			iIno, iOK = findInXfsDirPrefix(co, bio, mediaId, devBlkSz, sb,
				sb.rootIno, initrdPrefix[:], &initrdName, &initrdNameLen)
		}
	}
	if !iOK {
		writeASCII(co, "    no initramfs-*/initrd-* in root — continuing without initrd\r\n")
	} else {
		writeASCII(co, "  xfs initrd: ")
		for i := 0; i < initrdNameLen; i++ {
			oneCharBuf[0] = initrdName[i]
			writeASCII(co, oneCharStr)
		}
		writeASCII(co, " (inode=")
		writeDec(co, iIno)
		writeASCII(co, ")\r\n")

		if !readXfsInode(co, bio, mediaId, devBlkSz, sb, iIno) ||
			!parseXfsInode(xfsInodeBuf[:], &ino) {
			return false
		}
		initrdSize = ino.size
		writeASCII(co, "    initrd size = ")
		writeDec(co, initrdSize)
		writeASCII(co, " bytes\r\n")

		initrdDataPtr = 0
		if efiCall3(bs.allocatePool, efiLoaderData, uintptr(initrdSize),
			uintptr(unsafe.Pointer(&initrdDataPtr))) != efiSuccess || initrdDataPtr == 0 {
			writeASCII(co, "    AllocatePool(initrd) failed\r\n")
			return false
		}
		writeASCII(co, "    initrdDataPtr=")
		writeHex64(co, uint64(initrdDataPtr))
		writeASCII(co, "\r\n")
		igot := readXfsFile(co, bio, mediaId, devBlkSz, sb, iIno, initrdDataPtr, initrdSize)
		if igot != initrdSize {
			writeASCII(co, "    short initrd read\r\n")
			return false
		}
		if !installInitrdProtocol(co, bs) {
			return false
		}
		writeASCII(co, "    initrd protocols installed\r\n")
	}

	chainKernel(co, bs, imageHandle, loadedKernelSize)
	return true
}

// initramfsPrefix matches the RHEL-family convention (initramfs-*.img).
var initramfsPrefix = [...]byte{'i', 'n', 'i', 't', 'r', 'a', 'm', 'f', 's', '-'}

// findInXfsDirPrefix scans dirIno for the first entry whose name
// starts with `prefix`. Returns the matching inode + full name on
// success. Handles both short-form and block-form root dirs.
//
// Implemented WITHOUT closures: TinyGo's `gc: leaking` runtime
// promotes captured variables to heap which under UEFI ends at
// VirtualAlloc → instruction abort. So the dir walk lives inline
// and the match result goes through package-scope vars.
func findInXfsDirPrefix(co *efiSimpleTextOutput, bio uintptr, mediaId, devBlkSz uint32,
	sb *xfsSB, dirIno uint64, prefix []byte,
	outNameBuf *[255]byte, outNameLen *int,
) (childIno uint64, found bool) {
	writeASCII(co, "    findInXfsDirPrefix: reading inode\r\n")
	if !readXfsInode(co, bio, mediaId, devBlkSz, sb, dirIno) {
		writeASCII(co, "    readXfsInode failed\r\n")
		return 0, false
	}
	writeASCII(co, "    readXfsInode OK, parsing\r\n")
	var ino xfsInode
	if !parseXfsInode(xfsInodeBuf[:], &ino) {
		return 0, false
	}
	isV5 := ino.version >= 3
	dfo := xfsDataForkOffset(ino.version)

	switch ino.format {
	case xfsFormatLocal:
		if uint32(len(xfsInodeBuf)) < dfo+uint32(ino.size) {
			return 0, false
		}
		return findInXfsShortForm(xfsInodeBuf[dfo:dfo+uint32(ino.size)], isV5,
			prefix, outNameBuf, outNameLen)
	case xfsFormatExtents:
		if ino.nextents == 0 {
			return 0, false
		}
		var e xfsExtent
		if !parseXfsExtent(xfsInodeBuf[dfo:dfo+16], &e) {
			return 0, false
		}
		byteOff := fsbToByteOff(e.startblock, sb)
		lba := byteOff / uint64(devBlkSz)
		for k := 0; k < len(dirBuf); k++ {
			dirBuf[k] = 0
		}
		if readBlocks(bio, mediaId, lba, uintptr(sb.blockSize),
			uintptr(unsafe.Pointer(&dirBuf[0]))) != efiSuccess {
			return 0, false
		}
		return findInXfsBlockForm(dirBuf[:], sb.blockSize, isV5,
			prefix, outNameBuf, outNameLen)
	}
	_ = co
	return 0, false
}

// findInXfsShortForm — closure-free prefix search through a
// short-form (inline) dir blob.
func findInXfsShortForm(sfData []byte, isV5 bool, prefix []byte,
	outNameBuf *[255]byte, outNameLen *int,
) (uint64, bool) {
	if len(sfData) < 2 {
		return 0, false
	}
	count := uint32(sfData[0])
	i8count := uint32(sfData[1])
	use8 := i8count > 0
	inumLen := uint32(4)
	if use8 {
		inumLen = 8
	}
	off := uint32(2 + inumLen)
	for i := uint32(0); i < count; i++ {
		if uint32(len(sfData)) < off+3 {
			return 0, false
		}
		namelen := uint32(sfData[off])
		off++
		off += 2
		if uint32(len(sfData)) < off+namelen+inumLen {
			return 0, false
		}
		name := sfData[off : off+namelen]
		off += namelen
		if isV5 {
			off++ // ftype
		}
		var inumber uint64
		if use8 {
			inumber = be64(sfData[off:])
		} else {
			inumber = uint64(be32(sfData[off:]))
		}
		off += inumLen
		if uint32(len(name)) >= uint32(len(prefix)) {
			ok := true
			for j := 0; j < len(prefix); j++ {
				if name[j] != prefix[j] {
					ok = false
					break
				}
			}
			if ok {
				n := len(name)
				if n > len(outNameBuf) {
					n = len(outNameBuf)
				}
				for j := 0; j < n; j++ {
					outNameBuf[j] = name[j]
				}
				*outNameLen = n
				return inumber, true
			}
		}
	}
	return 0, false
}

// findInXfsBlockForm — closure-free prefix search through a
// single-block dir's data area.
func findInXfsBlockForm(block []byte, blockSize uint32, isV5 bool, prefix []byte,
	outNameBuf *[255]byte, outNameLen *int,
) (uint64, bool) {
	if uint32(len(block)) < blockSize {
		return 0, false
	}
	magic := be32(block[0:])
	if magic != xfsDir3BlockMagic && magic != xfsDir2BlockMagic {
		return 0, false
	}
	hdrSize := uint32(xfsDir3HdrSize)
	if !isV5 || magic == xfsDir2BlockMagic {
		hdrSize = xfsDir2HdrSize
	}
	tailOff := blockSize - 8
	leafCount := be32(block[tailOff:])
	leafStart := tailOff - leafCount*8

	off := hdrSize
	for off+8 < leafStart {
		first2 := be16(block[off:])
		if first2 == 0xFFFF {
			length := uint32(be16(block[off+2:]))
			if length < 6 {
				return 0, false
			}
			off += length
			continue
		}
		inumber := be64(block[off:])
		namelen := uint32(block[off+8])
		if namelen == 0 || off+9+namelen > leafStart {
			return 0, false
		}
		name := block[off+9 : off+9+namelen]
		var recLen uint32
		if isV5 {
			recLen = 8 + 1 + namelen + 1 + 2
		} else {
			recLen = 8 + 1 + namelen + 2
		}
		recLen = (recLen + 7) &^ 7
		if uint32(len(name)) >= uint32(len(prefix)) {
			ok := true
			for j := 0; j < len(prefix); j++ {
				if name[j] != prefix[j] {
					ok = false
					break
				}
			}
			if ok {
				n := int(namelen)
				if n > len(outNameBuf) {
					n = len(outNameBuf)
				}
				for j := 0; j < n; j++ {
					outNameBuf[j] = name[j]
				}
				*outNameLen = n
				return inumber, true
			}
		}
		off += recLen
	}
	return 0, false
}

// listXfsRoot prints all entries in a partition's root directory.
// Diagnostic for the bring-up — handles both short-form (format=1,
// inline in inode) and block-form (format=2 with nextents=1, a
// single 4-KiB data block).
func listXfsRoot(co *efiSimpleTextOutput, bio uintptr, mediaId, devBlkSz uint32, sb *xfsSB) {
	if !readXfsInode(co, bio, mediaId, devBlkSz, sb, sb.rootIno) {
		writeASCII(co, "    listXfsRoot: read inode failed\r\n")
		return
	}
	var ino xfsInode
	if !parseXfsInode(xfsInodeBuf[:], &ino) {
		return
	}
	isV5 := ino.version >= 3
	dfo := xfsDataForkOffset(ino.version)

	switch ino.format {
	case xfsFormatLocal:
		// Short-form dir. Data lives at the inode's data-fork
		// offset, length = di_size.
		if uint32(len(xfsInodeBuf)) < dfo+uint32(ino.size) {
			writeASCII(co, "    short-form dir past inode\r\n")
			return
		}
		walkXfsDirShortForm(co, xfsInodeBuf[dfo:dfo+uint32(ino.size)], isV5,
			func(name []byte, inumber uint64, ftype uint8) bool {
				writeASCII(co, "      [ino=")
				writeDec(co, inumber)
				writeASCII(co, " ft=")
				writeDec(co, uint64(ftype))
				writeASCII(co, "] ")
				for i := 0; i < len(name); i++ {
					oneCharBuf[0] = name[i]
					writeASCII(co, oneCharStr)
				}
				writeASCII(co, "\r\n")
				return true
			})

	case xfsFormatExtents:
		// Block-form dir: read the single extent's block(s) and
		// walk. For the cloud-image /boot case nextents=1 covers it.
		if ino.nextents == 0 {
			writeASCII(co, "    extents-format dir but nextents=0\r\n")
			return
		}
		var e xfsExtent
		if !parseXfsExtent(xfsInodeBuf[dfo:dfo+16], &e) {
			return
		}
		byteOff := fsbToByteOff(e.startblock, sb)
		lba := byteOff / uint64(devBlkSz)
		for k := 0; k < len(dirBuf); k++ {
			dirBuf[k] = 0
		}
		if readBlocks(bio, mediaId, lba, uintptr(sb.blockSize),
			uintptr(unsafe.Pointer(&dirBuf[0]))) != efiSuccess {
			writeASCII(co, "    block-form dir read failed\r\n")
			return
		}
		walkXfsDirBlockForm(co, dirBuf[:], sb.blockSize, isV5,
			func(name []byte, inumber uint64, ftype uint8) bool {
				writeASCII(co, "      [ino=")
				writeDec(co, inumber)
				writeASCII(co, " ft=")
				writeDec(co, uint64(ftype))
				writeASCII(co, "] ")
				for i := 0; i < len(name); i++ {
					oneCharBuf[0] = name[i]
					writeASCII(co, oneCharStr)
				}
				writeASCII(co, "\r\n")
				return true
			})

	default:
		writeASCII(co, "    listXfsRoot: unsupported dir format ")
		writeDec(co, uint64(ino.format))
		writeASCII(co, "\r\n")
	}
}

func printXfsInode(co *efiSimpleTextOutput, ino *xfsInode) {
	writeASCII(co, "    xfs inode: magic=")
	writeHex64(co, uint64(ino.magic))
	writeASCII(co, " mode=")
	writeHex64(co, uint64(ino.mode))
	writeASCII(co, " version=")
	writeDec(co, uint64(ino.version))
	writeASCII(co, " format=")
	writeDec(co, uint64(ino.format))
	writeASCII(co, " size=")
	writeDec(co, ino.size)
	writeASCII(co, " nextents=")
	writeDec(co, uint64(ino.nextents))
	writeASCII(co, "\r\n")
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
	if len(data) >= 0x500 && le16(data[0x438:]) == 0xEF53 {
		writeASCII(co, "    fs: ext4")
		// s_volume_name at offset 0x478 (16 ASCII bytes).
		writeASCII(co, " label=\"")
		for i := 0x478; i < 0x488; i++ {
			if data[i] == 0 {
				break
			}
			oneCharBuf[0] = data[i]
			writeASCII(co, oneCharStr)
		}
		writeASCII(co, "\"\r\n")
		// Full superblock dump — populates sb for downstream use.
		if parseExt4SB(data, &lastSB) {
			lastSBValid = true
			printExt4SB(co, &lastSB)
		} else {
			writeASCII(co, "    (superblock parse failed)\r\n")
		}
		return
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

	// xfs magic at byte 0.
	if len(data) >= 0x80 && be32(data[0:]) == xfsMagic {
		writeASCII(co, "    fs: xfs\r\n")
		if parseXfsSB(data, &lastXfsSB) {
			lastXfsSBValid = true
			printXfsSB(co, &lastXfsSB)
		}
		return
	}

	writeASCII(co, "    fs: unknown at LBA 0 (first 8 bytes = ")
	if len(data) >= 8 {
		for i := 0; i < 8; i++ {
			writeHex64(co, uint64(data[i]))
			writeASCII(co, " ")
		}
	}
	writeASCII(co, ") — trying btrfs offset 64 KiB\r\n")
	// btrfs SB lives at offset 64 KiB, not 0. Probe there if the
	// first 4 KiB didn't match any of the offset-0 signatures.
	probeBtrfsPartition(co, lastBIO, lastMediaId, lastDevBlkSz)
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
		// Stash context so detectFilesystem's ext4 branch can issue
		// a follow-up GDT read without plumbing the args through.
		lastSBValid = false
		lastXfsSBValid = false
		lastBIO = bioHolder
		lastMediaId = media.mediaId
		lastDevBlkSz = media.blockSize
		detectFilesystem(co, probeBuf[:])
		if lastXfsSBValid && !xfsBooted {
			xfsBooted = tryXfsCloudBoot(co, bs, imageHandle,
				lastBIO, lastMediaId, lastDevBlkSz, &lastXfsSB)
		}
		if lastSBValid {
			ext4InspectGroupDesc(co, lastBIO, lastMediaId, lastDevBlkSz, &lastSB)
			bootIno, _, ok := findInDir(co, lastBIO, lastMediaId, lastDevBlkSz, &lastSB,
				2, bootNameBuf[:4])
			if !ok {
				writeASCII(co, "    /boot: not found in root\r\n")
			} else {
				// Find /boot/vmlinuz-* by prefix.
				kIno, kFT, kOK := findInDirPrefix(co, lastBIO, lastMediaId, lastDevBlkSz, &lastSB,
					bootIno, vmlinuzPrefix[:], &kernelName, &kernelNameLen)
				if !kOK {
					writeASCII(co, "    no vmlinuz-* in /boot\r\n")
				} else {
					writeASCII(co, "    kernel: ")
					for i := 0; i < kernelNameLen; i++ {
						oneCharBuf[0] = kernelName[i]
						writeASCII(co, oneCharStr)
					}
					writeASCII(co, " (inode=")
					writeDec(co, uint64(kIno))
					writeASCII(co, " ft=")
					writeDec(co, uint64(kFT))
					writeASCII(co, ")\r\n")
					readKernel(co, bs, lastBIO, lastMediaId, lastDevBlkSz, &lastSB, kIno)
					if loadedKernelSize > 0 && kernelBufPtr != 0 {
						// Load + register the initrd before StartImage
						// so the Linux EFI stub's LoadFile2 walk
						// finds our protocol.
						if readInitrd(co, bs, lastBIO, lastMediaId, lastDevBlkSz, &lastSB, bootIno) {
							installInitrdProtocol(co, bs)
						}
						chainKernel(co, bs, imageHandle, loadedKernelSize)
					}
				}
			}
		}
	}

	writeASCII(co, "DISK-PROBE-DONE\r\n")
	_ = imageHandle
	for {
	}
}

func main() {}
