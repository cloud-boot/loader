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
)

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
		// Stash context so detectFilesystem's ext4 branch can issue
		// a follow-up GDT read without plumbing the args through.
		lastSBValid = false
		lastBIO = bioHolder
		lastMediaId = media.mediaId
		lastDevBlkSz = media.blockSize
		detectFilesystem(co, probeBuf[:])
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
