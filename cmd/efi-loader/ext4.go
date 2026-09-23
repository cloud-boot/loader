// Phase 5d — ext4 disk-mode boot path.
//
// When no UKI is found on any FAT volume (Phase 5a-5c logic in
// main.go), the loader falls back to walking BlockIO handles for an
// ext4 partition that looks like a Linux rootfs, then reads
// /boot/vmlinuz-* + /boot/initrd.img-* directly out of that partition
// and chain-loads them. This replicates what GRUB does at first boot,
// but without GRUB in the picture — same flow Apple VZ supports
// (LoadImage + StartImage; the kernel's EFI stub calls
// ExitBootServices itself).
//
// All buffers package-scope per the loader's no-heap-under-UEFI
// convention. Logic is a straight port of the disk-probe scaffold
// (loader/cmd/disk-probe/main.go) — see its commit history for the
// step-by-step bring-up against the Debian Trixie arm64 cloud image.

package main

import "unsafe"

// ----- types missing from main.go -----

// EFI_BLOCK_IO_PROTOCOL — first three slots we actually call.
type efiBlockIO struct {
	revision    uint64
	media       uintptr // → efiBlockIOMedia
	reset       uintptr
	readBlocks  uintptr // 5 args: (this, mediaId, lba, size, buf)
	writeBlocks uintptr
	flushBlocks uintptr
}

// EFI_BLOCK_IO_MEDIA — UEFI 2.10 §13.9. We read MediaId, MediaPresent,
// LogicalPartition, BlockSize, LastBlock.
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
}

// EFI_LOAD_FILE2_PROTOCOL — single-method protocol installed on the
// initrd-bearing handle. The Linux EFI stub finds it by walking for
// the LINUX_EFI_INITRD_MEDIA_GUID device path.
type efiLoadFile2Protocol struct {
	loadFile uintptr
}

// loadFile2Ptr is defined in thunk-arm64.S — returns the runtime
// address of the asm `loadFile2` entry symbol.
//
//go:linkname loadFile2Ptr loadFile2Ptr
func loadFile2Ptr() uintptr

// ----- additional GUIDs / constants -----

var (
	// EFI_BLOCK_IO_PROTOCOL_GUID — 964e5b21-6459-11d2-8e39-00a0c969723b
	blockIOGUID = efiGUID{
		0x21, 0x5B, 0x4E, 0x96,
		0x59, 0x64,
		0xD2, 0x11,
		0x8E, 0x39, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B,
	}

	// EFI_DEVICE_PATH_PROTOCOL_GUID — 09576e91-6d3f-11d2-8e39-00a0c969723b
	devicePathGUID = efiGUID{
		0x91, 0x6E, 0x57, 0x09,
		0x3F, 0x6D,
		0xD2, 0x11,
		0x8E, 0x39, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B,
	}

	// EFI_LOAD_FILE2_PROTOCOL_GUID — 4006c0c1-fcb3-403e-996d-4a6c8724e06d
	loadFile2GUID = efiGUID{
		0xC1, 0xC0, 0x06, 0x40,
		0xB3, 0xFC,
		0x3E, 0x40,
		0x99, 0x6D, 0x4A, 0x6C, 0x87, 0x24, 0xE0, 0x6D,
	}

	// LINUX_EFI_INITRD_MEDIA_GUID — 5568e427-68fc-4f3d-ac74-ca555231cc68
	linuxInitrdGUID = efiGUID{
		0x27, 0xE4, 0x68, 0x55,
		0xFC, 0x68,
		0x3D, 0x4F,
		0xAC, 0x74, 0xCA, 0x55, 0x52, 0x31, 0xCC, 0x68,
	}
)

const efiInvalidParameter efiStatus = 0x8000000000000002

// efiLoaderData is already declared in main.go.

// ----- text helper missing from main.go -----

func writeDec(co *efiSimpleTextOutput, n uint64) {
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

// ----- package-scope BlockIO / probe buffers -----

var (
	bioHandleCount uintptr
	bioHandleBuf   uintptr
	bioHolder      uintptr

	// 4-KiB probe buffer — reads superblocks, GDT entries, inode tables.
	probeBuf [4096]byte

	// 4-KiB scratch for directory data blocks (kept distinct from
	// probeBuf so traversal can hold both live).
	dirBuf [4096]byte

	// 4-KiB scratch for one extent-tree leaf block (depth-1 walker).
	extentLeafBuf [4096]byte

	// 256-byte working area for the most-recently-read inode.
	rawInodeBuf [256]byte
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

// ----- ext4 superblock + group descriptor -----

type ext4SB struct {
	inodesCount      uint32
	blocksCountLo    uint32
	logBlockSize     uint32
	blocksPerGroup   uint32
	inodesPerGroup   uint32
	magic            uint16
	revLevel         uint32
	firstIno         uint32
	inodeSize        uint16
	featureCompat    uint32
	featureIncompat  uint32
	featureROCompat  uint32
	descSize         uint16
	blocksCountHi    uint32
	logGroupsPerFlex uint8

	blockSize   uint64
	is64bit     bool
	totalBlks   uint64
	totalGroups uint64
}

const (
	ext4FeatureIncompat64Bit  uint32 = 0x80
	ext4FeatureIncompatExtent uint32 = 0x40
)

func parseExt4SB(data []byte, sb *ext4SB) bool {
	if len(data) < 0x500 {
		return false
	}
	const o = 1024
	sb.inodesCount = le32(data[o+0x00:])
	sb.blocksCountLo = le32(data[o+0x04:])
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

	if sb.inodeSize == 0 {
		sb.inodeSize = 128
	}
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

// ----- inode + extent tree -----

const (
	extentHeaderMagic uint16 = 0xF30A
	inodeBlockOff     uint32 = 0x28
	inodeBlockSize    uint32 = 60
	inodeFlagExtents  uint32 = 0x80000
	inodeDirMaxBlocks        = 64
)

type ext4Inode struct {
	mode   uint16
	sizeLo uint32
	flags  uint32
	sizeHi uint32
}

type extentHeader struct {
	magic      uint16
	entries    uint16
	maxEntries uint16
	depth      uint16
	generation uint32
}

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

func parseInode(raw []byte, ino *ext4Inode) bool {
	if len(raw) < 0x80 {
		return false
	}
	ino.mode = le16(raw[0x00:])
	ino.sizeLo = le32(raw[0x04:])
	ino.flags = le32(raw[0x20:])
	ino.sizeHi = le32(raw[0x6C:])
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

// readInode reads inode `inoNum` into rawInodeBuf.
func readInode(co *efiSimpleTextOutput, bio uintptr, mediaId, devBlkSz uint32, sb *ext4SB, inoNum uint32) bool {
	if inoNum == 0 || sb.inodesPerGroup == 0 || sb.blockSize == 0 {
		return false
	}
	group := (inoNum - 1) / sb.inodesPerGroup
	idxInGroup := (inoNum - 1) % sb.inodesPerGroup
	if uint64(group) >= sb.totalGroups {
		return false
	}
	gdtByte := sb.blockSize
	if sb.blockSize == 1024 {
		gdtByte = 2 * 1024
	}
	entryByte := gdtByte + uint64(group)*uint64(sb.descSize)
	gdtBlkLBA := entryByte / uint64(devBlkSz)
	gdtBlkOff := entryByte % uint64(devBlkSz)
	for k := 0; k < len(probeBuf); k++ {
		probeBuf[k] = 0
	}
	if readBlocks(bio, mediaId, gdtBlkLBA, uintptr(devBlkSz),
		uintptr(unsafe.Pointer(&probeBuf[0]))) != efiSuccess {
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
	inoByte := inodeTableBlk*sb.blockSize + uint64(idxInGroup)*uint64(sb.inodeSize)
	inoLBA := inoByte / uint64(devBlkSz)
	inoOff := inoByte % uint64(devBlkSz)
	for k := 0; k < len(probeBuf); k++ {
		probeBuf[k] = 0
	}
	if readBlocks(bio, mediaId, inoLBA, uintptr(sb.blockSize),
		uintptr(unsafe.Pointer(&probeBuf[0]))) != efiSuccess {
		return false
	}
	for k := uint32(0); k < uint32(sb.inodeSize); k++ {
		rawInodeBuf[k] = probeBuf[uint32(inoOff)+k]
	}
	_ = co
	return true
}

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

// readDataBlock maps a file-relative block to a physical one via the
// cached inode extents and ReadBlocks one filesystem-block worth.
// Only handles depth-0 extent trees (the inline 4-leaf case) — depth-1
// is handled directly inside readFile for the multi-MiB kernel/initrd.
func readDataBlock(co *efiSimpleTextOutput, bio uintptr, mediaId, devBlkSz uint32,
	sb *ext4SB, logicalBlock uint32, out *[4096]byte) bool {
	if inodeExtentDepth != 0 {
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
			_ = co
			return rst == efiSuccess
		}
	}
	return false
}

// findInDir walks `dirIno` data blocks looking for an entry whose name
// matches `name` exactly.
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
				match := true
				for i := uint32(0); i < nameLen; i++ {
					if dirBuf[off+8+i] != name[i] {
						match = false
						break
					}
				}
				if match {
					return ent, ft, true
				}
			}
			off += recLen
		}
	}
	return 0, 0, false
}

// findInDirPrefix is findInDir's prefix-match cousin — returns the
// first entry whose name STARTS with `prefix` and writes the full
// filename to `outNameBuf` / `outNameLen`.
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

// readFile reads inode `inoNum`'s entire content into `outAddr`.
// Handles depth-0 and depth-1 extent trees (up to ~5 GiB files).
func readFile(co *efiSimpleTextOutput, bio uintptr, mediaId, devBlkSz uint32,
	sb *ext4SB, inoNum uint32, outAddr uintptr, outCap uint64,
) uint64 {
	if !readInode(co, bio, mediaId, devBlkSz, sb, inoNum) {
		return 0
	}
	var ino ext4Inode
	if !parseInode(rawInodeBuf[:], &ino) {
		return 0
	}
	fileSize := (uint64(ino.sizeHi) << 32) | uint64(ino.sizeLo)
	if fileSize > outCap {
		return 0
	}
	iblock := rawInodeBuf[inodeBlockOff : inodeBlockOff+inodeBlockSize]
	var eh extentHeader
	if !parseExtentHeader(iblock, &eh) {
		return 0
	}
	switch eh.depth {
	case 0:
		for i := uint16(0); i < eh.entries; i++ {
			off := 12 + int(i)*12
			eeBlock := le32(iblock[off+0:])
			eeLen := le16(iblock[off+4:])
			eeStartHi := le16(iblock[off+6:])
			eeStartLo := le32(iblock[off+8:])
			physStart := (uint64(eeStartHi) << 32) | uint64(eeStartLo)
			if !readExtentRange(bio, mediaId, devBlkSz, sb, physStart, uint64(eeLen),
				outAddr+uintptr(eeBlock)*uintptr(sb.blockSize)) {
				return 0
			}
		}
	case 1:
		for i := uint16(0); i < eh.entries; i++ {
			off := 12 + int(i)*12
			eiLeafLo := le32(iblock[off+4:])
			eiLeafHi := le16(iblock[off+8:])
			eiLeaf := (uint64(eiLeafHi) << 32) | uint64(eiLeafLo)
			leafLBA := eiLeaf * sb.blockSize / uint64(devBlkSz)
			for k := 0; k < len(extentLeafBuf); k++ {
				extentLeafBuf[k] = 0
			}
			if readBlocks(bio, mediaId, leafLBA, uintptr(sb.blockSize),
				uintptr(unsafe.Pointer(&extentLeafBuf[0]))) != efiSuccess {
				return 0
			}
			var leafEh extentHeader
			if !parseExtentHeader(extentLeafBuf[:], &leafEh) || leafEh.depth != 0 {
				return 0
			}
			for j := uint16(0); j < leafEh.entries; j++ {
				eoff := 12 + int(j)*12
				eeBlock := le32(extentLeafBuf[eoff+0:])
				eeLen := le16(extentLeafBuf[eoff+4:])
				eeStartHi := le16(extentLeafBuf[eoff+6:])
				eeStartLo := le32(extentLeafBuf[eoff+8:])
				physStart := (uint64(eeStartHi) << 32) | uint64(eeStartLo)
				if !readExtentRange(bio, mediaId, devBlkSz, sb, physStart, uint64(eeLen),
					outAddr+uintptr(eeBlock)*uintptr(sb.blockSize)) {
					return 0
				}
			}
		}
	default:
		return 0
	}
	_ = co
	return fileSize
}

func readExtentRange(bio uintptr, mediaId, devBlkSz uint32, sb *ext4SB,
	physStart, numBlocks uint64, dst uintptr,
) bool {
	if numBlocks == 0 {
		return true
	}
	lba := physStart * sb.blockSize / uint64(devBlkSz)
	bytes := numBlocks * sb.blockSize
	return readBlocks(bio, mediaId, lba, uintptr(bytes), dst) == efiSuccess
}

// ----- initrd LoadFile2 -----

var (
	initrdHandle          uintptr
	initrdDataPtr         uintptr
	initrdSize            uint64
	initrdProtocol        efiLoadFile2Protocol
	vendorMediaInitrdPath [24]byte

	kernelBufPtr     uintptr
	loadedKernelSize uint64

	kernelName    [255]byte
	kernelNameLen int

	initrdName    [255]byte
	initrdNameLen int
)

var vmlinuzPrefix = [...]byte{'v', 'm', 'l', 'i', 'n', 'u', 'z', '-'}
var initrdPrefix = [...]byte{'i', 'n', 'i', 't', 'r', 'd', '.', 'i', 'm', 'g', '-'}
var bootDirName = [...]byte{'b', 'o', 'o', 't'}

// goLoadFile2 — UEFI 2.10 §13.4. Two-pass: kernel calls with
// Buffer=NULL to discover size, then again with a sized buffer.
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
	for i := uint64(0); i < initrdSize; i++ {
		*(*byte)(unsafe.Pointer(buf + uintptr(i))) =
			*(*byte)(unsafe.Pointer(initrdDataPtr + uintptr(i)))
	}
	return uint64(efiSuccess)
}

// installInitrdProtocol publishes a fresh handle carrying both
// DevicePath (MEDIA_VENDOR with LINUX_EFI_INITRD_MEDIA_GUID) and
// LoadFile2. After this call, the Linux EFI stub's LoadFile2 walk
// finds our handle and calls goLoadFile2 to fetch the initrd bytes.
func installInitrdProtocol(co *efiSimpleTextOutput, bs *efiBootServices) bool {
	vendorMediaInitrdPath[0] = 0x04 // MEDIA_DEVICE_PATH
	vendorMediaInitrdPath[1] = 0x03 // MEDIA_VENDOR
	vendorMediaInitrdPath[2] = 20
	vendorMediaInitrdPath[3] = 0
	for i := 0; i < 16; i++ {
		vendorMediaInitrdPath[4+i] = linuxInitrdGUID[i]
	}
	vendorMediaInitrdPath[20] = 0x7F // END_OF_HARDWARE
	vendorMediaInitrdPath[21] = 0xFF
	vendorMediaInitrdPath[22] = 4
	vendorMediaInitrdPath[23] = 0

	initrdProtocol.loadFile = loadFile2Ptr()

	const efiNativeInterface = 0
	initrdHandle = 0
	if efiCall4(bs.installProtocolInterface,
		uintptr(unsafe.Pointer(&initrdHandle)),
		uintptr(unsafe.Pointer(&devicePathGUID)),
		efiNativeInterface,
		uintptr(unsafe.Pointer(&vendorMediaInitrdPath[0]))) != efiSuccess {
		writeASCII(co, "  installProtocol(DevicePath) failed\r\n")
		return false
	}
	if efiCall4(bs.installProtocolInterface,
		uintptr(unsafe.Pointer(&initrdHandle)),
		uintptr(unsafe.Pointer(&loadFile2GUID)),
		efiNativeInterface,
		uintptr(unsafe.Pointer(&initrdProtocol))) != efiSuccess {
		writeASCII(co, "  installProtocol(LoadFile2) failed\r\n")
		return false
	}
	return true
}

// ----- top-level disk-mode boot orchestrator -----

// cloudDiskCtx caches a single ext4 partition's BlockIO context once
// scanForExt4 lands on a partition that *also* contains a vmlinuz-*
// either at its root (Fedora-style separate /boot) or under /boot/
// (Debian-style single rootfs). cloudKernelDir records which inode
// the kernel lives in (2 for partition-root, /boot's inode for
// inside-rootfs); the initrd lookup uses the same directory.
var (
	cloudBIO       uintptr
	cloudMediaId   uint32
	cloudDevBlkSz  uint32
	cloudSB        ext4SB
	cloudFoundExt4 bool
	cloudKernelDir uint32 // inode of the directory holding vmlinuz-*
)

// tryCloudDiskBoot is the Phase 5d fallback: walk BlockIO handles
// looking for an ext4 partition whose root carries /boot/vmlinuz-*
// and /boot/initrd.img-*, read both files into pool memory, install
// LoadFile2 for the initrd, LoadImage the kernel, and populate
// childImageHandle so the existing _start StartImage path runs.
//
// Returns true if a kernel was loaded and is ready to start.
func tryCloudDiskBoot(co *efiSimpleTextOutput, bs *efiBootServices, imageHandle uintptr) bool {
	writeASCII(co, "trying cloud-disk fallback (ext4)\r\n")

	if !scanForExt4(co, bs) {
		writeASCII(co, "  no ext4 partition found\r\n")
		return false
	}
	writeASCII(co, "  ext4 partition found, blockSize=")
	writeDec(co, cloudSB.blockSize)
	writeASCII(co, "\r\n")

	// scanForExt4 already located the partition AND the directory
	// (cloudKernelDir) that holds vmlinuz-*. Re-resolve the inode
	// number now that the per-partition state is committed.
	kIno, _, kOK := findInDirPrefix(co, cloudBIO, cloudMediaId, cloudDevBlkSz, &cloudSB,
		cloudKernelDir, vmlinuzPrefix[:], &kernelName, &kernelNameLen)
	if !kOK {
		writeASCII(co, "  scanForExt4 picked a partition with no vmlinuz?\r\n")
		return false
	}
	writeASCII(co, "  kernel: ")
	for i := 0; i < kernelNameLen; i++ {
		oneCharBuf[0] = kernelName[i]
		writeASCII(co, oneCharStr)
	}
	writeASCII(co, "\r\n")

	// Read kernel.
	if !readInode(co, cloudBIO, cloudMediaId, cloudDevBlkSz, &cloudSB, kIno) {
		return false
	}
	var ino ext4Inode
	if !parseInode(rawInodeBuf[:], &ino) {
		return false
	}
	kernelSize := (uint64(ino.sizeHi) << 32) | uint64(ino.sizeLo)
	kernelBufPtr = 0
	if efiCall3(bs.allocatePool, efiLoaderData, uintptr(kernelSize),
		uintptr(unsafe.Pointer(&kernelBufPtr))) != efiSuccess || kernelBufPtr == 0 {
		writeASCII(co, "  AllocatePool(kernel) failed\r\n")
		return false
	}
	got := readFile(co, cloudBIO, cloudMediaId, cloudDevBlkSz, &cloudSB, kIno,
		kernelBufPtr, kernelSize)
	if got != kernelSize {
		writeASCII(co, "  short kernel read\r\n")
		return false
	}
	loadedKernelSize = got

	// If the kernel is gzip-wrapped (Ubuntu arm64 ships
	// /boot/vmlinuz-*-generic that way), decompress into a fresh
	// pool buffer and swap kernelBufPtr to the inflated copy.
	if isGzipped(kernelBufPtr) {
		if !maybeInflateKernel(co, bs, got) {
			return false
		}
	}

	// Find + read initrd in the same directory the kernel came from.
	// Try Debian "initrd.img-*" first, then RHEL "initramfs-*.img"
	// so a single ext4 walker handles both /boot-style and
	// dedicated-/boot-partition (Fedora) layouts.
	iIno, _, iOK := findInDirPrefix(co, cloudBIO, cloudMediaId, cloudDevBlkSz, &cloudSB,
		cloudKernelDir, initrdPrefix[:], &initrdName, &initrdNameLen)
	if !iOK {
		// initramfsPrefix is defined in xfs.go (RHEL family
		// convention) — share it so the ext4 walker also matches
		// Fedora-style /boot/initramfs-*.img.
		iIno, _, iOK = findInDirPrefix(co, cloudBIO, cloudMediaId, cloudDevBlkSz, &cloudSB,
			cloudKernelDir, initramfsPrefix[:], &initrdName, &initrdNameLen)
	}
	if !iOK {
		writeASCII(co, "  no initrd alongside kernel — continuing without\r\n")
	} else {
		writeASCII(co, "  initrd: ")
		for i := 0; i < initrdNameLen; i++ {
			oneCharBuf[0] = initrdName[i]
			writeASCII(co, oneCharStr)
		}
		writeASCII(co, "\r\n")
		if !readInode(co, cloudBIO, cloudMediaId, cloudDevBlkSz, &cloudSB, iIno) ||
			!parseInode(rawInodeBuf[:], &ino) {
			return false
		}
		initrdSize = (uint64(ino.sizeHi) << 32) | uint64(ino.sizeLo)
		initrdDataPtr = 0
		if efiCall3(bs.allocatePool, efiLoaderData, uintptr(initrdSize),
			uintptr(unsafe.Pointer(&initrdDataPtr))) != efiSuccess || initrdDataPtr == 0 {
			writeASCII(co, "  AllocatePool(initrd) failed\r\n")
			return false
		}
		igot := readFile(co, cloudBIO, cloudMediaId, cloudDevBlkSz, &cloudSB, iIno,
			initrdDataPtr, initrdSize)
		if igot != initrdSize {
			writeASCII(co, "  short initrd read\r\n")
			return false
		}
		if !installInitrdProtocol(co, bs) {
			return false
		}
		writeASCII(co, "  initrd protocols installed\r\n")
	}

	// LoadImage from buffer into childImageHandle so _start's
	// existing patchChildCmdline + StartImage path takes over.
	childImageHandle = 0
	if efiCall6(bs.loadImage,
		0,            // BootPolicy = FALSE
		imageHandle,  // ParentImageHandle
		0,            // DevicePath = NULL
		kernelBufPtr, // SourceBuffer
		uintptr(loadedKernelSize),
		uintptr(unsafe.Pointer(&childImageHandle))) != efiSuccess {
		writeASCII(co, "  LoadImage(kernel) failed\r\n")
		return false
	}
	writeASCII(co, "  cloud-disk kernel LoadImage OK, child=")
	writeHex64(co, uint64(childImageHandle))
	writeASCII(co, "\r\n")
	return true
}

// scanForExt4 walks every BlockIO handle and stops at the first ext4
// partition (skipping our own ESP and any other FAT volumes). On
// success populates cloudBIO / cloudMediaId / cloudDevBlkSz /
// cloudSB and returns true.
func scanForExt4(co *efiSimpleTextOutput, bs *efiBootServices) bool {
	bioHandleCount = 0
	bioHandleBuf = 0
	if efiCall5(bs.locateHandleBuffer,
		uintptr(2),
		uintptr(unsafe.Pointer(&blockIOGUID)),
		0,
		uintptr(unsafe.Pointer(&bioHandleCount)),
		uintptr(unsafe.Pointer(&bioHandleBuf))) != efiSuccess {
		return false
	}
	for i := uintptr(0); i < bioHandleCount; i++ {
		h := *(*uintptr)(unsafe.Pointer(bioHandleBuf + i*unsafe.Sizeof(uintptr(0))))
		bioHolder = 0
		if efiCall3(bs.handleProtocol,
			h,
			uintptr(unsafe.Pointer(&blockIOGUID)),
			uintptr(unsafe.Pointer(&bioHolder))) != efiSuccess || bioHolder == 0 {
			continue
		}
		bp := (*efiBlockIO)(unsafe.Pointer(bioHolder))
		media := (*efiBlockIOMedia)(unsafe.Pointer(bp.media))
		// Only consider logical partitions — skip the whole-disk
		// handles (GPT) and the firmware-installed FAT ESPs.
		if media.logicalPartition == 0 {
			continue
		}
		// Read first 4 KiB for ext4 magic.
		blocks := uintptr(4096) / uintptr(media.blockSize)
		if uintptr(4096)%uintptr(media.blockSize) != 0 {
			blocks++
		}
		for k := 0; k < len(probeBuf); k++ {
			probeBuf[k] = 0
		}
		if readBlocks(bioHolder, media.mediaId, 0,
			blocks*uintptr(media.blockSize),
			uintptr(unsafe.Pointer(&probeBuf[0]))) != efiSuccess {
			continue
		}
		if len(probeBuf) < 0x500 || le16(probeBuf[0x438:]) != 0xEF53 {
			continue
		}
		if !parseExt4SB(probeBuf[:], &cloudSB) {
			continue
		}
		// Provisionally commit to this partition while we look for
		// vmlinuz. If no kernel is here, keep walking; the next ext4
		// partition (if any) gets a turn.
		cloudBIO = bioHolder
		cloudMediaId = media.mediaId
		cloudDevBlkSz = media.blockSize
		// Try partition-root first (Fedora-style separate /boot), then
		// /boot/ inside the rootfs (Debian-style). Sanity-check that
		// the candidate kernel is actually a PE/COFF binary — Ubuntu's
		// cloudimg-rootfs has placeholder /boot/vmlinuz-* files that
		// FAIL LoadImage (the real kernel lives on the dedicated BOOT
		// partition). Without the PE check we'd lock onto the
		// placeholder and never try the real partition.
		kIno, _, ok := findInDirPrefix(co, cloudBIO, cloudMediaId, cloudDevBlkSz, &cloudSB,
			2, vmlinuzPrefix[:], &kernelName, &kernelNameLen)
		if ok && validatePEKernel(co, cloudBIO, cloudMediaId, cloudDevBlkSz, &cloudSB, kIno) {
			cloudKernelDir = 2
			cloudFoundExt4 = true
			return true
		}
		bootIno, _, hasBoot := findInDir(co, cloudBIO, cloudMediaId, cloudDevBlkSz, &cloudSB,
			2, bootDirName[:4])
		if hasBoot {
			kIno, _, ok = findInDirPrefix(co, cloudBIO, cloudMediaId, cloudDevBlkSz, &cloudSB,
				bootIno, vmlinuzPrefix[:], &kernelName, &kernelNameLen)
			if ok && validatePEKernel(co, cloudBIO, cloudMediaId, cloudDevBlkSz, &cloudSB, kIno) {
				cloudKernelDir = bootIno
				cloudFoundExt4 = true
				return true
			}
		}
		// No kernel here — continue to the next partition.
	}
	return false
}

// validatePEKernel reads the first fs-block of `kIno` and checks for
// the PE/COFF "MZ" header. Catches Ubuntu-cloudimg-rootfs's
// placeholder /boot/vmlinuz files (which exist but aren't valid
// EFI-stub kernels — the real ones live on the dedicated BOOT
// partition) so scanForExt4 can move on to the next partition.
//
// Reaches into the inode's extent tree directly (depth-0 inline OR
// depth-1 via extent-index pointers) — readDataBlock only handles
// depth-0 and would reject every modern kernel ≥ ~10 MiB.
func validatePEKernel(co *efiSimpleTextOutput, bio uintptr, mediaId, devBlkSz uint32,
	sb *ext4SB, inoNum uint32,
) bool {
	if !readInode(co, bio, mediaId, devBlkSz, sb, inoNum) {
		return false
	}
	var ino ext4Inode
	if !parseInode(rawInodeBuf[:], &ino) {
		return false
	}
	sz := (uint64(ino.sizeHi) << 32) | uint64(ino.sizeLo)
	if sz < 4096 {
		return false
	}
	iblock := rawInodeBuf[inodeBlockOff : inodeBlockOff+inodeBlockSize]
	var eh extentHeader
	if !parseExtentHeader(iblock, &eh) || eh.entries == 0 {
		return false
	}
	// Find the extent covering logical block 0.
	var phys uint64
	switch eh.depth {
	case 0:
		// First leaf entry covers block 0 in any non-sparse file.
		off := 12
		eeBlock := le32(iblock[off+0:])
		if eeBlock != 0 {
			return false
		}
		startHi := le16(iblock[off+6:])
		startLo := le32(iblock[off+8:])
		phys = (uint64(startHi) << 32) | uint64(startLo)
	case 1:
		// First idx entry points at the first leaf block.
		off := 12
		eiLeafLo := le32(iblock[off+4:])
		eiLeafHi := le16(iblock[off+8:])
		eiLeaf := (uint64(eiLeafHi) << 32) | uint64(eiLeafLo)
		leafLBA := eiLeaf * sb.blockSize / uint64(devBlkSz)
		if readBlocks(bio, mediaId, leafLBA, uintptr(sb.blockSize),
			uintptr(unsafe.Pointer(&extentLeafBuf[0]))) != efiSuccess {
			return false
		}
		var leafEh extentHeader
		if !parseExtentHeader(extentLeafBuf[:], &leafEh) || leafEh.depth != 0 || leafEh.entries == 0 {
			return false
		}
		off = 12
		eeBlock := le32(extentLeafBuf[off+0:])
		if eeBlock != 0 {
			return false
		}
		startHi := le16(extentLeafBuf[off+6:])
		startLo := le32(extentLeafBuf[off+8:])
		phys = (uint64(startHi) << 32) | uint64(startLo)
	default:
		return false
	}
	lba := phys * sb.blockSize / uint64(devBlkSz)
	if readBlocks(bio, mediaId, lba, uintptr(sb.blockSize),
		uintptr(unsafe.Pointer(&dirBuf[0]))) != efiSuccess {
		return false
	}
	// "MZ" → genuine PE/COFF EFI binary, the happy path.
	if dirBuf[0] == 'M' && dirBuf[1] == 'Z' {
		return true
	}
	// "1F 8B 08 …" → gzip-compressed kernel (Ubuntu arm64 ships
	// /boot/vmlinuz-*-generic as a gzip-wrapped raw Image). We
	// accept these too — the post-readFile gzipDecompress pass in
	// tryCloudDiskBoot inflates them before LoadImage.
	if dirBuf[0] == 0x1F && dirBuf[1] == 0x8B {
		return true
	}
	return false
}
