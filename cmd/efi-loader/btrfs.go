// btrfs cloud-disk path — ported from cmd/disk-probe.
//
// Boots a Linux distro whose root filesystem is btrfs (openSUSE
// MicroOS / Leap Micro) by walking the on-disk metadata: superblock
// at offset 64 KiB → sys_chunk_array bootstrap → chunk-tree extension
// → root-tree → default-subvol DIR_ITEM (or fallback to FS_TREE
// objectid=5) → per-subvol kernel discovery (vmlinuz- / Image-, at
// subvol root or under /boot) → INODE_ITEM for size → EXTENT_DATA
// items for file bytes → AllocatePool + readFile → LoadImage.
//
// Same plug point as tryCloudDiskBoot (ext4) and tryXfsCloudBoot
// (xfs): populates childImageHandle so _start's existing
// patchChildCmdline + StartImage path takes over unchanged.

package main

import "unsafe"

// ----- btrfs superblock -----

const btrfsSBMagic uint64 = 0x4D5F53665248425F // "_BHRfS_M"

type btrfsSB struct {
	magic             uint64
	generation        uint64
	rootLogical       uint64
	chunkRootLogical  uint64
	totalBytes        uint64
	sectorsize        uint32
	nodesize          uint32
	sysChunkArraySize uint32
	rootLevel         uint8
	chunkRootLevel    uint8
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
	return true
}

func le64(b []byte) uint64 {
	return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
}

// ----- chunk map (logical → physical) -----

const (
	btrfsKeySize         = 17
	btrfsChunkItemKey    = 0xE4 // BTRFS_CHUNK_ITEM_KEY
	btrfsFirstChunkObjID = 256  // BTRFS_FIRST_CHUNK_TREE_OBJECTID
	btrfsMaxChunks       = 256
)

type btrfsChunk struct {
	logical    uint64
	length     uint64
	physical   uint64
	numStripes uint16
}

var (
	btrfsChunkMap      [btrfsMaxChunks]btrfsChunk
	btrfsChunkMapCount int
)

// parseSysChunkArray seeds the chunk map from the SB's sys_chunk_array.
func parseSysChunkArray(sbData []byte, sysSize uint32) bool {
	const off0 = 811
	if uint32(len(sbData)) < off0+sysSize {
		return false
	}
	off := uint32(off0)
	end := off0 + sysSize
	for off+btrfsKeySize+48 <= end {
		ktype := sbData[off+8]
		koff := le64(sbData[off+9:])
		off += btrfsKeySize
		if ktype != btrfsChunkItemKey {
			return false
		}
		if btrfsChunkMapCount >= btrfsMaxChunks {
			return false
		}
		length := le64(sbData[off:])
		numStripes := le16(sbData[off+44:])
		off += 48
		if numStripes == 0 || off+uint32(numStripes)*32 > end {
			return false
		}
		physical := le64(sbData[off+8:])
		btrfsChunkMap[btrfsChunkMapCount].logical = koff
		btrfsChunkMap[btrfsChunkMapCount].length = length
		btrfsChunkMap[btrfsChunkMapCount].physical = physical
		btrfsChunkMap[btrfsChunkMapCount].numStripes = numStripes
		btrfsChunkMapCount++
		off += uint32(numStripes) * 32
	}
	return true
}

func btrfsLogicalToPhys(logical uint64) (uint64, bool) {
	for i := 0; i < btrfsChunkMapCount; i++ {
		c := &btrfsChunkMap[i]
		if logical >= c.logical && logical < c.logical+c.length {
			return c.physical + (logical - c.logical), true
		}
	}
	return 0, false
}

// ----- tree block I/O -----

const (
	btrfsHeaderSize = 101
	btrfsItemSize   = 25
	btrfsKeyPtrSize = 33
)

// btrfsTreeBuf holds the most-recently-read tree block. 16 KiB
// matches default sb.nodesize on cloud images.
var btrfsTreeBuf [16384]byte

func readBtrfsBlock(bio uintptr, mediaId, devBlkSz uint32, physical uint64,
	size uint32, out unsafe.Pointer,
) bool {
	lba := physical / uint64(devBlkSz)
	if physical%uint64(devBlkSz) != 0 {
		return false
	}
	return readBlocks(bio, mediaId, lba, uintptr(size), uintptr(out)) == efiSuccess
}

type btrfsItem struct {
	objectid uint64
	keyType  uint8
	keyOff   uint64
	dataOff  uint32
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

// ----- btrfs key constants -----
//
// Canonical from linux/fs/btrfs/ctree.h. Don't confuse 0x60 / 0x61
// (which are DIR_LOG_ITEM / DIR_LOG_INDEX, 60/72 decimal) with the
// on-disk dir entries we walk here (84/96 decimal, i.e. 0x54/0x60).

const (
	btrfsDirItemKey          = 0x54
	btrfsDirIndexKey         = 0x60
	btrfsInodeItemKey        = 0x01
	btrfsExtentDataKey       = 0x6C
	btrfsRootItemKey         = 0x84
	btrfsFirstFreeObjectID   = 256
	btrfsFsTreeObjectID      = 5
	btrfsRootTreeDirObjectID = 6
	btrfsRootItemBytenrOff   = 176
	btrfsRootItemLevelOff    = 238
)

// ----- depth-N B-tree walker with key-range pruning -----
//
// LIFO worklist. At each internal node we only push children whose
// first-key/last-key range overlaps (parentDirInode, *, *) — for a
// single-dir lookup that's typically 1-2 leaves total regardless of
// tree depth. Package-scope because TinyGo escape analysis would
// otherwise heap-promote any stack-local equivalent.

var (
	btrfsWalkBytenr [512]uint64
	btrfsWalkLevel  [512]uint8
	btrfsWalkCount  int
)

const btrfsWalkMaxSteps = 4096

// findInBtrfsDirPrefix walks an FS_TREE / subvol tree for the first
// DIR_INDEX / DIR_ITEM under parentDirInode whose name starts with
// `prefix`. Returns the matching child object id (file/dir inode
// number, or — for snapshot subvolume references — a different
// root_id), copies the name into outNameBuf, and returns true.
func findInBtrfsDirPrefix(bio uintptr, mediaId, devBlkSz uint32,
	fsTreeLogical uint64, fsTreeLevel uint8, nodesize uint32,
	parentDirInode uint64, prefix []byte,
	outNameBuf *[255]byte, outNameLen *int,
) (uint64, bool) {
	btrfsWalkCount = 0
	btrfsWalkBytenr[0] = fsTreeLogical
	btrfsWalkLevel[0] = fsTreeLevel
	btrfsWalkCount = 1
	steps := 0
	for btrfsWalkCount > 0 && steps < btrfsWalkMaxSteps {
		steps++
		btrfsWalkCount--
		cur := btrfsWalkBytenr[btrfsWalkCount]
		phys, ok := btrfsLogicalToPhys(cur)
		if !ok {
			continue
		}
		if !readBtrfsBlock(bio, mediaId, devBlkSz, phys, nodesize,
			unsafe.Pointer(&btrfsTreeBuf[0])) {
			continue
		}
		actualLevel := btrfsTreeBuf[100]
		if actualLevel == 0 {
			ino, found := scanBtrfsLeafForDirPrefix(parentDirInode, prefix,
				outNameBuf, outNameLen, nodesize)
			if found {
				return ino, true
			}
			continue
		}
		nritems := le32(btrfsTreeBuf[96:])
		for i := uint32(0); i < nritems; i++ {
			off := uint32(btrfsHeaderSize) + i*btrfsKeyPtrSize
			if off+btrfsKeyPtrSize > nodesize {
				break
			}
			thisObj := le64(btrfsTreeBuf[off:])
			if thisObj > parentDirInode {
				break
			}
			nextObj := uint64(0xFFFFFFFFFFFFFFFF)
			if i+1 < nritems {
				nOff := uint32(btrfsHeaderSize) + (i+1)*btrfsKeyPtrSize
				if nOff+btrfsKeyPtrSize <= nodesize {
					nextObj = le64(btrfsTreeBuf[nOff:])
				}
			}
			if nextObj < parentDirInode {
				continue
			}
			childBytenr := le64(btrfsTreeBuf[off+17:])
			if btrfsWalkCount >= len(btrfsWalkBytenr) {
				break
			}
			btrfsWalkBytenr[btrfsWalkCount] = childBytenr
			btrfsWalkLevel[btrfsWalkCount] = actualLevel - 1
			btrfsWalkCount++
		}
	}
	return 0, false
}

// scanBtrfsLeafForDirPrefix scans a leaf currently sitting in
// btrfsTreeBuf for the first DIR_INDEX_KEY or DIR_ITEM_KEY under
// parentDirInode whose name starts with `prefix`.
func scanBtrfsLeafForDirPrefix(parentDirInode uint64, prefix []byte,
	outNameBuf *[255]byte, outNameLen *int, nodesize uint32,
) (uint64, bool) {
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
		if it.keyType != btrfsDirIndexKey && it.keyType != btrfsDirItemKey {
			continue
		}
		dataPos := uint32(btrfsHeaderSize) + it.dataOff
		if dataPos+30 > nodesize {
			break
		}
		locObjID := le64(btrfsTreeBuf[dataPos:])
		nameLen := le16(btrfsTreeBuf[dataPos+27:])
		if uint32(nameLen) < uint32(len(prefix)) ||
			dataPos+30+uint32(nameLen) > nodesize {
			continue
		}
		match := true
		for j := 0; j < len(prefix); j++ {
			if btrfsTreeBuf[dataPos+30+uint32(j)] != prefix[j] {
				match = false
				break
			}
		}
		if !match {
			continue
		}
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
	return 0, false
}

// ----- root-tree walkers -----
//
// Two flavours, both single-leaf (cloud-image root trees have well
// under one nodesize of items, so level=0 is the typical case).
// If the root tree is deeper we'd need to extend findInBtrfsDirPrefix
// to take a tree id and key-range — out of scope here since real
// cloud images don't hit it.

func walkRootTreeForDefaultSubvol(bio uintptr, mediaId, devBlkSz uint32,
	rootLogical uint64, nodesize uint32,
) (uint64, bool) {
	rootPhys, ok := btrfsLogicalToPhys(rootLogical)
	if !ok {
		return 0, false
	}
	if !readBtrfsBlock(bio, mediaId, devBlkSz, rootPhys, nodesize,
		unsafe.Pointer(&btrfsTreeBuf[0])) {
		return 0, false
	}
	if btrfsTreeBuf[100] != 0 {
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
				return locObjID, true
			}
		}
	}
	return 0, false
}

func walkRootTreeForSubvolRoot(bio uintptr, mediaId, devBlkSz uint32,
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
		return true
	}
	return false
}

func walkRootTreeForFSTree(bio uintptr, mediaId, devBlkSz uint32,
	rootLogical uint64, nodesize uint32,
	outBytenr *uint64, outLevel *uint8,
) bool {
	return walkRootTreeForSubvolRoot(bio, mediaId, devBlkSz, rootLogical, nodesize,
		btrfsFsTreeObjectID, outBytenr, outLevel)
}

func walkChunkTreeLeaf(bio uintptr, mediaId, devBlkSz uint32,
	phys uint64, nodesize uint32,
) bool {
	if !readBtrfsBlock(bio, mediaId, devBlkSz, phys, nodesize,
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
		if it.keyType != btrfsChunkItemKey {
			continue
		}
		dataPos := uint32(btrfsHeaderSize) + it.dataOff
		if dataPos+48 > nodesize {
			break
		}
		length := le64(btrfsTreeBuf[dataPos:])
		numStripes := le16(btrfsTreeBuf[dataPos+44:])
		if numStripes == 0 || dataPos+48+uint32(numStripes)*32 > nodesize {
			break
		}
		physical := le64(btrfsTreeBuf[dataPos+48+8:])
		if btrfsChunkMapCount >= btrfsMaxChunks {
			break
		}
		btrfsChunkMap[btrfsChunkMapCount].logical = it.keyOff
		btrfsChunkMap[btrfsChunkMapCount].length = length
		btrfsChunkMap[btrfsChunkMapCount].physical = physical
		btrfsChunkMap[btrfsChunkMapCount].numStripes = numStripes
		btrfsChunkMapCount++
	}
	return true
}

// ----- subvolume scanner -----
//
// Walks every ROOT_ITEM_KEY in the root-tree leaf whose objectid >=
// 256 (user subvol IDs) and probes each for vmlinuz- or Image-, at
// subvol root or under /boot. First hit wins; populates the
// btrfsKernel* package vars so the file-reader knows which subvol
// tree to walk.

var (
	btrfsKernelSubvolRootID uint64
	btrfsKernelDirInode     uint64
	btrfsKernelBytenr       uint64
	btrfsKernelLevel        uint8

	btrfsCandIDs     [32]uint64
	btrfsCandBytenrs [32]uint64
	btrfsCandLevels  [32]uint8

	btrfsBootName    = [...]byte{'b', 'o', 'o', 't'}
	btrfsImagePrefix = [...]byte{'I', 'm', 'a', 'g', 'e', '-'}
)

func scanSubvolumesForKernel(bio uintptr, mediaId, devBlkSz uint32,
	rootLogical uint64, nodesize uint32,
	outName *[255]byte, outNameLen *int,
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
	candCount := 0
	for i := uint32(0); i < nritems; i++ {
		off := uint32(btrfsHeaderSize) + i*btrfsItemSize
		if off+btrfsItemSize > nodesize {
			break
		}
		var it btrfsItem
		if !parseBtrfsItem(btrfsTreeBuf[off:off+btrfsItemSize], &it) {
			break
		}
		if it.keyType != btrfsRootItemKey || it.objectid < 256 {
			continue
		}
		dataPos := uint32(btrfsHeaderSize) + it.dataOff
		if dataPos+239 > nodesize {
			break
		}
		bytenr := le64(btrfsTreeBuf[dataPos+btrfsRootItemBytenrOff:])
		level := btrfsTreeBuf[dataPos+btrfsRootItemLevelOff]
		if candCount >= len(btrfsCandIDs) {
			break
		}
		btrfsCandIDs[candCount] = it.objectid
		btrfsCandBytenrs[candCount] = bytenr
		btrfsCandLevels[candCount] = level
		candCount++
	}
	for k := 0; k < candCount; k++ {
		kIno, ok := findInBtrfsDirPrefix(bio, mediaId, devBlkSz,
			btrfsCandBytenrs[k], btrfsCandLevels[k], nodesize,
			btrfsFirstFreeObjectID, vmlinuzPrefix[:],
			outName, outNameLen)
		if ok {
			btrfsKernelSubvolRootID = btrfsCandIDs[k]
			btrfsKernelBytenr = btrfsCandBytenrs[k]
			btrfsKernelLevel = btrfsCandLevels[k]
			btrfsKernelDirInode = btrfsFirstFreeObjectID
			_ = kIno
			return true
		}
		kIno, ok = findInBtrfsDirPrefix(bio, mediaId, devBlkSz,
			btrfsCandBytenrs[k], btrfsCandLevels[k], nodesize,
			btrfsFirstFreeObjectID, btrfsImagePrefix[:],
			outName, outNameLen)
		if ok {
			btrfsKernelSubvolRootID = btrfsCandIDs[k]
			btrfsKernelBytenr = btrfsCandBytenrs[k]
			btrfsKernelLevel = btrfsCandLevels[k]
			btrfsKernelDirInode = btrfsFirstFreeObjectID
			_ = kIno
			return true
		}
		bIno, hasBoot := findInBtrfsDirPrefix(bio, mediaId, devBlkSz,
			btrfsCandBytenrs[k], btrfsCandLevels[k], nodesize,
			btrfsFirstFreeObjectID, btrfsBootName[:],
			outName, outNameLen)
		if !hasBoot || bIno == 0 {
			continue
		}
		kIno2, ok2 := findInBtrfsDirPrefix(bio, mediaId, devBlkSz,
			btrfsCandBytenrs[k], btrfsCandLevels[k], nodesize,
			bIno, vmlinuzPrefix[:],
			outName, outNameLen)
		if ok2 {
			btrfsKernelSubvolRootID = btrfsCandIDs[k]
			btrfsKernelBytenr = btrfsCandBytenrs[k]
			btrfsKernelLevel = btrfsCandLevels[k]
			btrfsKernelDirInode = bIno
			_ = kIno2
			return true
		}
		kIno2, ok2 = findInBtrfsDirPrefix(bio, mediaId, devBlkSz,
			btrfsCandBytenrs[k], btrfsCandLevels[k], nodesize,
			bIno, btrfsImagePrefix[:],
			outName, outNameLen)
		if ok2 {
			btrfsKernelSubvolRootID = btrfsCandIDs[k]
			btrfsKernelBytenr = btrfsCandBytenrs[k]
			btrfsKernelLevel = btrfsCandLevels[k]
			btrfsKernelDirInode = bIno
			_ = kIno2
			return true
		}
	}
	return false
}

// ----- INODE_ITEM + EXTENT_DATA reader -----
//
// Find the INODE_ITEM_KEY for `inoNum` in the subvol tree to learn
// the file's size. Then walk every EXTENT_DATA_KEY under that inode
// and copy each extent's bytes into the supplied output buffer.
//
// We support type=0 (INLINE — data lives inside the item) and type=1
// (REG — out-of-line extent at disk_bytenr+offset for num_bytes).
// type=2 (PREALLOC) shouldn't appear on a kernel file. Compression
// (lzo/zstd/zlib) is not implemented — production cloud kernels are
// stored uncompressed in btrfs.
//
// btrfs_file_extent_item layout:
//
//	0..8    generation
//	8..16   ram_bytes
//	16      compression
//	17      encryption
//	18..20  other_encoding
//	20      type (0=INLINE, 1=REG, 2=PREALLOC)
//	if not INLINE:
//	  21..29  disk_bytenr
//	  29..37  disk_num_bytes
//	  37..45  offset
//	  45..53  num_bytes
//	if INLINE:
//	  21..    inline data (item.dataSize - 21 bytes)

const (
	btrfsExtentTypeInline   = 0
	btrfsExtentTypeReg      = 1
	btrfsExtentTypePrealloc = 2
)

// btrfsLookupInode finds INODE_ITEM_KEY for inoNum and returns its
// size and mode. btrfs_inode_item layout: generation(8) transid(8)
// size(8) nbytes(8) block_group(8) nlink(4) uid(4) gid(4) mode(4)
// rdev(8) … so mode lives at offset 52. The full inode_item is 160
// bytes.
//
// Mode follows POSIX S_IF* bits in its high nibble:
//
//	0x8000 = S_IFREG (regular file)
//	0xA000 = S_IFLNK (symlink)
//	0x4000 = S_IFDIR (directory)
//
// Callers check (mode & 0xF000) to dispatch on file kind.
func btrfsLookupInode(bio uintptr, mediaId, devBlkSz uint32,
	subvolBytenr uint64, subvolLevel uint8, nodesize uint32,
	inoNum uint64,
) (size uint64, mode uint32, ok bool) {
	btrfsWalkCount = 0
	btrfsWalkBytenr[0] = subvolBytenr
	btrfsWalkLevel[0] = subvolLevel
	btrfsWalkCount = 1
	steps := 0
	for btrfsWalkCount > 0 && steps < btrfsWalkMaxSteps {
		steps++
		btrfsWalkCount--
		cur := btrfsWalkBytenr[btrfsWalkCount]
		phys, pok := btrfsLogicalToPhys(cur)
		if !pok {
			continue
		}
		if !readBtrfsBlock(bio, mediaId, devBlkSz, phys, nodesize,
			unsafe.Pointer(&btrfsTreeBuf[0])) {
			continue
		}
		actualLevel := btrfsTreeBuf[100]
		if actualLevel == 0 {
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
				if it.objectid != inoNum || it.keyType != btrfsInodeItemKey {
					continue
				}
				dataPos := uint32(btrfsHeaderSize) + it.dataOff
				if dataPos+160 > nodesize {
					return 0, 0, false
				}
				size = le64(btrfsTreeBuf[dataPos+16:])
				mode = le32(btrfsTreeBuf[dataPos+52:])
				ok = true
				return
			}
			continue
		}
		nritems := le32(btrfsTreeBuf[96:])
		for i := uint32(0); i < nritems; i++ {
			off := uint32(btrfsHeaderSize) + i*btrfsKeyPtrSize
			if off+btrfsKeyPtrSize > nodesize {
				break
			}
			thisObj := le64(btrfsTreeBuf[off:])
			if thisObj > inoNum {
				break
			}
			nextObj := uint64(0xFFFFFFFFFFFFFFFF)
			if i+1 < nritems {
				nOff := uint32(btrfsHeaderSize) + (i+1)*btrfsKeyPtrSize
				if nOff+btrfsKeyPtrSize <= nodesize {
					nextObj = le64(btrfsTreeBuf[nOff:])
				}
			}
			if nextObj < inoNum {
				continue
			}
			childBytenr := le64(btrfsTreeBuf[off+17:])
			if btrfsWalkCount >= len(btrfsWalkBytenr) {
				break
			}
			btrfsWalkBytenr[btrfsWalkCount] = childBytenr
			btrfsWalkLevel[btrfsWalkCount] = actualLevel - 1
			btrfsWalkCount++
		}
	}
	return 0, 0, false
}

// btrfsExtentRec is one EXTENT_DATA_KEY harvested from the subvol
// tree. We collect every extent first into a package-scope array
// (since the tree walker overwrites btrfsTreeBuf on every block read)
// and then issue one ReadBlocks per extent against the cloud-image
// device.
type btrfsExtentRec struct {
	fileOffset    uint64 // = item.keyOff
	extentType    uint8
	diskBytenr    uint64
	diskOffset    uint64 // offset within the extent
	numBytes      uint64
	inlineDataPos uint32 // dataPos+21 (offset into btrfsTreeBuf, valid only on the leaf that holds this record — used immediately, never deferred)
	inlineLen     uint32
}

// btrfsExtentRecs caps at 1024 extents per file — comfortably more
// than any cloud kernel image (Image-* is one mmap'd file with one
// extent; vmlinuz-* on a fresh install is typically <8 extents; even
// fragmented dracut initrds rarely exceed a few hundred).
var (
	btrfsExtentRecs  [1024]btrfsExtentRec
	btrfsExtentCount int

	// Scratch leaf for the EXTENT_DATA scan — we need to capture
	// inline-extent bytes while the leaf is still loaded. Inline
	// extents are tiny (≤ sectorsize so usually ≤ 4 KiB) so we just
	// copy them into a dedicated buffer at gather time.
	btrfsInlineBuf      [16384]byte
	btrfsInlineBufUsed  int
)

// btrfsCollectExtents walks the subvol tree, collecting every
// EXTENT_DATA_KEY under inoNum into btrfsExtentRecs.
func btrfsCollectExtents(bio uintptr, mediaId, devBlkSz uint32,
	subvolBytenr uint64, subvolLevel uint8, nodesize uint32,
	inoNum uint64,
) bool {
	btrfsExtentCount = 0
	btrfsInlineBufUsed = 0
	btrfsWalkCount = 0
	btrfsWalkBytenr[0] = subvolBytenr
	btrfsWalkLevel[0] = subvolLevel
	btrfsWalkCount = 1
	steps := 0
	for btrfsWalkCount > 0 && steps < btrfsWalkMaxSteps {
		steps++
		btrfsWalkCount--
		cur := btrfsWalkBytenr[btrfsWalkCount]
		phys, ok := btrfsLogicalToPhys(cur)
		if !ok {
			continue
		}
		if !readBtrfsBlock(bio, mediaId, devBlkSz, phys, nodesize,
			unsafe.Pointer(&btrfsTreeBuf[0])) {
			continue
		}
		actualLevel := btrfsTreeBuf[100]
		if actualLevel == 0 {
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
				if it.objectid != inoNum || it.keyType != btrfsExtentDataKey {
					continue
				}
				dataPos := uint32(btrfsHeaderSize) + it.dataOff
				if dataPos+21 > nodesize {
					break
				}
				if btrfsExtentCount >= len(btrfsExtentRecs) {
					return false
				}
				compression := btrfsTreeBuf[dataPos+16]
				if compression != 0 {
					return false
				}
				typ := btrfsTreeBuf[dataPos+20]
				rec := &btrfsExtentRecs[btrfsExtentCount]
				rec.fileOffset = it.keyOff
				rec.extentType = typ
				if typ == btrfsExtentTypeInline {
					inlineLen := it.dataSize - 21
					if dataPos+21+inlineLen > nodesize {
						return false
					}
					if btrfsInlineBufUsed+int(inlineLen) > len(btrfsInlineBuf) {
						return false
					}
					for j := uint32(0); j < inlineLen; j++ {
						btrfsInlineBuf[btrfsInlineBufUsed+int(j)] = btrfsTreeBuf[dataPos+21+j]
					}
					rec.inlineDataPos = uint32(btrfsInlineBufUsed)
					rec.inlineLen = inlineLen
					btrfsInlineBufUsed += int(inlineLen)
				} else if typ == btrfsExtentTypeReg {
					if dataPos+53 > nodesize {
						return false
					}
					rec.diskBytenr = le64(btrfsTreeBuf[dataPos+21:])
					rec.diskOffset = le64(btrfsTreeBuf[dataPos+37:])
					rec.numBytes = le64(btrfsTreeBuf[dataPos+45:])
				} else {
					// PREALLOC or unknown — leave as zeros (sparse).
					if dataPos+53 <= nodesize {
						rec.numBytes = le64(btrfsTreeBuf[dataPos+45:])
					}
				}
				btrfsExtentCount++
			}
			continue
		}
		nritems := le32(btrfsTreeBuf[96:])
		for i := uint32(0); i < nritems; i++ {
			off := uint32(btrfsHeaderSize) + i*btrfsKeyPtrSize
			if off+btrfsKeyPtrSize > nodesize {
				break
			}
			thisObj := le64(btrfsTreeBuf[off:])
			if thisObj > inoNum {
				break
			}
			nextObj := uint64(0xFFFFFFFFFFFFFFFF)
			if i+1 < nritems {
				nOff := uint32(btrfsHeaderSize) + (i+1)*btrfsKeyPtrSize
				if nOff+btrfsKeyPtrSize <= nodesize {
					nextObj = le64(btrfsTreeBuf[nOff:])
				}
			}
			if nextObj < inoNum {
				continue
			}
			childBytenr := le64(btrfsTreeBuf[off+17:])
			if btrfsWalkCount >= len(btrfsWalkBytenr) {
				break
			}
			btrfsWalkBytenr[btrfsWalkCount] = childBytenr
			btrfsWalkLevel[btrfsWalkCount] = actualLevel - 1
			btrfsWalkCount++
		}
	}
	return true
}

// btrfsReadExtents copies each previously-collected extent into the
// output buffer. Sparse regions (gaps between extents or PREALLOC
// records) are left zeroed.
func btrfsReadExtents(bio uintptr, mediaId, devBlkSz uint32,
	outPtr uintptr, outSize uint64,
) bool {
	for i := 0; i < btrfsExtentCount; i++ {
		rec := &btrfsExtentRecs[i]
		if rec.fileOffset >= outSize {
			continue
		}
		if rec.extentType == btrfsExtentTypeInline {
			n := uint64(rec.inlineLen)
			if rec.fileOffset+n > outSize {
				n = outSize - rec.fileOffset
			}
			dst := unsafe.Pointer(outPtr + uintptr(rec.fileOffset))
			src := unsafe.Pointer(&btrfsInlineBuf[rec.inlineDataPos])
			for j := uint64(0); j < n; j++ {
				*(*byte)(unsafe.Pointer(uintptr(dst) + uintptr(j))) =
					*(*byte)(unsafe.Pointer(uintptr(src) + uintptr(j)))
			}
			continue
		}
		if rec.extentType != btrfsExtentTypeReg {
			continue
		}
		if rec.diskBytenr == 0 {
			// Sparse / hole — leave zero.
			continue
		}
		// Physical address of this extent on disk.
		diskLogical := rec.diskBytenr + rec.diskOffset
		diskPhys, ok := btrfsLogicalToPhys(diskLogical)
		if !ok {
			return false
		}
		n := rec.numBytes
		if rec.fileOffset+n > outSize {
			n = outSize - rec.fileOffset
		}
		// ReadBlocks requires LBA-aligned + multiple-of-blocksize.
		// Round down for the start, read into a scratch, then copy.
		lba := diskPhys / uint64(devBlkSz)
		preBytes := diskPhys - lba*uint64(devBlkSz)
		totalBytes := preBytes + n
		blockCount := (totalBytes + uint64(devBlkSz) - 1) / uint64(devBlkSz)
		alignedSize := blockCount * uint64(devBlkSz)
		// Re-use btrfsTreeBuf if the extent is small enough,
		// otherwise read directly into the output buffer at the
		// file offset (the common case for big kernel extents).
		if preBytes == 0 && n%uint64(devBlkSz) == 0 {
			// Aligned: stream straight into the output buffer.
			dst := outPtr + uintptr(rec.fileOffset)
			if readBlocks(bio, mediaId, lba, uintptr(n), dst) != efiSuccess {
				return false
			}
			continue
		}
		// Mis-aligned head — read via btrfsTreeBuf in chunks. For
		// extents larger than the scratch we loop.
		off := uint64(0)
		for off < n {
			chunk := alignedSize
			if chunk > uint64(len(btrfsTreeBuf)) {
				chunk = uint64(len(btrfsTreeBuf))
			}
			// re-derive lba/preBytes for the current sub-chunk
			subLogical := diskPhys + off
			subLBA := subLogical / uint64(devBlkSz)
			subPre := subLogical - subLBA*uint64(devBlkSz)
			subRemaining := n - off
			subTotalNeeded := subPre + subRemaining
			subBlocks := (subTotalNeeded + uint64(devBlkSz) - 1) / uint64(devBlkSz)
			subAligned := subBlocks * uint64(devBlkSz)
			if subAligned > chunk {
				subAligned = chunk
			}
			if readBlocks(bio, mediaId, subLBA, uintptr(subAligned),
				uintptr(unsafe.Pointer(&btrfsTreeBuf[0]))) != efiSuccess {
				return false
			}
			usable := subAligned - subPre
			if usable > subRemaining {
				usable = subRemaining
			}
			dst := unsafe.Pointer(outPtr + uintptr(rec.fileOffset) + uintptr(off))
			src := unsafe.Pointer(&btrfsTreeBuf[subPre])
			for j := uint64(0); j < usable; j++ {
				*(*byte)(unsafe.Pointer(uintptr(dst) + uintptr(j))) =
					*(*byte)(unsafe.Pointer(uintptr(src) + uintptr(j)))
			}
			off += usable
		}
	}
	return true
}

// ----- symlink resolution -----
//
// openSUSE-style cloud images keep the on-disk kernel under
// /usr/lib/modules/<ver>/<file> and expose it via a relative symlink
// at /boot/<file>. btrfs stores those symlinks as a regular file
// whose single INLINE extent holds the target path bytes.
//
// btrfsResolveSymlink reads the target path (already in btrfsInlineBuf
// from the preceding btrfsCollectExtents call) and walks each
// component against the active subvol tree, returning the final
// inode number.
//
// Path semantics:
//   - leading '/'  → restart at subvol root (inode 256)
//   - '..'        → go up one directory; we track a small per-component
//                    stack and only allow up to 8 levels of nesting
//                    (cloud-image paths never go deeper than that).
//   - '.'         → no-op
//   - anything else → exact-name dir lookup in the current dir
//
// Notes:
//   - INODE_REF_KEY would let us track parent inodes properly, but the
//     paths we see here all start "../usr/..." from /boot — a single
//     '..' jump back to the subvol root is enough.

var btrfsSymlinkPathBuf [4096]byte

func btrfsResolveSymlink(bio uintptr, mediaId, devBlkSz uint32,
	nodesize uint32, subvolBytenr uint64, subvolLevel uint8,
	symlinkInode uint64, parentDirInode uint64, size uint64,
) (uint64, bool) {
	if size == 0 || size > uint64(len(btrfsSymlinkPathBuf)) {
		return 0, false
	}
	if !btrfsCollectExtents(bio, mediaId, devBlkSz,
		subvolBytenr, subvolLevel, nodesize, symlinkInode) {
		return 0, false
	}
	if btrfsExtentCount != 1 ||
		btrfsExtentRecs[0].extentType != btrfsExtentTypeInline ||
		uint64(btrfsExtentRecs[0].inlineLen) != size {
		return 0, false
	}
	pos := btrfsExtentRecs[0].inlineDataPos
	for i := uint32(0); i < uint32(size); i++ {
		btrfsSymlinkPathBuf[i] = btrfsInlineBuf[pos+i]
	}
	plen := int(size)
	cur := parentDirInode
	p := 0
	if btrfsSymlinkPathBuf[0] == '/' {
		cur = btrfsFirstFreeObjectID
		p++
	}
	for p < plen {
		for p < plen && btrfsSymlinkPathBuf[p] == '/' {
			p++
		}
		if p >= plen {
			break
		}
		start := p
		for p < plen && btrfsSymlinkPathBuf[p] != '/' {
			p++
		}
		compLen := p - start
		if compLen == 1 && btrfsSymlinkPathBuf[start] == '.' {
			continue
		}
		if compLen == 2 && btrfsSymlinkPathBuf[start] == '.' && btrfsSymlinkPathBuf[start+1] == '.' {
			// Without INODE_REF_KEY traversal we can only handle one
			// '..' (popping from the kernel dir to the subvol root).
			// Cloud-image symlinks never need more than this.
			cur = btrfsFirstFreeObjectID
			continue
		}
		ino, ok := findInBtrfsDirExact(bio, mediaId, devBlkSz,
			subvolBytenr, subvolLevel, nodesize,
			cur, btrfsSymlinkPathBuf[start:start+compLen])
		if !ok {
			return 0, false
		}
		cur = ino
	}
	if cur == 0 {
		return 0, false
	}
	return cur, true
}

// findInBtrfsDirExact is the exact-name variant of
// findInBtrfsDirPrefix. Used for path resolution where matching the
// first prefix-hit would silently take the wrong child.
var btrfsExactName [255]byte

func findInBtrfsDirExact(bio uintptr, mediaId, devBlkSz uint32,
	fsTreeLogical uint64, fsTreeLevel uint8, nodesize uint32,
	parentDirInode uint64, name []byte,
) (uint64, bool) {
	if len(name) == 0 || len(name) > len(btrfsExactName) {
		return 0, false
	}
	btrfsWalkCount = 0
	btrfsWalkBytenr[0] = fsTreeLogical
	btrfsWalkLevel[0] = fsTreeLevel
	btrfsWalkCount = 1
	steps := 0
	for btrfsWalkCount > 0 && steps < btrfsWalkMaxSteps {
		steps++
		btrfsWalkCount--
		cur := btrfsWalkBytenr[btrfsWalkCount]
		phys, ok := btrfsLogicalToPhys(cur)
		if !ok {
			continue
		}
		if !readBtrfsBlock(bio, mediaId, devBlkSz, phys, nodesize,
			unsafe.Pointer(&btrfsTreeBuf[0])) {
			continue
		}
		actualLevel := btrfsTreeBuf[100]
		if actualLevel == 0 {
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
				if it.keyType != btrfsDirIndexKey && it.keyType != btrfsDirItemKey {
					continue
				}
				dataPos := uint32(btrfsHeaderSize) + it.dataOff
				if dataPos+30 > nodesize {
					break
				}
				locObjID := le64(btrfsTreeBuf[dataPos:])
				nameLen := le16(btrfsTreeBuf[dataPos+27:])
				if uint32(nameLen) != uint32(len(name)) ||
					dataPos+30+uint32(nameLen) > nodesize {
					continue
				}
				match := true
				for j := 0; j < len(name); j++ {
					if btrfsTreeBuf[dataPos+30+uint32(j)] != name[j] {
						match = false
						break
					}
				}
				if !match {
					continue
				}
				return locObjID, true
			}
			continue
		}
		nritems := le32(btrfsTreeBuf[96:])
		for i := uint32(0); i < nritems; i++ {
			off := uint32(btrfsHeaderSize) + i*btrfsKeyPtrSize
			if off+btrfsKeyPtrSize > nodesize {
				break
			}
			thisObj := le64(btrfsTreeBuf[off:])
			if thisObj > parentDirInode {
				break
			}
			nextObj := uint64(0xFFFFFFFFFFFFFFFF)
			if i+1 < nritems {
				nOff := uint32(btrfsHeaderSize) + (i+1)*btrfsKeyPtrSize
				if nOff+btrfsKeyPtrSize <= nodesize {
					nextObj = le64(btrfsTreeBuf[nOff:])
				}
			}
			if nextObj < parentDirInode {
				continue
			}
			childBytenr := le64(btrfsTreeBuf[off+17:])
			if btrfsWalkCount >= len(btrfsWalkBytenr) {
				break
			}
			btrfsWalkBytenr[btrfsWalkCount] = childBytenr
			btrfsWalkLevel[btrfsWalkCount] = actualLevel - 1
			btrfsWalkCount++
		}
	}
	return 0, false
}

// ----- scanForBtrfs + tryBtrfsCloudBoot -----

var (
	btrfsBIO         uintptr
	btrfsMediaId     uint32
	btrfsDevBlkSz    uint32
	btrfsLastSB      btrfsSB
	btrfsKernelInode uint64
	btrfsInitrdInode uint64

	btrfsSBBuf [4096]byte

	// initramfs-* (RHEL) and initrd.img-* (Debian) prefixes — also
	// covers openSUSE's "initrd-<ver>-default".
	btrfsInitrdPrefix1 = [...]byte{'i', 'n', 'i', 't', 'r', 'd', '-'}
	btrfsInitrdPrefix2 = [...]byte{'i', 'n', 'i', 't', 'r', 'd', '.'}
	btrfsInitrdPrefix3 = [...]byte{'i', 'n', 'i', 't', 'r', 'a', 'm', 'f', 's', '-'}
)

func scanForBtrfs(co *efiSimpleTextOutput, bs *efiBootServices) bool {
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
		if media.logicalPartition == 0 {
			continue
		}
		// btrfs SB lives at offset 64 KiB. Compute LBA and read 4 KiB.
		lba := uint64(65536) / uint64(media.blockSize)
		if uint64(65536)%uint64(media.blockSize) != 0 {
			continue
		}
		for k := 0; k < len(btrfsSBBuf); k++ {
			btrfsSBBuf[k] = 0
		}
		if readBlocks(bioHolder, media.mediaId, lba,
			uintptr(len(btrfsSBBuf)),
			uintptr(unsafe.Pointer(&btrfsSBBuf[0]))) != efiSuccess {
			continue
		}
		if le64(btrfsSBBuf[64:]) != btrfsSBMagic {
			continue
		}
		if !parseBtrfsSB(btrfsSBBuf[:], &btrfsLastSB) {
			continue
		}
		// Bootstrap chunk map from sys_chunk_array.
		btrfsChunkMapCount = 0
		if !parseSysChunkArray(btrfsSBBuf[:], btrfsLastSB.sysChunkArraySize) {
			continue
		}
		// Extend with the on-disk chunk tree.
		chunkRootPhys, ok := btrfsLogicalToPhys(btrfsLastSB.chunkRootLogical)
		if !ok {
			continue
		}
		if !walkChunkTreeLeaf(bioHolder, media.mediaId, media.blockSize,
			chunkRootPhys, btrfsLastSB.nodesize) {
			continue
		}
		// Try default subvol first, else FS_TREE objectid=5.
		var subvolID uint64
		subvolID, _ = walkRootTreeForDefaultSubvol(bioHolder, media.mediaId, media.blockSize,
			btrfsLastSB.rootLogical, btrfsLastSB.nodesize)
		var fsBytenr uint64
		var fsLevel uint8
		if subvolID != 0 {
			if !walkRootTreeForSubvolRoot(bioHolder, media.mediaId, media.blockSize,
				btrfsLastSB.rootLogical, btrfsLastSB.nodesize,
				subvolID, &fsBytenr, &fsLevel) {
				subvolID = 0
			}
		}
		if subvolID == 0 {
			if !walkRootTreeForFSTree(bioHolder, media.mediaId, media.blockSize,
				btrfsLastSB.rootLogical, btrfsLastSB.nodesize,
				&fsBytenr, &fsLevel) {
				continue
			}
		}
		// Look for /boot/vmlinuz-* or /boot/Image-* or root-level
		// kernel under this subvol first.
		bootIno, hasBoot := findInBtrfsDirPrefix(bioHolder, media.mediaId, media.blockSize,
			fsBytenr, fsLevel, btrfsLastSB.nodesize,
			btrfsFirstFreeObjectID, btrfsBootName[:],
			&kernelName, &kernelNameLen)
		btrfsKernelSubvolRootID = subvolID
		btrfsKernelBytenr = fsBytenr
		btrfsKernelLevel = fsLevel
		found := false
		if hasBoot && bootIno != 0 {
			kIno, ok := findInBtrfsDirPrefix(bioHolder, media.mediaId, media.blockSize,
				fsBytenr, fsLevel, btrfsLastSB.nodesize,
				bootIno, vmlinuzPrefix[:], &kernelName, &kernelNameLen)
			if ok {
				btrfsKernelInode = kIno
				btrfsKernelDirInode = bootIno
				found = true
			} else {
				kIno, ok = findInBtrfsDirPrefix(bioHolder, media.mediaId, media.blockSize,
					fsBytenr, fsLevel, btrfsLastSB.nodesize,
					bootIno, btrfsImagePrefix[:], &kernelName, &kernelNameLen)
				if ok {
					btrfsKernelInode = kIno
					btrfsKernelDirInode = bootIno
					found = true
				}
			}
		}
		if !found {
			// Try at subvol root.
			kIno, ok := findInBtrfsDirPrefix(bioHolder, media.mediaId, media.blockSize,
				fsBytenr, fsLevel, btrfsLastSB.nodesize,
				btrfsFirstFreeObjectID, vmlinuzPrefix[:],
				&kernelName, &kernelNameLen)
			if ok {
				btrfsKernelInode = kIno
				btrfsKernelDirInode = btrfsFirstFreeObjectID
				found = true
			} else {
				kIno, ok = findInBtrfsDirPrefix(bioHolder, media.mediaId, media.blockSize,
					fsBytenr, fsLevel, btrfsLastSB.nodesize,
					btrfsFirstFreeObjectID, btrfsImagePrefix[:],
					&kernelName, &kernelNameLen)
				if ok {
					btrfsKernelInode = kIno
					btrfsKernelDirInode = btrfsFirstFreeObjectID
					found = true
				}
			}
		}
		if !found {
			// Last resort: brute-force scan every user subvolume.
			if !scanSubvolumesForKernel(bioHolder, media.mediaId, media.blockSize,
				btrfsLastSB.rootLogical, btrfsLastSB.nodesize,
				&kernelName, &kernelNameLen) {
				continue
			}
			// scanSubvolumesForKernel populated btrfsKernel* but not
			// the inode itself — re-look-up the kernel inode in the
			// selected subvol's dir.
			kIno, ok := findInBtrfsDirPrefix(bioHolder, media.mediaId, media.blockSize,
				btrfsKernelBytenr, btrfsKernelLevel, btrfsLastSB.nodesize,
				btrfsKernelDirInode, vmlinuzPrefix[:],
				&kernelName, &kernelNameLen)
			if !ok {
				kIno, ok = findInBtrfsDirPrefix(bioHolder, media.mediaId, media.blockSize,
					btrfsKernelBytenr, btrfsKernelLevel, btrfsLastSB.nodesize,
					btrfsKernelDirInode, btrfsImagePrefix[:],
					&kernelName, &kernelNameLen)
			}
			if !ok {
				continue
			}
			btrfsKernelInode = kIno
			found = true
		}
		if !found {
			continue
		}
		btrfsBIO = bioHolder
		btrfsMediaId = media.mediaId
		btrfsDevBlkSz = media.blockSize
		_ = co
		return true
	}
	return false
}

// tryBtrfsCloudBoot is the production-loader btrfs path. Locates the
// kernel + initrd in an unmodified cloud-image btrfs rootfs, reads
// both into AllocatePool buffers, installs LOAD_FILE2 for the initrd,
// LoadImages the kernel. _start's existing patchChildCmdline +
// StartImage flow takes over via the populated `childImageHandle`.
func tryBtrfsCloudBoot(co *efiSimpleTextOutput, bs *efiBootServices, imageHandle uintptr) bool {
	writeASCII(co, "trying cloud-disk fallback (btrfs)\r\n")
	if !scanForBtrfs(co, bs) {
		writeASCII(co, "  no btrfs cloud-image found\r\n")
		return false
	}
	writeASCII(co, "  btrfs subvol=")
	writeDec(co, btrfsKernelSubvolRootID)
	writeASCII(co, " kernel: ")
	for i := 0; i < kernelNameLen; i++ {
		oneCharBuf[0] = kernelName[i]
		writeASCII(co, oneCharStr)
	}
	writeASCII(co, "\r\n")

	// Read kernel: size + mode from INODE_ITEM. If the inode turns
	// out to be a symlink (openSUSE ships /boot/Image-* as a relative
	// symlink to /usr/lib/modules/<ver>/<file>), follow it before
	// allocating the kernel buffer.
	kSize, kMode, ok := btrfsLookupInode(btrfsBIO, btrfsMediaId, btrfsDevBlkSz,
		btrfsKernelBytenr, btrfsKernelLevel, btrfsLastSB.nodesize,
		btrfsKernelInode)
	if !ok || kSize == 0 {
		writeASCII(co, "  INODE_ITEM lookup failed\r\n")
		return false
	}
	if (kMode & 0xF000) == 0xA000 {
		// S_IFLNK — resolve target path under the active subvol.
		newIno, ok := btrfsResolveSymlink(btrfsBIO, btrfsMediaId, btrfsDevBlkSz,
			btrfsLastSB.nodesize, btrfsKernelBytenr, btrfsKernelLevel,
			btrfsKernelInode, btrfsKernelDirInode, kSize)
		if !ok {
			writeASCII(co, "  symlink resolution failed\r\n")
			return false
		}
		writeASCII(co, "  kernel is a symlink → inode ")
		writeDec(co, newIno)
		writeASCII(co, "\r\n")
		btrfsKernelInode = newIno
		kSize, kMode, ok = btrfsLookupInode(btrfsBIO, btrfsMediaId, btrfsDevBlkSz,
			btrfsKernelBytenr, btrfsKernelLevel, btrfsLastSB.nodesize,
			btrfsKernelInode)
		if !ok || kSize == 0 {
			writeASCII(co, "  resolved INODE_ITEM lookup failed\r\n")
			return false
		}
		_ = kMode
	}
	kernelBufPtr = 0
	if efiCall3(bs.allocatePool, efiLoaderData, uintptr(kSize),
		uintptr(unsafe.Pointer(&kernelBufPtr))) != efiSuccess || kernelBufPtr == 0 {
		writeASCII(co, "  AllocatePool(kernel) failed\r\n")
		return false
	}
	if !btrfsCollectExtents(btrfsBIO, btrfsMediaId, btrfsDevBlkSz,
		btrfsKernelBytenr, btrfsKernelLevel, btrfsLastSB.nodesize,
		btrfsKernelInode) {
		writeASCII(co, "  extent collection failed (compression?)\r\n")
		return false
	}
	if !btrfsReadExtents(btrfsBIO, btrfsMediaId, btrfsDevBlkSz, kernelBufPtr, kSize) {
		writeASCII(co, "  extent read failed\r\n")
		return false
	}
	loadedKernelSize = kSize

	// Inflate if gzip-wrapped (some arm64 distros do this).
	if isGzipped(kernelBufPtr) {
		if !maybeInflateKernel(co, bs, kSize) {
			return false
		}
	}

	// Find initrd alongside the kernel (same dir).
	iIno, iOK := findInBtrfsDirPrefix(btrfsBIO, btrfsMediaId, btrfsDevBlkSz,
		btrfsKernelBytenr, btrfsKernelLevel, btrfsLastSB.nodesize,
		btrfsKernelDirInode, btrfsInitrdPrefix1[:],
		&initrdName, &initrdNameLen)
	if !iOK {
		iIno, iOK = findInBtrfsDirPrefix(btrfsBIO, btrfsMediaId, btrfsDevBlkSz,
			btrfsKernelBytenr, btrfsKernelLevel, btrfsLastSB.nodesize,
			btrfsKernelDirInode, btrfsInitrdPrefix2[:],
			&initrdName, &initrdNameLen)
	}
	if !iOK {
		iIno, iOK = findInBtrfsDirPrefix(btrfsBIO, btrfsMediaId, btrfsDevBlkSz,
			btrfsKernelBytenr, btrfsKernelLevel, btrfsLastSB.nodesize,
			btrfsKernelDirInode, btrfsInitrdPrefix3[:],
			&initrdName, &initrdNameLen)
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
		btrfsInitrdInode = iIno
		iSize, iMode, iok := btrfsLookupInode(btrfsBIO, btrfsMediaId, btrfsDevBlkSz,
			btrfsKernelBytenr, btrfsKernelLevel, btrfsLastSB.nodesize,
			btrfsInitrdInode)
		if iok && (iMode&0xF000) == 0xA000 {
			newIno, sok := btrfsResolveSymlink(btrfsBIO, btrfsMediaId, btrfsDevBlkSz,
				btrfsLastSB.nodesize, btrfsKernelBytenr, btrfsKernelLevel,
				btrfsInitrdInode, btrfsKernelDirInode, iSize)
			if sok {
				btrfsInitrdInode = newIno
				iSize, iMode, iok = btrfsLookupInode(btrfsBIO, btrfsMediaId, btrfsDevBlkSz,
					btrfsKernelBytenr, btrfsKernelLevel, btrfsLastSB.nodesize,
					btrfsInitrdInode)
			} else {
				iok = false
			}
		}
		_ = iMode
		if iok && iSize > 0 {
			initrdSize = iSize
			initrdDataPtr = 0
			if efiCall3(bs.allocatePool, efiLoaderData, uintptr(iSize),
				uintptr(unsafe.Pointer(&initrdDataPtr))) != efiSuccess || initrdDataPtr == 0 {
				writeASCII(co, "  AllocatePool(initrd) failed\r\n")
				return false
			}
			if !btrfsCollectExtents(btrfsBIO, btrfsMediaId, btrfsDevBlkSz,
				btrfsKernelBytenr, btrfsKernelLevel, btrfsLastSB.nodesize,
				btrfsInitrdInode) {
				writeASCII(co, "  initrd extent collection failed\r\n")
				return false
			}
			if !btrfsReadExtents(btrfsBIO, btrfsMediaId, btrfsDevBlkSz, initrdDataPtr, iSize) {
				writeASCII(co, "  initrd extent read failed\r\n")
				return false
			}
			if !installInitrdProtocol(co, bs) {
				return false
			}
			writeASCII(co, "  initrd protocols installed\r\n")
		}
	}

	childImageHandle = 0
	if efiCall6(bs.loadImage,
		0,
		imageHandle,
		0,
		kernelBufPtr,
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
