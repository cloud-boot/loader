// Phase 5d — xfs disk-mode boot path.
//
// Sister to ext4.go: when the ext4 walker doesn't find a Linux rootfs
// (no /boot/vmlinuz-* on any ext4 partition), the loader falls
// through here and tries every xfs partition for a vmlinuz-* at its
// *root* — that's the RHEL/AlmaLinux/Rocky layout, where /boot is a
// separate xfs partition.
//
// All on-disk integers in xfs are BIG-endian (the opposite of ext4),
// so the be16/be32/be64 helpers live next to the parsers. The
// directory walkers are closure-free (TinyGo's gc:leaking would
// promote captured variables to heap → VirtualAlloc → trap).

package main

import "unsafe"

// ----- big-endian helpers -----

func be16(b []byte) uint16 { return uint16(b[1]) | uint16(b[0])<<8 }

func be32(b []byte) uint32 {
	return uint32(b[3]) | uint32(b[2])<<8 | uint32(b[1])<<16 | uint32(b[0])<<24
}

func be64(b []byte) uint64 {
	return uint64(b[7]) | uint64(b[6])<<8 | uint64(b[5])<<16 | uint64(b[4])<<24 |
		uint64(b[3])<<32 | uint64(b[2])<<40 | uint64(b[1])<<48 | uint64(b[0])<<56
}

// ----- xfs superblock -----
//
// Format reference: xfs/libxfs/xfs_format.h in the kernel. We pull
// only the fields needed to locate an inode and walk extents.

const xfsMagic uint32 = 0x58465342 // "XFSB"

type xfsSB struct {
	magic       uint32
	blockSize   uint32
	rootIno     uint64
	agblocks    uint32
	agcount     uint32
	versionnum  uint16
	inodesize   uint16
	inopblock   uint16
	blocklog    uint8
	inodelog    uint8
	inopblog    uint8
	agblklog    uint8
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
	sb.rootIno = be64(data[0x38:])
	sb.agblocks = be32(data[0x54:])
	sb.agcount = be32(data[0x58:])
	sb.versionnum = be16(data[0x64:])
	sb.inodesize = be16(data[0x68:])
	sb.inopblock = be16(data[0x6A:])
	sb.blocklog = data[0x78]
	sb.inodelog = data[0x7A]
	sb.inopblog = data[0x7B]
	sb.agblklog = data[0x7C]
	return true
}

// ----- xfs inode -----
//
// Core is 96 bytes (v4) or 176 bytes (v5, with CRC + changecount +
// lsn + flags2 + crtime + di_ino + uuid). Data fork follows.

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

func xfsDataForkOffset(version uint8) uint32 {
	if version >= 3 {
		return xfsCoreV5
	}
	return xfsCoreV4
}

// xfsInodeBuf is the working area for the most-recently-read xfs
// inode. 512 bytes covers both the legacy 256-B and the v5 512-B
// inode sizes.
var xfsInodeBuf [512]byte

// readXfsInode reads inode `inoNum` from the partition into
// xfsInodeBuf using the xfs number-to-position formula:
//
//	aginoLog = inopblog + agblklog
//	agno     = ino >> aginoLog
//	agino    = ino & ((1<<aginoLog)-1)
//	agbno    = agino >> inopblog
//	offset   = agino & ((1<<inopblog)-1)
//	byteOff  = agno*agblocks*blockSize + agbno*blockSize + offset*inodeSize
func readXfsInode(bio uintptr, mediaId, devBlkSz uint32, sb *xfsSB, inoNum uint64) bool {
	if sb.inopblock == 0 || sb.blockSize == 0 {
		return false
	}
	aginoLog := uint64(sb.inopblog) + uint64(sb.agblklog)
	agno := inoNum >> aginoLog
	agino := inoNum & ((1 << aginoLog) - 1)
	agbno := agino >> uint64(sb.inopblog)
	off := agino & ((1 << uint64(sb.inopblog)) - 1)
	if uint64(agno) >= uint64(sb.agcount) {
		return false
	}
	byteOff := agno*uint64(sb.agblocks)*uint64(sb.blockSize) +
		agbno*uint64(sb.blockSize) +
		off*uint64(sb.inodesize)
	lba := byteOff / uint64(devBlkSz)
	inSec := byteOff % uint64(devBlkSz)
	if inSec+uint64(sb.inodesize) > uint64(sb.blockSize) {
		return false
	}
	for k := 0; k < len(probeBuf); k++ {
		probeBuf[k] = 0
	}
	if readBlocks(bio, mediaId, lba, uintptr(sb.blockSize),
		uintptr(unsafe.Pointer(&probeBuf[0]))) != efiSuccess {
		return false
	}
	for k := uint32(0); k < uint32(sb.inodesize); k++ {
		xfsInodeBuf[k] = probeBuf[uint32(inSec)+k]
	}
	return true
}

// ----- xfs extent record decoding (128-bit BE bit-packed) -----
//
//	bit 0         flag (unwritten)
//	bits 1..54    startoff
//	bits 55..106  startblock (FSB)
//	bits 107..127 blockcount

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
	e.startoff = (w0 >> 9) & ((uint64(1) << 54) - 1)
	startblockHi := w0 & ((uint64(1) << 9) - 1)
	startblockLo := w1 >> 21
	e.startblock = (startblockHi << 43) | startblockLo
	e.count = uint32(w1 & ((uint64(1) << 21) - 1))
	return true
}

// fsbToByteOff converts an FSB (filesystem-block address: high bits
// = AG number, low bits = AG-relative block number) to a byte offset
// from the start of the partition.
func fsbToByteOff(fsb uint64, sb *xfsSB) uint64 {
	agno := fsb >> uint64(sb.agblklog)
	agbno := fsb & ((uint64(1) << uint64(sb.agblklog)) - 1)
	physBlk := agno*uint64(sb.agblocks) + agbno
	return physBlk * uint64(sb.blockSize)
}

// ----- xfs directory walkers (closure-free prefix search) -----
//
// Two formats in cloud-image use:
//   short-form (di_format=1): entries inline in the inode after the
//                              core. Tiny dirs only (<≈ 16 entries).
//   block-form (di_format=2, nextents=1): a single 4-KiB data block
//                              referenced by one extent.
//
// Each takes a `prefix` and returns the first matching child inode.
// outNameBuf+outNameLen receive the full name on success.

const (
	xfsDir3BlockMagic uint32 = 0x58444233 // "XDB3" — single-block dir, v5
	xfsDir2BlockMagic uint32 = 0x58443242 // "XD2B" — single-block dir, v4
	xfsDir3HdrSize           = 64
	xfsDir2HdrSize           = 16
)

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
	off := uint32(2 + inumLen) // skip hdr + parent
	for i := uint32(0); i < count; i++ {
		if uint32(len(sfData)) < off+3 {
			return 0, false
		}
		namelen := uint32(sfData[off])
		off++
		off += 2 // tag
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

// findInXfsDirPrefix dispatches on di_format → walks the right
// representation of dirIno's entries.
func findInXfsDirPrefix(bio uintptr, mediaId, devBlkSz uint32,
	sb *xfsSB, dirIno uint64, prefix []byte,
	outNameBuf *[255]byte, outNameLen *int,
) (uint64, bool) {
	if !readXfsInode(bio, mediaId, devBlkSz, sb, dirIno) {
		return 0, false
	}
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
	return 0, false
}

// ----- xfs file read via in-line extents -----
//
// Handles di_format=2 (extents stored inline in the inode's data
// fork). For files larger than ~21 extents the format flips to
// di_format=3 (btree) — out of scope here, but kernels + initrds on
// cloud images sit comfortably under that ceiling.

func readXfsFile(bio uintptr, mediaId, devBlkSz uint32,
	sb *xfsSB, inoNum uint64, outAddr uintptr, outCap uint64,
) uint64 {
	if !readXfsInode(bio, mediaId, devBlkSz, sb, inoNum) {
		return 0
	}
	var ino xfsInode
	if !parseXfsInode(xfsInodeBuf[:], &ino) {
		return 0
	}
	if ino.format != xfsFormatExtents {
		return 0
	}
	if ino.size > outCap {
		return 0
	}
	dfo := xfsDataForkOffset(ino.version)
	for i := uint32(0); i < ino.nextents; i++ {
		off := dfo + i*16
		if uint32(len(xfsInodeBuf)) < off+16 {
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
			return 0
		}
	}
	return ino.size
}

// ----- xfs orchestrator -----

// initramfsPrefix matches the RHEL/AlmaLinux/Rocky convention
// (initramfs-*.img). Debian's initrd.img-* is tried as a fallback.
var initramfsPrefix = [...]byte{'i', 'n', 'i', 't', 'r', 'a', 'm', 'f', 's', '-'}

// xfsCtx caches the BlockIO context of the first xfs partition that
// looks like a /boot — used by scanForXfs.
var (
	xfsBIO      uintptr
	xfsMediaId  uint32
	xfsDevBlkSz uint32
	xfsSBData   xfsSB
)

// scanForXfs walks every BlockIO handle, finds the first xfs
// partition that has a vmlinuz-* in its root (i.e. a /boot
// partition), and stashes its BlockIO context + SB into the
// `xfsCtx` package vars.
func scanForXfs(co *efiSimpleTextOutput, bs *efiBootServices) bool {
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
		// Read first 4 KiB for xfs magic.
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
		if len(probeBuf) < 0x80 || be32(probeBuf[0:]) != xfsMagic {
			continue
		}
		if !parseXfsSB(probeBuf[:], &xfsSBData) {
			continue
		}
		// Probe for vmlinuz-* at the root. If absent, this is
		// probably not a /boot partition — skip.
		_, ok := findInXfsDirPrefix(bioHolder, media.mediaId, media.blockSize,
			&xfsSBData, xfsSBData.rootIno, vmlinuzPrefix[:],
			&kernelName, &kernelNameLen)
		if !ok {
			continue
		}
		xfsBIO = bioHolder
		xfsMediaId = media.mediaId
		xfsDevBlkSz = media.blockSize
		_ = co
		return true
	}
	return false
}

// tryXfsCloudBoot is the production-loader xfs path: find a /boot
// xfs partition with vmlinuz-* in its root, read kernel + initramfs,
// install the LOAD_FILE2 protocol for the initrd, LoadImage the
// kernel. Mirrors tryCloudDiskBoot (ext4) so _start's existing
// patchChildCmdline + StartImage flow takes over via the populated
// `childImageHandle`.
func tryXfsCloudBoot(co *efiSimpleTextOutput, bs *efiBootServices, imageHandle uintptr) bool {
	writeASCII(co, "trying cloud-disk fallback (xfs)\r\n")
	if !scanForXfs(co, bs) {
		writeASCII(co, "  no xfs /boot partition found\r\n")
		return false
	}
	writeASCII(co, "  xfs /boot partition found\r\n")

	// scanForXfs already located vmlinuz-* and populated
	// kernelName/kernelNameLen plus xfsCtx. Re-resolve the inode
	// number for the kernel.
	kIno, kOK := findInXfsDirPrefix(xfsBIO, xfsMediaId, xfsDevBlkSz, &xfsSBData,
		xfsSBData.rootIno, vmlinuzPrefix[:], &kernelName, &kernelNameLen)
	if !kOK {
		return false
	}
	writeASCII(co, "  kernel: ")
	for i := 0; i < kernelNameLen; i++ {
		oneCharBuf[0] = kernelName[i]
		writeASCII(co, oneCharStr)
	}
	writeASCII(co, "\r\n")

	// Read kernel.
	if !readXfsInode(xfsBIO, xfsMediaId, xfsDevBlkSz, &xfsSBData, kIno) {
		return false
	}
	var ino xfsInode
	if !parseXfsInode(xfsInodeBuf[:], &ino) {
		return false
	}
	kernelBufPtr = 0
	if efiCall3(bs.allocatePool, efiLoaderData, uintptr(ino.size),
		uintptr(unsafe.Pointer(&kernelBufPtr))) != efiSuccess || kernelBufPtr == 0 {
		writeASCII(co, "  AllocatePool(kernel) failed\r\n")
		return false
	}
	got := readXfsFile(xfsBIO, xfsMediaId, xfsDevBlkSz, &xfsSBData, kIno,
		kernelBufPtr, ino.size)
	if got != ino.size {
		writeASCII(co, "  short kernel read\r\n")
		return false
	}
	loadedKernelSize = got

	// Find an initrd: try RHEL's initramfs-* first, fall back to
	// Debian's initrd.img-* convention.
	iIno, iOK := findInXfsDirPrefix(xfsBIO, xfsMediaId, xfsDevBlkSz, &xfsSBData,
		xfsSBData.rootIno, initramfsPrefix[:], &initrdName, &initrdNameLen)
	if !iOK {
		iIno, iOK = findInXfsDirPrefix(xfsBIO, xfsMediaId, xfsDevBlkSz, &xfsSBData,
			xfsSBData.rootIno, initrdPrefix[:], &initrdName, &initrdNameLen)
	}
	if !iOK {
		writeASCII(co, "  no initrd-* in root — continuing without\r\n")
	} else {
		writeASCII(co, "  initrd: ")
		for i := 0; i < initrdNameLen; i++ {
			oneCharBuf[0] = initrdName[i]
			writeASCII(co, oneCharStr)
		}
		writeASCII(co, "\r\n")
		if !readXfsInode(xfsBIO, xfsMediaId, xfsDevBlkSz, &xfsSBData, iIno) ||
			!parseXfsInode(xfsInodeBuf[:], &ino) {
			return false
		}
		initrdSize = ino.size
		initrdDataPtr = 0
		if efiCall3(bs.allocatePool, efiLoaderData, uintptr(initrdSize),
			uintptr(unsafe.Pointer(&initrdDataPtr))) != efiSuccess || initrdDataPtr == 0 {
			writeASCII(co, "  AllocatePool(initrd) failed\r\n")
			return false
		}
		igot := readXfsFile(xfsBIO, xfsMediaId, xfsDevBlkSz, &xfsSBData, iIno,
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
