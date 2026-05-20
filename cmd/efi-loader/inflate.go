// Phase 5e — minimal gzip / DEFLATE decoder for compressed kernels.
//
// Ubuntu's /boot/vmlinuz-*-generic on arm64 ships as a gzip-wrapped
// raw Image, not as the EFI-stub PE32+ binary the other distros use.
// Without an in-loader inflate, those kernels can't be chain-loaded
// (the "MZ" / "PE\0\0" sanity check in validatePEKernel deliberately
// rejects them so the loader doesn't crash inside LoadImage).
//
// This implementation is purpose-built for the cloud-boot loader's
// no-heap-under-UEFI environment:
//
//   - All buffers are package-scope.
//   - No closures.
//   - Output is written into a caller-supplied AllocatePool buffer.
//   - The sliding window is folded into the output buffer (we never
//     emit byte i without it being in the dictionary already, so
//     out[i-distance] is the correct back-reference target).
//
// References:
//   RFC 1951 (DEFLATE), RFC 1952 (gzip wrapper).

package main

import "unsafe"

// ----- gzip wrapper -----
//
// Gzip layout (RFC 1952):
//   0       ID1 = 0x1F
//   1       ID2 = 0x8B
//   2       CM  = 0x08 (DEFLATE)
//   3       FLG (bitmask: FTEXT, FHCRC, FEXTRA, FNAME, FCOMMENT)
//   4..8    MTIME (u32 LE)
//   8       XFL
//   9       OS
//   then optional:
//     if FEXTRA: XLEN (u16 LE), then XLEN bytes of extra data
//     if FNAME : NUL-terminated original filename
//     if FCOMMENT: NUL-terminated comment
//     if FHCRC : CRC16 over the header
//   then the DEFLATE stream
//   then ISIZE (mod-2^32 of the uncompressed length) + CRC32

const (
	gzipID1 byte = 0x1F
	gzipID2 byte = 0x8B
	gzipCM  byte = 0x08

	gzipFlagText    byte = 0x01
	gzipFlagHCRC    byte = 0x02
	gzipFlagExtra   byte = 0x04
	gzipFlagName    byte = 0x08
	gzipFlagComment byte = 0x10
)

// gzipBodyOffset locates the start of the DEFLATE bitstream inside a
// gzip member. Returns -1 if the header is malformed.
func gzipBodyOffset(in uintptr, inLen uint64) int64 {
	if inLen < 10 {
		return -1
	}
	if rdb(in, 0) != gzipID1 || rdb(in, 1) != gzipID2 || rdb(in, 2) != gzipCM {
		return -1
	}
	flg := rdb(in, 3)
	off := uint64(10) // fixed header

	if flg&gzipFlagExtra != 0 {
		if off+2 > inLen {
			return -1
		}
		xlen := uint64(rdb(in, off)) | uint64(rdb(in, off+1))<<8
		off += 2 + xlen
		if off > inLen {
			return -1
		}
	}
	if flg&gzipFlagName != 0 {
		for off < inLen && rdb(in, off) != 0 {
			off++
		}
		if off >= inLen {
			return -1
		}
		off++ // skip the NUL
	}
	if flg&gzipFlagComment != 0 {
		for off < inLen && rdb(in, off) != 0 {
			off++
		}
		if off >= inLen {
			return -1
		}
		off++
	}
	if flg&gzipFlagHCRC != 0 {
		off += 2
		if off > inLen {
			return -1
		}
	}
	return int64(off)
}

// rdb reads one byte from base+off.
func rdb(base uintptr, off uint64) byte {
	return *(*byte)(unsafe.Pointer(base + uintptr(off)))
}

// wrb writes one byte to base+off.
func wrb(base uintptr, off uint64, v byte) {
	*(*byte)(unsafe.Pointer(base + uintptr(off))) = v
}

// ----- bit-stream reader -----
//
// DEFLATE reads bits LSB-first within each byte. The bitReader is a
// package-scope state (so no stack-locals escape into heap allocs).

var (
	brBase   uintptr
	brLen    uint64
	brBytePos uint64
	brBuf    uint32 // accumulator
	brNbits  uint32 // valid bits in brBuf
)

func brInit(base uintptr, length uint64, startByte uint64) {
	brBase = base
	brLen = length
	brBytePos = startByte
	brBuf = 0
	brNbits = 0
}

// brBits returns the next n bits (n ≤ 24), or 0xFFFFFFFF if the
// stream is exhausted. We never request more than 15 bits in the
// Huffman decoder + 13 in the length/distance extras, so a 24-bit
// cap is conservative.
func brBits(n uint32) uint32 {
	for brNbits < n {
		if brBytePos >= brLen {
			return 0xFFFFFFFF
		}
		brBuf |= uint32(rdb(brBase, brBytePos)) << brNbits
		brBytePos++
		brNbits += 8
	}
	v := brBuf & ((uint32(1) << n) - 1)
	brBuf >>= n
	brNbits -= n
	return v
}

// brByteAlign discards remaining bits in the current byte. Required
// before reading a stored (BTYPE=00) block's LEN/NLEN.
func brByteAlign() {
	brBuf = 0
	brNbits = 0
}

// brReadByte returns the next whole byte (after byte-align).
func brReadByte() uint32 {
	if brBytePos >= brLen {
		return 0xFFFFFFFF
	}
	b := uint32(rdb(brBase, brBytePos))
	brBytePos++
	return b
}

// ----- DEFLATE tables -----
//
// Code lengths for the 19-symbol "code-length" alphabet, in the
// permuted order DEFLATE uses.
var clOrder = [19]byte{
	16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
}

// Length codes 257..285. lenBase[i] = base length for code 257+i.
// lenExtra[i] = number of extra bits.
var lenBase = [29]uint32{
	3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43,
	51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258,
}
var lenExtra = [29]byte{
	0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4,
	4, 4, 5, 5, 5, 5, 0,
}

// Distance codes 0..29.
var distBase = [30]uint32{
	1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257,
	385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289,
	16385, 24577,
}
var distExtra = [30]byte{
	0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9,
	10, 10, 11, 11, 12, 12, 13, 13,
}

// ----- Huffman decoder -----
//
// We use a simple symbol-table approach (no fancy fast lookup table)
// to keep the code small. Per RFC 1951 §3.2.2, codes are built by:
//
//   1. bl_count[N] = number of codes with length N.
//   2. next_code[N] = next available code value for length N.
//   3. assign codes to symbols in symbol-index order using the
//      smallest unused code at each length.
//
// hSymbols[] / hCounts[] / hOffsets[] together form a canonical
// table; decoding walks lengths 1..maxLen, accumulating bits MSB-
// first, and looks up the symbol when (code - first_at_len) < count.

const huffMaxLen = 15 // DEFLATE allows up to 15-bit codes

type huffTable struct {
	counts [huffMaxLen + 1]uint16
	// symbols listed in canonical order: all length-1 symbols first,
	// then length-2, …, then length-15.
	symbols [288]uint16
}

// hLit is the literal/length tree (max 288 symbols).
// hDist is the distance tree (max 30 symbols).
// hCL is the code-length tree (max 19 symbols), used to decode the
//      dynamic-tree spec at the start of a BTYPE=10 block.
var hLit, hDist, hCL huffTable

// huffBuildOffsets is shared scratch for buildHuffman — taking the
// address of a stack-local array under TinyGo trips escape-to-heap.
var huffBuildOffsets [huffMaxLen + 2]uint16

// buildHuffman fills `out` from `lengths[0..n]`. Returns true on
// success. Symbols with length 0 are skipped.
func buildHuffman(out *huffTable, lengths []byte, n int) bool {
	// Zero the table.
	for i := range out.counts {
		out.counts[i] = 0
	}
	for i := 0; i < n; i++ {
		l := lengths[i]
		if l > huffMaxLen {
			return false
		}
		out.counts[l]++
	}
	out.counts[0] = 0 // length-0 codes don't participate

	// Compute offsets per length to place symbols in canonical
	// order.
	for i := range huffBuildOffsets {
		huffBuildOffsets[i] = 0
	}
	for i := uint16(1); i <= huffMaxLen; i++ {
		huffBuildOffsets[i+1] = huffBuildOffsets[i] + out.counts[i]
	}
	for i := 0; i < n; i++ {
		l := lengths[i]
		if l == 0 {
			continue
		}
		out.symbols[huffBuildOffsets[l]] = uint16(i)
		huffBuildOffsets[l]++
	}
	return true
}

// huffDecode pulls one symbol from the bit stream using `t`.
// Returns 0xFFFFFFFF on stream exhaustion or invalid code.
func huffDecode(t *huffTable) uint32 {
	code := uint32(0)
	first := uint32(0)
	offset := uint32(0)
	for l := uint32(1); l <= huffMaxLen; l++ {
		bit := brBits(1)
		if bit == 0xFFFFFFFF {
			return 0xFFFFFFFF
		}
		code = (code << 1) | bit
		count := uint32(t.counts[l])
		if code-first < count {
			return uint32(t.symbols[offset+(code-first)])
		}
		offset += count
		first = (first + count) << 1
	}
	return 0xFFFFFFFF
}

// ----- DEFLATE decoder -----
//
// inflate reads a DEFLATE bit-stream from `in[startBit..inLen]`
// (startBit is a byte offset; bit-level state is in brBuf/brNbits)
// and writes uncompressed output into `out[0..outCap]`. Returns the
// number of bytes written, or 0 on error.

func inflate(in uintptr, inLen uint64, startOff uint64,
	out uintptr, outCap uint64,
) uint64 {
	brInit(in, inLen, startOff)
	var outPos uint64

	for {
		bfinal := brBits(1)
		btype := brBits(2)
		if bfinal == 0xFFFFFFFF || btype == 0xFFFFFFFF {
			return 0
		}
		switch btype {
		case 0: // stored
			brByteAlign()
			lenLo := brReadByte()
			lenHi := brReadByte()
			nlenLo := brReadByte()
			nlenHi := brReadByte()
			if lenLo == 0xFFFFFFFF || lenHi == 0xFFFFFFFF ||
				nlenLo == 0xFFFFFFFF || nlenHi == 0xFFFFFFFF {
				return 0
			}
			blen := lenLo | (lenHi << 8)
			nlen := nlenLo | (nlenHi << 8)
			if blen^0xFFFF != nlen {
				return 0
			}
			for i := uint32(0); i < blen; i++ {
				b := brReadByte()
				if b == 0xFFFFFFFF || outPos >= outCap {
					return 0
				}
				wrb(out, outPos, byte(b))
				outPos++
			}
		case 1: // fixed Huffman
			buildFixedHuffman()
			if !inflateBlock(out, &outPos, outCap) {
				return 0
			}
		case 2: // dynamic Huffman
			if !readDynamicTrees() {
				return 0
			}
			if !inflateBlock(out, &outPos, outCap) {
				return 0
			}
		default:
			return 0
		}
		if bfinal != 0 {
			break
		}
	}
	return outPos
}

// inflateBlock decodes literal+length codes using hLit and back-
// reference distances using hDist until it hits symbol 256
// (end-of-block).
func inflateBlock(out uintptr, outPos *uint64, outCap uint64) bool {
	for {
		sym := huffDecode(&hLit)
		if sym == 0xFFFFFFFF {
			return false
		}
		if sym < 256 {
			if *outPos >= outCap {
				return false
			}
			wrb(out, *outPos, byte(sym))
			*outPos++
			continue
		}
		if sym == 256 {
			return true
		}
		// Length code 257..285 → (base, extra-bits).
		lcode := sym - 257
		if lcode >= 29 {
			return false
		}
		length := lenBase[lcode]
		if lenExtra[lcode] > 0 {
			extra := brBits(uint32(lenExtra[lcode]))
			if extra == 0xFFFFFFFF {
				return false
			}
			length += extra
		}
		dsym := huffDecode(&hDist)
		if dsym == 0xFFFFFFFF || dsym >= 30 {
			return false
		}
		distance := distBase[dsym]
		if distExtra[dsym] > 0 {
			extra := brBits(uint32(distExtra[dsym]))
			if extra == 0xFFFFFFFF {
				return false
			}
			distance += extra
		}
		if uint64(distance) > *outPos {
			return false
		}
		src := *outPos - uint64(distance)
		for i := uint32(0); i < length; i++ {
			if *outPos >= outCap {
				return false
			}
			wrb(out, *outPos, rdb(out, src+uint64(i)))
			*outPos++
		}
	}
}

// fixedHuffLengthsBuilt avoids re-building the fixed table on every
// BTYPE=01 block. Length arrays are package-scope per the no-heap
// convention — TinyGo could otherwise promote `var [288]byte` on the
// stack to a heap allocation when the slice escapes into buildHuffman.
var (
	fixedHuffLengthsBuilt bool
	fixedLitLengths       [288]byte
	fixedDistLengths      [30]byte
)

func buildFixedHuffman() {
	if fixedHuffLengthsBuilt {
		return
	}
	for i := 0; i < 144; i++ {
		fixedLitLengths[i] = 8
	}
	for i := 144; i < 256; i++ {
		fixedLitLengths[i] = 9
	}
	for i := 256; i < 280; i++ {
		fixedLitLengths[i] = 7
	}
	for i := 280; i < 288; i++ {
		fixedLitLengths[i] = 8
	}
	buildHuffman(&hLit, fixedLitLengths[:], 288)
	for i := range fixedDistLengths {
		fixedDistLengths[i] = 5
	}
	buildHuffman(&hDist, fixedDistLengths[:], 30)
	fixedHuffLengthsBuilt = true
}

// dynLitLens / dynDistLens are the scratch buffers for the
// (HLIT + HDIST) code-length array decoded by the code-length tree
// at the start of a BTYPE=10 block.
var (
	dynLitLens  [320]byte
	dynDistLens [32]byte
	clLengths   [19]byte
)

func readDynamicTrees() bool {
	hlit := brBits(5)
	hdist := brBits(5)
	hclen := brBits(4)
	if hlit == 0xFFFFFFFF || hdist == 0xFFFFFFFF || hclen == 0xFFFFFFFF {
		return false
	}
	hlit += 257
	hdist += 1
	hclen += 4
	for i := range clLengths {
		clLengths[i] = 0
	}
	for i := uint32(0); i < hclen; i++ {
		v := brBits(3)
		if v == 0xFFFFFFFF {
			return false
		}
		clLengths[clOrder[i]] = byte(v)
	}
	if !buildHuffman(&hCL, clLengths[:], 19) {
		return false
	}

	// Decode hlit + hdist code lengths in a single pass; 16/17/18
	// are repeat codes.
	total := hlit + hdist
	if total > uint32(len(dynLitLens)) {
		return false
	}
	var i uint32
	for i < total {
		sym := huffDecode(&hCL)
		if sym == 0xFFFFFFFF {
			return false
		}
		if sym < 16 {
			dynLitLens[i] = byte(sym)
			i++
			continue
		}
		var repeat uint32
		var fill byte
		switch sym {
		case 16:
			if i == 0 {
				return false
			}
			rep := brBits(2)
			if rep == 0xFFFFFFFF {
				return false
			}
			repeat = rep + 3
			fill = dynLitLens[i-1]
		case 17:
			rep := brBits(3)
			if rep == 0xFFFFFFFF {
				return false
			}
			repeat = rep + 3
			fill = 0
		case 18:
			rep := brBits(7)
			if rep == 0xFFFFFFFF {
				return false
			}
			repeat = rep + 11
			fill = 0
		default:
			return false
		}
		if i+repeat > total {
			return false
		}
		for j := uint32(0); j < repeat; j++ {
			dynLitLens[i+j] = fill
		}
		i += repeat
	}

	// Split into literal/length and distance arrays.
	for j := uint32(0); j < hdist; j++ {
		dynDistLens[j] = dynLitLens[hlit+j]
	}
	if !buildHuffman(&hLit, dynLitLens[:], int(hlit)) {
		return false
	}
	if !buildHuffman(&hDist, dynDistLens[:], int(hdist)) {
		return false
	}
	return true
}

// ----- top-level gzip decompressor -----
//
// gzipDecompress detects a gzip stream at `in[0..]`, parses its
// header, runs inflate, and returns the decompressed byte count
// written into `out`. Returns 0 if the input isn't gzip or
// decompression failed.
func gzipDecompress(in uintptr, inLen uint64, out uintptr, outCap uint64) uint64 {
	bodyOff := gzipBodyOffset(in, inLen)
	if bodyOff < 0 {
		return 0
	}
	return inflate(in, inLen, uint64(bodyOff), out, outCap)
}

// isGzipped is a cheap magic check on the first two bytes.
func isGzipped(buf uintptr) bool {
	return rdb(buf, 0) == gzipID1 && rdb(buf, 1) == gzipID2
}

// inflatedKernelBuf is the AllocatePool'd destination for the
// decompressed kernel. Package-scope so it survives across the
// inflate → LoadImage handoff without re-allocating on retries.
var inflatedKernelBuf uintptr

// maybeInflateKernel reads the gzip ISIZE trailer (last 4 bytes of
// the compressed stream → uncompressed length mod 2^32), allocates a
// fresh EFI pool buffer of that size, inflates into it, and swaps
// kernelBufPtr / loadedKernelSize so the rest of the chain (LoadImage
// + cmdline patch + StartImage) sees the decompressed image.
//
// Returns false on any failure (gzip parse, AllocatePool, inflate
// short, output != ISIZE). The original compressed buffer is left
// allocated — FreePool would shake state we don't track.
func maybeInflateKernel(co *efiSimpleTextOutput, bs *efiBootServices, compressedSize uint64) bool {
	if compressedSize < 8 {
		writeASCII(co, "  gzip: input too short\r\n")
		return false
	}
	// ISIZE = LE u32 at the last 4 bytes of the member. The Linux
	// arm64 Image typically inflates to ~3-4× the gzip size, so
	// add headroom and round up.
	iLo := uint32(rdb(kernelBufPtr, compressedSize-4))
	iLo |= uint32(rdb(kernelBufPtr, compressedSize-3)) << 8
	iLo |= uint32(rdb(kernelBufPtr, compressedSize-2)) << 16
	iLo |= uint32(rdb(kernelBufPtr, compressedSize-1)) << 24
	inflatedSize := uint64(iLo)
	// Sanity: ISIZE is mod-2^32, so for files > 4 GiB it wraps. The
	// Linux kernel image is well under 4 GiB so the value is exact.
	// Defend against pathological inputs by capping at 256 MiB.
	if inflatedSize == 0 || inflatedSize > 256*1024*1024 {
		writeASCII(co, "  gzip: ISIZE rejected (")
		writeDec(co, inflatedSize)
		writeASCII(co, ")\r\n")
		return false
	}
	writeASCII(co, "  gzip: compressed=")
	writeDec(co, compressedSize)
	writeASCII(co, " inflated=")
	writeDec(co, inflatedSize)
	writeASCII(co, "\r\n")

	inflatedKernelBuf = 0
	if efiCall3(bs.allocatePool,
		efiLoaderData,
		uintptr(inflatedSize),
		uintptr(unsafe.Pointer(&inflatedKernelBuf))) != efiSuccess ||
		inflatedKernelBuf == 0 {
		writeASCII(co, "  AllocatePool(inflated) failed\r\n")
		return false
	}

	got := gzipDecompress(kernelBufPtr, compressedSize,
		inflatedKernelBuf, inflatedSize)
	if got == 0 {
		writeASCII(co, "  gzipDecompress failed\r\n")
		return false
	}
	if got != inflatedSize {
		writeASCII(co, "  inflate short: got ")
		writeDec(co, got)
		writeASCII(co, " expected ")
		writeDec(co, inflatedSize)
		writeASCII(co, "\r\n")
		return false
	}
	// Sanity: decompressed kernel should now be PE/COFF.
	if rdb(inflatedKernelBuf, 0) != 'M' || rdb(inflatedKernelBuf, 1) != 'Z' {
		writeASCII(co, "  inflate produced non-MZ bytes\r\n")
		return false
	}
	writeASCII(co, "  inflate OK, swapping kernelBufPtr\r\n")
	kernelBufPtr = inflatedKernelBuf
	loadedKernelSize = got
	return true
}
