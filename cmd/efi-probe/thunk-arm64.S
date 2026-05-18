// AAPCS64 thunks that adapt TinyGo's external-call register layout to
// the calling convention every EFI service uses on aarch64.
//
// On aarch64, Windows and Linux/SysV agree on the procedure-call
// standard (AAPCS64): the first eight integer args land in X0..X7,
// the return value comes back in X0, and the link register is X30.
// So the shuffle is straightforward — slide the fn pointer out of
// X0 into a scratch register (X9, which is intra-procedure call
// corruptible) and shift every subsequent arg one slot left, then
// BLR into the firmware.
//
// Because all five EFI arities we ship below fit inside the
// register-passed range (6 total args max — fn + 5 EFI args), no
// stack juggling is needed. The 16-byte alignment rule on aarch64 is
// satisfied trivially since we only push the (X29, X30) pair.
//
// Signatures (Go side):
//
//   //go:linkname efiCallN efiCallN
//   func efiCallN(fn, a, b, ...) uint64
//
// Register flow (efiCall2 shown):
//
//   In:  X0=fn  X1=a  X2=b
//   Out: X0=a   X1=b  then BLR X9 (with X9=fn)

    .text

    // efiCall1(fn, a) -> uint64
    .globl efiCall1
efiCall1:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    mov x9, x0
    mov x0, x1
    blr x9
    ldp x29, x30, [sp], #16
    ret

    // efiCall2(fn, a, b) -> uint64
    .globl efiCall2
efiCall2:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    mov x9, x0
    mov x0, x1
    mov x1, x2
    blr x9
    ldp x29, x30, [sp], #16
    ret

    // efiCall3(fn, a, b, c) -> uint64
    .globl efiCall3
efiCall3:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    mov x9, x0
    mov x0, x1
    mov x1, x2
    mov x2, x3
    blr x9
    ldp x29, x30, [sp], #16
    ret

    // efiCall4(fn, a, b, c, d) -> uint64
    .globl efiCall4
efiCall4:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    mov x9, x0
    mov x0, x1
    mov x1, x2
    mov x2, x3
    mov x3, x4
    blr x9
    ldp x29, x30, [sp], #16
    ret

    // efiCall5(fn, a, b, c, d, e) -> uint64
    .globl efiCall5
efiCall5:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    mov x9, x0
    mov x0, x1
    mov x1, x2
    mov x2, x3
    mov x3, x4
    mov x4, x5
    blr x9
    ldp x29, x30, [sp], #16
    ret

    // efiCall6(fn, a, b, c, d, e, f) -> uint64
    .globl efiCall6
efiCall6:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    mov x9, x0
    mov x0, x1
    mov x1, x2
    mov x2, x3
    mov x3, x4
    mov x4, x5
    mov x5, x6
    blr x9
    ldp x29, x30, [sp], #16
    ret

    // ----- LoadFile2 callback (phase 3b) -----
    //
    // The firmware calls `loadFile2` with the AAPCS64 calling convention
    // — which is also what TinyGo emits for a `//go:export`-ed Go
    // function on goos=windows / goarch=arm64. So this stub just tail-
    // calls the Go implementation. All real work (size check, byte
    // copy, status code) happens in `goLoadFile2` over there.
    //
    // We need the asm symbol so the protocol-struct pointer we hand the
    // firmware is a flat C entry point, not a Go fat function value.
    .globl loadFile2
loadFile2:
    b       goLoadFile2

    // loadFile2Ptr returns the runtime address of `loadFile2`. Self-
    // relative (adrp + add) — does not need a .reloc fixup, so it works
    // even when a tool like `pec.Append` shifts sections around and the
    // base-relocation table no longer covers our slot.
    .text
    .globl loadFile2Ptr
loadFile2Ptr:
    adrp    x0, loadFile2
    add     x0, x0, :lo12:loadFile2
    ret
