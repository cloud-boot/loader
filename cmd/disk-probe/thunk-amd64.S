// Microsoft x64 thunks that adapt TinyGo's external-call register layout
// to the calling convention every EFI service uses.
//
// Why we need this: a Go `func()` value is a fat pointer (code+context,
// 16 bytes wide) and Go's call sites don't always emit raw MS x64 args
// for function-value calls. So instead of putting EFI services into
// `func` fields and calling them through Go, we keep the firmware
// function pointers as plain `uintptr` and route every call through one
// of the thunks below. The Go declaration is, e.g.:
//
//   //go:linkname efiCall2 efiCall2
//   func efiCall2(fn, a, b uintptr) uint64
//
// On a TinyGo / goarch=amd64 / goos=windows external call the first
// four integer args land in RCX, RDX, R8, R9 (already MS x64). Each
// thunk just shifts the fn pointer out of RCX into RAX, slides every
// other arg one slot to the right, then calls `*RAX`. The shadow space
// (`sub $0x28`) keeps RSP 16-byte aligned at the inner CALL.
//
// Caller stack layout on entry to a 5-arg variant:
//
//   [rsp+0x00] return address
//   [rsp+0x08..0x27] caller-reserved shadow space (unused by us)
//   [rsp+0x28] 5th caller arg (1st arg that didn't fit in regs)
//   [rsp+0x30] 6th caller arg
//
// MS x64 requires that the stack be 16-byte aligned **before** the
// inner CALL. On entry RSP is 8 mod 16 (the outer CALL pushed 8 bytes
// of return address onto a 16-aligned stack). `sub $0x28` brings RSP
// back to 16-aligned (0x28 ≡ 8 mod 16, 8+8 ≡ 0 mod 16).

    .text

    // efiCall1(fn, a) -> uint64
    .globl efiCall1
efiCall1:
    subq    $0x28, %rsp
    movq    %rcx, %rax
    movq    %rdx, %rcx
    callq   *%rax
    addq    $0x28, %rsp
    retq

    // efiCall2(fn, a, b) -> uint64
    .globl efiCall2
efiCall2:
    subq    $0x28, %rsp
    movq    %rcx, %rax
    movq    %rdx, %rcx
    movq    %r8,  %rdx
    callq   *%rax
    addq    $0x28, %rsp
    retq

    // efiCall3(fn, a, b, c) -> uint64
    .globl efiCall3
efiCall3:
    subq    $0x28, %rsp
    movq    %rcx, %rax
    movq    %rdx, %rcx
    movq    %r8,  %rdx
    movq    %r9,  %r8
    callq   *%rax
    addq    $0x28, %rsp
    retq

    // efiCall4(fn, a, b, c, d) -> uint64
    .globl efiCall4
efiCall4:
    movq    0x28(%rsp), %r10        // d (5th caller arg, on caller's stack)
    subq    $0x28, %rsp
    movq    %rcx, %rax
    movq    %rdx, %rcx
    movq    %r8,  %rdx
    movq    %r9,  %r8
    movq    %r10, %r9
    callq   *%rax
    addq    $0x28, %rsp
    retq

    // efiCall5(fn, a, b, c, d, e) -> uint64
    .globl efiCall5
efiCall5:
    movq    0x28(%rsp), %r10        // d (5th caller arg)
    movq    0x30(%rsp), %r11        // e (6th caller arg)
    movq    %rcx, %rax              // rax = fn
    movq    %rdx, %rcx              // rcx = a
    movq    %r8,  %rdx              // rdx = b
    movq    %r9,  %r8               // r8  = c
    movq    %r10, %r9               // r9  = d
    subq    $0x28, %rsp             // shadow + 8 for stack-passed arg
    movq    %r11, 0x20(%rsp)        // e at [rsp+0x20] (MS x64 5th arg slot)
    callq   *%rax
    addq    $0x28, %rsp
    retq

    // efiCall6(fn, a, b, c, d, e, f) -> uint64
    //
    // Two of the seven args end up on the inner call's stack at
    // [rsp+0x20] (e) and [rsp+0x28] (f). d and e are read from the
    // caller frame into r10/r11 before adjusting RSP; f is read after
    // the sub from its caller-frame position (orig +0x38 → new +0x70).
    // Sub by 0x38 to keep the inner call site 16-byte aligned and to
    // leave a 0x20 shadow plus two stack-passed-arg slots.
    .globl efiCall6
efiCall6:
    movq    0x28(%rsp), %r10        // d (5th caller arg)
    movq    0x30(%rsp), %r11        // e (6th caller arg)
    subq    $0x38, %rsp             // 0x20 shadow + 0x10 args + 8 for align
    movq    %rcx, %rax              // rax = fn
    movq    %rdx, %rcx              // rcx = a
    movq    %r8,  %rdx              // rdx = b
    movq    %r9,  %r8               // r8  = c
    movq    %r10, %r9               // r9  = d
    movq    %r11, 0x20(%rsp)        // e at [rsp+0x20] (inner 5th arg slot)
    movq    0x70(%rsp), %r10        // f, now at +0x70 in our frame after sub
    movq    %r10, 0x28(%rsp)        // f at [rsp+0x28] (inner 6th arg slot)
    callq   *%rax
    addq    $0x38, %rsp
    retq

    // ----- LoadFile2 callback (phase 3b) -----
    //
    // The firmware calls `loadFile2` with the Microsoft x64 calling
    // convention — which is also what TinyGo emits for a //go:export-ed
    // Go function on goos=windows / goarch=amd64. So this stub just
    // tail-jumps into the Go implementation; size check, byte copy
    // and status code all live in `goLoadFile2`.
    //
    // We need the asm symbol so the protocol-struct pointer we hand
    // the firmware is a flat C entry point, not a Go fat function
    // value.
    .globl loadFile2
loadFile2:
    jmp     goLoadFile2

    // loadFile2Entry holds the address of loadFile2 above. We put it in
    // .data so the linker resolves the symbol value at link time and
    // _start does not have to compute it.
    // loadFile2Ptr returns the runtime address of `loadFile2`. RIP-
    // relative LEA — does not need a .reloc fixup, so it works even
    // when `pec.Append` shifts sections around and the base-relocation
    // table no longer covers our slot.
    .text
    .globl loadFile2Ptr
loadFile2Ptr:
    leaq    loadFile2(%rip), %rax
    retq
