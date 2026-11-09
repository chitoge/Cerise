// Minimal VMM guest blob.
//
// Zircon initialises the vCPU in 64-bit long mode with a flat GDT and an
// identity-mapped guest physical address space, so this code runs directly
// as 64-bit instructions.
//
// Protocol with the VMM:
//   - Write 0xDEAD to IO port 0x1234  → ZX_PKT_TYPE_GUEST_IO exit
//   - Execute HLT                       → ZX_PKT_TYPE_GUEST_VCPU exit (HLT)
//   - Spin forever (unreachable in practice)

.code64
.section .text, "ax", @progbits
.global _start

_start:
    // Announce arrival via IO trap so the VMM can log "vmm: guest hello via trap".
    movw    $0x1234, %dx
    movw    $0xdead, %ax
    outw    %ax, %dx

    // HLT — exits to the VMM so it can log "vmm: guest exited" and stop.
    hlt

.Lspin:
    jmp     .Lspin
