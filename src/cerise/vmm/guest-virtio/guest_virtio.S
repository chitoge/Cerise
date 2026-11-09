// Guest blob exercising virtio-console (port 0x5000) and virtio-net (port 0x5001).
// Each device sends a trigger value (0xbeef) to its trap port, then HLTs.
.code64
.section .text, "ax", @progbits
.global _start
_start:
    // Trigger virtio-console output trap (port 0x5000).
    movw    $0x5000, %dx
    movw    $0xbeef, %ax
    outw    %ax, %dx

    // Trigger virtio-net TX trap (port 0x5001).
    movw    $0x5001, %dx
    movw    $0xbeef, %ax
    outw    %ax, %dx

    // Signal done via the standard IO exit trap (port 0x1234) used.
    movw    $0x1234, %dx
    movw    $0xdead, %ax
    outw    %ax, %dx

    hlt
.Lspin: jmp .Lspin
