SECTIONS {
  BootCpuidLeaf : {
    PROVIDE_HIDDEN(__start_BootCpuidLeaf = .);
    KEEP(*(BootCpuidLeaf))
    PROVIDE_HIDDEN(__stop_BootCpuidLeaf = .);
  }
}

INSERT AFTER .rodata;