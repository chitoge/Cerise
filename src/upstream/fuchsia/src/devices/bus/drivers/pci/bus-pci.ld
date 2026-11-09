{
  global:
    /* ZIRCON_DRIVER registration symbols — the only two dlsym'd by
     * cerise_load_compat_module() (src/cerise/driver_host/src/dfv2_main.rs).
     * Everything else is internal: FIDL wire/natural vtables, ddk helpers.
     * compat.so reads symbols via fdf_internal::GetSymbol (map-based, not dlsym).
     */
    __zircon_driver_note__;
    __zircon_driver_rec__;
  local:
    *;
};
