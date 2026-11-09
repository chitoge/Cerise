{
  global:
    /* ZIRCON_DRIVER registration symbols — the only two dlsym'd by
     * cerise_load_compat_module() (src/cerise/dfv2_inproc_loader/loader.cc).
     * Everything else is internal: FIDL wire/natural vtables, ddk helpers, banjo
     * inline vtables. compat.so reads symbols via fdf_internal::GetSymbol.
     */
    __zircon_driver_note__;
    __zircon_driver_rec__;
  local:
    *;
};
