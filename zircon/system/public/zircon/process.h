#ifndef ZIRCON_PROCESS_H_
#define ZIRCON_PROCESS_H_

#include <zircon/syscalls.h>

__BEGIN_CDECLS

zx_handle_t zx_process_self(void);
zx_handle_t zx_thread_self(void);
zx_handle_t zx_vmar_root_self(void);
zx_handle_t zx_job_default(void);

__END_CDECLS

#endif  // ZIRCON_PROCESS_H_