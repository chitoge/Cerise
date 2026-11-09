#include <stddef.h>

void operator delete(void*) noexcept {}

void operator delete(void*, size_t) noexcept {}

void operator delete[](void*) noexcept {}

void operator delete[](void*, size_t) noexcept {}
