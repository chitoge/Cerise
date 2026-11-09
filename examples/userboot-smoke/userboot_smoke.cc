// Minimal freestanding userboot payload for the x64-smoke product.
//
// Booted directly as userboot.next (see build/kernel:kernel_storage_zbi). It is
// a self-relocating PIE that resolves the handful of vDSO syscalls it needs,
// reads the processargs bootstrap channel to find the debuglog handle, emits a
// single boot marker, and exits. No networking, no lwIP, no PCI — this is the
// smoke test that the kernel + userboot + vDSO bring-up chain works end to end.

#include <stddef.h>
#include <stdint.h>

extern "C" void* memcpy(void* dest, const void* src, size_t count) {
  auto* d = static_cast<uint8_t*>(dest);
  const auto* s = static_cast<const uint8_t*>(src);
  for (size_t i = 0; i < count; ++i) {
    d[i] = s[i];
  }
  return dest;
}

extern "C" void* memset(void* dest, int value, size_t count) {
  auto* d = static_cast<uint8_t*>(dest);
  for (size_t i = 0; i < count; ++i) {
    d[i] = static_cast<uint8_t>(value);
  }
  return dest;
}

namespace {

constexpr uint32_t kPtDynamic = 2;
constexpr int64_t kDtNull = 0;
constexpr int64_t kDtHash = 4;
constexpr int64_t kDtStrtab = 5;
constexpr int64_t kDtSymtab = 6;
constexpr int64_t kDtRela = 7;
constexpr int64_t kDtRelasz = 8;
constexpr int64_t kDtRelaent = 9;
constexpr uint32_t kR_X86_64Relative = 8;

// processargs handle-info types (subset).
constexpr uint32_t kPaFd = 0x30;
constexpr uint32_t kFdioFlagUseForStdio = 0x8000;

constexpr char kMarker[] = "CERISE-SMOKE-OK\n";

struct ProcArgs {
  uint32_t protocol;
  uint32_t version;
  uint32_t handle_info_off;
  uint32_t args_off;
  uint32_t args_num;
  uint32_t environ_off;
  uint32_t environ_num;
  uint32_t names_off;
  uint32_t names_num;
};

struct Elf64Ehdr {
  unsigned char ident[16];
  uint16_t type;
  uint16_t machine;
  uint32_t version;
  uint64_t entry;
  uint64_t phoff;
  uint64_t shoff;
  uint32_t flags;
  uint16_t ehsize;
  uint16_t phentsize;
  uint16_t phnum;
  uint16_t shentsize;
  uint16_t shnum;
  uint16_t shstrndx;
};

struct Elf64Phdr {
  uint32_t type;
  uint32_t flags;
  uint64_t offset;
  uint64_t vaddr;
  uint64_t paddr;
  uint64_t filesz;
  uint64_t memsz;
  uint64_t align;
};

struct Elf64Dyn {
  int64_t tag;
  uint64_t value;
};

struct Elf64Sym {
  uint32_t name;
  unsigned char info;
  unsigned char other;
  uint16_t shndx;
  uint64_t value;
  uint64_t size;
};

struct Elf64Rela {
  uint64_t offset;
  uint64_t info;
  int64_t addend;
};

extern "C" const unsigned char __ehdr_start[];

using ChannelRead = int (*)(uint32_t, uint32_t, void*, uint32_t*, uint32_t, uint32_t, uint32_t*,
                            uint32_t*);
using DebuglogWrite = int (*)(uint32_t, uint32_t, const void*, size_t);
using ProcessExit = void (*)(int64_t);

bool Equal(const char* left, const char* right) {
  while (*left == *right) {
    if (*left == '\0') {
      return true;
    }
    ++left;
    ++right;
  }
  return false;
}

uintptr_t ResolveVdsoSymbol(uintptr_t vdso_base, const char* symbol_name) {
  const auto* ehdr = reinterpret_cast<const Elf64Ehdr*>(vdso_base);
  const auto* phdrs = reinterpret_cast<const Elf64Phdr*>(vdso_base + ehdr->phoff);

  const Elf64Dyn* dynamic = nullptr;
  for (uint16_t index = 0; index < ehdr->phnum; ++index) {
    if (phdrs[index].type == kPtDynamic) {
      dynamic = reinterpret_cast<const Elf64Dyn*>(vdso_base + phdrs[index].vaddr);
      break;
    }
  }
  if (dynamic == nullptr) {
    return 0;
  }

  const Elf64Sym* symbols = nullptr;
  const char* strings = nullptr;
  const uint32_t* hash = nullptr;
  for (const Elf64Dyn* entry = dynamic; entry->tag != kDtNull; ++entry) {
    switch (entry->tag) {
      case kDtHash:
        hash = reinterpret_cast<const uint32_t*>(vdso_base + entry->value);
        break;
      case kDtStrtab:
        strings = reinterpret_cast<const char*>(vdso_base + entry->value);
        break;
      case kDtSymtab:
        symbols = reinterpret_cast<const Elf64Sym*>(vdso_base + entry->value);
        break;
      default:
        break;
    }
  }
  if (symbols == nullptr || strings == nullptr || hash == nullptr) {
    return 0;
  }

  const uint32_t chain_count = hash[1];
  for (uint32_t index = 0; index < chain_count; ++index) {
    if (Equal(strings + symbols[index].name, symbol_name)) {
      return vdso_base + symbols[index].value;
    }
  }
  return 0;
}

void ApplySelfRelocations() {
  const uintptr_t load_base = reinterpret_cast<uintptr_t>(&__ehdr_start[0]);
  const auto* ehdr = reinterpret_cast<const Elf64Ehdr*>(load_base);
  const auto* phdrs = reinterpret_cast<const Elf64Phdr*>(load_base + ehdr->phoff);

  const Elf64Dyn* dynamic = nullptr;
  for (uint16_t index = 0; index < ehdr->phnum; ++index) {
    if (phdrs[index].type == kPtDynamic) {
      dynamic = reinterpret_cast<const Elf64Dyn*>(load_base + phdrs[index].vaddr);
      break;
    }
  }
  if (dynamic == nullptr) {
    return;
  }

  const Elf64Rela* rela = nullptr;
  size_t rela_size = 0;
  size_t rela_entry_size = sizeof(Elf64Rela);
  for (const Elf64Dyn* entry = dynamic; entry->tag != kDtNull; ++entry) {
    switch (entry->tag) {
      case kDtRela:
        rela = reinterpret_cast<const Elf64Rela*>(load_base + entry->value);
        break;
      case kDtRelasz:
        rela_size = entry->value;
        break;
      case kDtRelaent:
        rela_entry_size = entry->value;
        break;
      default:
        break;
    }
  }
  if (rela == nullptr || rela_size == 0 || rela_entry_size < sizeof(Elf64Rela)) {
    return;
  }

  const size_t rela_count = rela_size / rela_entry_size;
  for (size_t index = 0; index < rela_count; ++index) {
    const auto* entry = reinterpret_cast<const Elf64Rela*>(
        reinterpret_cast<const uint8_t*>(rela) + index * rela_entry_size);
    const uint32_t type = static_cast<uint32_t>(entry->info & 0xffffffffu);
    if (type == kR_X86_64Relative) {
      auto* target = reinterpret_cast<uintptr_t*>(load_base + entry->offset);
      *target = load_base + static_cast<uintptr_t>(entry->addend);
    }
  }
}

uint32_t HandleType(uint32_t handle_info) { return handle_info & 0xff; }
uint32_t HandleArg(uint32_t handle_info) { return (handle_info >> 16) & 0xffff; }

}  // namespace

extern "C" [[noreturn]] void _start(uintptr_t bootstrap, uintptr_t vdso_base) {
  ApplySelfRelocations();

  auto channel_read = reinterpret_cast<ChannelRead>(ResolveVdsoSymbol(vdso_base, "_zx_channel_read"));
  auto debuglog_write =
      reinterpret_cast<DebuglogWrite>(ResolveVdsoSymbol(vdso_base, "_zx_debuglog_write"));
  auto process_exit = reinterpret_cast<ProcessExit>(ResolveVdsoSymbol(vdso_base, "_zx_process_exit"));

  if (channel_read != nullptr && debuglog_write != nullptr) {
    uint8_t bytes[1024];
    uint32_t handles[64];
    uint32_t actual_bytes = 0;
    uint32_t actual_handles = 0;

    const int status = channel_read(static_cast<uint32_t>(bootstrap), 0, bytes, handles,
                                    sizeof(bytes), 64, &actual_bytes, &actual_handles);
    if (status == 0 && actual_bytes >= sizeof(ProcArgs)) {
      const auto* procargs = reinterpret_cast<const ProcArgs*>(bytes);
      const auto* handle_info = reinterpret_cast<const uint32_t*>(bytes + procargs->handle_info_off);

      uint32_t debuglog = 0;
      for (uint32_t index = 0; index < actual_handles; ++index) {
        if (HandleType(handle_info[index]) == kPaFd &&
            (HandleArg(handle_info[index]) & kFdioFlagUseForStdio) != 0) {
          debuglog = handles[index];
          break;
        }
      }

      if (debuglog != 0) {
        debuglog_write(debuglog, 0, kMarker, sizeof(kMarker) - 1);
      }
    }
  }

  if (process_exit != nullptr) {
    process_exit(0);
  }
  __builtin_trap();
}
