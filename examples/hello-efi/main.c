// Minimal UEFI hello-world. Self-contained: no efi/ headers, no stdlib.
// Validates the full x86_64-unknown-uefi toolchain → lld-link → OVMF path.
//
// EFI types defined inline so this file compiles freestanding with
// -fshort-wchar (CHAR16 = unsigned short = wchar_t on UEFI targets).

typedef unsigned char      UINT8;
typedef unsigned short     UINT16;
typedef unsigned int       UINT32;
typedef unsigned long long UINT64;
typedef unsigned long long UINTN;
typedef long long          INTN;
typedef UINT16             CHAR16;
typedef void*              EFI_HANDLE;
typedef UINTN              EFI_STATUS;

#define EFI_SUCCESS  0ULL
#define IN
#define OUT
#define OPTIONAL
#define EFIAPI

// Minimal EFI table header (only size field matters for pointer arithmetic).
typedef struct {
    UINT64 Signature;
    UINT32 Revision;
    UINT32 HeaderSize;
    UINT32 CRC32;
    UINT32 Reserved;
} EFI_TABLE_HEADER;

// Minimal Simple Text Output Protocol — only OutputString needed.
typedef struct _EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL;
struct _EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL {
    EFI_STATUS (EFIAPI *Reset)(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL* self, int ExtendedVerification);
    EFI_STATUS (EFIAPI *OutputString)(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL* self, CHAR16* String);
    // remaining fields omitted — we never call them
};

// Minimal Boot Services (only Stall needed for our delay).
typedef struct {
    EFI_TABLE_HEADER Hdr;
    void* RaiseTpl;
    void* RestoreTpl;
    void* AllocatePages;
    void* FreePages;
    void* GetMemoryMap;
    void* AllocatePool;
    void* FreePool;
    void* CreateEvent;
    void* SetTimer;
    void* WaitForEvent;
    void* SignalEvent;
    void* CloseEvent;
    void* CheckEvent;
    void* InstallProtocolInterface;
    void* ReinstallProtocolInterface;
    void* UninstallProtocolInterface;
    void* HandleProtocol;
    void* Reserved;
    void* RegisterProtocolNotify;
    void* LocateHandle;
    void* LocateDevicePath;
    void* InstallConfigurationTable;
    void* LoadImage;
    void* StartImage;
    void* Exit;
    void* UnloadImage;
    void* ExitBootServices;
    void* GetNextMonotonicCount;
    EFI_STATUS (EFIAPI *Stall)(UINTN Microseconds);
} EFI_BOOT_SERVICES;

// Minimal System Table.
typedef struct {
    EFI_TABLE_HEADER                Hdr;
    CHAR16*                         FirmwareVendor;
    UINT32                          FirmwareRevision;
    EFI_HANDLE                      ConsoleInHandle;
    void*                           ConIn;
    EFI_HANDLE                      ConsoleOutHandle;
    EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL* ConOut;
    EFI_HANDLE                      StandardErrorHandle;
    EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL* StdErr;
    void*                           RuntimeServices;
    EFI_BOOT_SERVICES*              BootServices;
} EFI_SYSTEM_TABLE;

static void print(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL* out, const CHAR16* s) {
    out->OutputString(out, (CHAR16*)s);
}

EFI_STATUS EFIAPI EfiMain(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE* ST) {
    EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL* con = ST->ConOut;

    // Clear screen and print marker lines.
    print(con, L"\r\nhello-efi: EFI boot OK\r\n");
    print(con, L"hello-efi: firmware = ");
    print(con, ST->FirmwareVendor);
    print(con, L"\r\n");
    print(con, L"hello-efi: DONE\r\n");

    // Stall 3 seconds so the output is visible before OVMF exits.
    ST->BootServices->Stall(3 * 1000 * 1000);

    return EFI_SUCCESS;
}
