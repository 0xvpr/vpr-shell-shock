/**
 * Created by:      VPR
 * Created:         December 29th, 2022
 *
 * Updated by:      VPR
 * Updated:         March 23rd, 2024
 *
 * Description:     C/C++ Header only library for position independent shell-code generation.
 *
 * Credits:
 *                  Credits due to Dark VortEx of https://bruteratel.com
 *                  https://bruteratel.com/research/feature-update/2021/01/30/OBJEXEC/
 *                  Without reading that tutorial, this project would not have been started
**/

#ifndef    SHELL_SHOCK_HEADER
#define    SHELL_SHOCK_HEADER

#ifndef    VC_EXTRA_LEAN
#define    VC_EXTRA_LEAN
#endif  // VC_EXTRA_LEAN
#include   <windows.h>
#include   <winnt.h>
#include   <intrin.h>


#if        !defined(__cplusplus)
#include   <stdbool.h>
#include   <stdint.h>
#include   <string.h>
#include   <stdio.h>
#else   // defined(__cplusplus)
#include   <filesystem>
#include   <fstream>
#include   <cstring>
#include   <cstdint>
#endif  // defined(__cplusplus)


#if        !defined(__cplusplus)
#define    DEREF_64(name)        *((DWORD64 *)(name))
#define    DEREF_32(name)        *((DWORD *)(name))
#define    DEREF_16(name)        *((WORD *)(name))
#define    DEREF_8(name)         *((BYTE *)(name))
#define    DEREF(name)           *((UINT_PTR *)(name))
#else   // defined(__cplusplus)
#define    DEREF_64(name)        *(reinterpret_cast<DWORD64 *>(name))
#define    DEREF_32(name)        *(reinterpret_cast<DWORD *>(name))
#define    DEREF_16(name)        *(reinterpret_cast<WORD *>(name))
#define    DEREF_8(name)         *(reinterpret_cast<BYTE *>(name))
#define    DEREF(name)           *(reinterpret_cast<UINT_PTR *>(name))
#endif  // defined(__cplusplus)


////////////////////////////////////////////////////////////////////////////////
//                               Definitions
////////////////////////////////////////////////////////////////////////////////

#if       defined(__cplusplus)
constexpr DWORD KERNEL32DLL_HASH = 0x6A4ABC5B;
#else  // !defined(__cplusplus)
#define    KERNEL32DLL_HASH 0x6A4ABC5B
#endif // !defined(__cplusplus)

typedef struct _UNICODE_STR {
    USHORT                  Length;
    USHORT                  MaximumLength;
    PWSTR                   pBuffer;
} UNICODE_STR, *PUNICODE_STR;

typedef struct _PEB_LDR_DATA {
    DWORD                   dwLength;
    DWORD                   dwInitialized;
    LPVOID                  lpSsHandle;
    LIST_ENTRY              InLoadOrderModuleList;
    LIST_ENTRY              InMemoryOrderModuleList;
    LIST_ENTRY              InInitializationOrderModuleList;
    LPVOID                  lpEntryInProgress;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY              InMemoryOrderModuleList;
    LIST_ENTRY              InInitializationOrderModuleList;
    PVOID                   DllBase;
    PVOID                   EntryPoint;
    ULONG                   SizeOfImage;
    UNICODE_STR             FullDllName;
    UNICODE_STR             BaseDllName;
    ULONG                   Flags;
    SHORT                   LoadCount;
    SHORT                   TlsIndex;
    LIST_ENTRY              HashTableEntry;
    ULONG                   TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_FREE_BLOCK {
   struct _PEB_FREE_BLOCK * pNext;
   DWORD                    dwSize;
} PEB_FREE_BLOCK, *PPEB_FREE_BLOCK;

typedef struct __PEB {
   BYTE                     bInheritedAddressSpace;
   BYTE                     bReadImageFileExecOptions;
   BYTE                     bBeingDebugged;
   BYTE                     bSpareBool;
   LPVOID                   lpMutant;
   LPVOID                   lpImageBaseAddress;
   PPEB_LDR_DATA            pLdr;
   LPVOID                   lpProcessParameters;
   LPVOID                   lpSubSystemData;
   LPVOID                   lpProcessHeap;
   PRTL_CRITICAL_SECTION    pFastPebLock;
   LPVOID                   lpFastPebLockRoutine;
   LPVOID                   lpFastPebUnlockRoutine;
   DWORD                    dwEnvironmentUpdateCount;
   LPVOID                   lpKernelCallbackTable;
   DWORD                    dwSystemReserved;
   DWORD                    dwAtlThunkSListPtr32;
   PPEB_FREE_BLOCK          pFreeList;
   DWORD                    dwTlsExpansionCounter;
   LPVOID                   lpTlsBitmap;
   DWORD                    dwTlsBitmapBits[2];
   LPVOID                   lpReadOnlySharedMemoryBase;
   LPVOID                   lpReadOnlySharedMemoryHeap;
   LPVOID                   lpReadOnlyStaticServerData;
   LPVOID                   lpAnsiCodePageData;
   LPVOID                   lpOemCodePageData;
   LPVOID                   lpUnicodeCaseTableData;
   DWORD                    dwNumberOfProcessors;
   DWORD                    dwNtGlobalFlag;
   LARGE_INTEGER            liCriticalSectionTimeout;
   DWORD                    dwHeapSegmentReserve;
   DWORD                    dwHeapSegmentCommit;
   DWORD                    dwHeapDeCommitTotalFreeThreshold;
   DWORD                    dwHeapDeCommitFreeBlockThreshold;
   DWORD                    dwNumberOfHeaps;
   DWORD                    dwMaximumNumberOfHeaps;
   LPVOID                   lpProcessHeaps;
   LPVOID                   lpGdiSharedHandleTable;
   LPVOID                   lpProcessStarterHelper;
   DWORD                    dwGdiDCAttributeList;
   LPVOID                   lpLoaderLock;
   DWORD                    dwOSMajorVersion;
   DWORD                    dwOSMinorVersion;
   WORD                     wOSBuildNumber;
   WORD                     wOSCSDVersion;
   DWORD                    dwOSPlatformId;
   DWORD                    dwImageSubsystem;
   DWORD                    dwImageSubsystemMajorVersion;
   DWORD                    dwImageSubsystemMinorVersion;
   DWORD                    dwImageProcessAffinityMask;
   DWORD                    dwGdiHandleBuffer[34];
   LPVOID                   lpPostProcessInitRoutine;
   LPVOID                   lpTlsExpansionBitmap;
   DWORD                    dwTlsExpansionBitmapBits[32];
   DWORD                    dwSessionId;
   ULARGE_INTEGER           liAppCompatFlags;
   ULARGE_INTEGER           liAppCompatFlagsUser;
   LPVOID                   lppShimData;
   LPVOID                   lpAppCompatInfo;
   UNICODE_STR              usCSDVersion;
   LPVOID                   lpActivationContextData;
   LPVOID                   lpProcessAssemblyStorageMap;
   LPVOID                   lpSystemDefaultActivationContextData;
   LPVOID                   lpSystemAssemblyStorageMap;
   DWORD                    dwMinimumStackCommit;
} _PEB, * _PPEB;

////////////////////////////////////////////////////////////////////////////////
//                                   C API
////////////////////////////////////////////////////////////////////////////////

/** 
 * Rotate bits right by 13.
**/
__forceinline DWORD ror13(DWORD d) {
    return (d >> 13) | (d << (19));
}

/** 
 * Calculates hash of byte string.
**/
__forceinline DWORD hash(const BYTE* c) {
    DWORD h = 0;
    do {
        h = ror13( h );
        h += *c;
    } while ( *++c );

    return h;
}

/** 
 * Case-insesitive string compare.
**/
__forceinline bool istreq(char* _a, char* _b) {
    for (char *a = _a, *b = _b; *a; ++a, ++b) {
        if ((*a | 0x20) != (*b | 0x20) ) {
            return false;
        }
    }

    return true;
}

/** 
 * Function to fetch the base address of kernel32.dll from the Process Environment Block.
**/
__forceinline UINT_PTR get_kernel_32(void) {
    USHORT usCounter = 0;

#if       defined(__WIN64)
    auto kernel32dll = __readgsqword( 0x60 ); // TEB is at gs:[0x60] in 64 bit
#else  // !defined(__WIN64)
    auto kernel32dll = __readfsdword( 0x30 ); // TEB is at fs:[0x30] in 32 bit
#endif // !defined(__WIN64)

    kernel32dll = (ULONG_PTR)((_PPEB)kernel32dll)->pLdr;
    ULONG_PTR val1 = (ULONG_PTR)((PPEB_LDR_DATA)kernel32dll)->InMemoryOrderModuleList.Flink;
    while ( val1 ) {
        ULONG_PTR val2 = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)val1)->BaseDllName.pBuffer;
        ULONG_PTR val3 = 0;

        //calculate the hash of kernel32.dll
        usCounter = ((PLDR_DATA_TABLE_ENTRY)val1)->BaseDllName.Length;
        do {
            val3 = ror13( (DWORD)val3 );
            val3 += (*(BYTE *)val2) - ((*(BYTE *)val2) >= 'a') * 0x20;
            val2++;
        } while (--usCounter);

        // compare the hash kernel32.dll
        if ((DWORD)val3 == KERNEL32DLL_HASH) {
            //return kernel32.dll if found
            return (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)val1)->DllBase;
        }

        val1 = DEREF( val1 );
    }

    return 0;
}

__forceinline UINT_PTR get_symbol_address( UINT_PTR hModule,
                             LPCSTR lpProcName )
{
    UINT_PTR dllAddress             = hModule;
    UINT_PTR symbolAddress          = 0;
    UINT_PTR exportedAddressTable   = 0;
    UINT_PTR namePointerTable       = 0;
    UINT_PTR ordinalTable           = 0;

    if (hModule == 0) {
        return 0;
    }

    PIMAGE_NT_HEADERS ntHeaders = NULL;
    PIMAGE_DATA_DIRECTORY dataDirectory = NULL;
    PIMAGE_EXPORT_DIRECTORY exportDirectory = NULL;

    ntHeaders = (PIMAGE_NT_HEADERS)(dllAddress + (UINT_PTR)(((PIMAGE_DOS_HEADER)dllAddress)->e_lfanew));
    dataDirectory = (PIMAGE_DATA_DIRECTORY)&ntHeaders->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ];
    exportDirectory = (PIMAGE_EXPORT_DIRECTORY)( dllAddress + dataDirectory->VirtualAddress );
        
    exportedAddressTable = ( dllAddress + exportDirectory->AddressOfFunctions );
    namePointerTable = ( dllAddress + exportDirectory->AddressOfNames );
    ordinalTable = ( dllAddress + exportDirectory->AddressOfNameOrdinals );

    if (((UINT_PTR)lpProcName & 0xFFFF0000 ) == 0x00000000) {
        exportedAddressTable += ( ( IMAGE_ORDINAL( (UINT_PTR)lpProcName ) - exportDirectory->Base ) * sizeof(DWORD) );
        symbolAddress = (UINT_PTR)( dllAddress + DEREF_32(exportedAddressTable) );
    } else {
        DWORD dwCounter = exportDirectory->NumberOfNames;
        while (dwCounter--) {
            char* cpExportedFunctionName = (char *)(dllAddress + DEREF_32(namePointerTable));
            if ( istreq(cpExportedFunctionName, (char *)(lpProcName)) ) {
                exportedAddressTable += ( DEREF_16( ordinalTable ) * sizeof(DWORD) );
                symbolAddress = (UINT_PTR)(dllAddress + DEREF_32( exportedAddressTable ));
                break;
            }

            namePointerTable += sizeof(DWORD);
            ordinalTable += sizeof(WORD);
        }
    }

    return symbolAddress;
}

////////////////////////////////////////////////////////////////////////////////
//                                 C++ API
////////////////////////////////////////////////////////////////////////////////

#if defined(__cplusplus)
namespace ss {

class [[nodiscard]] shellshock {
    typedef UINT_PTR (WINAPI * LoadLibraryA_t)(LPCSTR);
public:
    shellshock(const shellshock&) = delete;
    shellshock& operator = (const shellshock&) = delete;
    shellshock(const shellshock&&) = delete;
    shellshock& operator = (const shellshock&&) = delete;

    __forceinline shellshock() noexcept
        : kernel32dll(get_kernel_32())
        , f_LoadLibraryA(set_loadlibrary_a(kernel32dll))
        , ntdll(0)
        , msvcrtdll(0)
        , user32dll(0)
        , ws2_32dll(0)
    {
    }

    ////////////////////////////////////////////////////////////////////////////
    //                Load functions from specific libraries
    ////////////////////////////////////////////////////////////////////////////

    template <typename FuncPtr> [[nodiscard]] __forceinline
    FuncPtr find_kernel32_func(LPCSTR param) noexcept {
        return reinterpret_cast<FuncPtr>(get_symbol_address(kernel32dll, param));
    }
    template <typename FuncPtr> [[nodiscard]] __forceinline
    FuncPtr find_ntdll_func(LPCSTR param) noexcept {
        if (!ntdll) {
            load_ntdll();
        }
        return reinterpret_cast<FuncPtr>(get_symbol_address(ntdll, param));
    }
    template <typename FuncPtr> [[nodiscard]] __forceinline
    FuncPtr find_msvcrt_func(LPCSTR param) noexcept {
        if (!msvcrtdll) {
            load_msvcrt();
        }

        return reinterpret_cast<FuncPtr>(get_symbol_address(msvcrtdll, param));
    }
    template <typename FuncPtr> [[nodiscard]] __forceinline
    FuncPtr find_user32_func(LPCSTR param) noexcept {
        if (!user32dll) {
            load_user32();
        }

        return reinterpret_cast<FuncPtr>(get_symbol_address(user32dll, param));
    }
    template <typename FuncPtr> [[nodiscard]] __forceinline
    FuncPtr find_ws2_32_func(LPCSTR param) noexcept {
        if (!ws2_32dll) {
            load_ws2_32();
        }
        return reinterpret_cast<FuncPtr>(get_symbol_address(ws2_32dll, param));
    }

    ////////////////////////////////////////////////////////////////////////////
    //               Initialize libraries for easy consumption
    ////////////////////////////////////////////////////////////////////////////

private:
    __forceinline LoadLibraryA_t set_loadlibrary_a(UINT_PTR _kernel32dll) const noexcept {
        char szLoadLibraryA[] = "LoadLibraryA";
        return reinterpret_cast<LoadLibraryA_t>(get_symbol_address(_kernel32dll, szLoadLibraryA));
    }
    __forceinline void load_ntdll() noexcept {
        if (f_LoadLibraryA) {
            char szNtdll[] = "ntdll.dll";
            msvcrtdll = f_LoadLibraryA(szNtdll);
        }
    }
    __forceinline void load_msvcrt() noexcept {
        if (f_LoadLibraryA) {
            char szMsvcrt[] = "msvcrt.dll";
            msvcrtdll = f_LoadLibraryA(szMsvcrt);
        }
    }
    __forceinline void load_user32() noexcept {
        if (f_LoadLibraryA) {
            char szUser32[] = "user32.dll";
            user32dll = f_LoadLibraryA(szUser32);
        }
    }
    __forceinline void load_ws2_32() noexcept {
        if (f_LoadLibraryA) {
            char szWs2_32[] = "ws2_32.dll";
            msvcrtdll = f_LoadLibraryA(szWs2_32);
        }
    }

    UINT_PTR        kernel32dll;
    LoadLibraryA_t  f_LoadLibraryA;
    UINT_PTR        ntdll;
    UINT_PTR        msvcrtdll;
    UINT_PTR        user32dll;
    UINT_PTR        ws2_32dll;
};

////////////////////////////////////////////////////////////////////////////////
//                         Payload Extraction Helper
////////////////////////////////////////////////////////////////////////////////

class [[nodiscard]] payload_data {
    typedef std::unique_ptr<const uint8_t[]> byte_ptr;
public:
    payload_data(const payload_data&) = delete;
    payload_data& operator=(const payload_data&) = delete;
    
    payload_data(payload_data&& other) noexcept
      : bytes_(std::move(other.bytes_))
      , size_(other.size_)
    {
        other.size_ = 0;
    }

    payload_data& operator=(payload_data&& other) noexcept {
        if (this != &other) {
            bytes_ = std::move(other.bytes_);
            size_ = other.size_;

            other.size_ = 0;
        }

        return *this;
    }

    template <typename FPTR_T, typename STUB_T>
    static payload_data build_from_payload(FPTR_T payload, STUB_T stub) {
        std::size_t size = reinterpret_cast<uintptr_t>(stub)
            - reinterpret_cast<uintptr_t>(payload);
        return payload_data(payload, size);
    }

    bool extract_to_file(std::filesystem::path outfile) const noexcept {
        std::ofstream file(outfile, std::ios::binary);

        if (!file.is_open()) {
            return false;
        }

        file.write(reinterpret_cast<const char*>(bytes_.get()), size_ & INT64_MAX);
        if (file.fail()) {
            return false;
        }

        return true;
    }

    const uint8_t* bytes() const noexcept { return bytes_.get(); }
    std::size_t size() const noexcept     { return size_;  }
private:
    byte_ptr    bytes_;
    std::size_t size_;

    template <typename FPTR_T>
    payload_data(FPTR_T payload, std::size_t size)
      : bytes_( new uint8_t[size] )
      , size_(size)
    {
        std::memcpy(const_cast<uint8_t *>(bytes_.get()), reinterpret_cast<void *>(payload), size_);
    }
};
} // namepsace ss

#endif // defined(__cplusplus)

#endif // SHELL_SHOCK_HEADER