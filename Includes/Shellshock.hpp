/**
 * Created by:      VPR
 * Created:         December 29th, 2022
 *
 * Updated by:      VPR
 * Updated:         January 3rd, 2023
 *
 * Description:     Header only library for position independent shell-code generation.
 *
 * Credits/Inspiration:
 *  [ TODO ]
**/

#ifndef SHELL_SHOCK_HEADER
#define SHELL_SHOCK_HEADER

#ifndef VC_EXTRA_LEAN
#define VC_EXTRA_LEAN
#include <windows.h>
#include <inttypes.h>
#endif  // VC_EXTRA_LEAN

#define DEREF_64(name) *(DWORD64 *)(name)
#define DEREF_32(name) *(DWORD *)(name)
#define DEREF_16(name) *(WORD *)(name)
#define DEREF_8(name)  *(BYTE *)(name)
#define DEREF(name)    *(UINT_PTR *)(name)

#ifndef STRING_OP
#define STRING_OP(x)         #x
#endif  // STRING_OP
#ifndef MAKE_STACK_STRING
#define MAKE_STACK_STRING(x) STRING_OP(x)
#endif  // MAKE_STACK_STRING
#ifndef SS
#define SS                   MAKE_STACK_STRING
#endif  // SS

constexpr unsigned KERNEL32DLL_HASH = 0x6A4ABC5B;

typedef struct _UNICODE_STR {
  USHORT                    Length;
  USHORT                    MaximumLength;
  PWSTR                     pBuffer;
} UNICODE_STR, *PUNICODE_STR;

typedef struct _PEB_LDR_DATA {
   DWORD                    dwLength;
   DWORD                    dwInitialized;
   LPVOID                   lpSsHandle;
   LIST_ENTRY               InLoadOrderModuleList;
   LIST_ENTRY               InMemoryOrderModuleList;
   LIST_ENTRY               InInitializationOrderModuleList;
   LPVOID                   lpEntryInProgress;
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

class [[nodiscard]] Shellshock {
public:
    Shellshock() noexcept
        : kernel32dll(GetKernel32())
        , msvcrtdll(0)
        , user32dll(0)
        , ws2_32dll(0)
        , ntdll(0)
        , f_LoadLibraryA(nullptr)
    {
    }

    // function to fetch the base address of kernel32.dll from the Process Environment Block
    [[nodiscard]]
    __forceinline uintptr_t GetKernel32() const noexcept {
        ULONG_PTR val1, val2, val3;
        USHORT usCounter;

        // kernel32.dll is at 0x60 offset and __readgsqword is compiler intrinsic,
        // so we don't need to extract it's symbol
        auto _kernel32dll = __readgsqword( 0x60 );

        _kernel32dll = (ULONG_PTR)((_PPEB)_kernel32dll)->pLdr;
        val1 = (ULONG_PTR)((PPEB_LDR_DATA)_kernel32dll)->InMemoryOrderModuleList.Flink;
        while( val1 ) {
            val2 = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)val1)->BaseDllName.pBuffer;
            usCounter = ((PLDR_DATA_TABLE_ENTRY)val1)->BaseDllName.Length;
            val3 = 0;

            //calculate the hash of kernel32.dll
            do {
                val3 = ror13( (DWORD)val3 );
                if( *((BYTE *)val2) >= 'a' ) {
                    val3 += *((ULONG_PTR *)val2) - 0x20;
                } else {
                    val3 += *((BYTE *)val2);
                }
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
public: // Load functions from specific libraries
    template <typename FuncPtr> [[nodiscard]]
    __forceinline auto GetMsvcrtFunc(LPCSTR param) const noexcept {
        return reinterpret_cast<FuncPtr>(GetSymbolAddress(msvcrtdll, param));
    }

    template <typename FuncPtr> [[nodiscard]]
    __forceinline auto GetUser32Func(LPCSTR param) const noexcept {
        return reinterpret_cast<FuncPtr>(GetSymbolAddress(user32dll, param));
    }

    template <typename FuncPtr> [[nodiscard]]
    __forceinline auto GetWs2_32Func(LPCSTR param) const noexcept {
        return reinterpret_cast<FuncPtr>(GetSymbolAddress(ws2_32dll, param));
    }

    template <typename FuncPtr> [[nodiscard]]
    __forceinline auto GetNtdllFunc(LPCSTR param) const noexcept {
        return reinterpret_cast<FuncPtr>(GetSymbolAddress(ntdll, param));
    }
public: // TODO Return object copies
    [[nodiscard]]
    __forceinline Shellshock& SetLoadLibraryA() noexcept {
        if (!f_LoadLibraryA) {
            char szLoadLibraryA[] = SS(LoadLibraryA);
            f_LoadLibraryA = (uintptr_t(*)(LPCSTR))GetSymbolAddress(kernel32dll, szLoadLibraryA);
        }

        return *this;
    }

    [[nodiscard]]
    __forceinline Shellshock& SetUser32() noexcept {
        if (f_LoadLibraryA) {
            char szUser32[] = SS(user32.dll);
            user32dll = f_LoadLibraryA(szUser32);
        }

        return *this;
    }
private:
    [[nodiscard]]
    __forceinline uintptr_t GetSymbolAddress(uintptr_t hModule, LPCSTR lpProcName) const noexcept {
        uintptr_t dllAddress = hModule;
        uintptr_t symbolAddress = 0;
        uintptr_t exportedAddressTable = 0;
        uintptr_t namePointerTable = 0;
        uintptr_t ordinalTable = 0;

        if (hModule == 0) {
            return 0;
        }

        PIMAGE_NT_HEADERS ntHeaders = nullptr;
        PIMAGE_DATA_DIRECTORY dataDirectory = nullptr;
        PIMAGE_EXPORT_DIRECTORY exportDirectory = nullptr;

        ntHeaders = (PIMAGE_NT_HEADERS)(dllAddress + (UINT64)(((PIMAGE_DOS_HEADER)dllAddress)->e_lfanew));
        dataDirectory = (PIMAGE_DATA_DIRECTORY)&ntHeaders->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ];
        exportDirectory = (PIMAGE_EXPORT_DIRECTORY)( dllAddress + dataDirectory->VirtualAddress );
            
        exportedAddressTable = ( dllAddress + exportDirectory->AddressOfFunctions );
        namePointerTable = ( dllAddress + exportDirectory->AddressOfNames );
        ordinalTable = ( dllAddress + exportDirectory->AddressOfNameOrdinals );

        if (((UINT64)lpProcName & 0xFFFF0000 ) == 0x00000000) {
            exportedAddressTable += ( ( IMAGE_ORDINAL( (UINT64)lpProcName ) - exportDirectory->Base ) * sizeof(DWORD) );
            symbolAddress = (uintptr_t)( dllAddress + DEREF_32(exportedAddressTable) );
        } else {
            DWORD dwCounter = exportDirectory->NumberOfNames;
            while (dwCounter--) {
                char* cpExportedFunctionName = (char *)(dllAddress + DEREF_32( namePointerTable));
                if (my_strcmp( cpExportedFunctionName, lpProcName ) == 0) {
                    exportedAddressTable += ( DEREF_16( ordinalTable ) * sizeof(DWORD) );
                    symbolAddress = (uintptr_t)(dllAddress + DEREF_32( exportedAddressTable ));
                    break;
                }

                namePointerTable += sizeof(DWORD);
                ordinalTable += sizeof(WORD);
            }
        }

        return symbolAddress;
    }

    // main hashing function for ror13
    [[nodiscard]]
    __forceinline DWORD ror13(DWORD d) const noexcept {
        return _rotr(d, 13);
    }

    [[nodiscard]]
    __forceinline DWORD hash(unsigned char* c ) const noexcept {
        DWORD h = 0;
        do {
            h = ror13( h );
            h += *c;
        } while ( *++c );

        return h;
    }

    // custom strcmp function since this function will be called by GetSymbolAddress
    // which means we have to call strcmp before loading msvcrt.dll
    // so we are writing our own my_strcmp so that we don't have to play with egg or chicken dilemma
    [[nodiscard]]
    __forceinline int my_strcmp (const char* p1, const char* p2) const noexcept {
        const unsigned char *s1 = (const unsigned char *) p1;
        const unsigned char *s2 = (const unsigned char *) p2;
        unsigned char c1, c2;
        do {
            c1 = (unsigned char) *s1++;
            c2 = (unsigned char) *s2++;
            if (c1 == '\0') {
                return c1 - c2;
            }
        } while (c1 == c2);

        return c1 - c2;
    }
private:
    uintptr_t kernel32dll;
    uintptr_t msvcrtdll;
    uintptr_t user32dll;
    uintptr_t ws2_32dll;
    uintptr_t ntdll;
    uintptr_t (WINAPI *  f_LoadLibraryA)(LPCSTR);
};

#endif // SHELL_SHOCK_HEADER
