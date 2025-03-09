/**
 * Created by:      VPR
 * Created:         January 2nd, 2023
 *
 * Updated by:      VPR
 * Updated:         March 9th, 2025
 *
 * Description:     A sample of functions that use the Shellshock library
 *                  in order to produce position independent code.
**/

#if       defined(__WIN64)
#define  SUFFIX    "_out64.bin"
#else  // !defined(__WIN64)
#define  SUFFIX    "_out32.bin"
#endif // !defined(__WIN64)

#include "vpr/shellshock.h"

typedef UINT_PTR (WINAPI * LoadLibraryA_t)(LPCSTR);
typedef int (WINAPI * MessageBoxA_t)(HWND, LPCSTR, LPCSTR, UINT);

////////////////////////////////////////////////////////////////////////////////
//                          C++ API usage example
////////////////////////////////////////////////////////////////////////////////

extern "C" int payload_cpp(void) {
    auto ss = vpr::ss::shellshock();

    // Load target function into a temporary variable.
    char szMessageBoxA[] = "MessageBoxA";
    auto fMessageBoxA = ss.find_user32_func<MessageBoxA_t>(szMessageBoxA);
    
    // Perform function call
    char szTitle[] = "Shellshock";
    char szMessage[] = "Success.";
    fMessageBoxA && fMessageBoxA(nullptr, szMessage, szTitle, 0);

    return 0;
}

int payload_stub_cpp() {
    return 0;
}

////////////////////////////////////////////////////////////////////////////////
//                           C API usage example
////////////////////////////////////////////////////////////////////////////////

extern "C" int payload_c(void) {
    char loadlibrarya_str[] = "LoadLibraryA";
    LoadLibraryA_t fLoadLibraryA = (LoadLibraryA_t)get_symbol_address(get_kernel_32(), loadlibrarya_str);

    char user32_str[] = "user32.dll";
    UINT_PTR user32 = (UINT_PTR)fLoadLibraryA(user32_str);

    char MessageBoxA_str[] = "MessageBoxA";
    MessageBoxA_t fMessageBoxA = (MessageBoxA_t)(get_symbol_address(user32, MessageBoxA_str));

    char szTitle[] = "Shellshock";
    char szMessage[] = "Success.";
    fMessageBoxA && fMessageBoxA(NULL, szMessage, szTitle, 0);

    return 0;
}

int payload_stub_c() {
    return 0;
}

int main() {
    using namespace vpr::ss; // payload_data

    auto pd_cpp = payload_data::build_from_payload(payload_cpp, payload_stub_cpp);
    pd_cpp.extract_to_file("cpp" SUFFIX);

    auto pd_c = payload_data::build_from_payload(payload_c, payload_stub_c);
    pd_c.extract_to_file("c" SUFFIX);
}
