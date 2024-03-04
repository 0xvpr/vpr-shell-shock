/**
 * Created by:      VPR
 * Created:         January 2nd, 2023
 *
 * Updated by:      VPR
 * Updated:         March 4th, 2024
 *
 * Description:     A sample of a function that uses the Shellshock library
 *                  in order to produce position independent code.
**/

#ifdef   __WIN64
#define  OUTFILE    "out64.bin"
#else
#define  OUTFILE    "out32.bin"
#endif //__WIN64

#include "../Shellshock/Shellshock.hpp"

typedef int (WINAPI * MessageBoxA_t)(HWND, LPCSTR, LPCSTR, UINT);

extern "C" auto payload() noexcept -> void {
    // Initialize object with required libraries
    auto ss = ss::shellshock().set_loadlibrary_a().load_user32();

    // Load function into a temporary variable.
    char szMessageBoxA[] = SZ(MessageBoxA);
    auto fMessageBoxA = ss.find_user32_func<MessageBoxA_t>(szMessageBoxA);
    
    // Perform function call
    char szTitle[] = SZ(Shellshock);
    char szMessage[] = SZ(Success.);
    fMessageBoxA && fMessageBoxA(NULL, szMessage, szTitle, 0);
}

[[gnu::noinline]]
int stub() {
    return 0;
}

int main() {
    auto pd = ss::payload_data::build_from_payload(payload, stub);
    pd.extract_to_file(OUTFILE);
}
