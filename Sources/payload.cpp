/**
 * Created by:      VPR
 * Created:         January 2nd, 2023
 *
 * Updated by:      VPR
 * Updated:         January 3nd, 2023
 *
 * Description:     A sample of a function that uses 
**/

#include "Shellshock.hpp"

typedef int (WINAPI * MessageBoxA_t)(HWND, LPCSTR, LPCSTR, UINT);

extern "C" auto payload() noexcept -> void {
    // Initiate Object
    auto ss = Shellshock().SetLoadLibraryA().SetUser32();

    // Load function into a temporary variable.
    char szMessageBoxA[] = SS(MessageBoxA);
    auto fMessageBoxA = ss.GetUser32Func<MessageBoxA_t>(szMessageBoxA);
    
    // Perform function call
    char szTitle[] = SS(Shellshock);
    char szMessage[] = SS(Success.);
    fMessageBoxA(NULL, szMessage, szTitle, 0);
}
