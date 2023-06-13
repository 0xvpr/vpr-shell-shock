<p align="center">
  <img src="https://img.shields.io/badge/Windows--x86__64-supported-green">
  <img src="https://img.shields.io/badge/Windows--x86-unsupported-red">
  <img src="https://img.shields.io/badge/Linux--x86__64-unsupported-red">
  <img src="https://img.shields.io/badge/Linux--x86-unsupported-red">
  <a href="https://mit-license.org/">
    <img src="https://img.shields.io/github/license/0xvpr/vpr-shell-shock?style=flat-square">
  </a>
  <a href="https://github.com/0xvpr/vpr-shell-shock/commits/master">
    <img src="https://img.shields.io/github/last-commit/0xvpr/vpr-shell-shock?style=flat-square">
  </a>
  <br>
  <h1 align="center">Shellshock</h1>
  <h3 align="center">Inspired by: Dark VortEx from bruteratel.com</h3>
  <br>
</p>

### How to use
One way to use the Shellshock.hpp header is to:
- Create a 'Shellshock' object
- Load in whatever libraries you intend to use via the member functions
- Resolve functions that you intend to use with said libraries
- Utilize a singular function and make sure that all variables are created  
  on the stack

Once something like this is achieved, you can compile the binary to an object  
file and dump the `.text` section out to a whatever you like. That dump **should**  
be position independent.

### Quick Example
```cpp
#include "Shellshock/Shellshock.hpp"

typedef int (WINAPI * MessageBoxA_t)(HWND, LPCSTR, LPCSTR, UINT);

extern "C" auto payload() noexcept -> void {
    // Initialize object with required libraries
    auto ss = Shellshock().SetLoadLibraryA().SetUser32();

    // Load function into a temporary variable.
    char szMessageBoxA[] = SS(MessageBoxA);
    auto fMessageBoxA = ss.GetUser32Func<MessageBoxA_t>(szMessageBoxA);
    
    // Perform function call
    char szTitle[] = SS(Shellshock);
    char szMessage[] = SS(Success.);
    fMessageBoxA(NULL, szMessage, szTitle, 0);
}
```

Compiling this code to an object **should** mean that the `payload` function of the  
`.text` section is out new position independent executable.
