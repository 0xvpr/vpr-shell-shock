<h1 align="center">shell-shock</h1>
<p align="center">
  <img src="https://img.shields.io/badge/Windows--x86__64-supported-green">
  <img src="https://img.shields.io/badge/Windows--x86-supported-green">
  <img src="https://img.shields.io/badge/Linux--x86__64-unsupported-red">
  <img src="https://img.shields.io/badge/Linux--x86-unsupported-red">
  <a href="https://mit-license.org/">
    <img src="https://img.shields.io/github/license/0xvpr/vpr-shell-shock?style=flat-square">
  </a>
  <br>
  <h3 align="center">Inspired by: Dark VortEx from bruteratel.com</h3>
  <br>
</p>

### How to use
One way to use the shellshock.h header is to:
- Create a 'Shellshock' object
- Resolve functions that you intend to use with the 'load_' member functions
- Utilize a singular function and make sure that all variables are created  
  on the stack

Once something like this is achieved, you can compile the binary to an object  
file and dump the `.text` section out to a whatever you like. That dump **should**  
be position independent.

### Integration Using CMake (MinGW)
```bash
git clone https://github.com/0xvpr/vpr-shell-shock.git
cd vpr-shell-shock
mkdir build && cd build
cmake .. -DCMAKE_INSTALL_PREFIX=</your/desired/path/>
make install
```

OR

```cmake
include(FetchContent)

FetchContent_Declare(
  vpr-shell-shock
  GIT_REPOSITORY https://github.com/0xvpr/vpr-shell-shock.git
  GIT_TAG main  # Or use a specific version tag like "v1.0.0"
)

FetchContent_MakeAvailable(vpr-shell-shock)

add_executable(myapp main.cpp)
target_link_libraries(myapp PRIVATE vpr-shell-shock::shell-shock)
```

### Quick Example
```cpp
#include "include/vpr/shellshock.h"

typedef int (WINAPI * MessageBoxA_t)(HWND, LPCSTR, LPCSTR, UINT);

extern "C" int payload_cpp(void) {
    auto ss = ss::shellshock();

    // Load target function into a temporary variable.
    char szMessageBoxA[] = "MessageBoxA";
    auto fMessageBoxA = ss.find_user32_func<MessageBoxA_t>(szMessageBoxA);
    
    // Perform function call
    char szTitle[] = "Shellshock";
    char szMessage[] = "Success.";
    fMessageBoxA && fMessageBoxA(nullptr, szMessage, szTitle, 0);

    return 0;
}
```

If you want the payload to be immediately exported to a file,  
you can do the following:
```cpp
// Payload that will be exported to shellcode
extern "C" auto payload() noexcept -> void { (...) }
// Immediately after the function ends
void stub() {
    return;
}

int main() {
    auto pd = ss::payload_data::build_from_payload(payload, stub);
    pd.extract_to_file("shellcode.bin");
}
```

### Compilation
Compiling this code to an executable **should** export the code to the specified  
file location.

Compiling this code to an object **should** mean that the `payload` function of  
the `.text` section is out new position independent executable.

NOTE: Compilation may fail if position-independent-code is not enabled AND/OR if function sections are enabled.
