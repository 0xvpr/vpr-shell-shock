# Example Usages
The header can be used with C++17 and above, and C99 and above

## C++ API
```cpp
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
```

```cpp
extern "C" int payload_cpp(void) {
    // Skip the construction and Load target function into a temporary variable.
    char szMessageBoxA[] = "MessageBoxA";
    auto fMessageBoxA = ss::shellshock().find_user32_func<MessageBoxA_t>(szMessageBoxA);
    
    // Perform function call
    char szTitle[] = "Shellshock";
    char szMessage[] = "Success.";
    fMessageBoxA && fMessageBoxA(nullptr, szMessage, szTitle, 0);

    return 0;
}
```

## C API
```c
 int payload_c(void) {
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
```
