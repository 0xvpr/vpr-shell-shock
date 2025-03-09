#!/usr/bin/env python3

import os
from pathlib import Path

def make_finder_template(name: str) -> str:
    func_name = name.replace(".dll",'').replace('.','').replace('-','_')
    var_name = name.replace('.','').replace('-','_')

    return ( f"    template <typename FuncPtr> [[nodiscard]] __forceinline\n"
             f"    FuncPtr find_{func_name}_func(LPCSTR param) noexcept {{\n"
             f"        if (!{var_name}) {{\n"
             f"            load_{func_name}();\n"
             f"        }}\n"
             f"        return reinterpret_cast<FuncPtr>(get_symbol_address({var_name}, param));\n"
             f"    }}" )

def make_loader_function(name: str) -> str:
    func_name = name.replace(".dll",'').replace('.','').replace('-','_')
    var_name = name.replace('.','').replace('-','_')

    return ( f"    __forceinline void load_{func_name}() noexcept {{\n"
             f"        if (f_LoadLibraryA) {{\n"
             f"            char {var_name}_str[] = \"{name}\";\n"
             f"            {var_name} = f_LoadLibraryA({var_name}_str);\n"
             f"        }}\n"
             f"    }}" )

def make_variable(name: str) -> str:
    var_name = name.replace('.','').replace('-','_')

    return ( f"    UINT_PTR         {var_name};" )

def make_initializer_list_entry(name: str) -> str:
    var_name = name.replace('.','').replace('-','_')

    return ( f"        , {var_name}(0)" )

if __name__ == "__main__":
    system32 = Path( "/mnt/c/Windows/System32/" )
    libs = [x for x in os.listdir(system32) if ".dll" in x and not x[0] in "1234567890"]
    libs.remove("kernel32.dll") # special case where it is already resolved by hand

    # print 'find_func' templates
    # for lib in libs:
        # print( make_finder_template(lib) )

    # print 'loader' functions
    # for lib in libs:
        # print( make_loader_function(lib) )

    # print variable name
    # for lib in libs:
        # print( make_variable(lib) )

    # print variable initializer list
    for lib in libs:
        print( make_initializer_list_entry(lib) )
