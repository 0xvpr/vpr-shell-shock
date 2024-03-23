TARGET    = payload

CXX32     = i686-w64-mingw32-g++
CXX64     = x86_64-w64-mingw32-g++

CXXFLAGS  = -Ofast -std=c++2a -static \
            -Wall -Wextra -Werror -Wshadow -Wconversion \
            -fPIC -fno-function-sections \
            -fno-exceptions -fno-rtti \
		    -fno-ident -fvisibility=hidden \
            -I..

LD32      = i686-w64-mingw32-ld
LD64      = x86_64-w64-mingw32-ld

ASM       = nasm
ASM32     = $(ASM) -f win32
ASM64     = $(ASM) -f win64

SRC       = src
BIN       = bin
BUILD     = build

all: target loader

target: payload32.exe payload64.exe 
loader: c_loader32.obj cpp_loader32.obj c_loader64.obj cpp_loader64.obj
	$(LD32) $(LDFLAGS) c_loader32.obj -o c_loader32.exe
	$(LD32) $(LDFLAGS) cpp_loader32.obj -o cpp_loader32.exe
	$(LD64) $(LDFLAGS) c_loader64.obj -o c_loader64.exe
	$(LD64) $(LDFLAGS) cpp_loader64.obj -o cpp_loader64.exe

%32.obj: %32.asm
	./$(TARGET)32.exe
	$(ASM32) $^ -o $@

%64.obj: %64.asm
	./$(TARGET)64.exe
	$(ASM64) $^ -o $@

%32.exe : %.cpp
	$(CXX32) $(CXXFLAGS) $^ -o $@

%64.exe : %.cpp
	$(CXX64) $(CXXFLAGS) $^ -o $@

.PHONY : clean
clean:
	rm -f `find . -name "*.bin"`
	rm -f `find . -name "*.obj"`
	rm -f `find . -name "*.exe"`