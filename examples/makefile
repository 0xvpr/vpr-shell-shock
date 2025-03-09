TARGET    = payload

CXX32     = i686-w64-mingw32-g++
CXX64     = x86_64-w64-mingw32-g++

CXXFLAGS  = -Ofast -std=c++2a -static \
            -Wall -Wextra -Werror -Wshadow -Wconversion \
            -fPIC -fno-function-sections \
            -fno-exceptions -fno-rtti \
            -I.. -I../include

LD32      = i686-w64-mingw32-ld
LD64      = x86_64-w64-mingw32-ld
LDFLAGS   = --entry=entry

ASM       = nasm
ASM32     = $(ASM) -f win32
ASM64     = $(ASM) -f win64

SRC       = src
BIN       = bin
BUILD     = build

all: target loader
target: bin build
loader: bin build

target: $(addprefix bin/,payload32.exe payload64.exe)
loader: $(addprefix build/,c_loader32.obj cpp_loader32.obj c_loader64.obj cpp_loader64.obj)
	$(LD32) $(LDFLAGS) build/c_loader32.obj -o   bin/c_loader32.exe
	$(LD32) $(LDFLAGS) build/cpp_loader32.obj -o bin/cpp_loader32.exe
	$(LD64) $(LDFLAGS) build/c_loader64.obj -o   bin/c_loader64.exe
	$(LD64) $(LDFLAGS) build/cpp_loader64.obj -o bin/cpp_loader64.exe

build/%32.obj: %32.asm
	bin/$(TARGET)32.exe
	$(ASM32) $^ -o $@

build/%64.obj: %64.asm
	bin/$(TARGET)64.exe
	$(ASM64) $^ -o $@

bin/%32.exe : %.cpp
	$(CXX32) $(CXXFLAGS) $^ -o $@

bin/%64.exe : %.cpp
	$(CXX64) $(CXXFLAGS) $^ -o $@

bin:
	mkdir -p bin

build:
	mkdir -p build

.PHONY : clean
clean:
	rm -f `find . -name "*.bin"`
	rm -f `find . -name "*.obj"`
	rm -f `find . -name "*.exe"`
