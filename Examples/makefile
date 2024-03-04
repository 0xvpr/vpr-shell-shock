TARGET   = payload

CC32     = i686-w64-mingw32-g++
CC64     = x86_64-w64-mingw32-g++
CFLAGS   = -O3 -std=c++2a \
           -Wall -Wextra -Werror -Wshadow -Wconversion \
           -nostdinc++ -fno-exceptions -fno-rtti -fno-ident \
           -fvisibility=hidden -fPIC \
           -I..

LD32     = i686-w64-mingw32-ld
LD64     = x86_64-w64-mingw32-ld
LDFLAGS  =

ASM32    = nasm -f win32
ASM64    = nasm -f win64

SRC      = src
BIN      = bin
BUILD    = build

all: target

target: $(TARGET)32.obj $(TARGET)64.obj loader32.obj loader64.obj
	$(LD32) $(LDFLAGS) loader32.obj payload32.obj -o example32.exe
	$(LD64) $(LDFLAGS) loader64.obj payload64.obj -o example64.exe

%32.obj: %32.asm
	$(ASM32) $^ -o $@

%64.obj: %64.asm
	$(ASM64) $^ -o $@

%32.obj : %.cpp
	$(CC32) $(CFLAGS) -c $^ -o $@

%64.obj : %.cpp
	$(CC64) $(CFLAGS) -c $^ -o $@

.PHONY : clean
clean:
	rm -f `find . -name "*.bin"`
	rm -f `find . -name "*.obj"`
	rm -f `find . -name "*.exe"`
