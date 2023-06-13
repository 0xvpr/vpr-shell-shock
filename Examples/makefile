TARGET   = payload

CC       = x86_64-w64-mingw32-g++
CFLAGS   = -O2 -std=c++2a \
           -Wall -Wextra -Werror -Wshadow -Wconversion \
           -fno-exceptions -fno-rtti -fno-ident \
           -ffunction-sections \
           -fvisibility=hidden -fPIC \
           -I..

all: target
target: $(TARGET).obj loader.obj
	x86_64-w64-mingw32-ld loader.obj payload.obj -o loader.exe

%.obj: %.asm
	nasm -f win64 loader.asm -o loader.obj

%.obj : %.cpp
	$(CC) $(CFLAGS) -c $^ -o $@

.PHONY : clean
clean:
	rm -f `find . -name "*.bin"`
	rm -f `find . -name "*.obj"`
	rm -f `find . -name "*.exe"`
