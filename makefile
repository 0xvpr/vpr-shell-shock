TARGET   = shellshock

ASM      = nasm
ASFLAGS  = -f win64

CC       = x86_64-w64-mingw32-g++
CFLAGS   = -O3 -std=c++2a \
           -Wall -Wextra -Werror -Wshadow -Wconversion \
           -fno-exceptions -fno-rtti -fno-ident \
		   -fvisibility=hidden -fPIC \
           -IIncludes

LD       = x86_64-w64-mingw32-ld
LDFLAGS  = -s \
		   -epayload \
		   -nostdlib

BIN      = Bin
BUILD    = Build

SOURCE   = Sources
SOURCES  = $(wildcard $(SOURCE)/*.cpp)

OBJECT   = Build
OBJECTS  = $(patsubst $(SOURCE)/%.cpp,$(OBJECT)/%.obj,$(SOURCES))

all: $(OBJECTS)

$(TARGET) : $(OBJECTS) $(BIN) $(BUILD)
	$(LD) $(OBJECTS) $(LDFLAGS) -o $(BIN)/$(TARGET).exe

$(OBJECT)/%.obj : $(SOURCE)/%.asm
	$(ASM) $(ASFLAGS) $^ -o $@

$(OBJECT)/%.obj : $(SOURCE)/%.cpp
	$(CC) $(CFLAGS) -c $^ -o $@

.PHONY : $(BIN)
$(BIN):
	mkdir -p $@

.PHONY : $(BUILD)
$(BUILD):
	mkdir -p $@

.PHONY : clean
clean:
	rm -f `find ./ -name "*.bin"`
	rm -f `find ./build -name "*.obj"`
	rm -f `find ./bin -name "*.exe"`

.PHONY : extra-clean
extra-clean:
	rm -fr bin
	rm -fr build
