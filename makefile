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
		   -nostdlib --section-alignment=16 --file-alignment=16

BIN      = Bin
BUILD    = Build

SOURCE   = Sources
SOURCES  = $(wildcard $(SOURCE)/*.cpp)

OBJECT   = Build
OBJECTS  = $(patsubst $(SOURCE)/%.cpp,$(OBJECT)/%.obj,$(SOURCES))

all: $(BIN)
all: $(BUILD)
all: $(OBJECTS)
target: $(TARGET)

$(TARGET) : $(BIN) $(BUILD) $(OBJECTS)
	$(LD) $(OBJECTS) $(LDFLAGS) -o $(BIN)/$(TARGET).exe

$(OBJECT)/%.obj : $(SOURCE)/%.asm
	$(ASM) $(ASFLAGS) $^ -o $@

$(OBJECT)/%.obj : $(SOURCE)/%.cpp
	$(CC) $(CFLAGS) -c $^ -o $@

$(BIN):
	mkdir -p $@

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
