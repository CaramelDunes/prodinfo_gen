rwildcard = $(foreach d, $(wildcard $1*), $(filter $(subst *, %, $2), $d) $(call rwildcard, $d/, $2))

ifeq ($(strip $(DEVKITARM)),)
$(error "Please set DEVKITARM in your environment. export DEVKITARM=<path to>devkitARM")
endif

include $(DEVKITARM)/base_rules

################################################################################

IPL_LOAD_ADDR := 0x40003000
LPVERSION_MAJOR := 0
LPVERSION_MINOR := 1
LPVERSION_BUGFX := 2

################################################################################

TARGET := prodinfo_gen
BUILDDIR := build
OUTPUTDIR := output
SOURCEDIR = source

OBJS =	$(patsubst $(SOURCEDIR)/%.S, $(BUILDDIR)/$(TARGET)/%.o, \
		$(patsubst $(SOURCEDIR)/%.c, $(BUILDDIR)/$(TARGET)/%.o, \
		$(call rwildcard, $(SOURCEDIR), *.S *.c)))

################################################################################

CUSTOMDEFINES := -DIPL_LOAD_ADDR=$(IPL_LOAD_ADDR)
CUSTOMDEFINES += -DLP_VER_MJ=$(LPVERSION_MAJOR) -DLP_VER_MN=$(LPVERSION_MINOR) -DLP_VER_BF=$(LPVERSION_BUGFX)

ARCH := -march=armv4t -mtune=arm7tdmi -mthumb -mthumb-interwork
CFLAGS = $(ARCH) -O2 -nostdlib -ffunction-sections -fno-inline -fdata-sections -fomit-frame-pointer -std=gnu11 -Wall $(CUSTOMDEFINES)
LDFLAGS = $(ARCH) -nostartfiles -lgcc -Wl,--nmagic,--gc-sections -Xlinker --defsym=IPL_LOAD_ADDR=$(IPL_LOAD_ADDR)

################################################################################

.PHONY: all clean

all: $(OUTPUTDIR)/$(TARGET).bin

clean:
	@rm -rf $(BUILDDIR)
	@rm -rf $(OUTPUTDIR)

$(OUTPUTDIR)/$(TARGET).bin: $(BUILDDIR)/$(TARGET)/$(TARGET).elf
	@mkdir -p "$(@D)"
	$(OBJCOPY) -S -O binary $< $@
	@echo -n "Payload size is "
	@wc -c < $@
	@echo "Max size is 126296 Bytes."

$(BUILDDIR)/$(TARGET)/$(TARGET).elf: $(OBJS)
	$(CC) $(LDFLAGS) -T $(SOURCEDIR)/link.ld $^ -o $@

$(BUILDDIR)/$(TARGET)/%.o: $(SOURCEDIR)/%.c
	@mkdir -p "$(@D)"
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILDDIR)/$(TARGET)/%.o: $(SOURCEDIR)/%.S
	@mkdir -p "$(@D)"
	$(CC) $(CFLAGS) -c $< -o $@
