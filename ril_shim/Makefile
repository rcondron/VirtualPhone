# Build the VirtualPhone RIL shim
#
# The shim is compiled statically so it runs inside the redroid Android
# container without depending on bionic libc.

CC      ?= gcc
CFLAGS  ?= -static -O2 -Wall -Wextra -Wno-unused-parameter
LDFLAGS ?= -static -lpthread
TARGET  = ril_shim

.PHONY: all clean

all: $(TARGET)

$(TARGET): ril_shim.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET)
