CC ?= gcc
TARGET ?= server
SRC := server.c

PKG_CFLAGS := $(shell pkg-config --cflags open62541 2>/dev/null)
PKG_LIBS := $(shell pkg-config --libs open62541 2>/dev/null)
CFLAGS += -O2 -Wall -Wextra -std=c11 $(PKG_CFLAGS)
LDFLAGS += $(PKG_LIBS)

ifeq ($(strip $(PKG_LIBS)),)
LDFLAGS += -lopen62541
endif

all: build

build:
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)

run: build
	./$(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all build run clean
