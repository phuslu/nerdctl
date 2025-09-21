CC = gcc
CFLAGS = -Os -ffunction-sections -fdata-sections -fno-unwind-tables -fno-asynchronous-unwind-tables
LDFLAGS = -Wl,--gc-sections -s -static

nerdctl-internal-logging: main.c
	$(CC) $(CFLAGS) main.c -o nerdctl-internal-logging $(LDFLAGS)

clean:
	rm -f nerdctl-internal-logging

debug: main.c
	$(CC) -g -O0 main.c -o nerdctl-internal-logging-debug

.PHONY: clean debug
