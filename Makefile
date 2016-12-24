# All we need is C99 and POSIX, which this should make available
CFLAGS = -std=gnu99
NAMES = bfc-amd64-linux bfc-amd64-openbsd

all: $(NAMES)

%-linux: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ -DTARGET_LINUX
%-openbsd: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ -DTARGET_OPENBSD
clean:
	rm -f $(NAMES)

.PHONY: all clean
