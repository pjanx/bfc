# All we need is C99 and POSIX, which this should make available
CFLAGS = -std=gnu99
NAMES = bfc-amd64-linux

all: $(NAMES)

%: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@
clean:
	rm -f $(NAMES)

.PHONY: all clean
