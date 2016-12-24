CFLAGS = -std=gnu99 -O3

NAMES = bf bf-faster-loops bf-optimizing \
	bf-jit bf-jit-opt bf-jit-unsafe bf-jit-unsafe-opt

all: $(NAMES)

%: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@
clean:
	rm -f $(NAMES)

.PHONY: all clean
