// This is an exercise in futility more than anything else
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <errno.h>

#ifdef __unix__
#include <fcntl.h>
#endif

#define exit_fatal(...)                                                        \
	do {                                                                       \
		fprintf (stderr, "fatal: " __VA_ARGS__);                               \
		exit (EXIT_FAILURE);                                                   \
	} while (0)

// --- Safe memory management --------------------------------------------------

static void *
xcalloc (size_t m, size_t n)
{
	void *p = calloc (m, n);
	if (!p)
		exit_fatal ("calloc: %s\n", strerror (errno));
	return p;
}

static void *
xrealloc (void *o, size_t n)
{
	void *p = realloc (o, n);
	if (!p && n)
		exit_fatal ("realloc: %s\n", strerror (errno));
	return p;
}

// --- Dynamically allocated strings -------------------------------------------

struct str
{
	char *str;                          ///< String data, null terminated
	size_t alloc;                       ///< How many bytes are allocated
	size_t len;                         ///< How long the string actually is
};

static void
str_init (struct str *self)
{
	self->len = 0;
	self->str = xcalloc (1, (self->alloc = 16));
}

static void
str_ensure_space (struct str *self, size_t n)
{
	// We allocate at least one more byte for the terminating null character
	size_t new_alloc = self->alloc;
	while (new_alloc <= self->len + n)
		new_alloc <<= 1;
	if (new_alloc != self->alloc)
		self->str = xrealloc (self->str, (self->alloc = new_alloc));
}

static void
str_append_data (struct str *self, const void *data, size_t n)
{
	str_ensure_space (self, n);
	memcpy (self->str + self->len, data, n);
	self->str[self->len += n] = '\0';
}

static void
str_append_c (struct str *self, char c)
{
	str_append_data (self, &c, 1);
}

// --- Application -------------------------------------------------------------

enum command
{
	RIGHT, LEFT, INC, DEC, IN, OUT, BEGIN, END,
	SET, EAT, INCACC, DECACC
};

bool grouped[] = { 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0 };
struct instruction { enum command cmd; int offset; size_t arg; };
#define INSTRUCTION(c, o, a) (struct instruction) { (c), (o), (a) }

// - - Debugging - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

#ifdef DEBUG
static void
debug_dump_instruction (FILE *fp, const struct instruction *in)
{
	const char *name;
	switch (in->cmd)
	{
	case RIGHT:  name = "RIGHT "; break;
	case LEFT:   name = "LEFT  "; break;
	case INC:    name = "INC   "; break;
	case DEC:    name = "DEC   "; break;
	case OUT:    name = "OUT   "; break;
	case IN:     name = "IN    "; break;
	case BEGIN:  name = "BEGIN "; break;
	case END:    name = "END   "; break;
	case SET:    name = "SET   "; break;
	case EAT:    name = "EAT   "; break;
	case INCACC: name = "INCACC"; break;
	case DECACC: name = "DECACC"; break;
	}
	fprintf (fp, "%s %zu", name, in->arg);
	if (in->offset != 0)
		fprintf (fp, " [%d]", in->offset);
	fprintf (fp, "\n");
}

static void
debug_dump (const char *filename, struct instruction *in, size_t len)
{
	FILE *fp = fopen (filename, "w");
	long indent = 0;
	for (size_t i = 0; i < len; i++)
	{
		if (in[i].cmd == END)
			indent--;
		for (long k = 0; k < indent; k++)
			fputs ("  ", fp);
		debug_dump_instruction (fp, &in[i]);
		if (in[i].cmd == BEGIN)
			indent++;
	}
	fclose (fp);
}
#else
#define debug_dump(...)
#endif

// - - Optimization passes - - - - - - - - - - - - - - - - - - - - - - - - - - -

static size_t
optimize_assignment (struct instruction *irb, size_t irb_len)
{
	size_t in = 0, out = 0;
	for (; in < irb_len; in++, out++)
	{
		if (in + 2 < irb_len
		 && irb[in    ].cmd == BEGIN
		 && irb[in + 1].cmd == DEC && irb[in + 1].arg == 1
		 && irb[in + 2].cmd == END)
		{
			irb[out] = INSTRUCTION (SET, 0, 0);
			in += 2;
		}
		else if (out && irb[out - 1].cmd == SET && irb[in].cmd == INC)
			irb[--out].arg += irb[in].arg;
		else if (out != in)
			irb[out] = irb[in];
	}
	return out;
}

// Add the offset of the LEFT/RIGHT instruction to the accumulator
static bool
add_direction_offset (struct instruction *irb, intptr_t *acc)
{
	if (irb->cmd == RIGHT)
		*acc += irb->arg;
	else if (irb->cmd == LEFT)
		*acc -= (intptr_t) irb->arg;
	else
		return false;
	return true;
}

// Add offsets to INC/DEC/SET stuck between LEFT/RIGHT
// and compress the LEFT/RIGHT sequences
static size_t
optimize_offseted_inc_dec (struct instruction *irb, size_t irb_len)
{
	size_t in = 0, out = 0;
	for (in = 0, out = 0; in < irb_len; in++, out++)
	{
		intptr_t dir = 0;
		if (!add_direction_offset (&irb[in], &dir))
		{
			irb[out] = irb[in];
			continue;
		}

		while (in + 2 < irb_len)
		{
			// An immediate offset has its limits on x86-64
			if (dir < INT8_MIN || dir > INT8_MAX)
				break;
			intptr_t diff = 0;
			if (!add_direction_offset (&irb[in + 2], &diff))
				break;
			int cmd = irb[in + 1].cmd;
			if (cmd != INC && cmd != DEC && cmd != SET)
				break;

			irb[out] = irb[in + 1];
			irb[out].offset = dir;

			dir += diff;
			out += 1;
			in += 2;
		}

		for (; in + 1 < irb_len; in++)
			if (!add_direction_offset (&irb[in + 1], &dir))
				break;

		if (!dir)
			out--;
		else if (dir > 0)
			irb[out] = INSTRUCTION (RIGHT, 0, dir);
		else
			irb[out] = INSTRUCTION (LEFT, 0, -dir);
	}
	return out;
}

// Try to eliminate loops that eat a cell and add/subtract its value
// to/from some other cell
static size_t
optimize_inc_dec_loops (struct instruction *irb, size_t irb_len)
{
	size_t in = 0, out = 0;
	for (in = 0, out = 0; in < irb_len; in++, out++)
	{
		irb[out] = irb[in];
		if (irb[in].cmd != BEGIN)
			continue;

		bool ok = false;
		size_t count = 0;
		for (size_t k = in + 1; k < irb_len; k++)
		{
			if (irb[k].cmd == END)
			{
				ok = true;
				break;
			}
			if (irb[k].cmd != INC
			 && irb[k].cmd != DEC)
				break;
			count++;
		}
		if (!ok)
			continue;

		// Stable sort operations by their offsets, put [0] first
		bool sorted;
		do
		{
			sorted = true;
			for (size_t k = 1; k < count; k++)
			{
				if (irb[in + k].offset == 0)
					continue;
				if (irb[in + k + 1].offset != 0
				 && irb[in + k].offset <= irb[in + k + 1].offset)
					continue;

				struct instruction tmp = irb[in + k + 1];
				irb[in + k + 1] = irb[in + k];
				irb[in + k] = tmp;
				sorted = false;
			}
		}
		while (!sorted);

		// Abort the optimization on duplicate offsets (complication with [0])
		for (size_t k = 1; k < count; k++)
			if (irb[in + k].offset == irb[in + k + 1].offset)
				ok = false;
		// XXX: can't make the code longer either
		for (size_t k = 1; k <= count; k++)
			if (irb[in + k].arg != 1)
				ok = false;
		if (!ok
		 || irb[in + 1].cmd != DEC
		 || irb[in + 1].offset != 0)
			continue;

		int min_safe_left_offset = 0;
		if (in > 1 && irb[in - 1].cmd == RIGHT)
			min_safe_left_offset = -irb[in - 1].arg;

		bool cond_needed_for_safety = false;
		for (size_t k = 0; k < count; k++)
			if (irb[in + k + 1].offset < min_safe_left_offset)
			{
				cond_needed_for_safety = true;
				break;
			}

		in++;
		if (cond_needed_for_safety)
			out++;

		irb[out] = INSTRUCTION (EAT, 0, 0);
		for (size_t k = 1; k < count; k++)
			irb[out + k] = INSTRUCTION (irb[in + k].cmd == INC
				? INCACC : DECACC, irb[in + k].offset, 0);

		in += count;
		out += count;

		if (cond_needed_for_safety)
			irb[out] = INSTRUCTION (END, 0, 0);
		else
			out--;
	}
	return out;
}

// - - Loop pairing  - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

static void
pair_loops (struct instruction *irb, size_t irb_len)
{
	size_t nesting = 0;
	size_t *stack = xcalloc (sizeof *stack, irb_len);
	for (size_t i = 0; i < irb_len; i++)
	{
		switch (irb[i].cmd)
		{
		case BEGIN:
			stack[nesting++] = i;
			break;
		case END:
			if (nesting <= 0)
				exit_fatal ("unbalanced loops\n");

			--nesting;
			irb[stack[nesting]].arg = i + 1;

			// Looping can be disabled by optimizations
			if (irb[i].arg)
				irb[i].arg = stack[nesting] + 1;
		default:
			break;
		}
	}
	free (stack);

	if (nesting != 0)
		exit_fatal ("unbalanced loops\n");
}

// - - Main  - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

int
main (int argc, char *argv[])
{
	if (argc > 3)
		exit_fatal ("usage: %s [INPUT-FILE] [OUTPUT-FILE]\n", argv[0]);

	FILE *input_file = stdin;
	if (argc > 1 && !(input_file = fopen (argv[1], "r")))
		exit_fatal ("fopen: %s: %s\n", argv[1], strerror (errno));

	const char *output_path = "a.out";
	if (argc > 2)
		output_path = argv[2];

	struct str buffer;
	str_init (&buffer);

	int c;
	while ((c = fgetc (input_file)) != EOF)
		str_append_c (&buffer, c);
	if (ferror (input_file))
		exit_fatal ("can't read program\n");
	fclose (input_file);

// - - Decode, group and optimize  - - - - - - - - - - - - - - - - - - - - - - -

	// This is our Intermediate Representation Buffer
	struct instruction *irb = xcalloc (sizeof *irb, buffer.len);
	size_t irb_len = 0;

	for (size_t i = 0; i < buffer.len; i++)
	{
		enum command cmd;
		switch (buffer.str[i])
		{
		case '>': cmd = RIGHT; break;
		case '<': cmd = LEFT;  break;
		case '+': cmd = INC;   break;
		case '-': cmd = DEC;   break;
		case '.': cmd = OUT;   break;
		case ',': cmd = IN;    break;
		case '[': cmd = BEGIN; break;
		case ']': cmd = END;   break;
		default:  continue;
		}

		// The most basic optimization is to group identical commands together
		if (!irb_len || !grouped[cmd] || irb[irb_len - 1].cmd != cmd)
			irb_len++;

		irb[irb_len - 1].cmd = cmd;
		irb[irb_len - 1].arg++;
	}

	debug_dump ("bf-no-opt.txt",            irb, irb_len);
	irb_len = optimize_assignment          (irb, irb_len);
	debug_dump ("bf-pre-offsets.txt",       irb, irb_len);
	irb_len = optimize_offseted_inc_dec    (irb, irb_len);
	debug_dump ("bf-pre-incdec-unloop.txt", irb, irb_len);
	irb_len = optimize_inc_dec_loops       (irb, irb_len);
	debug_dump ("bf-optimized.txt",         irb, irb_len);
	pair_loops                             (irb, irb_len);
	debug_dump ("bf-final.txt",             irb, irb_len);

// - - Code generation - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	str_init (&buffer);
	size_t *offsets    = xcalloc (sizeof *offsets,    irb_len + 1);
	bool   *sets_flags = xcalloc (sizeof *sets_flags, irb_len);

#define CODE(x) { char t[] = x; str_append_data (&buffer, t, sizeof t - 1); }
#define LE(v) (uint8_t[]) { v, v>>8, v>>16, v>>24, v>>32, v>>40, v>>48, v>>56 }
#define DB(x) { uint64_t v = (x); str_append_data (&buffer, LE (v), 1); }
#define DW(x) { uint64_t v = (x); str_append_data (&buffer, LE (v), 2); }
#define DD(x) { uint64_t v = (x); str_append_data (&buffer, LE (v), 4); }
#define DQ(x) { uint64_t v = (x); str_append_data (&buffer, LE (v), 8); }

	enum
	{
		ELF_LOAD_CODE = 0x400000,             // where code is loaded (usual)
		ELF_LOAD_DATA = 0x800000              // where the tape is placed
	};

	CODE ("\xB8") DD (ELF_LOAD_DATA)          // mov rax, "ELF_LOAD_DATA"
	CODE ("\x30\xDB")                         // xor bl, bl

	for (size_t i = 0; i < irb_len; i++)
	{
		offsets[i] = buffer.len;

		size_t arg = irb[i].arg;
		assert (arg <= UINT32_MAX);

		int offset = irb[i].offset;
		assert (offset <= INT8_MAX && offset >= INT8_MIN);

		// Don't save what we've just loaded
		if (irb[i].cmd == LEFT || irb[i].cmd == RIGHT)
			if (i < 2 || i + 1 >= irb_len
			 || (irb[i - 2].cmd != LEFT && irb[i - 2].cmd != RIGHT)
			 || irb[i - 1].cmd != BEGIN
			 || irb[i + 1].cmd != END)
				CODE ("\x88\x18")             // mov [rax], bl

		switch (irb[i].cmd)
		{
		case RIGHT:
			// add rax, "arg" -- optimistic, no boundary checking
			if (arg > INT8_MAX) { CODE ("\x48\x05")     DD (arg) }
			else                { CODE ("\x48\x83\xC0") DB (arg) }
			break;
		case LEFT:
			// sub rax, "arg" -- optimistic, no boundary checking
			if (arg > INT8_MAX) { CODE ("\x48\x2D")     DD (arg) }
			else                { CODE ("\x48\x83\xE8") DB (arg) }
			break;

		case EAT:
			// NOTE: the kernel destroys rcx and r11 on syscalls,
			//   there must be no OUT or IN between EAT and INCACC/DECACC
			CODE ("\x88\xD9" "\x30\xDB")      // mov cl, bl; xor bl, bl
			sets_flags[i] = true;
			break;
		case INCACC:
			if (offset)
			{
				CODE ("\x00\x48") DB (offset) // add [rax+"offset"], cl
			}
			else
			{
				CODE ("\x00\xCB")             // add bl, cl
				sets_flags[i] = true;
			}
			break;
		case DECACC:
			if (offset)
			{
				CODE ("\x28\x48") DB (offset) // sub [rax+"offset"], cl
			}
			else
			{
				CODE ("\x28\xCB")             // sub bl, cl
				sets_flags[i] = true;
			}
			break;

		case INC:
			if (offset)
			{
				CODE ("\x80\x40") DB (offset) // add byte [rax+"offset"], "arg"
			}
			else
			{
				CODE ("\x80\xC3")             // add bl, "arg"
				sets_flags[i] = true;
			}
			DB (arg)
			break;
		case DEC:
			if (offset)
			{
				CODE ("\x80\x68") DB (offset) // sub byte [rax+"offset"], "arg"
			}
			else
			{
				CODE ("\x80\xEB")             // sub bl, "arg"
				sets_flags[i] = true;
			}
			DB (arg)
			break;
		case SET:
			if (offset)
			{
				CODE ("\xC6\x40") DB (offset) // mov byte [rax+"offset"], "arg"
			}
			else
				CODE ("\xB3")                 // mov bl, "arg"
			DB (arg)
			break;

		case OUT:
			CODE ("\xE8") DD (0)              // call "write"
			break;
		case IN:
			CODE ("\xE8") DD (0)              // call "read"
			break;

		case BEGIN:
			// Don't test the register when the flag has been set already;
			// this doesn't have much of an effect in practice
			if (!i || !sets_flags[i - 1])
				CODE ("\x84\xDB")             // test bl, bl
			CODE ("\x0F\x84\x00\x00\x00\x00") // jz "offsets[arg]"
			break;
		case END:
			// We know that the cell is zero, make this an "if", not a "loop";
			// this doesn't have much of an effect in practice
			if (!arg)
				break;

			if (!i || !sets_flags[i - 1])
				CODE ("\x84\xDB")             // test bl, bl
			CODE ("\x0F\x85\x00\x00\x00\x00") // jnz "offsets[arg]"
			break;
		}

		// No sense in reading it out when we overwrite it immediately;
		// this doesn't have much of an effect in practice
		if (irb[i].cmd == LEFT || irb[i].cmd == RIGHT)
			if (i + 1 >= irb_len
			 || irb[i + 1].cmd != SET
			 || irb[i + 1].offset != 0)
				CODE ("\x8A\x18")             // mov bl, [rax]
	}
	// When there is a loop at the end we need to be able to jump past it
	offsets[irb_len] = buffer.len;

	// Write an epilog which handles all the OS interfacing
	//
	// System V x86-64 ABI:
	//   rax <-> both syscall number and return value
	//   args -> rdi, rsi, rdx, r10, r8, r9
	//   trashed <- rcx, r11

#ifdef TARGET_OPENBSD
	enum { SYS_READ = 3, SYS_WRITE = 4, SYS_EXIT = 1 };
#elif defined TARGET_LINUX
	enum { SYS_READ = 0, SYS_WRITE = 1, SYS_EXIT = 60 };
#else
#error Target not supported
#endif

	CODE ("\xB8") DD (SYS_EXIT)  // mov eax, 0x3c
	CODE ("\x48\x31\xFF")        // xor rdi, rdi
	CODE ("\x0F\x05")            // syscall

	size_t fatal_offset = buffer.len;
	CODE ("\x48\x89\xF7")        // mov rdi, rsi -- use the string in rsi
	CODE ("\x30\xC0")            // xor al, al -- look for the nil byte
	CODE ("\x48\x31\xC9")        // xor rcx, rcx
	CODE ("\x48\xF7\xD1")        // not rcx -- start from -1
	CODE ("\xFC" "\xF2\xAE")     // cld; repne scasb -- decrement until found
	CODE ("\x48\xF7\xD1")        // not rcx
	CODE ("\x48\x8D\x51\xFF")    // lea rdx, [rcx-1] -- save length in rdx
	CODE ("\xB8") DD (SYS_WRITE) // mov eax, "SYS_WRITE"
	CODE ("\xBF") DD (2)         // mov edi, "STDERR_FILENO"
	CODE ("\x0F\x05")            // syscall

	CODE ("\xB8") DD (SYS_EXIT)  // mov eax, "SYS_EXIT"
	CODE ("\xBF") DD (1)         // mov edi, "EXIT_FAILURE"
	CODE ("\x0F\x05")            // syscall

	size_t read_offset = buffer.len;
	CODE ("\x50")                // push rax -- save tape position
	CODE ("\xB8") DD (SYS_READ)  // mov eax, "SYS_READ"
	CODE ("\xBF") DD (0)         // mov edi, "STDIN_FILENO"
	CODE ("\x66\x6A\x00")        // push word 0 -- the default value for EOF
	CODE ("\x48\x89\xE6")        // mov rsi, rsp -- the char starts at rsp
	CODE ("\xBA") DD (1)         // mov edx, 1 -- count
	CODE ("\x0F\x05")            // syscall
	CODE ("\x66\x5B")            // pop bx

	CODE ("\x48\x83\xF8\x00")    // cmp rax, 0
	CODE ("\x48\x8D\x35") DD (8) // lea rsi, [rel read_message]
	CODE ("\x0F\x8C")            // jl "fatal_offset" -- write failure message
	DD ((intptr_t) fatal_offset - (intptr_t) (buffer.len + 4))
	CODE ("\x58")                // pop rax -- restore tape position
	CODE ("\xC3")                // ret
	CODE ("fatal: read failed\n\0")

	size_t write_offset = buffer.len;
	CODE ("\x50")                // push rax -- save tape position
	CODE ("\xB8") DD (SYS_WRITE) // mov eax, "SYS_WRITE"
	CODE ("\xBF") DD (1)         // mov edi, "STDOUT_FILENO"
	CODE ("\x66\x53")            // push bx
	CODE ("\x48\x89\xE6")        // mov rsi, rsp -- the char starts at rsp
	CODE ("\xBA") DD (1)         // mov edx, 1 -- count
	CODE ("\x0F\x05")            // syscall
	CODE ("\x66\x5B")            // pop bx

	CODE ("\x48\x83\xF8\x00")    // cmp rax, 0
	CODE ("\x48\x8D\x35") DD (8) // lea rsi, [rel write_message]
	CODE ("\x0F\x8C")            // jl "fatal_offset" -- write failure message
	DD ((intptr_t) fatal_offset - (intptr_t) (buffer.len + 4))
	CODE ("\x58")                // pop rax -- restore tape position
	CODE ("\xC3")                // ret
	CODE ("fatal: write failed\n\0")

	// Now that we know where each instruction is, fill in relative jumps
	for (size_t i = 0; i < irb_len; i++)
	{
		if (!irb[i].arg)
			continue;

		// This must accurately reflect the code generators
		intptr_t target, fixup = offsets[i];
		if (irb[i].cmd == BEGIN || irb[i].cmd == END)
		{
			fixup += (i && sets_flags[i - 1]) ? 2 : 4;
			target = offsets[irb[i].arg];
		}
		else if (irb[i].cmd == IN)  { fixup++; target = read_offset;  }
		else if (irb[i].cmd == OUT) { fixup++; target = write_offset; }
		else continue;

		uint64_t v = target - (fixup + 4);
		memcpy (buffer.str + fixup, LE (v), 4);
	}
	free (offsets);
	free (sets_flags);

// - - Output  - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	// Now that we know how long the machine code is, we can write the header.
	// Note that for PIE we would need to depend on the dynamic linker, so no.
	//
	// Recommended reading:
	//   http://www.muppetlabs.com/~breadbox/software/tiny/teensy.html
	//   man 5 elf

	struct str code = buffer;
	str_init (&buffer);

	enum
	{
		ELF_HEADER_SIZE = 64,           // size of the ELF header
		ELF_PROGRAM_ENTRY_SIZE = 56,    // size of a program header
		ELF_SECTION_ENTRY_SIZE = 64,    // size of a section header
		ELF_META_SIZE = ELF_HEADER_SIZE + 2 * ELF_PROGRAM_ENTRY_SIZE
	};

	// ELF header
	CODE ("\x7F" "ELF\x02\x01\x01")     // ELF, 64-bit, little endian, v1
#ifdef TARGET_OPENBSD
	// OpenBSD either requires its ABI or a PT_NOTE with "OpenBSD" in it
	CODE ("\x0C\x00" "\0\0\0\0\0\0\0")  // OpenBSD ABI, v0, padding
#else
	CODE ("\x00\x00" "\0\0\0\0\0\0\0")  // Unix System V ABI, v0, padding
#endif
	DW (2) DW (62) DD (1)               // executable, x86-64, v1
	DQ (ELF_LOAD_CODE + ELF_META_SIZE)  // entry point address
	DQ (ELF_HEADER_SIZE) DQ (0)         // program, section header offset
	DD (0)                              // no processor-specific flags
	DW (ELF_HEADER_SIZE)                // ELF header size
	DW (ELF_PROGRAM_ENTRY_SIZE) DW (2)  // program hdr tbl entry size, count
	DW (ELF_SECTION_ENTRY_SIZE) DW (0)  // section hdr tbl entry size, count
	DW (0)                              // no section index for strings

	// Program header for code
	// The entry point address seems to require alignment, so map start of file
	DD (1) DD (5)                       // PT_LOAD, PF_R | PF_X
	DQ (0)                              // offset within the file
	DQ (ELF_LOAD_CODE)                  // address in virtual memory
	DQ (ELF_LOAD_CODE)                  // address in physical memory
	DQ (ELF_META_SIZE + code.len)       // length within the file
	DQ (ELF_META_SIZE + code.len)       // length within memory
	DQ (4096)                           // segment alignment

	// Program header for the tape
	DD (1) DD (6)                       // PT_LOAD, PF_R | PF_W
	DQ (0)                              // offset within the file
	DQ (ELF_LOAD_DATA)                  // address in virtual memory
	DQ (ELF_LOAD_DATA)                  // address in physical memory
	DQ (0)                              // length within the file
	DQ (1 << 20)                        // one megabyte of memory
	DQ (4096)                           // segment alignment

	// The section header table is optional and we don't need it for anything

	FILE *output_file;
#ifdef __unix__
	int output_fd;
	if ((output_fd = open (output_path, O_CREAT | O_WRONLY, 0777)) < 0)
		exit_fatal ("open: %s: %s\n", output_path, strerror (errno));
	if (!(output_file = fdopen (output_fd, "w")))
		exit_fatal ("fdopen: %s\n", strerror (errno));
#else
	if (!(output_file = fopen (output_path, "w")))
		exit_fatal ("fopen: %s: %s\n", output_path, strerror (errno));
#endif

	fwrite (buffer.str, buffer.len, 1, output_file);
	fwrite (code.str, code.len, 1, output_file);
	fclose (output_file);
	return 0;
}
