// This is an exercise in futility more than anything else
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <errno.h>

#if (defined __x86_64__ || defined __amd64__) && defined __unix__
	#include <unistd.h>
	#include <sys/mman.h>
#else
	#error Platform not supported
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

enum command { RIGHT, LEFT, INC, DEC, SET, IN, OUT, BEGIN, END,
	EAT, INCACC, DECACC };
bool grouped[] = { 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0 };
struct instruction { enum command cmd; int offset; size_t arg; };
#define INSTRUCTION(c, o, a) (struct instruction) { (c), (o), (a) }

// - - Callbacks - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

FILE *input;                            ///< User input

static int
cin (void)
{
	int c = fgetc (input);
	assert (c != EOF);
	return c;
}

// - - Main  - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

#ifdef DEBUG
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
			fprintf (fp, "  ");

		switch (in[i].cmd)
		{
		case RIGHT:  fputs ("RIGHT ", fp); break;
		case LEFT:   fputs ("LEFT  ", fp); break;
		case INC:    fputs ("INC   ", fp); break;
		case DEC:    fputs ("DEC   ", fp); break;
		case OUT:    fputs ("OUT   ", fp); break;
		case IN:     fputs ("IN    ", fp); break;
		case BEGIN:  fputs ("BEGIN ", fp); break;
		case END:    fputs ("END   ", fp); break;
		case SET:    fputs ("SET   ", fp); break;
		case EAT:    fputs ("EAT   ", fp); break;
		case INCACC: fputs ("INCACC", fp); break;
		case DECACC: fputs ("DECACC", fp); break;
		}
		fprintf (fp, " %zu [%d]\n", in[i].arg, in[i].offset);
		if (in[i].cmd == BEGIN)
			indent++;
	}
	fclose (fp);
}
#else
#define debug_dump(...)
#endif

int
main (int argc, char *argv[])
{
	(void) argc;
	(void) argv;

	struct str program;
	str_init (&program);

	int c;
	while ((c = fgetc (stdin)) != EOF)
		str_append_c (&program, c);
	if (ferror (stdin))
		exit_fatal ("can't read program\n");
	if (!(input = fopen ("/dev/tty", "rb")))
		exit_fatal ("can't open terminal for reading\n");

// - - Decode and group  - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	struct instruction *parsed = xcalloc (sizeof *parsed, program.len);
	size_t parsed_len = 0;

	for (size_t i = 0; i < program.len; i++)
	{
		enum command cmd;
		switch (program.str[i])
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
		if (!parsed_len || !grouped[cmd] || parsed[parsed_len - 1].cmd != cmd)
			parsed_len++;

		parsed[parsed_len - 1].cmd = cmd;
		parsed[parsed_len - 1].arg++;
	}

// - - Optimization passes - - - - - - - - - - - - - - - - - - - - - - - - - - -

	debug_dump ("bf-no-opt.txt", parsed, parsed_len);

	size_t in = 0, out = 0;
	for (; in < parsed_len; in++, out++)
	{
		if (in + 2 < parsed_len
		 && parsed[in    ].cmd == BEGIN
		 && parsed[in + 1].cmd == DEC && parsed[in + 1].arg == 1
		 && parsed[in + 2].cmd == END)
		{
			parsed[out] = INSTRUCTION (SET, 0, 0);
			in += 2;
		}
		else if (out && parsed[out - 1].cmd == SET && parsed[in].cmd == INC)
			parsed[--out].arg += parsed[in].arg;
		else if (out != in)
			parsed[out] = parsed[in];
	}
	parsed_len = out;

	debug_dump ("bf-pre-offsets.txt", parsed, parsed_len);

	// Add offsets to INC/DEC/SET stuck between LEFT/RIGHT
	// and compress the LEFT/RIGHT sequences
	for (in = 0, out = 0; in < parsed_len; in++, out++)
	{
		ssize_t dir = 0;
		if (parsed[in].cmd == RIGHT)
			dir = parsed[in].arg;
		else if (parsed[in].cmd == LEFT)
			dir = -(ssize_t) parsed[in].arg;
		else
		{
			parsed[out] = parsed[in];
			continue;
		}

		while (in + 2 < parsed_len)
		{
			// An immediate offset has its limits
			if (dir < INT8_MIN || dir > INT8_MAX)
				break;

			ssize_t diff;
			if (parsed[in + 2].cmd == RIGHT)
				diff = parsed[in + 2].arg;
			else if (parsed[in + 2].cmd == LEFT)
				diff = -(ssize_t) parsed[in + 2].arg;
			else
				break;

			int cmd = parsed[in + 1].cmd;
			if (cmd != INC && cmd != DEC && cmd != SET)
				break;

			parsed[out] = parsed[in + 1];
			parsed[out].offset = dir;

			dir += diff;
			out += 1;
			in += 2;
		}

		for (; in + 1 < parsed_len; in++)
		{
			if (parsed[in + 1].cmd == RIGHT)
				dir += parsed[in + 1].arg;
			else if (parsed[in + 1].cmd == LEFT)
				dir -= (ssize_t) parsed[in + 1].arg;
			else
				break;
		}

		if (!dir)
			out--;
		else if (dir > 0)
			parsed[out] = INSTRUCTION (RIGHT, 0, dir);
		else
			parsed[out] = INSTRUCTION (LEFT, 0, -dir);
	}
	parsed_len = out;

	debug_dump ("bf-pre-incdec-unloop.txt", parsed, parsed_len);

	// Try to eliminate loops that eat a cell and add/subtract its value
	// to/from some other cell
	for (in = 0, out = 0; in < parsed_len; in++, out++)
	{
		parsed[out] = parsed[in];
		if (parsed[in].cmd != BEGIN)
			continue;

		bool ok = false;
		size_t count = 0;
		for (size_t k = in + 1; k < parsed_len; k++)
		{
			if (parsed[k].cmd == END)
			{
				ok = true;
				break;
			}
			if (parsed[k].cmd != INC
			 && parsed[k].cmd != DEC)
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
				if (parsed[in + k].offset == 0)
					continue;
				if (parsed[in + k + 1].offset != 0
				 && parsed[in + k].offset <= parsed[in + k + 1].offset)
					continue;

				struct instruction tmp = parsed[in + k + 1];
				parsed[in + k + 1] = parsed[in + k];
				parsed[in + k] = tmp;
				sorted = false;
			}
		}
		while (!sorted);

		// Abort the optimization on duplicate offsets (complication with [0])
		for (size_t k = 1; k < count; k++)
			if (parsed[in + k].offset == parsed[in + k + 1].offset)
				ok = false;
		// XXX: can't make the code longer either
		for (size_t k = 1; k <= count; k++)
			if (parsed[in + k].arg != 1)
				ok = false;
		if (!ok
		 || parsed[in + 1].cmd != DEC
		 || parsed[in + 1].offset != 0)
			continue;

		int min_safe_left_offset = 0;
		if (in > 1 && parsed[in - 1].cmd == RIGHT)
			min_safe_left_offset = -parsed[in - 1].arg;

		bool cond_needed_for_safety = false;
		for (size_t k = 0; k < count; k++)
			if (parsed[in + k + 1].offset < min_safe_left_offset)
			{
				cond_needed_for_safety = true;
				break;
			}

		in++;
		if (cond_needed_for_safety)
			out++;

		parsed[out] = INSTRUCTION (EAT, 0, 0);
		for (size_t k = 1; k < count; k++)
			parsed[out + k] = INSTRUCTION (parsed[in + k].cmd == INC
				? INCACC : DECACC, parsed[in + k].offset, 0);

		in += count;
		out += count;

		if (cond_needed_for_safety)
			parsed[out] = INSTRUCTION (END, 0, 0);
		else
			out--;
	}
	parsed_len = out;

	debug_dump ("bf-optimized.txt", parsed, parsed_len);

// - - Loop pairing  - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	size_t nesting = 0;
	size_t *stack = xcalloc (sizeof *stack, parsed_len);
	for (size_t i = 0; i < parsed_len; i++)
	{
		switch (parsed[i].cmd)
		{
		case BEGIN:
			stack[nesting++] = i;
			break;
		case END:
			assert (nesting > 0);

			--nesting;
			parsed[stack[nesting]].arg = i + 1;

			// Looping can be disabled by optimizations
			if (parsed[i].arg)
				parsed[i].arg = stack[nesting] + 1;
		default:
			break;
		}
	}
	free (stack);
	assert (nesting == 0);

	debug_dump ("bf-final.txt", parsed, parsed_len);

// - - JIT - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	// Functions preserve the registers rbx, rsp, rbp, r12, r13, r14, and r15;
	// while rax, rdi, rsi, rdx, rcx, r8, r9, r10, r11 are scratch registers.

	str_init (&program);
	size_t *offsets = xcalloc (sizeof *offsets, parsed_len + 1);
	uint8_t *arith  = xcalloc (sizeof *arith,   parsed_len);

#define CODE(x) { char t[] = x; str_append_data (&program, t, sizeof t - 1); }
#define WORD(x) { size_t t = (size_t)(x); str_append_data (&program, &t, 8); }
#define DWRD(x) { size_t t = (size_t)(x); str_append_data (&program, &t, 4); }

	CODE ("\x48\x89\xF8")                     // mov rax, rdi
	CODE ("\x30\xDB")                         // xor bl, bl

	for (size_t i = 0; i < parsed_len; i++)
	{
		offsets[i] = program.len;

		size_t arg = parsed[i].arg;
		assert (arg <= UINT32_MAX);

		int offset = parsed[i].offset;
		assert (offset <= INT8_MAX && offset >= INT8_MIN);

		// Don't save what we've just loaded
		if (parsed[i].cmd == LEFT || parsed[i].cmd == RIGHT)
			if (i < 2 || i + 1 >= parsed_len
			 || (parsed[i - 2].cmd != LEFT && parsed[i - 2].cmd != RIGHT)
			 || parsed[i - 1].cmd != BEGIN
			 || parsed[i + 1].cmd != END)
				CODE ("\x88\x18")             // mov [rax], bl

		switch (parsed[i].cmd)
		{
		case RIGHT:
			// add rax, "arg" -- optimistic, no boundary checking
			if (arg > INT8_MAX)
				{ CODE ("\x48\x05")     DWRD (arg) }
			else
				{ CODE ("\x48\x83\xC0") str_append_c (&program, arg); }
			break;
		case LEFT:
			// sub rax, "arg" -- optimistic, no boundary checking
			if (arg > INT8_MAX)
				{ CODE ("\x48\x2D")     DWRD (arg) }
			else
				{ CODE ("\x48\x83\xE8") str_append_c (&program, arg); }
			break;

		case EAT:
			CODE ("\x41\x88\xDC")             // mov r12b, bl
			CODE ("\x30\xDB")                 // xor bl, bl
			arith[i] = 1;
			break;
		case INCACC:
			if (offset)
			{
				CODE ("\x44\x00\x60")         // add [rax+"offset"], r12b
				str_append_c (&program, offset);
			}
			else
			{
				CODE ("\x44\x00\xE3")         // add bl, r12b
				arith[i] = 1;
			}
			break;
		case DECACC:
			if (offset)
			{
				CODE ("\x44\x28\x60")         // sub [rax+"offset"], r12b
				str_append_c (&program, offset);
			}
			else
			{
				CODE ("\x44\x28\xE3")         // sub bl, r12b
				arith[i] = 1;
			}
			break;

		case INC:
			if (offset)
			{
				CODE ("\x80\x40")             // add byte [rax+"offset"], "arg"
				str_append_c (&program, offset);
			}
			else
			{
				arith[i] = 1;
				CODE ("\x80\xC3")             // add bl, "arg"
			}
			str_append_c (&program, arg);
			break;
		case DEC:
			if (offset)
			{
				CODE ("\x80\x68")             // sub byte [rax+"offset"], "arg"
				str_append_c (&program, offset);
			}
			else
			{
				arith[i] = 1;
				CODE ("\x80\xEB")             // sub bl, "arg"
			}
			str_append_c (&program, arg);
			break;
		case SET:
			if (offset)
			{
				CODE ("\xC6\x40")             // mov byte [rax+"offset"], "arg"
				str_append_c (&program, offset);
			}
			else
				CODE ("\xB3")                 // mov bl, "arg"
			str_append_c (&program, arg);
			break;

		case OUT:
			CODE ("\x50\x53")                 // push rax, push rbx
			CODE ("\x48\x0F\xB6\xFB")         // movzx rdi, bl
			CODE ("\x48\xBE") WORD (stdout)   // mov rsi, "stdout"
			CODE ("\x48\xB8") WORD (fputc)    // mov rax, "fputc"
			CODE ("\xFF\xD0")                 // call rax
			CODE ("\x5B\x58")                 // pop rbx, pop rax
			break;
		case IN:
			CODE ("\x50")                     // push rax
			CODE ("\x48\xB8") WORD (cin)      // mov rax, "cin"
			CODE ("\xFF\xD0")                 // call rax
			CODE ("\x88\xC3")                 // mov bl, al
			CODE ("\x58")                     // pop rax
			break;

		case BEGIN:
			// Don't test the register when the flag has been set already;
			// this doesn't have much of an effect in practice
			if (!i || !arith[i - 1])
				CODE ("\x84\xDB")             // test bl, bl
			CODE ("\x0F\x84\x00\x00\x00\x00") // jz "offsets[i]"
			break;
		case END:
			// We know that the cell is zero, make this an "if", not a "loop";
			// this doesn't have much of an effect in practice
			if (!arg)
				break;

			if (!i || !arith[i - 1])
				CODE ("\x84\xDB")             // test bl, bl
			CODE ("\x0F\x85\x00\x00\x00\x00") // jnz "offsets[i]"
			break;
		}

		// No sense in reading it out when we overwrite it immediately;
		// this doesn't have much of an effect in practice
		if (parsed[i].cmd == LEFT || parsed[i].cmd == RIGHT)
			if (i + 1 >= parsed_len
			 || parsed[i + 1].cmd != SET
			 || parsed[i + 1].offset != 0)
				CODE ("\x8A\x18")             // mov bl, [rax]
	}
	// When there is a loop at the end we need to be able to jump past it
	offsets[parsed_len] = program.len;
	str_append_c (&program, '\xC3');          // ret

	// Now that we know where each instruction is, fill in relative jumps;
	// this must accurately reflect code generators for BEGIN and END
	for (size_t i = 0; i < parsed_len; i++)
	{
		if ((parsed[i].cmd != BEGIN && parsed[i].cmd != END)
		 || !parsed[i].arg)
			continue;

		size_t fixup = offsets[i] + 2;
		if (!i || !arith[i - 1])
			fixup += 2;

		*(int32_t *)(program.str + fixup) =
			((intptr_t)(offsets[parsed[i].arg]) - (intptr_t)(fixup + 4));
	}
	free (offsets);
	free (arith);

#ifdef DEBUG
	FILE *bin = fopen ("bf-jit.bin", "w");
	fwrite (program.str, program.len, 1, bin);
	fclose (bin);
#endif

// - - Runtime - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	// Some systems may have W^X
	void *executable = mmap (NULL, program.len, PROT_READ | PROT_WRITE,
		MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (!executable)
		exit_fatal ("mmap: %s\n", strerror (errno));

	memcpy (executable, program.str, program.len);
	if (mprotect (executable, program.len, PROT_READ | PROT_EXEC))
		exit_fatal ("mprotect: %s\n", strerror (errno));

	// We create crash zones on both ends of the tape for some minimum safety
	long pagesz = sysconf (_SC_PAGESIZE);
	assert (pagesz > 0);

	const size_t tape_len = (1 << 20) + 2 * pagesz;
	char *tape = mmap (NULL, tape_len, PROT_READ | PROT_WRITE,
		MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (!tape)
		exit_fatal ("mmap: %s\n", strerror (errno));

	memset (tape, 0, tape_len);
	if (mprotect (tape,                     pagesz, PROT_NONE)
	 || mprotect (tape + tape_len - pagesz, pagesz, PROT_NONE))
		exit_fatal ("mprotect: %s\n", strerror (errno));

	((void (*) (char *)) executable)(tape + pagesz);
	return 0;
}
