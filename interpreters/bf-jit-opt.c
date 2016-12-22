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

struct str data;                        ///< Data tape
volatile size_t dataptr;                ///< Current location on the tape
FILE *input;                            ///< User input

enum command { RIGHT, LEFT, INC, DEC, SET, IN, OUT, BEGIN, END,
	EAT, INCACC, DECACC };
bool grouped[] = { 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0 };
struct instruction { enum command cmd; size_t arg; };
#define INSTRUCTION(c, a) (struct instruction) { (c), (a) }

// - - Callbacks - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

// Some things I just really don't want to write in assembly even though it
// is effectively a big performance hit, eliminating the advantage of JIT

static void
right (size_t arg)
{
	assert (SIZE_MAX - dataptr > arg);
	dataptr += arg;

	while (dataptr >= data.len)
		str_append_c (&data, 0);
}

static void
left (size_t arg)
{
	assert (dataptr >= arg);
	dataptr -= arg;
}

static void
cin (void)
{
	int c;
	data.str[dataptr] = c = fgetc (input);
	assert (c != EOF);
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
		case RIGHT:  fprintf (fp, "RIGHT  %zu\n", in[i].arg); break;
		case LEFT:   fprintf (fp, "LEFT   %zu\n", in[i].arg); break;
		case INC:    fprintf (fp, "INC    %zu\n", in[i].arg); break;
		case DEC:    fprintf (fp, "DEC    %zu\n", in[i].arg); break;
		case OUT:    fprintf (fp, "OUT    %zu\n", in[i].arg); break;
		case IN:     fprintf (fp, "IN     %zu\n", in[i].arg); break;
		case BEGIN:  fprintf (fp, "BEGIN  %zu\n", in[i].arg); break;
		case END:    fprintf (fp, "END    %zu\n", in[i].arg); break;
		case SET:    fprintf (fp, "SET    %zu\n", in[i].arg); break;
		case EAT:    fprintf (fp, "EAT    %zu\n", in[i].arg); break;
		case INCACC: fprintf (fp, "INCACC %zu\n", in[i].arg); break;
		case DECACC: fprintf (fp, "DECACC %zu\n", in[i].arg); break;
		}
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
		// This shows up in mandelbrot.bf a lot but actually helps hanoi.bf
		if (in + 5 < parsed_len
		 && parsed[in].cmd == BEGIN && parsed[in + 5].cmd == END
		 && parsed[in + 1].cmd == DEC && parsed[in + 1].arg == 1

		 && parsed[in + 2].cmd == LEFT && parsed[in + 4].cmd == RIGHT
		 && parsed[in + 2].arg == parsed[in + 4].arg

		 && (parsed[in + 3].cmd == INC || parsed[in + 3].cmd == DEC)
		 && parsed[in + 3].arg == 1)
		{
			// This mustn't make the move when the cell is zero already
			parsed[out] = parsed[in];
			parsed[out + 1] = INSTRUCTION (EAT, 0);
			parsed[out + 2] = parsed[in + 2];
			parsed[out + 3] = INSTRUCTION
				(parsed[in + 3].cmd == INC ? INCACC : DECACC, 0);
			parsed[out + 4] = parsed[in + 4];
			// This disables the looping further in the code;
			// this doesn't have much of an effect in practice
			parsed[out + 5] = INSTRUCTION (END, 0);
			in += 5;
			out += 5;
		}
		// The simpler case that cannot crash and thus can avoid the loop
		else if (in + 5 < parsed_len
		 && parsed[in].cmd == BEGIN && parsed[in + 5].cmd == END
		 && parsed[in + 1].cmd == DEC && parsed[in + 1].arg == 1

		 && parsed[in + 2].cmd == RIGHT && parsed[in + 4].cmd == LEFT
		 && parsed[in + 2].arg == parsed[in + 4].arg

		 && (parsed[in + 3].cmd == INC || parsed[in + 3].cmd == DEC)
		 && parsed[in + 3].arg == 1)
		{
			parsed[out] = INSTRUCTION (EAT, 0);
			parsed[out + 1] = parsed[in + 2];
			parsed[out + 2] = INSTRUCTION
				(parsed[in + 3].cmd == INC ? INCACC : DECACC, 0);
			parsed[out + 3] = parsed[in + 4];
			in += 5;
			out += 3;
		}
		else if (in + 2 < parsed_len
		 && parsed[in    ].cmd == BEGIN
		 && parsed[in + 1].cmd == DEC && parsed[in + 1].arg == 1
		 && parsed[in + 2].cmd == END)
		{
			parsed[out] = INSTRUCTION (SET, 0);
			in += 2;
		}
		else if (out && parsed[out - 1].cmd == SET && parsed[in].cmd == INC)
			parsed[--out].arg += parsed[in].arg;
		else if (out != in)
			parsed[out] = parsed[in];
	}
	parsed_len = out;

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
			parsed[out] = INSTRUCTION (RIGHT, dir);
		else
			parsed[out] = INSTRUCTION (LEFT, -dir);
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

	CODE ("\x49\xBD") WORD (&dataptr)         // mov r13, qword "&dataptr"
	CODE ("\x49\xBF") WORD (&data.str)        // mov r15, qword "&data.str"
	CODE ("\x4D\x8B\x37")                     // mov r14, qword [r15]
	CODE ("\x30\xDB")                         // xor bl, bl

	for (size_t i = 0; i < parsed_len; i++)
	{
		offsets[i] = program.len;

		size_t arg = parsed[i].arg;
		assert (arg <= UINT32_MAX);
		switch (parsed[i].cmd)
		{
		case RIGHT:
			CODE ("\x41\x88\x1E")             // mov [r14], bl
			CODE ("\xBF") DWRD (arg)          // mov edi, "arg"
			CODE ("\x48\xB8") WORD (right)    // mov rax, "right"
			CODE ("\xFF\xD0")                 // call rax

			// The data could get reallocated, so reload the address
			CODE ("\x4D\x8B\x37")             // mov r14, qword [r15]
			CODE ("\x4D\x03\x75\x00")         // add r14, [r13]
			break;
		case LEFT:
			CODE ("\x41\x88\x1E")             // mov [r14], bl
			CODE ("\xBF") DWRD (arg)          // mov edi, "arg"
			CODE ("\x49\x29\xFE")             // sub r14, rdi -- optimistic
			CODE ("\x48\xB8") WORD (left)     // mov rax, "left"
			CODE ("\xFF\xD0")                 // call rax
			break;

		case EAT:
			CODE ("\x41\x88\xDC")             // mov r12b, bl
			CODE ("\x30\xDB")                 // xor bl, bl
			arith[i] = 1;
			break;
		case INCACC:
			CODE ("\x44\x00\xE3")             // add bl, r12b
			arith[i] = 1;
			break;
		case DECACC:
			CODE ("\x44\x28\xE3")             // sub bl, r12b
			arith[i] = 1;
			break;

		case INC:
			CODE ("\x80\xC3")                 // add bl, "arg"
			str_append_c (&program, arg);
			arith[i] = 1;
			break;
		case DEC:
			CODE ("\x80\xEB")                 // sub bl, "arg"
			str_append_c (&program, arg);
			arith[i] = 1;
			break;
		case SET:
			CODE ("\xB3")                     // mov bl, "arg"
			str_append_c (&program, arg);
			break;

		case OUT:
			CODE ("\x48\x0F\xB6\xFB")         // movzx rdi, bl
			CODE ("\x48\xBE") WORD (stdout)   // mov rsi, "stdout"
			CODE ("\x48\xB8") WORD (fputc)    // mov rax, "fputc"
			CODE ("\xFF\xD0")                 // call rax
			break;
		case IN:
			CODE ("\x48\xB8") WORD (cin)      // mov rax, "cin"
			CODE ("\xFF\xD0")                 // call rax
			CODE ("\x41\x8A\x1E")             // mov bl, [r14]
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
			 || parsed[i + 1].cmd != SET)
				CODE ("\x41\x8A\x1E")         // mov bl, [r14]
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

	str_init (&data);
	str_append_c (&data, 0);
	((void (*) (void)) executable)();
	return 0;
}
