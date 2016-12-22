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

enum command { RIGHT, LEFT, INC, DEC, SET, IN, OUT, BEGIN, END };
bool grouped[] = { 1, 1, 1, 1, 1, 0, 0, 0, 0 };
struct instruction { enum command cmd; size_t arg; };

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

static int
cin (void)
{
	int c = fgetc (input);
	assert (c != EOF);
	return c;
}

// - - Main  - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

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

		if (!parsed_len || !grouped[cmd] || parsed[parsed_len - 1].cmd != cmd)
			parsed_len++;

		parsed[parsed_len - 1].cmd = cmd;
		parsed[parsed_len - 1].arg++;
	}

// - - Simple optimization pass  - - - - - - - - - - - - - - - - - - - - - - - -

	size_t in = 0, out = 0;
	for (; in < parsed_len; in++, out++)
	{
		if (in + 2 < parsed_len
		 && parsed[in    ].cmd == BEGIN
		 && parsed[in + 1].cmd == DEC && parsed[in + 1].arg == 1
		 && parsed[in + 2].cmd == END)
		{
			parsed[out].cmd = SET;
			parsed[out].arg = 0;
			in += 2;
		}
		else if (out && parsed[out - 1].cmd == SET && parsed[in].cmd == INC)
			parsed[--out].arg += parsed[in].arg;
		else if (out != in)
			parsed[out] = parsed[in];
	}

	parsed_len = out;

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
			parsed[i].arg = stack[nesting] + 1;
		default:
			break;
		}
	}
	free (stack);
	assert (nesting == 0);

// - - JIT - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	// Functions preserve the registers rbx, rsp, rbp, r12, r13, r14, and r15;
	// while rax, rdi, rsi, rdx, rcx, r8, r9, r10, r11 are scratch registers.

	str_init (&program);
	size_t *offsets = xcalloc (sizeof *offsets, parsed_len + 1);

#define CODE(x) { char t[] = x; str_append_data (&program, t, sizeof t - 1); }
#define WORD(x) { size_t t = (size_t)(x); str_append_data (&program, &t, 8); }

	CODE ("\x49\xBD") WORD (&dataptr)         // mov r13, qword "&dataptr"
	CODE ("\x49\xBF") WORD (&data.str)        // mov r15, qword "&data.str"
	CODE ("\x4D\x8B\x37")                     // mov r14, qword [r15]
	CODE ("\x30\xDB")                         // xor bl, bl

	for (size_t i = 0; i < parsed_len; i++)
	{
		offsets[i] = program.len;

		size_t arg = parsed[i].arg;
		switch (parsed[i].cmd)
		{
		case RIGHT:
			CODE ("\x41\x88\x1E")             // mov [r14], bl
			CODE ("\x48\xBF") WORD (arg)      // mov rdi, "arg"
			CODE ("\x48\xB8") WORD (right)    // mov rax, "right"
			CODE ("\xFF\xD0")                 // call rax

			// The data could get reallocated, so reload the address
			CODE ("\x4D\x8B\x37")             // mov r14, qword [r15]
			CODE ("\x4D\x03\x75\x00")         // add r14, [r13]
			CODE ("\x41\x8A\x1E")             // mov bl, [r14]
			break;
		case LEFT:
			CODE ("\x41\x88\x1E")             // mov [r14], bl
			CODE ("\x48\xBF") WORD (arg)      // mov rdi, "arg"
			CODE ("\x49\x29\xFE")             // sub r14, rdi -- optimistic
			CODE ("\x48\xB8") WORD (left)     // mov rax, "left"
			CODE ("\xFF\xD0")                 // call rax
			CODE ("\x41\x8A\x1E")             // mov bl, [r14]
			break;

		case INC:
			CODE ("\x80\xC3")                 // add bl, "arg"
			str_append_c (&program, arg);
			break;
		case DEC:
			CODE ("\x80\xEB")                 // sub bl, "arg"
			str_append_c (&program, arg);
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
			CODE ("\x88\xC3")                 // mov bl, al
			break;

		case BEGIN:
			CODE ("\x84\xDB")                 // test bl, bl
			CODE ("\x0F\x84\x00\x00\x00\x00") // jz "offsets[i]"
			break;
		case END:
			CODE ("\x84\xDB")                 // test bl, bl
			CODE ("\x0F\x85\x00\x00\x00\x00") // jnz "offsets[i]"
			break;
		}
	}
	// When there is a loop at the end we need to be able to jump past it
	offsets[parsed_len] = program.len;
	str_append_c (&program, '\xC3');          // ret

	// Now that we know where each instruction is, fill in relative jumps
	for (size_t i = 0; i < parsed_len; i++)
	{
		if (parsed[i].cmd != BEGIN && parsed[i].cmd != END)
			continue;
		size_t fixup = offsets[i] + 4;
		*(int32_t *)(program.str + fixup) =
			((intptr_t)(offsets[parsed[i].arg]) - (intptr_t)(fixup + 4));
	}
	free (offsets);

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
