#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <errno.h>

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

// --- Main --------------------------------------------------------------------

struct str program;                     ///< Raw program
struct str data;                        ///< Data tape

enum command { RIGHT, LEFT, INC, DEC, SET, IN, OUT, BEGIN, END };
bool grouped[] = { 1, 1, 1, 1, 1, 0, 0, 0, 0 };
struct instruction { enum command cmd; size_t arg; };

int
main (int argc, char *argv[])
{
	(void) argc; str_init (&program);
	(void) argv; str_init (&data);

	int c;
	while ((c = fgetc (stdin)) != EOF)
		str_append_c (&program, c);
	if (ferror (stdin))
		exit_fatal ("can't read program\n");

	FILE *input = fopen ("/dev/tty", "rb");
	if (!input)
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
			parsed[stack[nesting]].arg = i;
			parsed[i].arg = stack[nesting];
		default:
			break;
		}
	}
	assert (nesting == 0);

// - - Runtime - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	size_t dataptr = 0;
	str_append_c (&data, 0);

	for (size_t i = 0; i < parsed_len; i++)
	{
		size_t arg = parsed[i].arg;
		switch (parsed[i].cmd)
		{
		case RIGHT:
			assert (SIZE_MAX - dataptr > arg);
			dataptr += arg;

			while (dataptr >= data.len)
				str_append_c (&data, 0);
			break;
		case LEFT:
			assert (dataptr >= arg);
			dataptr -= arg;
			break;

		case INC: data.str[dataptr] += arg; break;
		case DEC: data.str[dataptr] -= arg; break;
		case SET: data.str[dataptr]  = arg; break;

		case OUT:
			fputc (data.str[dataptr], stdout);
			break;
		case IN:
			data.str[dataptr] = c = fgetc (input);
			assert (c != EOF);
			break;

		case BEGIN: if (!data.str[dataptr]) i = arg; break;
		case END:   if ( data.str[dataptr]) i = arg; break;
		}
	}
	return 0;
}
