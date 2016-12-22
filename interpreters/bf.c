#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <errno.h>

#define exit_fatal(...)                                                        \
	do {                                                                       \
		fprintf (stderr, "fatal: " __VA_ARGS__);                               \
		exit (EXIT_FAILURE);                                                   \
	} while (0)

// --- Safe memory management --------------------------------------------------

static void *
xmalloc (size_t n)
{
	void *p = malloc (n);
	if (!p)
		exit_fatal ("malloc: %s\n", strerror (errno));
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
	self->alloc = 16;
	self->len = 0;
	self->str = strcpy (xmalloc (self->alloc), "");
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
	self->len += n;
	self->str[self->len] = '\0';
}

static void
str_append_c (struct str *self, char c)
{
	str_append_data (self, &c, 1);
}

// --- Main --------------------------------------------------------------------

int
main (int argc, char *argv[])
{
	struct str program; str_init (&program);
	struct str data;    str_init (&data);

	int c;
	while ((c = fgetc (stdin)) != EOF)
		str_append_c (&program, c);
	if (ferror (stdin))
		exit_fatal ("can't read program\n");

	FILE *input = fopen ("/dev/tty", "rb");
	if (!input)
		exit_fatal ("can't open terminal for reading\n");

	size_t dataptr = 0;
	str_append_c (&data, 0);

	for (size_t i = 0; i < program.len; i++)
	{
		switch (program.str[i])
		{
			long pairs;
		case '>':
			assert (dataptr != SIZE_MAX);
			dataptr++;
			if (dataptr == data.len)
				str_append_c (&data, 0);
			break;
		case '<':
			assert (dataptr != 0);
			dataptr--;
			break;

		case '+': data.str[dataptr]++; break;
		case '-': data.str[dataptr]--; break;

		case '.':
			fputc (data.str[dataptr], stdout);
			break;
		case ',':
			data.str[dataptr] = c = fgetc (input);
			assert (c != EOF);
			break;

		case '[':
			if (data.str[dataptr]) break;

			for (pairs = 0; i < program.len; i++)
			{
				switch (program.str[i])
				{
				case '[': pairs++; break;
				case ']': pairs--; break;
				}
				if (!pairs)
					break;
			}
			assert (!pairs);
			break;
		case ']':
			if (!data.str[dataptr]) break;

			for (pairs = 0; i != SIZE_MAX; i--)
			{
				switch (program.str[i])
				{
				case '[': pairs--; break;
				case ']': pairs++; break;
				}
				if (!pairs)
					break;
			}
			assert (!pairs);
			break;
		default:
			break;
		}
	}
	return 0;
}
