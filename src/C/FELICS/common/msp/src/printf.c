/****************************************************************************** 
 *
 * msp430 printf function compatible with mspdebug simulator
 * Originally for mspgcc libc, only modificatin was to inline vuprintf
 * inside printf
 *
 ******************************************************************************/


#include <msp430.h>

extern int putchar(int c) __attribute__((weak));

#undef __MSP430LIBC_PRINTF_INT32__
#undef __MSP430LIBC_PRINTF_INT64__
#undef __MSP430LIBC_PRINTF_INT20__

#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>
#include <string.h>
#include <stdint.h>

/** Format modifier indicating following int should be treated as a
 * 20-bit value */
#define A20_MODIFIER '\x8a'

/**
 * Internal state tracking.
 * Saves memory and parameters when compacted in a bit field.
 */
typedef struct
{
#if __MSP430X__
	uint8_t is_long20:1;		///< process a 20-bit integer
#endif /* __MSP430X__ */
#if __MSP430LIBC_PRINTF_INT32__ || __MSP430LIBC_PRINTF_INT64__
	uint8_t is_long32:1;		///< process a 32-bit integer
#endif				/* __MSP430LIBC_PRINTF_INT32__ */
#if __MSP430LIBC_PRINTF_INT64__
	uint8_t is_long64:1;		///< process a 64-bit integer
#endif				/* __MSP430LIBC_PRINTF_INT64__ */
	uint8_t is_signed:1;		///< process a signed number
	uint8_t is_alternate_form:1;	///< alternate output
	uint8_t left_align:1;		///< if != 0 pad on right side, else on left side
	uint8_t emit_octal_prefix:1;	///< emit a prefix 0
	uint8_t emit_hex_prefix:1;	///< emit a prefix 0x
	uint8_t fill_zero:1;		///< pad left with zero instead of space
	uint8_t uppercase:1;		///< print hex digits in upper case
	uint8_t zero_pad_precision:1;	///< add precision zeros before text
	uint8_t truncate_precision:1;	///< limit text to precision characters
	char sign_char;		///< character to emit as sign (NUL no emit)
	uint8_t precision;		///< value related to format precision specifier
} flags_t;

/** Maximum number of characters in any (numeric) prefix.  The only
 * prefix at the moment is "0x". */
#define MAX_PREFIX_CHARS 2

#ifndef __MSP430LIBC_PRINTF_INT20__
#define __MSP430LIBC_PRINTF_INT20__ __MSP430X__ - 0
#endif /* __MSP430LIBC_PRINTF_INT20__ */

/** Maximum number of characters for formatted numbers, including sign
 * and EOS but excluding prefix.  The longest representation will be
 * in octal, so assume one char for every three bits in the
 * representation. */
#if __MSP430LIBC_PRINTF_INT64__
#define MAX_FORMAT_LENGTH (((64 + 2) / 3) + 1 + 1)
#elif __MSP430LIBC_PRINTF_INT32__
#define MAX_FORMAT_LENGTH (((32 + 2) / 3) + 1 + 1)
#elif __MSP430_LIBC_PRINTF_INT20__
#define MAX_FORMAT_LENGTH (((20 + 2) / 3) + 1 + 1)
#else /* __MSP430LIBC_PRINTF_INT*__ */
#define MAX_FORMAT_LENGTH (((16 + 2) / 3) + 1 + 1)
#endif /* __MSP430LIBC_PRINTF_INT*__ */

/**
 * Helper function to generate anything that precedes leading zeros.
 *
 * @param write_char    [in] function used to write characters
 * @param flags         [in] flags that specify how the field is aligned
 * @return the number of characters that were written
 */
static int build_numeric_prefix (char *prefix_buffer, flags_t flags)
{
	char *p = prefix_buffer;
	if (flags.emit_hex_prefix)
	{
		*p++ = '0';
		*p++ = (flags.uppercase ? 'X' : 'x');
	}
	else if (flags.emit_octal_prefix)
	{
		*p++ = '0';
	}
	else if (flags.sign_char)
	{
		*p++ = flags.sign_char;
	}
	return (p - prefix_buffer);
}

/**
 * Helper function to print strings and fill to the defined width, with the
 * given fill character.
 *
 * @param write_char    [in] function used to write characters
 * @param char_p        [in] the string that is written
 * @param width         [in] field width. 0 is without limitation of width.
 * @param flags         [in] flags that specify how the field is aligned
 * @return the number of characters that were written
 */
static int print_field (int (*write_char) (int), const char *char_p, unsigned int width, flags_t flags)
{
	int character_count = 0;
	char prefix_buffer[MAX_PREFIX_CHARS];
	int prefix_idx = 0;
	unsigned int truncate_precision = flags.precision;
	int prefix_len = build_numeric_prefix (prefix_buffer, flags);

	if (!flags.truncate_precision)
	{
		truncate_precision = UINT16_MAX;
	}

	// if right aligned, pad
	if (!flags.left_align)
	{
		char leading_fill = ' ';
		unsigned int len = strlen (char_p);

		// Account for the prefix we'll write
		if (prefix_len <= width)
		{
			width -= prefix_len;
		}
		else
		{
			width = 0;
		}

		// Account for leading zeros required by a numeric precision specifier
		if (flags.zero_pad_precision)
		{
			if (flags.precision <= width)
			{
				width -= flags.precision;
			}
			else
			{
				width = 0;
			}
		}

		// Account for short writes of strings due to precision specifier
		if (truncate_precision < len)
		{
			len = truncate_precision;
		}

		// emit numeric prefix prior to padded zeros
		if (flags.fill_zero)
		{
			leading_fill = '0';
			character_count += prefix_len;
			while (prefix_idx < prefix_len)
			{
				write_char(prefix_buffer[prefix_idx++]);
			}
		}

		while (len < width)
		{
			write_char(leading_fill);
			character_count++;
			len++;
		}
	}

	// emit any unemitted prefix
	while (prefix_idx < prefix_len)
	{
		character_count++;
		write_char(prefix_buffer[prefix_idx++]);
	}

	// emit zeros to meet precision requirements
	if (flags.zero_pad_precision)
	{
			while (flags.precision--)
			{
				write_char ('0');
				character_count++;
			}
	}

	// output the buffer contents up to the maximum length
	while (*char_p && truncate_precision--)
	{
		write_char(*char_p);
		char_p++;
		character_count++;
	}
	// if left aligned, pad
	while (character_count < width)
	{
		write_char(' ');
		character_count++;
	}
	// return how many characters have been output
	return character_count;
}


int printf (const char *format, ...)
{
	va_list args;
	va_start (args, format);
	int (*write_char)(int) = putchar;

	int character_count = 0x00;
	enum { DIRECT, FORMATING } mode = DIRECT;
	unsigned int wp_value = 0x34;
	unsigned int width = 0;
	flags_t flags;
	const char* specifier = format;
	char *char_p;
	char character;
	int radix;
	bool have_wp_value = false;
	bool have_precision = false;
	bool is_zero = false;
	bool is_negative = false;
	union
	{
		int16_t i16;
		intptr_t ptr;
	#if __MSP430LIBC_PRINTF_INT20__
		int20_t i20;
	#endif /* __MSP430X__ */
	#if __MSP430LIBC_PRINTF_INT32__
		int32_t i32;
	#endif				/* __MSP430LIBC_PRINTF_INT32__ */
	#if __MSP430LIBC_PRINTF_INT64__
		int64_t i64;
	#endif				/* __MSP430LIBC_PRINTF_INT64__ */
	} number;
	char buffer[MAX_FORMAT_LENGTH];	// used to print numbers

	while ((character = *format++))
    {				// test and save character
		if (mode == DIRECT)
		{
			// output characters from the format string directly, except the
			// '%' sign which changes the mode
			if (character == '%')
			{
				width = wp_value = 0;
				memset (&flags, 0, sizeof (flags));
				have_wp_value = have_precision = is_zero = is_negative = false;
				specifier = format - 1;
				mode = FORMATING;
			}
			else
			{
			write_character:
				write_char(character);
				character_count++;
				mode = DIRECT;
			}
		}
		else
		{			//FORMATING
			// process format characters
			switch (character)
			{
				// output '%' itself
				case '%':
					goto write_character;	// character is already the %
			
				// alternate form flag
				case '#':
					flags.is_alternate_form = true;
					break;

#if __MSP430LIBC_PRINTF_INT20__
				// 20-bit integer follows
				case A20_MODIFIER:
					flags.is_long20 = true;
					break;
#endif
				// interpret next number as long integer
				case 'l':
#if __MSP430LIBC_PRINTF_INT64__
					if (flags.is_long32)
					{
						flags.is_long32 = false;
						flags.is_long64 = true;
					}
					else
					{
#endif /* __MSP430LIBC_PRINTF_INT64__ */
#if __MSP430LIBC_PRINTF_INT32__
						if (flags.is_long32)
						{
							goto bad_format;
						}
						flags.is_long32 = true;
#else /* __MSP430LIBC_PRINTF_INT32__ */
						goto bad_format;
#endif /* __MSP430LIBC_PRINTF_INT32__ */
#if __MSP430LIBC_PRINTF_INT64__
					}
#endif /* __MSP430LIBC_PRINTF_INT64__ */
					break;

				// left align instead of right align
				case '-':
					flags.left_align = true;
					break;
				
				// emit a + before a positive number
				case '+':
					flags.sign_char = '+';
					break;
				
				// emit a space before a positive number
				case ' ':
					// + overrides space as a flag character
					if ('+' != flags.sign_char)
					{
						flags.sign_char = ' ';
					}
					break;

				case '.':
					// explicit precision is present
					if (have_wp_value)
					{
						width = wp_value;
						wp_value = 0;
						have_wp_value = false;
					}
					have_precision = true;
					break;
					// fetch length from argument list instead of the format
					// string itself

				case '*':
				{
					int val = va_arg (args, int);
				
					if (val >= 0)
					{
						wp_value = val;
					}
					else if (have_precision)
					{
						wp_value = 0;
					}
					else
					{
						flags.left_align = true;
						wp_value = -val;
					}
					have_wp_value = true;
					break;
				}

				// format field width. zero needs special treatment
				// as when it occurs as first number it is the
				// flag to pad with zeroes instead of spaces
				case '0':
					// a leading zero means filling with zeros
					// it must be a leading zero if 'width' is zero
					// otherwise it is in a number as in "10"
					if (wp_value == 0 && !have_precision)
					{
						flags.fill_zero = !flags.left_align;
						break;
					}
				/*@fallthrough@ */
				case '1':
				case '2':
				case '3':
				case '4':
				case '5':
				case '6':
				case '7':
				case '8':
				case '9':
					wp_value *= 10;
					wp_value += character - '0';
					have_wp_value = true;
					break;
				
				// placeholder for one character
				case 'c':
					character = va_arg (args, int);
					if (! have_precision && ! have_wp_value)
					{
						goto write_character;
					}
					char_p = buffer;
					buffer[0] = character;
					buffer[1] = 0;
					goto emit_string;

				// placeholder for arbitrary length null terminated
				// string
				case 's':
					char_p = va_arg (args, char *);
					emit_string:
					/* Note: Zero-padding on strings is undefined; it
					 * is legitimate to zero-pad */
					if (have_precision)
					{
						flags.truncate_precision = true;
						flags.precision = wp_value;
					}
					else if (have_wp_value)
					{
						width = wp_value;
					}
					character_count += print_field(write_char, (char_p != NULL) ? char_p : "(null)", width, flags);
					mode = DIRECT;
					break;
				
				  // placeholder for an address
				  // addresses are automatically in alternate form and
				  // hexadecimal.
				case 'p':
				  number.ptr = (intptr_t) va_arg (args, void *);
				  number.ptr &= UINTPTR_MAX;
				  radix = 16;
				  flags.is_alternate_form = (0 != number.ptr);
				  goto emit_number;
				
				  // placeholder for hexadecimal output
				case 'X':
				  flags.uppercase = true;
				  /*@fallthrough@ */
				case 'x':
				  radix = 16;
				  goto fetch_number;
				
				  // placeholder for octal output
				case 'o':
				  radix = 8;
				  goto fetch_number;

				// placeholder for signed numbers
				case 'd':
				case 'i':
					flags.is_signed = true;
				/*@fallthrough@ */
				// placeholder for unsigned numbers
				case 'u':
					radix = 10;
					// label for number outputs including argument fetching
					fetch_number:
#if __MSP430LIBC_PRINTF_INT64__
					if (flags.is_long64)
					{
						number.i64 = va_arg (args, int64_t);
						is_zero = (number.i64 == 0);
						is_negative = (number.i64 < 0);
					}
					else
#endif /* __MSP430LIBC_PRINTF_INT64__ */
#if __MSP430LIBC_PRINTF_INT32__
						if (flags.is_long32)
						{
							number.i32 = va_arg (args, int32_t);
							is_zero = (number.i32 == 0);
							is_negative = (number.i32 < 0);
						}
						else
#endif /* __MSP430LIBC_PRINTF_INT32__ */
#if __MSP430LIBC_PRINTF_INT20__
							if (flags.is_long20)
							{
								number.i20 = va_arg (args, int20_t);
								is_zero = (number.i20 == 0);
								is_negative = (number.i20 < 0);
							}
							else
#endif /* __MSP430LIBC_PRINTF_INT20__ */
							{
								number.i16 = va_arg (args, int16_t);
								is_zero = (number.i16 == 0);
								is_negative = (number.i16 < 0);
							}
					// label for number outputs excluding argument fetching
					// 'number' already contains the value
					emit_number:
					// only non-zero numbers get hex/octal alternate form
					if (flags.is_alternate_form && !is_zero)
					{
						if (radix == 16)
						{
							flags.emit_hex_prefix = true;
						}
						else if (radix == 8)
						{
							flags.emit_octal_prefix = true;
						}
					}
					if (flags.is_signed && is_negative)
					{
						// save sign for radix 10 conversion
						flags.sign_char = '-';
#if __MSP430LIBC_PRINTF_INT64__
						if (flags.is_long64)
						{
							number.i64 = -number.i64;
						}
						else
#endif /* __MSP430LIBC_PRINTF_INT64__ */
#if __MSP430LIBC_PRINTF_INT32__
							if (flags.is_long32)
								number.i32 = -number.i32;
							else
#endif /* __MSP430LIBC_PRINTF_INT32__ */
#if __MSP430LIBC_PRINTF_INT20__
								if (flags.is_long20)
									number.i20 = -number.i20;
								else
#endif /* __MSP430LIBC_PRINTF_INT20__ */
									number.i16 = -number.i16;
					}

					// go to the end of the buffer and null terminate
					char_p = &buffer[sizeof (buffer) - 1];
					*char_p-- = '\0';

					// divide and save digits, fill from the lowest
					// significant digit

	#define CONVERT_LOOP(_unsigned, _number) \
		do \
		{ \
			int digit = (_unsigned) _number % radix;		\
			if (digit < 10)					\
			{ \
			  *char_p-- = digit + '0'; \
			} \
			else \
			{ \
				*char_p-- = digit + (flags.uppercase ? ('A' - 10) : ('a' - 10)); \
			} \
			_number = ((_unsigned) _number) / radix; \
		} \
		while ((_unsigned) _number > 0)

#if __MSP430LIBC_PRINTF_INT64__
					if (flags.is_long64)
						CONVERT_LOOP (uint64_t, number.i64);
					else
#endif /* __MSP430LIBC_PRINTF_INT64__ */
#if __MSP430LIBC_PRINTF_INT32__
						if (flags.is_long32)
							CONVERT_LOOP (uint32_t, number.i32);
						else
#endif /* __MSP430LIBC_PRINTF_INT32__ */
#if __MSP430LIBC_PRINTF_INT20__
							if (flags.is_long20)
								CONVERT_LOOP (uint20_t, number.i20);
							else
#endif /* __MSP430LIBC_PRINTF_INT20__ */
								CONVERT_LOOP (uint16_t, number.i16);
#undef CONVERT_LOOP

					// only decimal numbers get signs
					if (radix != 10)
					{
						flags.sign_char = 0;
					}
					
					// write padded result
					if (have_precision)
					{
						int number_width = buffer + sizeof (buffer) - char_p - 2;
						if (number_width < wp_value)
						{
							flags.zero_pad_precision = true;
							flags.precision = wp_value - number_width;
						}
					}
					else if (have_wp_value)
					{
					width = wp_value;
					}
					character_count += print_field(write_char, 1 + char_p, width, flags);
					mode = DIRECT;
					break;
					
				default:
				bad_format:
					while (specifier < format)
					{
						write_char (*specifier++);
						++character_count;
					}
					mode = DIRECT;
					break;
			}
		}
	}
	va_end (args);
	return character_count;
}
