#ifndef _STR_UTILS_H
#define _STR_UTILS_H

_Pragma("GCC diagnostic push");
_Pragma("GCC diagnostic ignored \"-Wunused-function\"");

/**
 * @brief: compare two string. require s1 s2 align to 8 bytes
 *      and has at least one tailing zero 8-bytes.
 * @param s1 first string to compare, must be aligned to 8 bytes
 * @param s2 second string to compare, must be aligned to 8 bytes
 * @param n s1 and s2 must has a buffer of at least n bytes;
 * @return 0 if s1 and s2 matches, else none zero.
 */
static long strncmp(const char *s1, const char *s2, long n)
{
	if (n < 0)
	{
		return 0; // Ensure n is not negative
	}
	// Compare in chunks of long size
	while (n >= sizeof(long))
	{
		const long *p1 = (const long *)s1;
		const long *p2 = (const long *)s2;
		if (*p1 != *p2)
		{
			return (*p1 - *p2); // Return comparison result
		}
		if (*p1 == 0)
		{
			return 0; // Stop if end of string is reached
		}
		s1 += sizeof(long); // Move pointers
		s2 += sizeof(long);
		n -= sizeof(long);
	}
	// Compare remaining characters
	while (n > 0)
	{
		if (*s1 != *s2)
		{
			return (*s1 - *s2); // Return comparison result
		}
		if (*s1 == 0)
		{
			return 0; // Stop if end of string is reached
		}
		s1++;
		s2++;
		n--; // Move to next character
	}
	return 0; // All compared characters are equal
}

/**
 * @brief: calculate the length of a string.
 * @param s the string to calculate the length of, must be aligned to 8 bytes
 * @param n the maximum number of bytes to check
 * @return the length of the string
 */
static long strlen(const char *s, long n)
{
	const unsigned long *p = (const unsigned long *)s;
	long slen = 0;
	while (n > sizeof(long))
	{
		if (*p == 0)
		{
			break;
		}

		p++;
		n -= sizeof(long);
		slen += sizeof(long);
	}

	const char *c = (const char *)(p - 1);
	slen -= sizeof(long);

	if (c < s)
	{
		return 0;
	}

	if (slen <= 0)
	{
		return 0;
	}

	while (slen < n)
	{
		if (*c == 0)
		{
			break;
		}

		c++;
		slen++;
	}
	return slen;
}

/**
 * @brief: the legacy way to copy a string to a destination buffer.
 * @param dst the destination buffer
 * @param src the source string
 * @param n the maximum number of bytes to copy
 * @return the number of characters copied, including the null terminator
 */
static long legacy_strncpy(char *dst, const char *src, long n)
{
	long i = 0;
	for (; i < n - 1; i++)
	{
		if (src[i] == 0)
		{
			break;
		}
		dst[i] = src[i];
	}
	dst[i] = 0;
	return i + 1;
}

/**
 * @brief: copy a string to a destination buffer. require src and dst aligned to
 * long, and has a buffer size of at least n.
 * @param dst the destination buffer, must be aligned to 8 bytes
 * @param src the source string, must be aligned to 8 bytes
 * @param n the maximum number of bytes to copy
 * @return the number of characters copied
 */
static long strncpy(char *dst, const char *src, long n)
{
	long ret = 0;
	unsigned long *d = (unsigned long *)dst;
	const unsigned long *s = (const unsigned long *)src;
	while (n > sizeof(long))
	{
		if (*s == 0)
		{
			*d = 0;
			break;
		}

		*d = *s;
		d++;
		s++;
		n -= sizeof(long);
		ret += sizeof(long);
	}

	char *cs = (char *)(s);
	char *cd = (char *)(d);

	while (n > 0)
	{
		if (*cs == 0)
		{
			*cd = 0;
			break;
		}

		*cd = *cs;
		cd++;
		cs++;
		n -= 1;
		ret += 1;
	}

	return ret;
}

/**
 * @brief: find the first occurrence of a character in a string.
 * @param s the string to search, must be aligned to 8 bytes
 * @param n the maximum number of bytes to check
 * @param c the character to find
 * @return the index of the first occurrence of the character, or -1 if not
 * found
 */
static long strchr(const char *s, long n, char c)
{
	const unsigned long *p = (const unsigned long *)s;
	long slen = 0;
	while (n > sizeof(long))
	{
		if (*p == 0)
		{
			break;
		}

		if ((*p & 0xff) == c)
		{
			return slen;
		}

		if ((*p & 0xff00) == c)
		{
			return slen + 1;
		}

		if ((*p & 0xff0000) == c)
		{
			return slen + 2;
		}

		if ((*p & 0xff000000) == c)
		{
			return slen + 3;
		}

		p++;
		n -= sizeof(long);
		slen += sizeof(long);
	}

	const char *cs = (const char *)(p);
	while (n > 0)
	{
		if (*cs == 0)
		{
			break;
		}

		if (*cs == c)
		{
			return slen;
		}

		cs++;
		n -= 1;
		slen += 1;
	}

	return -1;
}

/**
 * @brief: match a string with a pattern. suffix wildcard * is supported.
 * @param pattern the pattern to match, must be aligned to 8 bytes
 * @param str the string to match against the pattern, must be aligned to 8
 * bytes
 * @param n the maximum number of bytes to check
 * @return 0 if the string matches the pattern, else non-zero
 */
static long wildcard_match(const char *pattern, const char *str, long n)
{
	const char *s1 = pattern;
	const char *s2 = str;
	if (n < 0)
	{
		return 0; // Ensure n is not negative
	}
	// Compare in chunks of long size
	while (n >= sizeof(long))
	{
		const unsigned long *p1 = (const unsigned long *)s1;
		const unsigned long *p2 = (const unsigned long *)s2;
		if (*p1 != *p2)
		{
			if (n > sizeof(long))
			{
				n = sizeof(long);
			}

			while (n > 0)
			{
				if (*s1 == '*')
				{
					return 0;
				}

				if (*s1 != *s2)
				{
					return (*s1 - *s2); // Return comparison result
				}
				if (*s1 == 0)
				{
					return 0; // Stop if end of string is reached
				}
				s1++;
				s2++;
				n--; // Move to next character
			}
			return *p1 - *p2;
		}
		if (*p1 == 0)
		{
			return 0; // Stop if end of string is reached
		}
		s1 += sizeof(long); // Move pointers
		s2 += sizeof(long);
		n -= sizeof(long);
	}

	while (n > 0)
	{
		if (*s1 == '*')
		{
			return 0;
		}

		if (*s1 != *s2)
		{
			return (*s1 - *s2); // Return comparison result
		}
		if (*s1 == 0)
		{
			return 0; // Stop if end of string is reached
		}
		s1++;
		s2++;
		n--; // Move to next character
	}
	return 0; // All compared characters are equal
}

/**
 * @brief: compare two memory blocks. d1 and d2 should be aligned to long.
 * @param d1 the first memory block to compare, must be aligned to 8 bytes
 * @param d2 the second memory block to compare, must be aligned to 8 bytes
 * @param n the number of bytes to compare
 * @return 0 if the memory blocks match, else non-zero
 */
static long memncmp(const void *d1, const void *d2, long n)
{
	if (n < 0)
	{
		return 0; // Ensure n is not negative
	}
	// Compare in chunks of long size
	while (n >= sizeof(long))
	{
		const long *p1 = (const long *)d1;
		const long *p2 = (const long *)d2;
		if (*p1 != *p2)
		{
			return (*p1 - *p2); // Return comparison result
		}
		if (*p1 == 0)
		{
			return 0; // Stop if end of string is reached
		}
		d1 += sizeof(long); // Move pointers
		d2 += sizeof(long);
		n -= sizeof(long);
	}
	const char *c1 = (const char *)d1;
	const char *c2 = (const char *)d2;
	// Compare remaining characters
	while (n > 0)
	{
		if (*c1 != *c2)
		{
			return (*c1 - *c2); // Return comparison result
		}
		if (*c1 == 0)
		{
			return 0; // Stop if end of string is reached
		}
		c1++;
		c2++;
		n--; // Move to next character
	}
	return 0; // All compared characters are equal
}

/**
 * @brief: set a memory block to a specified value.
 * @param data the memory block to set, data + n must be aligned to 8 bytes
 * @param val the value to set
 * @param offset the offset within the memory block to start setting
 * @param n the number of bytes to set
 * @note 'offset' and 'n' must be able to be conformed at compiling time
 */
static __attribute__((no_builtin)) void
memset(void *data, long val, unsigned long offset, unsigned long n)
{
	char *d = (char *)data;
	long c = offset;
	while (c % sizeof(long) && c < n)
	{
		/**
		 * clang will optimize this to memset
		 * which cause compiling error:
		 * error: A call to built-in function 'memset' is not supported.
		 * so the compiling option -fno-builtin is added.
		 */
		d[c] = 0;
		c++;
	}
	/**
	 * don't compare the address directly like this:
	 *
	 *  long *ls = (long*)((char*)data + c);
	 *  long *le = (long*)((char*)data + n);
	 *  while (ls < le)
	 *  {
	 *      *ls = 0;
	 *      ls++;
	 *  }
	 *
	 * the kernel BPF verifier cannot judge the condition
	 * of address comparing properly.
	 * In clang 17.x, the c code for address comparison will generate
	 * corresponding assembly code to compare two addresses
	 * without any modification, thus makes the BPF verifier judge
	 * wrongly, and complains about invalid access like below：
	 *
	 *  ; *ls = 0;
	 *  305: (7b) *(u64 *)(r3 +0) = r2        ; frame1: R2=0
	 * R3=map_value(off=4088,ks=8,vs=4096,imm=0) ; ls++; 306: (07) r3 += 8 ;
	 * frame1: R3_w=map_value(off=4096,ks=8,vs=4096,imm=0) ; while (ls < le)
	 *  307: (2d) if r1 > r3 goto pc-3        ; frame1:
	 * R1=map_value(off=4096,ks=8,vs=4096,imm=0) R2=0
	 * R3_w=map_value(off=4096,ks=8,vs=4096,imm=0) R10=fp0 ; *ls = 0; 305: (7b)
	 * *(u64 *)(r3 +0) = r2 invalid access to map value, value_size=4096
	 * off=4096 size=8
	 *
	 * in above throw-out message, we can see in line 307, the BPF verifier
	 * doesn't think r1 > r3 like we do, but in clang 18.x, the code for address
	 * comparing is ok, because clang 18.x will translate them to index(against
	 * the origin address) comparing.
	 *
	 *
	 * for reasons explained above, use the code below instead
	 */
	long *ls = (long *)((char *)data + c);
	long left = (n - c) / sizeof(long);
	while (left > 0)
	{
		*ls = 0;
		ls++;
		left--;
	}
}

/**
 * @brief: set the tail of a string buffer to 0.
 * @param str the string buffer
 * @param n the size of the buffer
 */
static __attribute__((no_builtin)) void
zero_str_tail(char *str, unsigned long n)
{
	unsigned long i = 0;
	for (; i < n; i++)
	{
		if (str[i] == 0)
		{
			break;
		}
	}

	memset(str, 0, i, n);
}

/**
 * @brief: print a memory block as a hex string.
 * @param dst the destination buffer
 * @param src the source memory block
 * @param n the number of bytes to print
 * @return the number of characters printed
 */
static long hex_print(char *dst, const void *src, long n)
{
	long i = 0;
	const unsigned char *s = (const unsigned char *)src;
	for (; i < n / 2; i++)
	{
		unsigned char c = s[i];
		dst[i * 2] = "0123456789abcdef"[c >> 4];
		dst[i * 2 + 1] = "0123456789abcdef"[c & 0xf];
	}
	return i * 2;
}

_Pragma("GCC diagnostic pop")

#endif