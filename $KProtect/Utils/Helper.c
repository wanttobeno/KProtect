#include "Helper.h"

unsigned char* FindPattern(const unsigned char* haystack, size_t hlen,
	const unsigned char* needle, const char* mask)
{
	size_t scan, nlen = strlen(mask);
	size_t bad_char_skip[256];

	for (scan = 0; scan < 256; scan++)
		bad_char_skip[scan] = nlen;

	size_t last = nlen - 1;

	for (scan = 0; scan < last; scan++)
		if (mask[scan] != '?')
			bad_char_skip[needle[scan]] = last - scan;

	while (hlen >= nlen)
	{
		for (scan = last; mask[scan] == '?' || haystack[scan] == needle[scan]; scan--)
			if (scan == 0)
				return (unsigned char*)haystack;

		hlen -= bad_char_skip[haystack[last]];
		haystack += bad_char_skip[haystack[last]];
	}

	return 0;
}



