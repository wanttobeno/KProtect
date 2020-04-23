#ifndef Helper_h__
#define Helper_h__

#include <crtdefs.h>

// http://www.d3scene.com/forum/development/79766-c-c-faster-findpattern-function-tutorial.html
unsigned char* FindPattern(const unsigned char* haystack, size_t hlen,
	const unsigned char* needle, const char* mask);



#endif // Helper_h__