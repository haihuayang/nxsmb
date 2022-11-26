
#include "include/utils.hxx"
#include <openssl/rand.h>

void x_rand_bytes(void *out, size_t len)
{
	RAND_bytes((uint8_t *)out, int(len));
}

