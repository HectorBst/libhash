
#include <stdio.h>

#include "sha224.h"
#include "sha256_internal.h"

void sha224(const void * const data, const size_t size, uint8_t hash[SHA224_HASH_SIZE]) {
	word_t state[8] = {
		0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
	};
	unsigned int i, j;

	sha256_compute(data, size, state);

	for (i = 0; i < WORD_SIZE; i++) {
		for (j = 0; j < SHA224_HASH_SIZE / WORD_SIZE; j++) {
			hash[i + WORD_SIZE * j] = state[j] >> (WORD_SIZE_BITS - 8 - i * 8);
		}
	}
}

void sha224_hash_to_string(const uint8_t hash[SHA224_HASH_SIZE], char dest[SHA224_STRING_HASH_SIZE]) {
	int i;
	for (i = 0; i < SHA224_HASH_SIZE; i++) {
		sprintf(dest + i * 2, "%.2x", hash[i]);
	}
}