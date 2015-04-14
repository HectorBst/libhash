
#include <stdio.h>

#include "sha384.h"
#include "sha512_internal.h"

void sha384(const void * const data, const size_t size, uint8_t hash[SHA384_HASH_SIZE]) {
	word_t state[8] = {
		0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
		0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4
	};
	unsigned int i, j;

	sha512_compute(data, size, state);

	for (i = 0; i < WORD_SIZE; i++) {
		for (j = 0; j < SHA384_HASH_SIZE / WORD_SIZE; j++) {
			hash[i + WORD_SIZE * j] = state[j] >> (WORD_SIZE_BITS - 8 - i * 8);
		}
	}
}

void sha384_hash_to_string(const uint8_t hash[SHA384_HASH_SIZE], char dest[SHA384_STRING_HASH_SIZE]) {
	int i;
	for (i = 0; i < SHA384_HASH_SIZE; i++) {
		sprintf(dest + i * 2, "%.2x", hash[i]);
	}
}