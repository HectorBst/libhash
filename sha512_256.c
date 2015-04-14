
#include <stdio.h>

#include "sha512_256.h"
#include "sha512_internal.h"

void sha512_256(const void * const data, const size_t size, uint8_t hash[SHA512_256_HASH_SIZE]) {
	word_t state[8] = {
		0x22312194fc2bf72c, 0x9f555fa3c84c64c2, 0x2393b86b6f53b151, 0x963877195940eabd,
		0x96283ee2a88effe3, 0xbe5e1e2553863992, 0x2b0199fc2c85b8aa, 0x0eb72ddc81c52ca2
	};
	unsigned int i, j;

	sha512_compute(data, size, state);

	for (i = 0; i < WORD_SIZE; i++) {
		for (j = 0; j < SHA512_256_HASH_SIZE / WORD_SIZE; j++) {
			hash[i + WORD_SIZE * j] = state[j] >> (WORD_SIZE_BITS - 8 - i * 8);
		}
	}
}

void sha512_256_hash_to_string(const uint8_t hash[SHA512_256_HASH_SIZE], char dest[SHA512_256_STRING_HASH_SIZE]) {
	int i;
	for (i = 0; i < SHA512_256_HASH_SIZE; i++) {
		sprintf(dest + i * 2, "%.2x", hash[i]);
	}
}