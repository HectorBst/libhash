
#include <stdio.h>

#include "sha512.h"
#include "sha512_internal.h"

void sha512(const void * const data, const size_t size, uint8_t hash[SHA512_HASH_SIZE]) {
	word_t state[8] = {
		0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
		0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
	};
	unsigned int i, j;

	sha512_compute(data, size, state);

	for (i = 0; i < WORD_SIZE; i++) {
		for (j = 0; j < SHA512_HASH_SIZE / WORD_SIZE; j++) {
			hash[i + WORD_SIZE * j] = state[j] >> (WORD_SIZE_BITS - 8 - i * 8);
		}
	}
}

void sha512_hash_to_string(const uint8_t hash[SHA512_HASH_SIZE], char dest[SHA512_STRING_HASH_SIZE]) {
	int i;
	for (i = 0; i < SHA512_HASH_SIZE; i++) {
		sprintf(dest + i * 2, "%.2x", hash[i]);
	}
}