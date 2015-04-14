
#include <stdio.h>

#include "sha256.h"
#include "sha256_internal.h"

void sha256(const void * const data, const size_t size, uint8_t hash[SHA256_HASH_SIZE]) {
	word_t state[8] = {
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
	};
	unsigned int i, j;

	sha256_compute(data, size, state);

	for (i = 0; i < WORD_SIZE; i++) {
		for (j = 0; j < SHA256_HASH_SIZE / WORD_SIZE; j++) {
			hash[i + WORD_SIZE * j] = state[j] >> (WORD_SIZE_BITS - 8 - i * 8);
		}
	}
}

void sha256_hash_to_string(const uint8_t hash[SHA256_HASH_SIZE], char dest[SHA256_STRING_HASH_SIZE]) {
	int i;
	for (i = 0; i < SHA256_HASH_SIZE; i++) {
		sprintf(dest + i * 2, "%.2x", hash[i]);
	}
}