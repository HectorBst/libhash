
#include <stdio.h>

#include "sha512_224.h"
#include "sha512_internal.h"

void sha512_224(const void * const data, const size_t size, uint8_t hash[SHA512_224_HASH_SIZE]) {
	word_t state[8] = {
		0x8c3d37c819544da2, 0x73e1996689dcd4d6, 0x1dfab7ae32ff9c82, 0x679dd514582f9fcf,
		0x0f6d2b697bd44da8, 0x77e36f7304c48942, 0x3f9d85a86a1d36c8, 0x1112e6ad91d692a1
	};
	unsigned int i, j;

	sha512_compute(data, size, state);

	for (i = 0; i < WORD_SIZE; i++) {
		for (j = 0; j < SHA512_224_HASH_SIZE / WORD_SIZE; j++) {
			hash[i + WORD_SIZE * j] = state[j] >> (WORD_SIZE_BITS - 8 - i * 8);
		}
	}
	for (i = 0; i < SHA512_224_HASH_SIZE % WORD_SIZE; i++) {
		hash[SHA512_224_HASH_SIZE - (SHA512_224_HASH_SIZE % WORD_SIZE) + i] = state[SHA512_224_HASH_SIZE % WORD_SIZE - 1] >> (WORD_SIZE_BITS - 8 - i * 8);
	}
}

void sha512_224_hash_to_string(const uint8_t hash[SHA512_224_HASH_SIZE], char dest[SHA512_224_STRING_HASH_SIZE]) {
	int i;
	for (i = 0; i < SHA512_224_HASH_SIZE; i++) {
		sprintf(dest + i * 2, "%.2x", hash[i]);
	}
}