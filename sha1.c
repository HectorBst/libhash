
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "sha1.h"

typedef uint32_t word_t;

#define WORD_SIZE sizeof(word_t)
#define WORD_SIZE_BITS (WORD_SIZE * 8)
#define BLOCK_SIZE (WORD_SIZE * 16)
#define BLOCK_SIZE_BITS (BLOCK_SIZE * 8)

#define TURNS 80

#define ROTL(a, b) (((a) << (b)) | ((a) >> (WORD_SIZE_BITS-(b))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define PAR(x, y, z) (x ^ y ^ z)

static const word_t SHA1_CONSTANTS[TURNS] = {
	0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999,
	0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999,
	0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1,
	0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1,
	0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc,
	0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc,
	0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6,
	0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6
};

void sha1_compress(word_t res[BLOCK_SIZE], word_t state[5]) {
	word_t a, b, c, d, e, t;
	word_t m[TURNS] = {
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	};
	unsigned int i, j, k;

	for (i = 0, j = 0; i < 16; i++, j += WORD_SIZE) {
		for (k = 0; k < WORD_SIZE; k++) {
			m[i] |= (res[j + k] << (WORD_SIZE_BITS - 8 - k * 8));
		}
	}
	for (; i < TURNS; i++) {
		m[i] = ROTL(m[i - 3] ^ m[i - 8] ^ m[i - 14] ^ m[i - 16], 1);
	}

	a = state[0];
	b = state[1];
	c = state[2];
	d = state[3];
	e = state[4];

	for (i = 0; i < TURNS / 4; i++) {
		t = ROTL(a, 5) + CH(b, c, d) + e + SHA1_CONSTANTS[i] + m[i];
		e = d;
		d = c;
		c = ROTL(b, 30);
		b = a;
		a = t;
	}
	for (; i < TURNS / 4 + 20; i++) {
		t = ROTL(a, 5) + PAR(b, c, d) + e + SHA1_CONSTANTS[i] + m[i];
		e = d;
		d = c;
		c = ROTL(b, 30);
		b = a;
		a = t;
	}
	for (; i < TURNS / 4 + 40; i++) {
		t = ROTL(a, 5) + MAJ(b, c, d) + e + SHA1_CONSTANTS[i] + m[i];
		e = d;
		d = c;
		c = ROTL(b, 30);
		b = a;
		a = t;
	}
	for (; i < TURNS / 4 + 60; i++) {
		t = ROTL(a, 5) + PAR(b, c, d) + e + SHA1_CONSTANTS[i] + m[i];
		e = d;
		d = c;
		c = ROTL(b, 30);
		b = a;
		a = t;
	}

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
	state[4] += e;
}

void sha1(const void * const d, const size_t size, uint8_t hash[SHA1_HASH_SIZE]) {
	word_t datalength = 0;
	uint64_t bitlength = 0;
	word_t state[5] = {
		0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0
	};
	word_t result[BLOCK_SIZE];
	unsigned int i, j;
	const uint8_t * const data = d;

	//compressing
	for (i = 0; i < size; i++) {
		result[datalength] = data[i];
		datalength++;
		if (datalength == BLOCK_SIZE) {
			sha1_compress(result, state);
			bitlength += BLOCK_SIZE_BITS;
			datalength = 0;
		}
	}

	i = datalength;

	//padding
	if (datalength < BLOCK_SIZE - 8) {
		result[i++] = 0x80;
		while (i < BLOCK_SIZE - 8) {
			result[i++] = 0;
		}
	} else {
		result[i++] = 0x80;
		while (i < BLOCK_SIZE) {
			result[i++] = 0;
		}
		sha1_compress(result, state);
		memset(result, 0, BLOCK_SIZE - 8);
	}

	//append
	bitlength += datalength * 8;
	for (i = 0; i < 8; i++) {
		result[BLOCK_SIZE - 1 - i] = bitlength >> (i * 8);
	}
	sha1_compress(result, state);

	//convert
	for (i = 0; i < WORD_SIZE; i++) {
		for (j = 0; j < SHA1_HASH_SIZE / WORD_SIZE; j++) {
			hash[i + WORD_SIZE * j] = state[j] >> (WORD_SIZE_BITS - 8 - i * 8);
		}
	}
}

void sha1_hash_to_string(const uint8_t hash[SHA1_HASH_SIZE], char dest[SHA1_STRING_HASH_SIZE]) {
	int i;
	for (i = 0; i < SHA1_HASH_SIZE; i++) {
		sprintf(dest + i * 2, "%.2x", hash[i]);
	}
}