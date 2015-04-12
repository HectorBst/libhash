
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "sha256.h"

typedef uint32_t word_t;

#define WORD_SIZE sizeof(word_t)
#define WORD_SIZE_BITS (WORD_SIZE * 8)
#define BLOCK_SIZE (WORD_SIZE * 16)
#define BLOCK_SIZE_BITS (BLOCK_SIZE * 8)
#define TURNS 64

#define SHR(a,b) ((a) >> (b))
#define ROTR(a,b) (((a) >> (b)) | ((a) << (WORD_SIZE_BITS-(b))))

#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTR(x,2) ^ ROTR(x,13) ^ ROTR(x,22))
#define EP1(x) (ROTR(x,6) ^ ROTR(x,11) ^ ROTR(x,25))
#define SIG0(x) (ROTR(x,7) ^ ROTR(x,18) ^ SHR(x, 3))
#define SIG1(x) (ROTR(x,17) ^ ROTR(x,19) ^ SHR(x, 10))

static const word_t constants[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static void sha256_compress(word_t res[BLOCK_SIZE], word_t state[8]) {
	word_t a, b, c, d, e, f, g, h, t1, t2, m[TURNS];
	unsigned int i, j, k;

	for (i = 0, j = 0; i < 16; i++, j += WORD_SIZE) {
		m[i] = res[j] << (WORD_SIZE_BITS - 8);
		for (k = 1; k < WORD_SIZE; k++) {
			m[i] |= (res[j + k] << (WORD_SIZE_BITS - 8 - k * 8));
		}
	}
	for (; i < BLOCK_SIZE; i++) {
		m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];
	}

	a = state[0];
	b = state[1];
	c = state[2];
	d = state[3];
	e = state[4];
	f = state[5];
	g = state[6];
	h = state[7];

	for (i = 0; i < TURNS; i++) {
		t1 = h + EP1(e) + CH(e, f, g) + constants[i] + m[i];
		t2 = EP0(a) + MAJ(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
	state[4] += e;
	state[5] += f;
	state[6] += g;
	state[7] += h;
}

void sha256(const uint8_t data[], const size_t size, uint8_t hash[SHA256_HASH_SIZE]) {
	word_t datalength = 0;
	uint64_t bitlength = 0;
	word_t state[8] = {
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
	};
	word_t res[BLOCK_SIZE];
	unsigned int i, j;

	//compressing
	for (i = 0; i < size; i++) {
		res[datalength] = data[i];
		datalength++;
		if (datalength == BLOCK_SIZE) {
			sha256_compress(res, state);
			bitlength += BLOCK_SIZE_BITS;
			datalength = 0;
		}
	}

	i = datalength;

	//padding
	if (datalength < BLOCK_SIZE - 8) {
		res[i++] = 0x80;
		while (i < BLOCK_SIZE - 8) {
			res[i++] = 0;
		}
	} else {
		res[i++] = 0x80;
		while (i < BLOCK_SIZE) {
			res[i++] = 0;
		}
		sha256_compress(res, state);
		memset(res, 0, BLOCK_SIZE - 8);
	}

	//append
	bitlength += datalength * 8;
	for (i = 0; i < 8; i++) {
		res[BLOCK_SIZE - 1 - i] = bitlength >> (i * 8);
	}
	sha256_compress(res, state);

	//convert
	for (i = 0; i < WORD_SIZE; i++) {
		for (j = 0; j < 8; j++) {
			hash[i + WORD_SIZE * j] = state[j] >> (WORD_SIZE_BITS - 8 - i * 8);
		}
	}
}

void sha256_hash_to_str(const uint8_t hash[SHA256_HASH_SIZE], char dest[SHA256_STRING_HASH_SIZE]) {
	int i;
	for (i = 0; i < SHA256_HASH_SIZE; i++) {
		sprintf(dest + i * 2, "%.2x", hash[i]);
	}
}