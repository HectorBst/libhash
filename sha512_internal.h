
#ifndef SHA512_INTERNAL_H
#define	SHA512_INTERNAL_H

typedef uint64_t word_t;

#define WORD_SIZE sizeof(word_t)
#define WORD_SIZE_BITS (WORD_SIZE * 8)

void sha512_compute(const uint8_t data[], const size_t size, word_t state[8]);

#endif