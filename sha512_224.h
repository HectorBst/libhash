
#ifndef SHA512_224_H
#define	SHA512_224_H

#include <stdint.h>

#define SHA512_224_HASH_SIZE 28
#define SHA512_224_STRING_HASH_SIZE ((SHA512_224_HASH_SIZE * 2) + 1)

void sha512_224(const void * const data, const size_t size, uint8_t hash[SHA512_224_HASH_SIZE]);

void sha512_224_hash_to_string(const uint8_t hash[SHA512_224_HASH_SIZE], char dest[SHA512_224_STRING_HASH_SIZE]);

#endif