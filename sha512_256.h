
#ifndef SHA512_256_H
#define	SHA512_256_H

#include <stdint.h>

#define SHA512_256_HASH_SIZE 32
#define SHA512_256_STRING_HASH_SIZE ((SHA512_256_HASH_SIZE * 2) + 1)

void sha512_256(const void * const data, const size_t size, uint8_t hash[SHA512_256_HASH_SIZE]);

void sha512_256_hash_to_string(const uint8_t hash[SHA512_256_HASH_SIZE], char dest[SHA512_256_STRING_HASH_SIZE]);

#endif