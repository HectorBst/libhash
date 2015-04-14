
#ifndef SHA512_H
#define	SHA512_H

#include <stdint.h>

#define SHA512_HASH_SIZE 64
#define SHA512_STRING_HASH_SIZE ((SHA512_HASH_SIZE * 2) + 1)

void sha512(const void * const data, const size_t size, uint8_t hash[SHA512_HASH_SIZE]);

void sha512_hash_to_string(const uint8_t hash[SHA512_HASH_SIZE], char dest[SHA512_STRING_HASH_SIZE]);

#endif