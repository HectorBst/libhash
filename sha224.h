
#ifndef SHA224_H
#define	SHA224_H

#include <stdint.h>

#define SHA224_HASH_SIZE 28
#define SHA224_STRING_HASH_SIZE ((SHA224_HASH_SIZE * 2) + 1)

void sha224(const void * const data, const size_t size, uint8_t hash[SHA224_HASH_SIZE]);

void sha224_hash_to_string(const uint8_t hash[SHA224_HASH_SIZE], char dest[SHA224_STRING_HASH_SIZE]);

#endif