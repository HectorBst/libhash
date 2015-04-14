
#ifndef SHA256_H
#define	SHA256_H

#include <stdint.h>

#define SHA256_HASH_SIZE 32
#define SHA256_STRING_HASH_SIZE ((SHA256_HASH_SIZE * 2) + 1)

void sha256(const void * const data, const size_t size, uint8_t hash[SHA256_HASH_SIZE]);

void sha256_hash_to_string(const uint8_t hash[SHA256_HASH_SIZE], char dest[SHA256_STRING_HASH_SIZE]);

#endif