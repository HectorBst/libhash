
#ifndef SHA1_H
#define	SHA1_H

#include <stdint.h>

#define SHA1_HASH_SIZE 20
#define SHA1_STRING_HASH_SIZE ((SHA1_HASH_SIZE * 2) + 1)

void sha1(const void * const data, const size_t size, uint8_t hash[SHA1_HASH_SIZE]);

void sha1_hash_to_string(const uint8_t hash[SHA1_HASH_SIZE], char dest[SHA1_STRING_HASH_SIZE]);

#endif