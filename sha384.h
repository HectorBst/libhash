
#ifndef SHA384_H
#define	SHA384_H

#include <stdint.h>

#define SHA384_HASH_SIZE 48
#define SHA384_STRING_HASH_SIZE ((SHA384_HASH_SIZE * 2) + 1)

void sha384(const void * const data, const size_t size, uint8_t hash[SHA384_HASH_SIZE]);

void sha384_hash_to_string(const uint8_t hash[SHA384_HASH_SIZE], char dest[SHA384_STRING_HASH_SIZE]);

#endif