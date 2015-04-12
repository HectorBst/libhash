
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sha256.h"
#include "sha512.h"

void test_sha256() {
	const char * tests[4] = {
		"", "A", "0123456789", "abcdefghijklmnopqrstuvwxyz"
	};
	const char * oks[4] = {
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"559aead08264d5795d3909718cdd05abd49572e84fe55590eef31a88a08fdffd",
		"84d89877f0d4041efb6bf91a16f0248f2fd573e6af05c19f96bedb9f882f7882",
		"71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73"
	};
	uint8_t hash[SHA256_HASH_SIZE];
	char string[SHA256_STRING_HASH_SIZE];
	int i;
	puts("\nTesting SHA256...\n");
	for (i = 0; i < 4; i++) {
		sha256((uint8_t *) tests[i], strlen(tests[i]), hash);
		sha256_hash_to_str(hash, string);
		printf("%s\n%s\n--> %s\n\n", tests[i], string, strcmp(string, oks[i]) == 0 ? "OK" : "FAIL");
	}
	puts("\nTest done.\n");
}

void test_sha512() {
	const char * tests[4] = {
		"", "A", "0123456789", "abcdefghijklmnopqrstuvwxyz"
	};
	const char * oks[4] = {
		"cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
		"21b4f4bd9e64ed355c3eb676a28ebedaf6d8f17bdc365995b319097153044080516bd083bfcce66121a3072646994c8430cc382b8dc543e84880183bf856cff5",
		"bb96c2fc40d2d54617d6f276febe571f623a8dadf0b734855299b0e107fda32cf6b69f2da32b36445d73690b93cbd0f7bfc20e0f7f28553d2a4428f23b716e90",
		"4dbff86cc2ca1bae1e16468a05cb9881c97f1753bce3619034898faa1aabe429955a1bf8ec483d7421fe3c1646613a59ed5441fb0f321389f77f48a879c7b1f1"
	};
	uint8_t hash[SHA512_HASH_SIZE];
	char string[SHA512_STRING_HASH_SIZE];
	int i;
	puts("\nTesting SHA512...\n");
	for (i = 0; i < 4; i++) {
		sha512((uint8_t *) tests[i], strlen(tests[i]), hash);
		sha512_hash_to_str(hash, string);
		printf("%s\n%s\n--> %s\n\n", tests[i], string, strcmp(string, oks[i]) == 0 ? "OK" : "FAIL");
	}
	puts("\nTest done.\n");
}

int main() {
	test_sha256();
	test_sha512();
	exit(0);
}