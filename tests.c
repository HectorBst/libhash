
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sha256.h"

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
	puts("\nTesting SHA256...");
	for (i = 0; i < 4; i++) {
		sha256((uint8_t *) tests[i], strlen(tests[i]), hash);
		sha256_hash_to_str(hash, string);
		printf("%s\n%s\n--> %s\n\n", tests[i], string, strcmp(string, oks[i]) == 0 ? "OK" : "FAIL");
	}
	puts("\nTest done.\n");
}

int main() {
	test_sha256();
	exit(0);
}