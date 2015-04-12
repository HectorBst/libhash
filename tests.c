
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sha224.h"
#include "sha256.h"
#include "sha384.h"
#include "sha512.h"
#include "sha512_224.h"
#include "sha512_256.h"

void test_sha224() {
	const char * tests[4] = {
		"", "A", "0123456789", "abcdefghijklmnopqrstuvwxyz"
	};
	const char * oks[4] = {
		"d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
		"5cfe2cddbb9940fb4d8505e25ea77e763a0077693dbb01b1a6aa94f2",
		"f28ad8ecd48ba6f914c114821685ad08f0d6103649ff156599a90426",
		"45a5f72c39c5cff2522eb3429799e49e5f44b356ef926bcf390dccc2"
	};
	uint8_t hash[SHA224_HASH_SIZE];
	char string[SHA224_STRING_HASH_SIZE];
	int i;
	puts("\n\nTesting SHA224...\n");
	for (i = 0; i < 4; i++) {
		sha224((uint8_t *) tests[i], strlen(tests[i]), hash);
		sha224_hash_to_str(hash, string);
		printf("%s\n%s\n--> %s\n\n", tests[i], string, strcmp(string, oks[i]) == 0 ? "OK" : "FAIL");
	}
	puts("\nTest done.\n");
}

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
	puts("\n\nTesting SHA256...\n");
	for (i = 0; i < 4; i++) {
		sha256((uint8_t *) tests[i], strlen(tests[i]), hash);
		sha256_hash_to_str(hash, string);
		printf("%s\n%s\n--> %s\n\n", tests[i], string, strcmp(string, oks[i]) == 0 ? "OK" : "FAIL");
	}
	puts("\nTest done.\n");
}

void test_sha384() {
	const char * tests[4] = {
		"", "A", "0123456789", "abcdefghijklmnopqrstuvwxyz"
	};
	const char * oks[4] = {
		"38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
		"ad14aaf25020bef2fd4e3eb5ec0c50272cdfd66074b0ed037c9a11254321aac0729985374beeaa5b80a504d048be1864",
		"90ae531f24e48697904a4d0286f354c50a350ebb6c2b9efcb22f71c96ceaeffc11c6095e9ca0df0ec30bf685dcf2e5e5",
		"feb67349df3db6f5924815d6c3dc133f091809213731fe5c7b5f4999e463479ff2877f5f2936fa63bb43784b12f3ebb4"
	};
	uint8_t hash[SHA384_HASH_SIZE];
	char string[SHA384_STRING_HASH_SIZE];
	int i;
	puts("\n\nTesting SHA384...\n");
	for (i = 0; i < 4; i++) {
		sha384((uint8_t *) tests[i], strlen(tests[i]), hash);
		sha384_hash_to_str(hash, string);
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
	puts("\n\nTesting SHA512...\n");
	for (i = 0; i < 4; i++) {
		sha512((uint8_t *) tests[i], strlen(tests[i]), hash);
		sha512_hash_to_str(hash, string);
		printf("%s\n%s\n--> %s\n\n", tests[i], string, strcmp(string, oks[i]) == 0 ? "OK" : "FAIL");
	}
	puts("\nTest done.\n");
}

void test_sha512_224() {
	const char * tests[4] = {
		"", "A", "0123456789", "abcdefghijklmnopqrstuvwxyz"
	};
	const char * oks[4] = {
		"6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4",
		"1def1e6a5344538a07a3c93a3a765fa1d2859a576947791a9047c3e6",
		"8e4c8d3d5aa0f2d55f50ca6e4eb53bd602309e43ef171a1862207f27",
		"ff83148aa07ec30655c1b40aff86141c0215fe2a54f767d3f38743d8"
	};
	uint8_t hash[SHA512_224_HASH_SIZE];
	char string[SHA512_224_STRING_HASH_SIZE];
	int i;
	puts("\n\nTesting SHA512/224...\n");
	for (i = 0; i < 4; i++) {
		sha512_224((uint8_t *) tests[i], strlen(tests[i]), hash);
		sha512_224_hash_to_str(hash, string);
		printf("%s\n%s\n--> %s\n\n", tests[i], string, strcmp(string, oks[i]) == 0 ? "OK" : "FAIL");
	}
	puts("\nTest done.\n");
}

void test_sha512_256() {
	const char * tests[4] = {
		"", "A", "0123456789", "abcdefghijklmnopqrstuvwxyz"
	};
	const char * oks[4] = {
		"c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a",
		"65a992ad19967492b5780d76a4733af553f796f688b79102d01ec7fde5590cab",
		"d48b2aa4a50d1c3e324a1a762d3b2165244661ef80e004dd3669a77e02c489d8",
		"fc3189443f9c268f626aea08a756abe7b726b05f701cb08222312ccfd6710a26"
	};
	uint8_t hash[SHA512_256_HASH_SIZE];
	char string[SHA512_256_STRING_HASH_SIZE];
	int i;
	puts("\n\nTesting SHA512/256...\n");
	for (i = 0; i < 4; i++) {
		sha512_256((uint8_t *) tests[i], strlen(tests[i]), hash);
		sha512_256_hash_to_str(hash, string);
		printf("%s\n%s\n--> %s\n\n", tests[i], string, strcmp(string, oks[i]) == 0 ? "OK" : "FAIL");
	}
	puts("\nTest done.\n");
}

int main() {
	test_sha224();
	test_sha256();
	test_sha384();
	test_sha512();
	test_sha512_224();
	test_sha512_256();
	exit(0);
}