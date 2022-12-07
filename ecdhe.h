#include <assert.h>
#include <stdio.h>

#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/evp.h>

EC_KEY *create_key(void)
{
	EC_KEY *key;
	if (NULL == (key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1))) {
		printf("Failed to create key curve\n");
		return NULL;
	}

	if (1 != EC_KEY_generate_key(key)) {
		printf("Failed to generate key\n");
		return NULL;
	}
	return key;
}

unsigned char *get_secret(EC_KEY *key, const EC_POINT *peer_pub_key,
			size_t *secret_len)
{
	int field_size;
	unsigned char *secret;

	field_size = EC_GROUP_get_degree(EC_KEY_get0_group(key));
	*secret_len = (field_size + 7) / 8;

	if (NULL == (secret = OPENSSL_malloc(*secret_len))) {
		printf("Failed to allocate memory for secret");
		return NULL;
	}

	*secret_len = ECDH_compute_key(secret, *secret_len,
					peer_pub_key, key, NULL);

	if (*secret_len <= 0) {
		OPENSSL_free(secret);
		return NULL;
	}
	return secret;
}

