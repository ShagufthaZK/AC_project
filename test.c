//by Aashish Dugar
/**
 * See https://wiki.openssl.org/index.php/Elliptic_Curve_Diffie_Hellman
 * for source. The function below are based on the ecdh_low algorithm
 * described on that page and utilizes the OpenSSL low-level APIs for
 * Elliptic Curve Diffie Hellman key exchange algorithm.
 */

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

int main(int argc, char *argv[])
{
	EC_KEY *alice = create_key();
	EC_KEY *bob = create_key();
	assert(alice != NULL && bob != NULL);
	unsigned char buf[100];
	int len;

	const EC_POINT *alice_public = EC_KEY_get0_public_key(alice);
	const EC_POINT *bob_public = EC_KEY_get0_public_key(bob);
	EC_POINT *alice_public1 = EC_POINT_new(EC_KEY_get0_group(alice)); 
	
	len = EC_POINT_point2oct(EC_KEY_get0_group(alice), alice_public, POINT_CONVERSION_UNCOMPRESSED,
                             buf, sizeof(buf), NULL);
                             
        printf("%d\n",len);
        
        printf("%d\n",EC_POINT_oct2point(EC_KEY_get0_group(bob), alice_public1, buf, len, NULL));
        printf("%d\n",EC_POINT_cmp(EC_KEY_get0_group(alice),alice_public,alice_public1,NULL));
        
	
	size_t alice_secret_len;
	size_t bob_secret_len;

	unsigned char *alice_secret = get_secret(alice, bob_public, &alice_secret_len);
	unsigned char *bob_secret = get_secret(bob, alice_public, &bob_secret_len);
	printf("%s",alice_secret);
	assert(alice_secret != NULL && bob_secret != NULL
		&& alice_secret_len == bob_secret_len);

	for (int i = 0; i < alice_secret_len; i++)
		assert(alice_secret[i] == bob_secret[i]);

	EC_KEY_free(alice);
	EC_KEY_free(bob);
	OPENSSL_free(alice_secret);
	OPENSSL_free(bob_secret);

	return 0;
}
