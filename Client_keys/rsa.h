
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <stdio.h>


//change the deprecated functions
RSA * createRSAWithFilename(char * filename,int public)
{
    FILE * fp = fopen(filename,"r");
 
    if(fp == NULL)
    {
        printf("Unable to open file %s \n",filename);
        return NULL;    
    }
    RSA *rsa= RSA_new() ;
 
    if(public)
    {
        rsa = PEM_read_RSA_PUBKEY(fp, &rsa,NULL, NULL);
    }
    else
    {
        rsa = PEM_read_RSAPrivateKey(fp, &rsa,NULL, NULL);
    }
 
    return rsa;
}
int padding = RSA_PKCS1_PADDING;
 
int public_encrypt(unsigned char * data,int data_len,char * filename, unsigned char *encrypted)
{
    RSA * rsa = createRSAWithFilename(filename,1);
    int result = RSA_public_encrypt(data_len,data,encrypted,rsa,padding);
    return result;
}
int private_decrypt(unsigned char * enc_data,int data_len,char * filename, unsigned char *decrypted)
{
    RSA * rsa = createRSAWithFilename(filename,0);
    int  result = RSA_private_decrypt(data_len,enc_data,decrypted,rsa,padding);
    return result;
}
 
 
int private_encrypt(unsigned char * data,int data_len,char * filename, unsigned char *encrypted)
{
    RSA * rsa = createRSAWithFilename(filename,0);
    int result = RSA_private_encrypt(data_len,data,encrypted,rsa,padding);
    return result;
}
int public_decrypt(unsigned char * enc_data,int data_len,char * filename, unsigned char *decrypted)
{
    RSA * rsa = createRSAWithFilename(filename,1);
    int  result = RSA_public_decrypt(data_len,enc_data,decrypted,rsa,padding);
    return result;
}

/*
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/ssl.h>
#include <openssl/md5.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#define RSA_KEY_LENGTH 1024
static const char rnd_seed[] = "string to make the random number generator initialized";



int openssl_evp_rsa_encrypt(    unsigned char *plain_text, size_t plain_len,
                                unsigned char *cipher_text, size_t *cipher_len,
                                unsigned char *pem_file)
{
    int ret = 0;
    RSA *rsa = NULL;
    EVP_PKEY* public_evp_key = NULL;
    FILE *fp = NULL;
    BIO *bp = NULL;
    EVP_PKEY_CTX *ctx = NULL;


    if (plain_text == NULL || plain_len == 0 || cipher_text == NULL || *cipher_len == 0) {
        printf("input parameters error, plain_text cipher_text or plain_len is NULL or 0.\n");
        ret = -1;
        goto finish;
    }
    if (NULL == pem_file) {
        printf("input pem_file name is invalid\n");
        ret = -1;
        goto finish;
    }
    fp = fopen((const char*)pem_file, "r");
    if (NULL == fp) {
        printf("input pem_file is not exit.\n");
        ret = -1;
        goto finish;
    }
    fclose(fp);
    fp = NULL;

    //OpenSSL_add_all_algorithms();
    bp = BIO_new(BIO_s_file());
    if (bp == NULL) {
        printf("BIO_new is failed.\n");
        ret = -1;
        goto finish;
    }

    ret = BIO_read_filename(bp, pem_file);
    rsa = PEM_read_bio_RSAPublicKey(bp, NULL, NULL, NULL);
    if (rsa == NULL) {
        ret = -1;
        printf("open_public_key failed to PEM_read_bio_RSAPublicKey Failed, ret=%d\n", ret);
        goto finish;
    }
    public_evp_key = EVP_PKEY_new();
    if (public_evp_key == NULL) {
        ret = -1;
        printf("open_public_key EVP_PKEY_new failed\n");
        goto finish;
    }
    EVP_PKEY_assign_RSA(public_evp_key, rsa);


    ctx = EVP_PKEY_CTX_new(public_evp_key, NULL);
    if (ctx == NULL) {
        ret = -1;
        printf("EVP_PKEY_CTX_new failed\n");
        goto finish;
    }
    ret = EVP_PKEY_encrypt_init(ctx);
    if (ret < 0) {
        printf("ras_pubkey_encrypt failed to EVP_PKEY_encrypt_init. ret = %d\n", ret);
        goto finish;
    }
    ret = EVP_PKEY_CTX_set_rsa_padding(ctx, EVP_PADDING_PKCS7);
    if (ret != 1) {
        printf("EVP_PKEY_CTX_set_rsa_padding failed. ret = %d\n", ret);
        goto finish;
    }
    ret = EVP_PKEY_encrypt(ctx, cipher_text, cipher_len, plain_text, plain_len);
    if (ret < 0) {
        printf("ras_pubkey_encrypt failed to EVP_PKEY_encrypt. ret = %d\n", ret);
        goto finish;
    }
    ret = 0;

finish:
    if (public_evp_key != NULL)
        EVP_PKEY_free(public_evp_key);
    if (bp != NULL)
        BIO_free(bp);
    if (ctx != NULL)
        EVP_PKEY_CTX_free(ctx);

    return ret;
}



int openssl_evp_rsa_decrypt(unsigned char *cipher_text, size_t cipher_len,
                               unsigned char *plain_text, size_t *plain_len,
                               const unsigned char *pem_file, const unsigned char *passwd)
{
    int ret = 0;
    size_t out_len = 0;
    EVP_PKEY* private_evp_key = NULL;
    RSA *rsa = NULL;
    BIO *bp = NULL;
    FILE *fp = NULL;
    EVP_PKEY_CTX *ctx = NULL;


    if (plain_text == NULL || *plain_len == 0 || cipher_text == NULL || cipher_len == 0) {
        printf("input parameters error, plain_text cipher_text or plain_len is NULL or 0.\n");
        ret = -1;
        goto finish;
    }
    if (NULL == pem_file) {
        printf("input pem_file name is invalid\n");
        ret = -1;
        goto finish;
    }
    fp = fopen((const char*)pem_file, "r");
    if (NULL == fp) {
        printf("input pem_file is not exit.\n");
        ret = -1;
        goto finish;
    }
    fclose(fp);
    fp = NULL;

    //OpenSSL_add_all_algorithms();
    bp = BIO_new(BIO_s_file());
    if (bp == NULL) {
        printf("BIO_new is failed.\n");
        ret = -1;
        goto finish;
    }

    ret = BIO_read_filename(bp, pem_file);
    rsa = PEM_read_bio_RSAPrivateKey(bp, &rsa, NULL, (void*)passwd);
    if (rsa == NULL) {
        ret = -1;
        printf("open_private_key failed to PEM_read_bio_RSAPrivateKey Failed, ret=%d\n", ret);
        goto finish;
    }
    private_evp_key = EVP_PKEY_new();
    if (private_evp_key == NULL) {
        ret = -1;
        printf("open_private_key EVP_PKEY_new failed\n");
        goto finish;
    }
    EVP_PKEY_assign_RSA(private_evp_key, rsa);

    ctx = EVP_PKEY_CTX_new(private_evp_key, NULL);
    if (ctx == NULL) {
        ret = -1;
        printf("EVP_PKEY_CTX_new failed\n");
        goto finish;
    }
    ret = EVP_PKEY_decrypt_init(ctx);
    if (ret != 1) {
        printf("rsa_private_key decrypt failed to EVP_PKEY_decrypt_init. ret = %d\n", ret);
        goto finish;
    }
    ret = EVP_PKEY_CTX_set_rsa_padding(ctx, EVP_PADDING_PKCS7);
    if (ret != 1) {
        printf("EVP_PKEY_CTX_set_rsa_padding failed. ret = %d\n", ret);
        goto finish;
    }

    ret = EVP_PKEY_decrypt(ctx, NULL, &out_len, cipher_text, cipher_len);
    if (ret != 1) {
        printf("rsa_prikey_decrypt failed to EVP_PKEY_decrypt. ret = %d\n", ret);
        goto finish;
    }
    *plain_len = out_len;
    ret = EVP_PKEY_decrypt(ctx, plain_text, plain_len, cipher_text, cipher_len);
    if (ret != 1) {
        printf("rsa_prikey_decrypt failed to EVP_PKEY_decrypt. ret = %d\n", ret);
        goto finish;
    }
    ret = 0;
finish:
    if (private_evp_key != NULL)
        EVP_PKEY_free(private_evp_key);
    if (bp != NULL)
        BIO_free(bp);
    if (ctx != NULL)
        EVP_PKEY_CTX_free(ctx);

    return ret;
}

// RSA_PKCS1_PADDING  RSA_OAEP_PADDING
int openssl_evp_rsa_signature(unsigned char *sign_rom, size_t sign_rom_len,
                                unsigned char *result, size_t *result_len,
                                const unsigned char *priv_pem_file, const unsigned char *passwd)
{
    int ret = 0;
    FILE *fp = NULL;
    EVP_PKEY* private_evp_key = NULL;
    RSA *rsa = NULL;
    BIO *bp = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_MD_CTX *evp_md_ctx = NULL;


    if (sign_rom == NULL || sign_rom_len == 0 || result == NULL || *result_len == 0) {
        printf("input parameters error, content or len is NULL or 0.\n");
        ret = -1;
        goto finish;
    }
    if (NULL == priv_pem_file) {
        printf("input pem_file name is invalid\n");
        ret = -1;
        return ret;
    }
    fp = fopen((const char*)priv_pem_file, "r");
    if (NULL == fp) {
        printf("input pem_file is not exit.\n");
        ret = -1;
        goto finish;
    }
    fclose(fp);
    fp = NULL;

    //OpenSSL_add_all_algorithms();
    bp = BIO_new(BIO_s_file());
    if (bp == NULL) {
        printf("BIO_new is failed.\n");
        ret = -1;
        goto finish;
    }
    ret = BIO_read_filename(bp, priv_pem_file);
    rsa = PEM_read_bio_RSAPrivateKey(bp, &rsa, NULL, (void*)passwd);
    if (rsa == NULL) {
        ret = -1;
        printf("open_private_key failed to PEM_read_bio_RSAPrivateKey Failed, ret=%d\n", ret);
        goto finish;
    }
    private_evp_key = EVP_PKEY_new();
    if (private_evp_key == NULL) {
        ret = -1;
        printf("open_private_key EVP_PKEY_new failed\n");
        goto finish;
    }
    EVP_PKEY_assign_RSA(private_evp_key, rsa);

    evp_md_ctx = EVP_MD_CTX_new();
    if (evp_md_ctx == NULL) {
        printf("EVP_MD_CTX_new failed.\n");
        ret = -1;
        goto finish;
    }
    EVP_MD_CTX_init(evp_md_ctx);
    ret = EVP_SignInit_ex(evp_md_ctx, EVP_md5(), NULL);
    if (ret != 1) {
        printf("EVP_SignInit_ex failed, ret = %d\n", ret);
        goto finish;
    }
    ret = EVP_SignUpdate(evp_md_ctx, sign_rom, sign_rom_len);
    if (ret != 1) {
        printf("EVP_SignUpdate failed, ret = %d\n", ret);
        goto finish;
    }
    ret = EVP_SignFinal(evp_md_ctx, result, (unsigned int*)result_len, private_evp_key);
    if (ret != 1) {
        printf("EVP_SignFinal failed, ret = %d\n", ret);
        goto finish;
    }
    ret = 0;
finish:
    if (private_evp_key != NULL)
        EVP_PKEY_free(private_evp_key);
    if (bp != NULL)
        BIO_free(bp);
    if (evp_md_ctx != NULL)
        EVP_MD_CTX_free(evp_md_ctx);
    if (ctx != NULL)
        EVP_PKEY_CTX_free(ctx);
    return ret;
}

int openssl_evp_rsa_verify(unsigned char *sign_rom, size_t sign_rom_len,
                            unsigned char *result, size_t result_len,
                            const unsigned char *pub_pem_file)
{
    int ret = 0;
    FILE *fp = NULL;
    EVP_PKEY* public_evp_key = NULL;
    RSA *rsa = NULL;
    BIO *bp = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_MD_CTX *evp_md_ctx = NULL;


    if (sign_rom == NULL || sign_rom_len == 0 || result == NULL || result_len == 0) {
        printf("input parameters error, content or len is NULL or 0.\n");
        ret = -1;
        goto finish;
    }
    if (NULL == pub_pem_file) {
        printf("input pem_file name is invalid\n");
        ret = -1;
        goto finish;
    }
    fp = fopen((const char*)pub_pem_file, "r");
    if (NULL == fp) {
        printf("input pem_file is not exit.\n");
        ret = -1;
        goto finish;
    }
    fclose(fp);
    fp = NULL;

    //OpenSSL_add_all_algorithms();
    bp = BIO_new(BIO_s_file());
    if (bp == NULL) {
        printf("BIO_new is failed.\n");
        ret = -1;
        goto finish;
    }
    ret = BIO_read_filename(bp, pub_pem_file);
    rsa = PEM_read_bio_RSAPublicKey(bp, NULL, NULL, NULL);
    if (rsa == NULL) {
        ret = -1;
        printf("open_public_key failed to PEM_read_bio_RSAPublicKey Failed, ret=%d\n", ret);
        goto finish;
    }
    public_evp_key = EVP_PKEY_new();
    if (public_evp_key == NULL) {
        ret = -1;
        goto finish;
    }
    EVP_PKEY_assign_RSA(public_evp_key, rsa);

    evp_md_ctx = EVP_MD_CTX_new();
    if (evp_md_ctx == NULL) {
        printf("EVP_MD_CTX_new failed.\n");
        ret = -1;
        goto finish;
    }
    EVP_MD_CTX_init(evp_md_ctx);f
    ret = EVP_VerifyInit_ex(evp_md_ctx, EVP_md5(), NULL);
    if (ret != 1) {
        printf("EVP_VerifyInit_ex failed, ret = %d\n", ret);
        goto finish;
    }
    ret = EVP_VerifyUpdate(evp_md_ctx, result, result_len);
    if (ret != 1) {
        printf("EVP_VerifyUpdate failed, ret = %d\n", ret);
        goto finish;
    }
    ret = EVP_VerifyFinal(evp_md_ctx, sign_rom, (unsigned int)sign_rom_len, public_evp_key);
    if (ret != 1) {
        printf("EVP_VerifyFinal failed, ret = %d\n", ret);
        goto finish;
    }
    ret = 0;
finish:
    if (public_evp_key != NULL)
        EVP_PKEY_free(public_evp_key);
    if (bp != NULL)
        BIO_free(bp);
    if (evp_md_ctx != NULL)
        EVP_MD_CTX_free(evp_md_ctx);
    if (ctx != NULL)
        EVP_PKEY_CTX_free(ctx);

    return ret;
}
*/
