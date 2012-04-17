
int s3crypt_sha512(TALLOC_CTX *mmectx,
                   const char *key, const char *salt, char **_hash);
int s3crypt_gen_salt(TALLOC_CTX *memctx, char **_salt);

/* Methods of obfuscation. */
enum obfmethod {
    AES_256,
    NUM_OBFMETHODS
};

int test2(void);

char *sss_base64_encode(TALLOC_CTX *mem_ctx,
                        const unsigned char *in,
                        size_t insize);

unsigned char *sss_base64_decode(TALLOC_CTX *mem_ctx,
                                 const char *in,
                                 size_t *outsize);

#define SSS_SHA1_LENGTH 20

int sss_hmac_sha1(const unsigned char *key,
                  size_t key_len,
                  const unsigned char *in,
                  size_t in_len,
                  unsigned char *out);

int sss_password_encrypt(TALLOC_CTX *mem_ctx, const char *password, int plen,
                         enum obfmethod meth, char **obfpwd);

int sss_password_decrypt(TALLOC_CTX *mem_ctx, char *b64encoded,
                         char **password);
