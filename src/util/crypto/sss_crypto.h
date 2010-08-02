
int s3crypt_sha512(TALLOC_CTX *mmectx,
                   const char *key, const char *salt, char **_hash);
int s3crypt_gen_salt(TALLOC_CTX *memctx, char **_salt);

/* Methods of obfuscation. */
enum obfmethod {
    AES_256,
    NUM_OBFMETHODS
};

int test2(void);

int sss_password_encrypt(TALLOC_CTX *mem_ctx, const char *password, int plen,
                         enum obfmethod meth, char **obfpwd);

int sss_password_decrypt(TALLOC_CTX *mem_ctx, char *b64encoded,
                         char **password);
