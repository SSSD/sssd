#include <talloc.h>
#include <errno.h>

#include "util/crypto/sss_crypto.h"

int sss_password_encrypt(TALLOC_CTX *mem_ctx, const char *password, int plen,
                         enum obfmethod meth, char **obfpwd)
{
    return ENOSYS;
}

int sss_password_decrypt(TALLOC_CTX *mem_ctx, char *b64encoded,
                         char **password)
{
    return ENOSYS;
}
