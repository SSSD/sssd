/* This file is based on the work of Ulrich Drepper
 * (http://people.redhat.com/drepper/SHA-crypt.txt). I have replaced the
 * included SHA512 implementation by calls to NSS
 * (http://www.mozilla.org/projects/security/pki/nss/).
 *
 *  Sumit Bose <sbose@redhat.com>
 */
/* SHA512-based UNIX crypt implementation.
   Released into the Public Domain by Ulrich Drepper <drepper@redhat.com>.  */

#include "config.h"

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/types.h>

#include "util/util.h"
#include "util/sss_endian.h"
#include "util/crypto/nss/nss_util.h"

#include <prinit.h>
#include <nss.h>
#include <sechash.h>
#include <pk11func.h>

/* Define our magic string to mark salt for SHA512 "encryption" replacement. */
const char sha512_salt_prefix[] = "$6$";
#define SALT_PREF_SIZE (sizeof(sha512_salt_prefix) - 1)

/* Prefix for optional rounds specification. */
const char sha512_rounds_prefix[] = "rounds=";
#define ROUNDS_SIZE (sizeof(sha512_rounds_prefix) - 1)

#define SALT_LEN_MAX 16
#define ROUNDS_DEFAULT 5000
#define ROUNDS_MIN 1000
#define ROUNDS_MAX 999999999

/* Table with characters for base64 transformation.  */
const char b64t[64] =
    "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/* base64 conversion function */
static inline void b64_from_24bit(char **dest, size_t *len, size_t n,
                                  uint8_t b2, uint8_t b1, uint8_t b0)
{
    uint32_t w;
    size_t i;

    if (*len < n) n = *len;

    w = (b2 << 16) | (b1 << 8) | b0;
    for (i = 0; i < n; i++) {
        (*dest)[i] = b64t[w & 0x3f];
        w >>= 6;
    }

    *len -= i;
    *dest += i;
}

#define PTR_2_INT(x) ((x) - ((__typeof__ (x)) NULL))
#define ALIGN64 __alignof__(uint64_t)

static int sha512_crypt_r(const char *key,
                          const char *salt,
                          char *buffer, size_t buflen)
{
    unsigned char temp_result[64] __attribute__((__aligned__(ALIGN64)));
    unsigned char alt_result[64] __attribute__((__aligned__(ALIGN64)));
    size_t rounds = ROUNDS_DEFAULT;
    bool rounds_custom = false;
    HASHContext *alt_ctx = NULL;
    HASHContext *ctx = NULL;
    size_t salt_len;
    size_t key_len;
    size_t cnt;
    char *copied_salt = NULL;
    char *copied_key = NULL;
    char *p_bytes = NULL;
    char *s_bytes = NULL;
    int p1, p2, p3, pt, n;
    unsigned int part;
    char *cp, *tmp;
    int ret;

    /* Find beginning of salt string. The prefix should normally always be
     * present. Just in case it is not. */
    if (strncmp(salt, sha512_salt_prefix, SALT_PREF_SIZE) == 0) {
        /* Skip salt prefix.  */
        salt += SALT_PREF_SIZE;
    }

    if (strncmp(salt, sha512_rounds_prefix, ROUNDS_SIZE) == 0) {
        unsigned long int srounds;
        const char *num;
        char *endp;

        num = salt + ROUNDS_SIZE;
        srounds = strtoul(num, &endp, 10);
        if (*endp == '$') {
            salt = endp + 1;
            if (srounds < ROUNDS_MIN) srounds = ROUNDS_MIN;
            if (srounds > ROUNDS_MAX) srounds = ROUNDS_MAX;
            rounds = srounds;
            rounds_custom = true;
        }
    }

    salt_len = MIN(strcspn(salt, "$"), SALT_LEN_MAX);
    key_len = strlen(key);

    if ((PTR_2_INT(key) % ALIGN64) != 0) {
        tmp = (char *)alloca(key_len + ALIGN64);
        key = copied_key = memcpy(tmp + ALIGN64 - PTR_2_INT(tmp) % ALIGN64, key, key_len);
    }

    if (PTR_2_INT(salt) % ALIGN64 != 0) {
        tmp = (char *)alloca(salt_len + ALIGN64);
        salt = copied_salt = memcpy(tmp + ALIGN64 - PTR_2_INT(tmp) % ALIGN64, salt, salt_len);
    }

    ret = nspr_nss_init();
    if (ret != EOK) {
        ret = EIO;
        goto done;
    }

    ctx = HASH_Create(HASH_AlgSHA512);
    if (!ctx) {
        ret = EIO;
        goto done;
    }

    alt_ctx = HASH_Create(HASH_AlgSHA512);
    if (!alt_ctx) {
        ret = EIO;
        goto done;
    }

    /* Prepare for the real work.  */
    HASH_Begin(ctx);

    /* Add the key string.  */
    HASH_Update(ctx, (const unsigned char *)key, key_len);

    /* The last part is the salt string. This must be at most 16
     * characters and it ends at the first `$' character (for
     * compatibility with existing implementations). */
    HASH_Update(ctx, (const unsigned char *)salt, salt_len);


    /* Compute alternate SHA512 sum with input KEY, SALT, and KEY.
     * The final result will be added to the first context. */
    HASH_Begin(alt_ctx);

    /* Add key. */
    HASH_Update(alt_ctx, (const unsigned char *)key, key_len);

    /* Add salt. */
    HASH_Update(alt_ctx, (const unsigned char *)salt, salt_len);

    /* Add key again. */
    HASH_Update(alt_ctx, (const unsigned char *)key, key_len);

    /* Now get result of this (64 bytes) and add it to the other context. */
    HASH_End(alt_ctx, alt_result, &part, HASH_ResultLenContext(alt_ctx));

    /* Add for any character in the key one byte of the alternate sum. */
    for (cnt = key_len; cnt > 64; cnt -= 64) {
        HASH_Update(ctx, alt_result, 64);
    }
    HASH_Update(ctx, alt_result, cnt);

    /* Take the binary representation of the length of the key and for every
     * 1 add the alternate sum, for every 0 the key. */
    for (cnt = key_len; cnt > 0; cnt >>= 1) {
        if ((cnt & 1) != 0) {
            HASH_Update(ctx, alt_result, 64);
        } else {
            HASH_Update(ctx, (const unsigned char *)key, key_len);
        }
    }

    /* Create intermediate result. */
    HASH_End(ctx, alt_result, &part, HASH_ResultLenContext(ctx));

    /* Start computation of P byte sequence. */
    HASH_Begin(alt_ctx);

    /* For every character in the password add the entire password. */
    for (cnt = 0; cnt < key_len; cnt++) {
        HASH_Update(alt_ctx, (const unsigned char *)key, key_len);
    }

    /* Finish the digest. */
    HASH_End(alt_ctx, temp_result, &part, HASH_ResultLenContext(alt_ctx));

    /* Create byte sequence P. */
    cp = p_bytes = alloca(key_len);
    for (cnt = key_len; cnt >= 64; cnt -= 64) {
        cp = mempcpy(cp, temp_result, 64);
    }
    memcpy(cp, temp_result, cnt);

    /* Start computation of S byte sequence. */
    HASH_Begin(alt_ctx);

    /* For every character in the password add the entire salt. */
    for (cnt = 0; cnt < 16 + alt_result[0]; cnt++) {
        HASH_Update(alt_ctx, (const unsigned char *)salt, salt_len);
    }

    /* Finish the digest. */
    HASH_End(alt_ctx, temp_result, &part, HASH_ResultLenContext(alt_ctx));

    /* Create byte sequence S.  */
    cp = s_bytes = alloca(salt_len);
    for (cnt = salt_len; cnt >= 64; cnt -= 64) {
        cp = mempcpy(cp, temp_result, 64);
    }
    memcpy(cp, temp_result, cnt);

    /* Repeatedly run the collected hash value through SHA512 to burn CPU cycles. */
    for (cnt = 0; cnt < rounds; cnt++) {

        HASH_Begin(ctx);

        /* Add key or last result. */
        if ((cnt & 1) != 0) {
            HASH_Update(ctx, (const unsigned char *)p_bytes, key_len);
        } else {
            HASH_Update(ctx, alt_result, 64);
        }

        /* Add salt for numbers not divisible by 3. */
        if (cnt % 3 != 0) {
            HASH_Update(ctx, (const unsigned char *)s_bytes, salt_len);
        }

        /* Add key for numbers not divisible by 7. */
        if (cnt % 7 != 0) {
            HASH_Update(ctx, (const unsigned char *)p_bytes, key_len);
        }

        /* Add key or last result. */
        if ((cnt & 1) != 0) {
            HASH_Update(ctx, alt_result, 64);
        } else {
            HASH_Update(ctx, (const unsigned char *)p_bytes, key_len);
        }

        /* Create intermediate result. */
        HASH_End(ctx, alt_result, &part, HASH_ResultLenContext(ctx));
    }

    /* Now we can construct the result string.
     * It consists of three parts. */
    if (buflen <= SALT_PREF_SIZE) {
        ret = ERANGE;
        goto done;
    }

    cp = memcpy(buffer, sha512_salt_prefix, SALT_PREF_SIZE);
    buflen -= SALT_PREF_SIZE;

    if (rounds_custom) {
        n = snprintf(cp, buflen, "%s%zu$",
                     sha512_rounds_prefix, rounds);
        if (n < 0 || n >= buflen) {
            ret = ERANGE;
            goto done;
        }
        cp += n;
        buflen -= n;
    }

    if (buflen <= salt_len + 1) {
        ret = ERANGE;
        goto done;
    }
    cp = stpncpy(cp, salt, salt_len);
    *cp++ = '$';
    buflen -= salt_len + 1;

    /* fuzzyfill the base 64 string */
    p1 = 0;
    p2 = 21;
    p3 = 42;
    for (n = 0; n < 21; n++) {
        b64_from_24bit(&cp, &buflen, 4, alt_result[p1], alt_result[p2], alt_result[p3]);
        if (buflen == 0) {
            ret = ERANGE;
            goto done;
        }
        pt = p1;
        p1 = p2 + 1;
        p2 = p3 + 1;
        p3 = pt + 1;
    }
    /* 64th and last byte */
    b64_from_24bit(&cp, &buflen, 2, 0, 0, alt_result[p3]);
    if (buflen == 0) {
        ret = ERANGE;
        goto done;
    }

    *cp = '\0';
    ret = EOK;

done:
    /* Clear the buffer for the intermediate result so that people attaching
     * to processes or reading core dumps cannot get any information. We do it
     * in this way to clear correct_words[] inside the SHA512 implementation
     * as well.  */
    if (ctx) HASH_Destroy(ctx);
    if (alt_ctx) HASH_Destroy(alt_ctx);
    if (p_bytes) memset(p_bytes, '\0', key_len);
    if (s_bytes) memset(s_bytes, '\0', salt_len);
    if (copied_key) memset(copied_key, '\0', key_len);
    if (copied_salt) memset(copied_salt, '\0', salt_len);
    memset(temp_result, '\0', sizeof(temp_result));

    return ret;
}

int s3crypt_sha512(TALLOC_CTX *memctx,
                   const char *key, const char *salt, char **_hash)
{
    char *hash;
    int hlen = (sizeof (sha512_salt_prefix) - 1
                + sizeof (sha512_rounds_prefix) + 9 + 1
                + strlen (salt) + 1 + 86 + 1);
    int ret;

    hash = talloc_size(memctx, hlen);
    if (!hash) return ENOMEM;

    ret = sha512_crypt_r(key, salt, hash, hlen);
    if (ret) return ret;

    *_hash = hash;
    return ret;
}

#define SALT_RAND_LEN 12

int s3crypt_gen_salt(TALLOC_CTX *memctx, char **_salt)
{
    uint8_t rb[SALT_RAND_LEN];
    char *salt, *cp;
    size_t slen;
    int ret;

    ret = nspr_nss_init();
    if (ret != EOK) {
        return EIO;
    }

    salt = talloc_size(memctx, SALT_LEN_MAX + 1);
    if (!salt) {
        return ENOMEM;
    }

    ret = PK11_GenerateRandom(rb, SALT_RAND_LEN);
    if (ret != SECSuccess) {
        return EIO;
    }

    slen = SALT_LEN_MAX;
    cp = salt;
    b64_from_24bit(&cp, &slen, 4, rb[0], rb[1], rb[2]);
    b64_from_24bit(&cp, &slen, 4, rb[3], rb[4], rb[5]);
    b64_from_24bit(&cp, &slen, 4, rb[6], rb[7], rb[8]);
    b64_from_24bit(&cp, &slen, 4, rb[9], rb[10], rb[11]);
    *cp = '\0';

    *_salt = salt;

    return EOK;
}
