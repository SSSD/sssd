/* This file is based on the work of Ulrich Drepper
 * (http://people.redhat.com/drepper/SHA-crypt.txt). I have replaced the
 * included SHA512 implementation by calls to NSS
 * (http://www.mozilla.org/projects/security/pki/nss/).
 *
 *  Sumit Bose <sbose@redhat.com>
 */
/* SHA512-based Unix crypt implementation.
   Released into the Public Domain by Ulrich Drepper <drepper@redhat.com>.  */

#define _GNU_SOURCE
#include <endian.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/types.h>

#include <prinit.h>
#include <nss.h>
#include <sechash.h>
#include <pk11func.h>


static int nspr_nss_init_done = 0;

/* according to
 * http://www.mozilla.org/projects/security/pki/nss/ref/ssl/sslfnc.html#1234224
 * PR_Init must be called, but at least for the HASH_* calls it seems to work
 * quite well without. */
static int nspr_nss_init(void)
{
  int ret;
  PR_Init(PR_USER_THREAD, PR_PRIORITY_NORMAL, 0);
  ret = NSS_NoDB_Init(NULL);
  if (ret != SECSuccess) {
    return ret;
  }
  nspr_nss_init_done = 1;
  return 0;
}

/* added for completness, so far not used */
static int nspr_nss_cleanup(void)
{
  int ret;
  ret=NSS_Shutdown();
  if (ret != SECSuccess ) {
    return ret;
  }
  PR_Cleanup();
  nspr_nss_init_done = 0;
  return 0;
}

/* Define our magic string to mark salt for SHA512 "encryption"
   replacement.  */
static const char sha512_salt_prefix[] = "$6$";

/* Prefix for optional rounds specification.  */
static const char sha512_rounds_prefix[] = "rounds=";

/* Maximum salt string length.  */
#define SALT_LEN_MAX 16
/* Default number of rounds if not explicitly specified.  */
#define ROUNDS_DEFAULT 5000
/* Minimum number of rounds.  */
#define ROUNDS_MIN 1000
/* Maximum number of rounds.  */
#define ROUNDS_MAX 999999999

/* Table with characters for base64 transformation.  */
static const char b64t[64] =
"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";


static char *
sha512_crypt_r (const char *key, const char *salt, char *buffer, int buflen)
{
  unsigned char alt_result[64]
    __attribute__ ((__aligned__ (__alignof__ (uint64_t))));
  unsigned char temp_result[64]
    __attribute__ ((__aligned__ (__alignof__ (uint64_t))));
  HASHContext *ctx;
  HASHContext *alt_ctx;
  size_t salt_len;
  size_t key_len;
  size_t cnt;
  char *cp;
  char *copied_key = NULL;
  char *copied_salt = NULL;
  char *p_bytes;
  char *s_bytes;
  /* Default number of rounds.  */
  size_t rounds = ROUNDS_DEFAULT;
  bool rounds_custom = false;

  int ret;
  unsigned int part;

  /* Find beginning of salt string.  The prefix should normally always
     be present.  Just in case it is not.  */
  if (strncmp (sha512_salt_prefix, salt, sizeof (sha512_salt_prefix) - 1) == 0)
    /* Skip salt prefix.  */
    salt += sizeof (sha512_salt_prefix) - 1;

  if (strncmp (salt, sha512_rounds_prefix, sizeof (sha512_rounds_prefix) - 1)
      == 0)
    {
      const char *num = salt + sizeof (sha512_rounds_prefix) - 1;
      char *endp;
      unsigned long int srounds = strtoul (num, &endp, 10);
      if (*endp == '$')
    {
      salt = endp + 1;
      rounds = MAX (ROUNDS_MIN, MIN (srounds, ROUNDS_MAX));
      rounds_custom = true;
    }
    }

  salt_len = MIN (strcspn (salt, "$"), SALT_LEN_MAX);
  key_len = strlen (key);

  if ((key - (char *) 0) % __alignof__ (uint64_t) != 0)
    {
      char *tmp = (char *) alloca (key_len + __alignof__ (uint64_t));
      key = copied_key =
    memcpy (tmp + __alignof__ (uint64_t)
        - (tmp - (char *) 0) % __alignof__ (uint64_t),
        key, key_len);
    }

  if ((salt - (char *) 0) % __alignof__ (uint64_t) != 0)
    {
      char *tmp = (char *) alloca (salt_len + __alignof__ (uint64_t));
      salt = copied_salt =
    memcpy (tmp + __alignof__ (uint64_t)
        - (tmp - (char *) 0) % __alignof__ (uint64_t),
        salt, salt_len);
    }


  if (!nspr_nss_init_done) {
    ret = nspr_nss_init();
    if (ret != SECSuccess) return NULL;
  }

  ctx = HASH_Create(HASH_AlgSHA512);
  if ( ctx == NULL ) {
    return NULL;
  }

  alt_ctx = HASH_Create(HASH_AlgSHA512);
  if ( alt_ctx == NULL ) {
    return NULL;
  }


  /* Prepare for the real work.  */
  HASH_Begin(ctx);

  /* Add the key string.  */
  HASH_Update(ctx, key, key_len);

  /* The last part is the salt string.  This must be at most 16
     characters and it ends at the first `$' character (for
     compatibility with existing implementations).  */
  HASH_Update(ctx, salt, salt_len);


  /* Compute alternate SHA512 sum with input KEY, SALT, and KEY.  The
     final result will be added to the first context.  */
  HASH_Begin(alt_ctx);

  /* Add key.  */
  HASH_Update(alt_ctx, key, key_len);

  /* Add salt.  */
  HASH_Update(alt_ctx, salt, salt_len);

  /* Add key again.  */
  HASH_Update(alt_ctx, key, key_len);

  /* Now get result of this (64 bytes) and add it to the other
     context.  */
  HASH_End(alt_ctx, alt_result, &part, HASH_ResultLenContext(alt_ctx));

  /* Add for any character in the key one byte of the alternate sum.  */
  for (cnt = key_len; cnt > 64; cnt -= 64) {
    HASH_Update(ctx, alt_result, 64);
  }
  HASH_Update(ctx, alt_result, cnt);

  /* Take the binary representation of the length of the key and for every
     1 add the alternate sum, for every 0 the key.  */
  for (cnt = key_len; cnt > 0; cnt >>= 1)
    if ((cnt & 1) != 0) {
      HASH_Update(ctx, alt_result, 64);
    } else {
      HASH_Update(ctx, key, key_len);
    }

  /* Create intermediate result.  */
  HASH_End(ctx, alt_result, &part, HASH_ResultLenContext(ctx));

  /* Start computation of P byte sequence.  */
  HASH_Begin(alt_ctx);

  /* For every character in the password add the entire password.  */
  for (cnt = 0; cnt < key_len; ++cnt) {
    HASH_Update(alt_ctx, key, key_len);
  }

  /* Finish the digest.  */
  HASH_End(alt_ctx, temp_result, &part, HASH_ResultLenContext(alt_ctx));

  /* Create byte sequence P.  */
  cp = p_bytes = alloca (key_len);
  for (cnt = key_len; cnt >= 64; cnt -= 64)
    cp = mempcpy (cp, temp_result, 64);
  memcpy (cp, temp_result, cnt);

  /* Start computation of S byte sequence.  */
  HASH_Begin(alt_ctx);

  /* For every character in the password add the entire password.  */
  for (cnt = 0; cnt < 16 + alt_result[0]; ++cnt) {
    HASH_Update(alt_ctx, salt, salt_len);
  }

  /* Finish the digest.  */
  HASH_End(alt_ctx, temp_result, &part, HASH_ResultLenContext(alt_ctx));

  /* Create byte sequence S.  */
  cp = s_bytes = alloca (salt_len);
  for (cnt = salt_len; cnt >= 64; cnt -= 64)
    cp = mempcpy (cp, temp_result, 64);
  memcpy (cp, temp_result, cnt);

  /* Repeatedly run the collected hash value through SHA512 to burn
     CPU cycles.  */
  for (cnt = 0; cnt < rounds; ++cnt)
    {
      /* New context.  */
      HASH_Begin(ctx);

      /* Add key or last result.  */
      if ((cnt & 1) != 0) {
        HASH_Update(ctx, p_bytes, key_len);
      } else {
        HASH_Update(ctx, alt_result, 64);
      }

      /* Add salt for numbers not divisible by 3.  */
      if (cnt % 3 != 0) {
        HASH_Update(ctx, s_bytes, salt_len);
      }

      /* Add key for numbers not divisible by 7.  */
      if (cnt % 7 != 0) {
        HASH_Update(ctx, p_bytes, key_len);
      }

      /* Add key or last result.  */
      if ((cnt & 1) != 0) {
        HASH_Update(ctx, alt_result, 64);
      } else {
        HASH_Update(ctx, p_bytes, key_len);
      }

      /* Create intermediate result.  */
      HASH_End(ctx, alt_result, &part, HASH_ResultLenContext(ctx));
    }

  /* Now we can construct the result string.  It consists of three
     parts.  */
  cp = __stpncpy (buffer, sha512_salt_prefix, MAX (0, buflen));
  buflen -= sizeof (sha512_salt_prefix) - 1;

  if (rounds_custom)
    {
      int n = snprintf (cp, MAX (0, buflen), "%s%zu$",
            sha512_rounds_prefix, rounds);
      cp += n;
      buflen -= n;
    }

  cp = __stpncpy (cp, salt, MIN ((size_t) MAX (0, buflen), salt_len));
  buflen -= MIN ((size_t) MAX (0, buflen), salt_len);

  if (buflen > 0)
    {
      *cp++ = '$';
      --buflen;
    }

#define b64_from_24bit(B2, B1, B0, N)                         \
  do {                                        \
    unsigned int w = ((B2) << 16) | ((B1) << 8) | (B0);               \
    int n = (N);                                  \
    while (n-- > 0 && buflen > 0)                         \
      {                                       \
    *cp++ = b64t[w & 0x3f];                           \
    --buflen;                                 \
    w >>= 6;                                  \
      }                                       \
  } while (0)

  b64_from_24bit (alt_result[0], alt_result[21], alt_result[42], 4);
  b64_from_24bit (alt_result[22], alt_result[43], alt_result[1], 4);
  b64_from_24bit (alt_result[44], alt_result[2], alt_result[23], 4);
  b64_from_24bit (alt_result[3], alt_result[24], alt_result[45], 4);
  b64_from_24bit (alt_result[25], alt_result[46], alt_result[4], 4);
  b64_from_24bit (alt_result[47], alt_result[5], alt_result[26], 4);
  b64_from_24bit (alt_result[6], alt_result[27], alt_result[48], 4);
  b64_from_24bit (alt_result[28], alt_result[49], alt_result[7], 4);
  b64_from_24bit (alt_result[50], alt_result[8], alt_result[29], 4);
  b64_from_24bit (alt_result[9], alt_result[30], alt_result[51], 4);
  b64_from_24bit (alt_result[31], alt_result[52], alt_result[10], 4);
  b64_from_24bit (alt_result[53], alt_result[11], alt_result[32], 4);
  b64_from_24bit (alt_result[12], alt_result[33], alt_result[54], 4);
  b64_from_24bit (alt_result[34], alt_result[55], alt_result[13], 4);
  b64_from_24bit (alt_result[56], alt_result[14], alt_result[35], 4);
  b64_from_24bit (alt_result[15], alt_result[36], alt_result[57], 4);
  b64_from_24bit (alt_result[37], alt_result[58], alt_result[16], 4);
  b64_from_24bit (alt_result[59], alt_result[17], alt_result[38], 4);
  b64_from_24bit (alt_result[18], alt_result[39], alt_result[60], 4);
  b64_from_24bit (alt_result[40], alt_result[61], alt_result[19], 4);
  b64_from_24bit (alt_result[62], alt_result[20], alt_result[41], 4);
  b64_from_24bit (0, 0, alt_result[63], 2);

  if (buflen <= 0)
    {
      errno = ERANGE;
      buffer = NULL;
    }
  else
    *cp = '\0';     /* Terminate the string.  */

  /* Clear the buffer for the intermediate result so that people
     attaching to processes or reading core dumps cannot get any
     information.  We do it in this way to clear correct_words[]
     inside the SHA512 implementation as well.  */
  HASH_Destroy(ctx);
  HASH_Destroy(alt_ctx);

  memset (temp_result, '\0', sizeof (temp_result));
  memset (p_bytes, '\0', key_len);
  memset (s_bytes, '\0', salt_len);
  memset (&ctx, '\0', sizeof (ctx));
  memset (&alt_ctx, '\0', sizeof (alt_ctx));
  if (copied_key != NULL)
    memset (copied_key, '\0', key_len);
  if (copied_salt != NULL)
    memset (copied_salt, '\0', salt_len);

  return buffer;
}


/* This entry point is equivalent to the `crypt' function in Unix
   libcs.  */
char *
nss_sha512_crypt (const char *key, const char *salt)
{
  /* We don't want to have an arbitrary limit in the size of the
     password.  We can compute an upper bound for the size of the
     result in advance and so we can prepare the buffer we pass to
     `sha512_crypt_r'.  */
  static char *buffer;
  static int buflen;
  int needed = (sizeof (sha512_salt_prefix) - 1
        + sizeof (sha512_rounds_prefix) + 9 + 1
        + strlen (salt) + 1 + 86 + 1);

  if (buflen < needed)
    {
      char *new_buffer = (char *) realloc (buffer, needed);
      if (new_buffer == NULL)
    return NULL;

      buffer = new_buffer;
      buflen = needed;
    }

  return sha512_crypt_r (key, salt, buffer, buflen);
}

char *gen_salt(void)
{
  int ret;
  unsigned char bin_rand[12];
  static char b64_rand[17];
  char *cp;
  int buflen;

  if (!nspr_nss_init_done) {
    ret = nspr_nss_init();
    if (ret != SECSuccess) return NULL;
  }

  ret = PK11_GenerateRandom(bin_rand, sizeof(bin_rand)-1);
  cp = b64_rand;
  buflen = 16;
  b64_from_24bit (bin_rand[0], bin_rand[1], bin_rand[2], 4);
  b64_from_24bit (bin_rand[3], bin_rand[4], bin_rand[5], 4);
  b64_from_24bit (bin_rand[6], bin_rand[7], bin_rand[8], 4);
  b64_from_24bit (bin_rand[9], bin_rand[10], bin_rand[11], 4);

  *cp++ = '\0';

  return b64_rand;

}

