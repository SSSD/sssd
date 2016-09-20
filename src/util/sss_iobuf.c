#include <talloc.h>

#include "util/util.h"
#include "util/sss_iobuf.h"

/**
 * @brief The iobuf structure that holds the data, its capacity and
 * a pointer to the data.
 *
 * @see sss_iobuf_init_empty()
 * @see sss_iobuf_init_readonly()
 */
struct sss_iobuf {
    uint8_t *data;          /* Start of the data buffer */

    size_t dp;              /* Data pointer */
    size_t size;            /* Current data buffer size */
    size_t capacity;        /* Maximum capacity */
};

struct sss_iobuf *sss_iobuf_init_empty(TALLOC_CTX *mem_ctx,
                                       size_t size,
                                       size_t capacity)
{
    struct sss_iobuf *iobuf;
    uint8_t *buf;

    iobuf = talloc_zero(mem_ctx, struct sss_iobuf);
    if (iobuf == NULL) {
        return NULL;
    }

    buf = talloc_zero_array(iobuf, uint8_t, size);
    if (buf == NULL) {
        talloc_free(iobuf);
        return NULL;
    }

    if (capacity == 0) {
        capacity = SIZE_MAX / 2;
    }

    iobuf->data = buf;
    iobuf->size = size;
    iobuf->capacity = capacity;
    iobuf->dp = 0;

    return iobuf;
}

struct sss_iobuf *sss_iobuf_init_readonly(TALLOC_CTX *mem_ctx,
                                          uint8_t *data,
                                          size_t size)
{
    struct sss_iobuf *iobuf;

    iobuf = sss_iobuf_init_empty(mem_ctx, size, size);
    if (iobuf == NULL) {
        return NULL;
    }

    if (data != NULL) {
        memcpy(iobuf->data, data, size);
    }

    return iobuf;
}

size_t sss_iobuf_get_len(struct sss_iobuf *iobuf)
{
    if (iobuf == NULL) {
        return 0;
    }

    return iobuf->dp;
}

size_t sss_iobuf_get_capacity(struct sss_iobuf *iobuf)
{
    if (iobuf == NULL) {
        return 0;
    }

    return iobuf->capacity;
}

size_t sss_iobuf_get_size(struct sss_iobuf *iobuf)
{
    if (iobuf == NULL) {
        return 0;
    }

    return iobuf->size;
}

uint8_t *sss_iobuf_get_data(struct sss_iobuf *iobuf)
{
    if (iobuf == NULL) {
        return NULL;
    }

    return iobuf->data;
}

static size_t iobuf_get_len(struct sss_iobuf *iobuf)
{
    if (iobuf == NULL) {
        return 0;
    }

    return (iobuf->size - iobuf->dp);
}

static errno_t ensure_bytes(struct sss_iobuf *iobuf,
                            size_t nbytes)
{
    size_t wantsize;
    size_t newsize;
    uint8_t *newdata;

    if (iobuf == NULL) {
        return EINVAL;
    }

    wantsize = iobuf->dp + nbytes;
    if (wantsize <= iobuf->size) {
        /* Enough space already */
        return EOK;
    }

    /* Else, try to extend the iobuf */
    if (wantsize > iobuf->capacity) {
        /* We will never grow past capacity */
        return ENOBUFS;
    }

    /* Double the size until we add at least nbytes, but stop if we double past capacity */
    for (newsize = iobuf->size;
         (newsize < wantsize) && (newsize < iobuf->capacity);
         newsize *= 2)
        ;

    if (newsize > iobuf->capacity) {
        newsize = iobuf->capacity;
    }

    newdata = talloc_realloc(iobuf, iobuf->data, uint8_t, newsize);
    if (newdata == NULL) {
        return ENOMEM;
    }

    iobuf->data = newdata;
    iobuf->size = newsize;

    return EOK;
}

static inline uint8_t *iobuf_ptr(struct sss_iobuf *iobuf)
{
    return iobuf->data + iobuf->dp;
}

errno_t sss_iobuf_read(struct sss_iobuf *iobuf,
                       size_t len,
                       uint8_t *_buf,
                       size_t *_read)
{
    size_t remaining;

    if (iobuf == NULL || _buf == NULL) {
        return EINVAL;
    }

    remaining = iobuf_get_len(iobuf);
    if (len > remaining) {
        len = remaining;
    }

    safealign_memcpy(_buf, iobuf_ptr(iobuf), len, &iobuf->dp);
    if (_read != NULL) {
        *_read = len;
    }

    return EOK;
}

errno_t sss_iobuf_write_len(struct sss_iobuf *iobuf,
                            uint8_t *buf,
                            size_t len)
{
    errno_t ret;

    if (iobuf == NULL || buf == NULL) {
        return EINVAL;
    }

    ret = ensure_bytes(iobuf, len);
    if (ret != EOK) {
        return ret;
    }

    safealign_memcpy(iobuf_ptr(iobuf), buf, len, &iobuf->dp);

    return EOK;
}
