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
                                          const uint8_t *data,
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

struct sss_iobuf *sss_iobuf_init_steal(TALLOC_CTX *mem_ctx,
                                       uint8_t *data,
                                       size_t size)
{
    struct sss_iobuf *iobuf;

    iobuf = talloc_zero(mem_ctx, struct sss_iobuf);
    if (iobuf == NULL) {
        return NULL;
    }

    iobuf->data = talloc_steal(iobuf, data);
    iobuf->size = size;
    iobuf->capacity = size;
    iobuf->dp = 0;

    return iobuf;
}

void sss_iobuf_cursor_reset(struct sss_iobuf *iobuf)
{
    iobuf->dp = 0;
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

errno_t sss_iobuf_read_len(struct sss_iobuf *iobuf,
                           size_t len,
                           uint8_t *_buf)
{
    size_t read_bytes;
    errno_t ret;

    ret = sss_iobuf_read(iobuf, len, _buf, &read_bytes);
    if (ret != EOK) {
        return ret;
    }

    if (read_bytes != len) {
        return ENOBUFS;
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

errno_t sss_iobuf_read_varlen(TALLOC_CTX *mem_ctx,
                              struct sss_iobuf *iobuf,
                              uint8_t **_out,
                              size_t *_len)
{
    uint8_t *out;
    uint32_t len;
    size_t slen;
    errno_t ret;

    if (iobuf == NULL || _out == NULL || _len == NULL) {
        return EINVAL;
    }

    ret = sss_iobuf_read_uint32(iobuf, &len);
    if (ret != EOK) {
        return ret;
    }

    if (len == 0) {
        *_out = NULL;
        *_len = 0;
        return EOK;
    }

    out = talloc_array(mem_ctx, uint8_t, len);
    if (out == NULL) {
        return ENOMEM;
    }

    slen = len;
    ret = sss_iobuf_read_len(iobuf, slen, out);
    if (ret != EOK) {
        talloc_free(out);
        return ret;
    }

    *_out = out;
    *_len = slen;

    return EOK;
}

errno_t sss_iobuf_write_varlen(struct sss_iobuf *iobuf,
                               uint8_t *data,
                               size_t len)
{
    errno_t ret;

    if (iobuf == NULL || (data == NULL && len != 0)) {
        return EINVAL;
    }

    ret = sss_iobuf_write_uint32(iobuf, len);
    if (ret != EOK) {
        return ret;
    }

    if (len == 0) {
        return EOK;
    }

    return sss_iobuf_write_len(iobuf, data, len);
}

errno_t sss_iobuf_read_iobuf(TALLOC_CTX *mem_ctx,
                             struct sss_iobuf *iobuf,
                             struct sss_iobuf **_out)
{
    struct sss_iobuf *out;
    uint8_t *data;
    size_t len;
    errno_t ret;

    ret = sss_iobuf_read_varlen(NULL, iobuf, &data, &len);
    if (ret != EOK) {
        return ret;
    }

    out = sss_iobuf_init_steal(mem_ctx, data, len);
    if (out == NULL) {
        return ENOMEM;
    }

    *_out = out;

    return EOK;
}

errno_t sss_iobuf_write_iobuf(struct sss_iobuf *iobuf,
                              struct sss_iobuf *data)
{
    return sss_iobuf_write_varlen(iobuf, data->data, data->size);
}

errno_t sss_iobuf_read_uint8(struct sss_iobuf *iobuf,
                             uint8_t *_val)
{
    SAFEALIGN_COPY_UINT8_CHECK(_val, iobuf_ptr(iobuf),
                               iobuf->capacity, &iobuf->dp);
    return EOK;
}

errno_t sss_iobuf_read_uint32(struct sss_iobuf *iobuf,
                              uint32_t *_val)
{
    SAFEALIGN_COPY_UINT32_CHECK(_val, iobuf_ptr(iobuf),
                                iobuf->capacity, &iobuf->dp);
    return EOK;
}

errno_t sss_iobuf_read_int32(struct sss_iobuf *iobuf,
                             int32_t *_val)
{
    SAFEALIGN_COPY_INT32_CHECK(_val, iobuf_ptr(iobuf),
                               iobuf->capacity, &iobuf->dp);
    return EOK;
}

errno_t sss_iobuf_write_uint8(struct sss_iobuf *iobuf,
                              uint8_t val)
{
    errno_t ret;

    ret = ensure_bytes(iobuf, sizeof(uint8_t));
    if (ret != EOK) {
        return ret;
    }

    SAFEALIGN_SETMEM_UINT8(iobuf_ptr(iobuf), val, &iobuf->dp);
    return EOK;
}

errno_t sss_iobuf_write_uint32(struct sss_iobuf *iobuf,
                               uint32_t val)
{
    errno_t ret;

    ret = ensure_bytes(iobuf, sizeof(uint32_t));
    if (ret != EOK) {
        return ret;
    }

    SAFEALIGN_SETMEM_UINT32(iobuf_ptr(iobuf), val, &iobuf->dp);
    return EOK;
}

errno_t sss_iobuf_write_int32(struct sss_iobuf *iobuf,
                              int32_t val)
{
    errno_t ret;

    ret = ensure_bytes(iobuf, sizeof(int32_t));
    if (ret != EOK) {
        return ret;
    }

    SAFEALIGN_SETMEM_INT32(iobuf_ptr(iobuf), val, &iobuf->dp);
    return EOK;
}

errno_t sss_iobuf_read_stringz(struct sss_iobuf *iobuf,
                               const char **_out)
{
    uint8_t *end;
    size_t len;

    if (iobuf == NULL) {
        return EINVAL;
    }

    if (_out == NULL) {
        return EINVAL;
    }

    *_out = NULL;

    end = memchr(iobuf_ptr(iobuf), '\0', sss_iobuf_get_size(iobuf));
    if (end == NULL) {
        return EINVAL;
    }

    len = end + 1 - iobuf_ptr(iobuf);
    if (sss_iobuf_get_size(iobuf) < len) {
        return EINVAL;
    }

    *_out = (const char *) iobuf_ptr(iobuf);
    iobuf->dp += len;
    return EOK;
}

errno_t sss_iobuf_write_stringz(struct sss_iobuf *iobuf,
                                const char *str)
{
    if (iobuf == NULL || str == NULL) {
        return EINVAL;
    }

    SAFEALIGN_MEMCPY_CHECK(iobuf_ptr(iobuf),
                           str, strlen(str)+1,
                           sss_iobuf_get_size(iobuf),
                           &iobuf->dp);
    return EOK;
}
