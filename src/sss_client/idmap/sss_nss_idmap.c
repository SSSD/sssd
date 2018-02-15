/*
    SSSD

    NSS Responder Interface for ID-SID mappings

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2013 Red Hat

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdlib.h>
#include <errno.h>
#include <nss.h>

#include "sss_client/sss_cli.h"
#include "sss_client/idmap/sss_nss_idmap.h"
#include "util/strtonum.h"

#define DATA_START (3 * sizeof(uint32_t))
union input {
    const char *str;
    uint32_t id;
};

struct output {
    enum sss_id_type type;
    union {
        char *str;
        uint32_t id;
        struct sss_nss_kv *kv_list;
    } d;
};

int nss_status_to_errno(enum nss_status nret) {
    switch (nret) {
    case NSS_STATUS_TRYAGAIN:
        return EAGAIN;
    case NSS_STATUS_SUCCESS:
        return EOK;
    case NSS_STATUS_UNAVAIL:
    default:
        return ENOENT;
    }

    return EINVAL;
}

void sss_nss_free_kv(struct sss_nss_kv *kv_list)
{
    size_t c;

    if (kv_list != NULL) {
        for (c = 0; kv_list[c].key != NULL; c++) {
            free(kv_list[c].key);
            free(kv_list[c].value);
        }
        free(kv_list);
    }
}

static int  buf_to_kv_list(uint8_t *buf, size_t buf_len,
                           struct sss_nss_kv **kv_list)
{
    size_t c;
    size_t count = 0;
    struct sss_nss_kv *list;
    uint8_t *p;
    int ret;

    for (c = 0; c < buf_len; c++) {
        if (buf[c] == '\0') {
            count++;
        }
    }

    if ((count % 2) != 0) {
        return EINVAL;
    }
    count /= 2;

    list = calloc((count + 1), sizeof(struct sss_nss_kv));
    if (list == NULL) {
        return ENOMEM;
    }

    p = buf;
    for (c = 0; c < count; c++) {
        list[c].key = strdup((char *) p);
        if (list[c].key == NULL) {
            ret = ENOMEM;
            goto done;
        }

        p = memchr(p, '\0', buf_len - (p - buf));
        if (p == NULL) {
            ret = EINVAL;
            goto done;
        }
        p++;

        list[c].value = strdup((char *) p);
        if (list[c].value == NULL) {
            ret = ENOMEM;
            goto done;
        }

        p = memchr(p, '\0', buf_len - (p - buf));
        if (p == NULL) {
            ret = EINVAL;
            goto done;
        }
        p++;
    }

    *kv_list = list;

    ret = EOK;

done:
    if (ret != EOK) {
        sss_nss_free_kv(list);
    }

    return ret;
}

static int sss_nss_getyyybyxxx(union input inp, enum sss_cli_command cmd ,
                               struct output *out)
{
    int ret;
    size_t inp_len;
    struct sss_cli_req_data rd;
    uint8_t *repbuf = NULL;
    size_t replen;
    int errnop;
    enum nss_status nret;
    uint32_t num_results;
    char *str = NULL;
    size_t data_len;
    uint32_t c;
    struct sss_nss_kv *kv_list;

    switch (cmd) {
    case SSS_NSS_GETSIDBYNAME:
    case SSS_NSS_GETNAMEBYSID:
    case SSS_NSS_GETIDBYSID:
    case SSS_NSS_GETORIGBYNAME:
    case SSS_NSS_GETNAMEBYCERT:
        ret = sss_strnlen(inp.str, 2048, &inp_len);
        if (ret != EOK) {
            return EINVAL;
        }

        rd.len = inp_len + 1;
        rd.data = inp.str;

        break;
    case SSS_NSS_GETSIDBYID:
        rd.len = sizeof(uint32_t);
        rd.data = &inp.id;

        break;
    default:
        return EINVAL;
    }

    sss_nss_lock();

    nret = sss_nss_make_request(cmd, &rd, &repbuf, &replen, &errnop);
    if (nret != NSS_STATUS_SUCCESS) {
        ret = nss_status_to_errno(nret);
        goto done;
    }

    if (replen < 8) {
        ret = EBADMSG;
        goto done;
    }

    SAFEALIGN_COPY_UINT32(&num_results, repbuf, NULL);
    if (num_results == 0) {
        ret = ENOENT;
        goto done;
    } else if (num_results > 1) {
        ret = EBADMSG;
        goto done;
    }

    /* Skip first two 32 bit values (number of results and
     * reserved padding) */
    SAFEALIGN_COPY_UINT32(&out->type, repbuf + 2 * sizeof(uint32_t), NULL);

    data_len = replen - DATA_START;

    switch(cmd) {
    case SSS_NSS_GETSIDBYID:
    case SSS_NSS_GETSIDBYNAME:
    case SSS_NSS_GETNAMEBYSID:
    case SSS_NSS_GETNAMEBYCERT:
        if (data_len <= 1 || repbuf[replen - 1] != '\0') {
            ret = EBADMSG;
            goto done;
        }

        str = malloc(sizeof(char) * data_len);
        if (str == NULL) {
            ret = ENOMEM;
            goto done;
        }

        strncpy(str, (char *) repbuf + DATA_START, data_len);

        out->d.str = str;

        break;
    case SSS_NSS_GETIDBYSID:
        if (data_len != sizeof(uint32_t)) {
            ret = EBADMSG;
            goto done;
        }

        SAFEALIGN_COPY_UINT32(&c, repbuf + DATA_START, NULL);
        out->d.id = c;

        break;
    case SSS_NSS_GETORIGBYNAME:
        ret = buf_to_kv_list(repbuf + DATA_START, data_len, &kv_list);
        if (ret != EOK) {
            goto done;
        }

        out->d.kv_list = kv_list;

        break;
    default:
        ret = EINVAL;
        goto done;
    }

    ret = EOK;

done:
    sss_nss_unlock();
    free(repbuf);
    if (ret != EOK) {
        free(str);
    }

    return ret;
}

int sss_nss_getsidbyname(const char *fq_name, char **sid,
                         enum sss_id_type *type)
{
    int ret;
    union input inp;
    struct output out;

    if (sid == NULL || fq_name == NULL || *fq_name == '\0') {
        return EINVAL;
    }

    inp.str = fq_name;

    ret = sss_nss_getyyybyxxx(inp, SSS_NSS_GETSIDBYNAME, &out);
    if (ret == EOK) {
        *sid = out.d.str;
        *type = out.type;
    }

    return ret;
}

int sss_nss_getsidbyid(uint32_t id, char **sid, enum sss_id_type *type)
{
    int ret;
    union input inp;
    struct output out;

    if (sid == NULL) {
        return EINVAL;
    }

    inp.id = id;

    ret = sss_nss_getyyybyxxx(inp, SSS_NSS_GETSIDBYID, &out);
    if (ret == EOK) {
        *sid = out.d.str;
        *type = out.type;
    }

    return ret;
}

int sss_nss_getnamebysid(const char *sid, char **fq_name,
                         enum sss_id_type *type)
{
    int ret;
    union input inp;
    struct output out;

    if (fq_name == NULL || sid == NULL || *sid == '\0') {
        return EINVAL;
    }

    inp.str = sid;

    ret = sss_nss_getyyybyxxx(inp, SSS_NSS_GETNAMEBYSID, &out);
    if (ret == EOK) {
        *fq_name = out.d.str;
        *type = out.type;
    }

    return ret;
}

int sss_nss_getidbysid(const char *sid, uint32_t *id, enum sss_id_type *id_type)
{
    int ret;
    union input inp;
    struct output out;

    if (id == NULL || id_type == NULL || sid == NULL || *sid == '\0') {
        return EINVAL;
    }

    inp.str = sid;

    ret = sss_nss_getyyybyxxx(inp, SSS_NSS_GETIDBYSID, &out);
    if (ret == EOK) {
        *id = out.d.id;
        *id_type = out.type;
    }

    return ret;
}

int sss_nss_getorigbyname(const char *fq_name, struct sss_nss_kv **kv_list,
                         enum sss_id_type *type)
{
    int ret;
    union input inp;
    struct output out;

    if (kv_list == NULL || fq_name == NULL || *fq_name == '\0') {
        return EINVAL;
    }

    inp.str = fq_name;

    ret = sss_nss_getyyybyxxx(inp, SSS_NSS_GETORIGBYNAME, &out);
    if (ret == EOK) {
        *kv_list = out.d.kv_list;
        *type = out.type;
    }

    return ret;
}

int sss_nss_getnamebycert(const char *cert, char **fq_name,
                          enum sss_id_type *type)
{
    int ret;
    union input inp;
    struct output out;

    if (fq_name == NULL || cert == NULL || *cert == '\0') {
        return EINVAL;
    }

    inp.str = cert;

    ret = sss_nss_getyyybyxxx(inp, SSS_NSS_GETNAMEBYCERT, &out);
    if (ret == EOK) {
        *fq_name = out.d.str;
        *type = out.type;
    }

    return ret;
}
