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
#include "sss_client/nss_mc.h"
#include "sss_client/idmap/sss_nss_idmap.h"
#include "sss_client/idmap/sss_nss_idmap_private.h"
#include "util/strtonum.h"

#define DATA_START (3 * sizeof(uint32_t))
#define LIST_START (2 * sizeof(uint32_t))
#define NO_TIMEOUT ((unsigned int) -1)

union input {
    const char *str;
    uint32_t id;
};

struct output {
    enum sss_id_type type;
    enum sss_id_type *types;
    union {
        char *str;
        uint32_t id;
        struct sss_nss_kv *kv_list;
        char **names;
    } d;
};

static int sss_nss_status_to_errno(enum nss_status nret) {
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

void sss_nss_free_list(char **l)
{
    size_t c;

    if (l != NULL) {
        for (c = 0; l[c] != NULL; c++) {
            free(l[c]);
        }
        free(l);
    }
}

static int buf_to_name_type_list(uint8_t *buf, size_t buf_len, uint32_t num,
                                 char ***names, enum sss_id_type **types)
{
    int ret;
    size_t c;
    char **n = NULL;
    enum sss_id_type *t = NULL;
    size_t rp = 0;

    n = calloc(num + 1, sizeof(char *));
    if (n == NULL) {
        ret = ENOMEM;
        goto done;
    }

    t = calloc(num + 1, sizeof(enum sss_id_type));
    if (t == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (c = 0; c < num; c++) {
        SAFEALIGN_COPY_UINT32(&(t[c]), buf + rp, &rp);
        n[c] = strdup((char *) buf + rp);
        if (n[c] == NULL) {
            ret = ENOMEM;
            goto done;
        }
        rp += strlen(n[c]) + 1;
    }

    ret = EOK;

done:
    if (ret != EOK) {
        sss_nss_free_list(n);
        free(t);
    } else {
        *names = n;
        *types = t;
    }

    return ret;
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

static errno_t sss_nss_mc_get(union input inp, enum sss_cli_command cmd,
                              struct output *out)
{
    switch (cmd) {
    case SSS_NSS_GETSIDBYID:
        return sss_nss_mc_get_sid_by_id(inp.id, &out->d.str, &out->type);

    case SSS_NSS_GETSIDBYUID:
        return sss_nss_mc_get_sid_by_uid(inp.id, &out->d.str, &out->type);

    case SSS_NSS_GETSIDBYGID:
        return sss_nss_mc_get_sid_by_gid(inp.id, &out->d.str, &out->type);

    case SSS_NSS_GETIDBYSID:
        return sss_nss_mc_get_id_by_sid(inp.str, &out->d.id, &out->type);

    default:
        return ENOENT;
    }
}

static int sss_nss_getyyybyxxx(union input inp, enum sss_cli_command cmd,
                               unsigned int timeout, struct output *out)
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
    char **names;
    enum sss_id_type *types;
    int time_left = SSS_CLI_SOCKET_TIMEOUT;

    ret = sss_nss_mc_get(inp, cmd, out);
    if (ret == EOK) {
        return 0;
    }

    switch (cmd) {
    case SSS_NSS_GETSIDBYNAME:
    case SSS_NSS_GETSIDBYUSERNAME:
    case SSS_NSS_GETSIDBYGROUPNAME:
    case SSS_NSS_GETNAMEBYSID:
    case SSS_NSS_GETIDBYSID:
    case SSS_NSS_GETORIGBYNAME:
    case SSS_NSS_GETORIGBYUSERNAME:
    case SSS_NSS_GETORIGBYGROUPNAME:
        ret = sss_strnlen(inp.str, 2048, &inp_len);
        if (ret != EOK) {
            return EINVAL;
        }

        rd.len = inp_len + 1;
        rd.data = inp.str;

        break;
    case SSS_NSS_GETNAMEBYCERT:
    case SSS_NSS_GETLISTBYCERT:
        ret = sss_strnlen(inp.str, 10 * 1024 , &inp_len);
        if (ret != EOK) {
            return EINVAL;
        }

        rd.len = inp_len + 1;
        rd.data = inp.str;

        break;
    case SSS_NSS_GETSIDBYID:
    case SSS_NSS_GETSIDBYUID:
    case SSS_NSS_GETSIDBYGID:
        rd.len = sizeof(uint32_t);
        rd.data = &inp.id;

        break;
    default:
        return EINVAL;
    }

    if (timeout == NO_TIMEOUT) {
        sss_nss_lock();
    } else {
        ret = sss_nss_timedlock(timeout, &time_left);
        if (ret != 0) {
            return ret;
        }
    }

    /* previous thread might already initialize entry in mmap cache */
    ret = sss_nss_mc_get(inp, cmd, out);
    if (ret == EOK) {
        sss_nss_unlock();
        return 0;
    }

    nret = sss_nss_make_request_timeout(cmd, &rd, time_left, &repbuf, &replen,
                                        &errnop);
    if (nret != NSS_STATUS_SUCCESS) {
        ret = sss_nss_status_to_errno(nret);
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
    } else if (num_results > 1 && cmd != SSS_NSS_GETLISTBYCERT) {
        ret = EBADMSG;
        goto done;
    }

    if (replen < DATA_START) { /* make sure 'type' is present */
        ret = EBADMSG;
        goto done;
    }

    /* Skip first two 32 bit values (number of results and
     * reserved padding) */
    SAFEALIGN_COPY_UINT32(&out->type, repbuf + 2 * sizeof(uint32_t), NULL);

    data_len = replen - DATA_START;

    switch(cmd) {
    case SSS_NSS_GETSIDBYID:
    case SSS_NSS_GETSIDBYUID:
    case SSS_NSS_GETSIDBYGID:
    case SSS_NSS_GETSIDBYNAME:
    case SSS_NSS_GETSIDBYUSERNAME:
    case SSS_NSS_GETSIDBYGROUPNAME:
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

        strncpy(str, (char *) repbuf + DATA_START, data_len-1);
        str[data_len-1] = '\0';

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
    case SSS_NSS_GETLISTBYCERT:
        ret = buf_to_name_type_list(repbuf + LIST_START, replen - LIST_START,
                                    num_results,
                                    &names, &types);
        if (ret != EOK) {
            goto done;
        }

        out->types = types;
        out->d.names = names;

        break;
    case SSS_NSS_GETORIGBYNAME:
    case SSS_NSS_GETORIGBYUSERNAME:
    case SSS_NSS_GETORIGBYGROUPNAME:
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

static int _sss_nss_getsidbyxxxname_timeout(enum sss_cli_command cmd,
                                            const char *fq_name,
                                            unsigned int timeout,
                                            char **sid,
                                            enum sss_id_type *type)
{
    int ret;
    union input inp;
    struct output out;

    if (sid == NULL || fq_name == NULL || *fq_name == '\0') {
        return EINVAL;
    }

    inp.str = fq_name;

    ret = sss_nss_getyyybyxxx(inp, cmd, timeout, &out);
    if (ret == EOK) {
        *sid = out.d.str;
        *type = out.type;
    }

    return ret;
}

int sss_nss_getsidbyname_timeout(const char *fq_name, unsigned int timeout,
                                 char **sid, enum sss_id_type *type)
{
    return _sss_nss_getsidbyxxxname_timeout(SSS_NSS_GETSIDBYNAME, fq_name,
                                            timeout, sid, type);
}

int sss_nss_getsidbyname(const char *fq_name, char **sid,
                         enum sss_id_type *type)
{
    return _sss_nss_getsidbyxxxname_timeout(SSS_NSS_GETSIDBYNAME, fq_name,
                                            NO_TIMEOUT, sid, type);
}

int sss_nss_getsidbyusername_timeout(const char *fq_name,
                                     unsigned int timeout,
                                     char **sid,
                                     enum sss_id_type *type)
{
    return _sss_nss_getsidbyxxxname_timeout(SSS_NSS_GETSIDBYUSERNAME, fq_name,
                                            timeout, sid, type);
}

int sss_nss_getsidbyusername(const char *fq_name,
                             char **sid,
                             enum sss_id_type *type)
{
    return _sss_nss_getsidbyxxxname_timeout(SSS_NSS_GETSIDBYUSERNAME, fq_name,
                                            NO_TIMEOUT, sid, type);
}

int sss_nss_getsidbygroupname_timeout(const char *fq_name,
                                      unsigned int timeout,
                                      char **sid,
                                      enum sss_id_type *type)
{
    return _sss_nss_getsidbyxxxname_timeout(SSS_NSS_GETSIDBYGROUPNAME, fq_name,
                                            timeout, sid, type);
}

int sss_nss_getsidbygroupname(const char *fq_name,
                              char **sid,
                              enum sss_id_type *type)
{
    return _sss_nss_getsidbyxxxname_timeout(SSS_NSS_GETSIDBYGROUPNAME, fq_name,
                                            NO_TIMEOUT, sid, type);
}

int sss_nss_getsidbyid_timeout(uint32_t id, unsigned int timeout,
                               char **sid, enum sss_id_type *type)
{
    int ret;
    union input inp;
    struct output out;

    if (sid == NULL) {
        return EINVAL;
    }

    inp.id = id;

    ret = sss_nss_getyyybyxxx(inp, SSS_NSS_GETSIDBYID, timeout, &out);
    if (ret == EOK) {
        *sid = out.d.str;
        *type = out.type;
    }

    return ret;
}

int sss_nss_getsidbyid(uint32_t id, char **sid, enum sss_id_type *type)
{
    return sss_nss_getsidbyid_timeout(id, NO_TIMEOUT, sid, type);
}

int sss_nss_getsidbyuid_timeout(uint32_t uid, unsigned int timeout,
                                char **sid, enum sss_id_type *type)
{
    int ret;
    union input inp;
    struct output out;

    if (sid == NULL) {
        return EINVAL;
    }

    inp.id = uid;

    ret = sss_nss_getyyybyxxx(inp, SSS_NSS_GETSIDBYUID, timeout, &out);
    if (ret == EOK) {
        *sid = out.d.str;
        *type = out.type;
    }

    return ret;
}

int sss_nss_getsidbyuid(uint32_t uid, char **sid, enum sss_id_type *type)
{
    return sss_nss_getsidbyuid_timeout(uid, NO_TIMEOUT, sid, type);
}

int sss_nss_getsidbygid_timeout(uint32_t gid, unsigned int timeout,
                                char **sid, enum sss_id_type *type)
{
    int ret;
    union input inp;
    struct output out;

    if (sid == NULL) {
        return EINVAL;
    }

    inp.id = gid;

    ret = sss_nss_getyyybyxxx(inp, SSS_NSS_GETSIDBYGID, timeout, &out);
    if (ret == EOK) {
        *sid = out.d.str;
        *type = out.type;
    }

    return ret;
}

int sss_nss_getsidbygid(uint32_t gid, char **sid, enum sss_id_type *type)
{
    return sss_nss_getsidbygid_timeout(gid, NO_TIMEOUT, sid, type);
}

int sss_nss_getnamebysid_timeout(const char *sid, unsigned int timeout,
                                 char **fq_name, enum sss_id_type *type)
{
    int ret;
    union input inp;
    struct output out;

    if (fq_name == NULL || sid == NULL || *sid == '\0') {
        return EINVAL;
    }

    inp.str = sid;

    ret = sss_nss_getyyybyxxx(inp, SSS_NSS_GETNAMEBYSID, timeout, &out);
    if (ret == EOK) {
        *fq_name = out.d.str;
        *type = out.type;
    }

    return ret;
}

int sss_nss_getnamebysid(const char *sid, char **fq_name,
                         enum sss_id_type *type)
{
    return sss_nss_getnamebysid_timeout(sid, NO_TIMEOUT, fq_name, type);
}

int sss_nss_getidbysid_timeout(const char *sid, unsigned int timeout,
                               uint32_t *id, enum sss_id_type *id_type)
{
    int ret;
    union input inp;
    struct output out;

    if (id == NULL || id_type == NULL || sid == NULL || *sid == '\0') {
        return EINVAL;
    }

    inp.str = sid;

    ret = sss_nss_getyyybyxxx(inp, SSS_NSS_GETIDBYSID, timeout, &out);
    if (ret == EOK) {
        *id = out.d.id;
        *id_type = out.type;
    }

    return ret;
}

int sss_nss_getidbysid(const char *sid, uint32_t *id, enum sss_id_type *id_type)
{
    return sss_nss_getidbysid_timeout(sid, NO_TIMEOUT, id, id_type);
}

int sss_nss_getorigbyname_timeout_common(const char *fq_name,
                                         unsigned int timeout,
                                         enum sss_cli_command cmd,
                                         struct sss_nss_kv **kv_list,
                                         enum sss_id_type *type)
{
    int ret;
    union input inp;
    struct output out;

    if (kv_list == NULL || fq_name == NULL || *fq_name == '\0') {
        return EINVAL;
    }

    inp.str = fq_name;

    ret = sss_nss_getyyybyxxx(inp, cmd, timeout, &out);
    if (ret == EOK) {
        *kv_list = out.d.kv_list;
        *type = out.type;
    }

    return ret;
}

int sss_nss_getorigbyname_timeout(const char *fq_name, unsigned int timeout,
                                  struct sss_nss_kv **kv_list,
                                  enum sss_id_type *type)
{
    return sss_nss_getorigbyname_timeout_common(fq_name, timeout,
                                                SSS_NSS_GETORIGBYNAME, kv_list,
                                                type);
}

int sss_nss_getorigbyname(const char *fq_name, struct sss_nss_kv **kv_list,
                          enum sss_id_type *type)
{
    return sss_nss_getorigbyname_timeout(fq_name, NO_TIMEOUT, kv_list, type);
}

int sss_nss_getorigbyusername_timeout(const char *fq_name, unsigned int timeout,
                                      struct sss_nss_kv **kv_list,
                                      enum sss_id_type *type)
{
    return sss_nss_getorigbyname_timeout_common(fq_name, timeout,
                                                SSS_NSS_GETORIGBYUSERNAME,
                                                kv_list, type);
}

int sss_nss_getorigbyusername(const char *fq_name, struct sss_nss_kv **kv_list,
                             enum sss_id_type *type)
{
    return sss_nss_getorigbyusername_timeout(fq_name, NO_TIMEOUT, kv_list, type);
}

int sss_nss_getorigbygroupname_timeout(const char *fq_name, unsigned int timeout,
                                       struct sss_nss_kv **kv_list,
                                       enum sss_id_type *type)
{
    return sss_nss_getorigbyname_timeout_common(fq_name, timeout,
                                                SSS_NSS_GETORIGBYGROUPNAME,
                                                kv_list, type);
}

int sss_nss_getorigbygroupname(const char *fq_name, struct sss_nss_kv **kv_list,
                             enum sss_id_type *type)
{
    return sss_nss_getorigbygroupname_timeout(fq_name, NO_TIMEOUT, kv_list, type);
}

int sss_nss_getnamebycert_timeout(const char *cert, unsigned int timeout,
                                  char **fq_name, enum sss_id_type *type)
{
    int ret;
    union input inp;
    struct output out;

    if (fq_name == NULL || cert == NULL || *cert == '\0') {
        return EINVAL;
    }

    inp.str = cert;

    ret = sss_nss_getyyybyxxx(inp, SSS_NSS_GETNAMEBYCERT, timeout, &out);
    if (ret == EOK) {
        *fq_name = out.d.str;
        *type = out.type;
    }

    return ret;
}

int sss_nss_getnamebycert(const char *cert, char **fq_name,
                          enum sss_id_type *type)
{
    return sss_nss_getnamebycert_timeout(cert, NO_TIMEOUT, fq_name, type);
}

int sss_nss_getlistbycert_timeout(const char *cert, unsigned int timeout,
                                  char ***fq_name, enum sss_id_type **type)
{
    int ret;
    union input inp;
    struct output out;

    if (fq_name == NULL || cert == NULL || *cert == '\0') {
        return EINVAL;
    }

    inp.str = cert;

    ret = sss_nss_getyyybyxxx(inp, SSS_NSS_GETLISTBYCERT, timeout, &out);
    if (ret == EOK) {
        *fq_name = out.d.names;
        *type = out.types;
    }

    return ret;
}

int sss_nss_getlistbycert(const char *cert, char ***fq_name,
                          enum sss_id_type **type)
{
    return sss_nss_getlistbycert_timeout(cert, NO_TIMEOUT, fq_name, type);
}
