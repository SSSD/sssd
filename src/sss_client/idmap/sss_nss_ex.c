/*
    SSSD

    Extended NSS Responder Interface

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2017 Red Hat

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

#include <sys/param.h> /* for MIN() */

#include "sss_client/sss_cli.h"
#include "sss_client/nss_mc.h"
#include "sss_client/nss_common.h"
#include "sss_client/idmap/sss_nss_idmap.h"
#include "sss_client/idmap/sss_nss_idmap_private.h"

#ifndef discard_const
#define discard_const(ptr) ((void *)((uintptr_t)(ptr)))
#endif

struct sss_nss_initgr_rep {
    gid_t *groups;
    long int *ngroups;
    long int *start;
};

struct nss_input {
    union {
        const char *name;
        uid_t uid;
        gid_t gid;
    } input;
    struct sss_cli_req_data rd;
    enum sss_cli_command cmd;
    union {
        struct sss_nss_pw_rep pwrep;
        struct sss_nss_gr_rep grrep;
        struct sss_nss_initgr_rep initgrrep;
    } result;
};

static errno_t sss_nss_mc_get(struct nss_input *inp)
{
    switch(inp->cmd) {
    case SSS_NSS_GETPWNAM:
    case SSS_NSS_GETPWNAM_EX:
        return sss_nss_mc_getpwnam(inp->input.name, strlen(inp->input.name),
                                   inp->result.pwrep.result,
                                   inp->result.pwrep.buffer,
                                   inp->result.pwrep.buflen);
        break;
    case SSS_NSS_GETPWUID:
    case SSS_NSS_GETPWUID_EX:
        return sss_nss_mc_getpwuid(inp->input.uid,
                                   inp->result.pwrep.result,
                                   inp->result.pwrep.buffer,
                                   inp->result.pwrep.buflen);
        break;
    case SSS_NSS_GETGRNAM:
    case SSS_NSS_GETGRNAM_EX:
        return sss_nss_mc_getgrnam(inp->input.name, strlen(inp->input.name),
                                   inp->result.grrep.result,
                                   inp->result.grrep.buffer,
                                   inp->result.grrep.buflen);
        break;
    case SSS_NSS_GETGRGID:
    case SSS_NSS_GETGRGID_EX:
        return sss_nss_mc_getgrgid(inp->input.gid,
                                   inp->result.grrep.result,
                                   inp->result.grrep.buffer,
                                   inp->result.grrep.buflen);
        break;
    case SSS_NSS_INITGR:
    case SSS_NSS_INITGR_EX:
        return sss_nss_mc_initgroups_dyn(inp->input.name,
                                         strlen(inp->input.name),
                                         -1 /* currently ignored */,
                                         inp->result.initgrrep.start,
                                         inp->result.initgrrep.ngroups,
                                         &(inp->result.initgrrep.groups),
                                         /* no limit so that needed size can
                                          * be returned properly */
                                         -1);
        break;
    default:
        return EINVAL;
    }
}

static int check_flags(struct nss_input *inp, uint32_t flags,
                       bool *skip_mc, bool *skip_data)
{
    bool no_data = false;

    /* SSS_NSS_EX_FLAG_NO_CACHE and SSS_NSS_EX_FLAG_INVALIDATE_CACHE are
     * mutually exclusive */
    if ((flags & SSS_NSS_EX_FLAG_NO_CACHE) != 0
            && (flags & SSS_NSS_EX_FLAG_INVALIDATE_CACHE) != 0) {
        return EINVAL;
    }

    *skip_mc = false;
    if ((flags & SSS_NSS_EX_FLAG_NO_CACHE) != 0
            || (flags & SSS_NSS_EX_FLAG_INVALIDATE_CACHE) != 0) {
        *skip_mc = true;
    }

    switch(inp->cmd) {
    case SSS_NSS_GETPWNAM:
    case SSS_NSS_GETPWNAM_EX:
    case SSS_NSS_GETPWUID:
    case SSS_NSS_GETPWUID_EX:
        if (inp->result.pwrep.buffer == NULL
                || inp->result.pwrep.buflen == 0) {
            no_data = true;
        }
        break;
    case SSS_NSS_GETGRNAM:
    case SSS_NSS_GETGRNAM_EX:
    case SSS_NSS_GETGRGID:
    case SSS_NSS_GETGRGID_EX:
        if (inp->result.grrep.buffer == NULL
                || inp->result.grrep.buflen == 0) {
            no_data = true;
        }
        break;
    case SSS_NSS_INITGR:
    case SSS_NSS_INITGR_EX:
        if (inp->result.initgrrep.ngroups == 0
                || inp->result.initgrrep.groups == NULL) {
            return EINVAL;
        }
        break;
    default:
        return EINVAL;
    }

    *skip_data = false;
    /* Allow empty buffer with SSS_NSS_EX_FLAG_INVALIDATE_CACHE */
    if (no_data) {
        if ((flags & SSS_NSS_EX_FLAG_INVALIDATE_CACHE) != 0) {
            *skip_data = true;
        } else {
            return ERANGE;
        }
    }

    return 0;
}

static int sss_get_ex(struct nss_input *inp, uint32_t flags,
                      unsigned int timeout)
{
    uint8_t *repbuf = NULL;
    size_t replen;
    size_t len;
    uint32_t num_results;
    int ret;
    int time_left;
    int errnop;
    size_t c;
    gid_t *new_groups;
    size_t idx;
    bool skip_mc = false;
    bool skip_data = false;

    ret = check_flags(inp, flags, &skip_mc, &skip_data);
    if (ret != 0) {
        return ret;
    }

    if (!skip_mc && !skip_data) {
        ret = sss_nss_mc_get(inp);
        switch (ret) {
        case 0:
            return 0;
        case ERANGE:
            return ERANGE;
        case ENOENT:
            /* fall through, we need to actively ask the parent
             * if no entry is found */
            break;
        default:
            /* if using the mmapped cache failed,
             * fall back to socket based comms */
            break;
        }
    }

    ret = sss_nss_timedlock(timeout, &time_left);
    if (ret != 0) {
        return ret;
    }

    if (!skip_mc && !skip_data) {
        /* previous thread might already initialize entry in mmap cache */
        ret = sss_nss_mc_get(inp);
        switch (ret) {
        case 0:
            ret = 0;
            goto out;
        case ERANGE:
            ret = ERANGE;
            goto out;
        case ENOENT:
            /* fall through, we need to actively ask the parent
             * if no entry is found */
            break;
        default:
            /* if using the mmapped cache failed,
             * fall back to socket based comms */
            break;
        }
    }

    ret = sss_nss_make_request_timeout(inp->cmd, &inp->rd, time_left,
                                       &repbuf, &replen, &errnop);
    if (ret != NSS_STATUS_SUCCESS) {
        ret = errnop != 0 ? errnop : EIO;
        goto out;
    }

    /* Get number of results from repbuf. */
    SAFEALIGN_COPY_UINT32(&num_results, repbuf, NULL);

    /* no results if not found */
    if (num_results == 0) {
        ret = ENOENT;
        goto out;
    }

    if (skip_data) {
        /* No data requested, just return the return code */
        ret = 0;
        goto out;
    }

    if (inp->cmd == SSS_NSS_INITGR || inp->cmd == SSS_NSS_INITGR_EX) {
        if ((*(inp->result.initgrrep.ngroups) - *(inp->result.initgrrep.start))
                    < num_results) {
            new_groups = realloc(inp->result.initgrrep.groups,
                                 (num_results + *(inp->result.initgrrep.start))
                                    * sizeof(gid_t));
            if (new_groups == NULL) {
                ret = ENOMEM;
                goto out;
            }

            inp->result.initgrrep.groups = new_groups;
        }
        *(inp->result.initgrrep.ngroups) = num_results
                                            + *(inp->result.initgrrep.start);

        idx = 2 * sizeof(uint32_t);
        for (c = 0; c < num_results; c++) {
            SAFEALIGN_COPY_UINT32(
                &(inp->result.initgrrep.groups[*(inp->result.initgrrep.start)]),
                repbuf + idx, &idx);
            *(inp->result.initgrrep.start) += 1;
        }

        ret = 0;
        goto out;
    }

    /* only 1 result is accepted for this function */
    if (num_results != 1) {
        ret = EBADMSG;
        goto out;
    }

    len = replen - 8;

    switch(inp->cmd) {
    case SSS_NSS_GETPWNAM:
    case SSS_NSS_GETPWUID:
    case SSS_NSS_GETPWNAM_EX:
    case SSS_NSS_GETPWUID_EX:
        ret = sss_nss_getpw_readrep(&(inp->result.pwrep), repbuf+8, &len);
        break;
    case SSS_NSS_GETGRNAM:
    case SSS_NSS_GETGRGID:
    case SSS_NSS_GETGRNAM_EX:
    case SSS_NSS_GETGRGID_EX:
        ret = sss_nss_getgr_readrep(&(inp->result.grrep), repbuf+8, &len);
        break;
    default:
        ret = EINVAL;
    }
    if (ret != 0) {
        goto out;
    }

    if (len == 0) {
        /* no extra data */
        ret = 0;
        goto out;
    }

out:
    free(repbuf);

    sss_nss_unlock();
    return ret;
}

static int make_name_flag_req_data(const char *name, uint32_t flags,
                                   struct sss_cli_req_data *rd)
{
    size_t len;
    size_t name_len;
    uint8_t *data;
    int ret;

    if (name == NULL) {
        return EINVAL;
    }

    ret = sss_strnlen(name, SSS_NAME_MAX, &name_len);
    if (ret != 0) {
        return ret;
    }
    name_len++;

    len = name_len + sizeof(uint32_t);
    data = malloc(len);
    if (data == NULL) {
        return ENOMEM;
    }

    memcpy(data, name, name_len);
    SAFEALIGN_COPY_UINT32(data + name_len, &flags, NULL);

    rd->len = len;
    rd->data = data;

    return 0;
}

int sss_nss_getpwnam_timeout(const char *name, struct passwd *pwd,
                             char *buffer, size_t buflen,
                             struct passwd **result,
                             uint32_t flags, unsigned int timeout)
{
    int ret;
    struct nss_input inp = {
        .input.name = name,
        .cmd = SSS_NSS_GETPWNAM_EX,
        .result.pwrep.result = pwd,
        .result.pwrep.buffer = buffer,
        .result.pwrep.buflen = buflen};

    ret = make_name_flag_req_data(name, flags, &inp.rd);
    if (ret != 0) {
        return ret;
    }

    ret = sss_get_ex(&inp, flags, timeout);
    free(discard_const(inp.rd.data));

    if (result != NULL) {
        if (ret == 0) {
            *result = inp.result.pwrep.result;
        } else {
            *result = NULL;
        }
    }

    return ret;
}

int sss_nss_getpwuid_timeout(uid_t uid, struct passwd *pwd,
                             char *buffer, size_t buflen,
                             struct passwd **result,
                             uint32_t flags, unsigned int timeout)
{
    int ret;
    uint32_t req_data[2];
    struct nss_input inp = {
        .input.uid = uid,
        .cmd = SSS_NSS_GETPWUID_EX,
        .rd.len = 2 * sizeof(uint32_t),
        .rd.data = &req_data,
        .result.pwrep.result = pwd,
        .result.pwrep.buffer = buffer,
        .result.pwrep.buflen = buflen};

    SAFEALIGN_COPY_UINT32(&req_data[0], &uid, NULL);
    SAFEALIGN_COPY_UINT32(&req_data[1], &flags, NULL);

    ret = sss_get_ex(&inp, flags, timeout);

    if (result != NULL) {
        if (ret == 0) {
            *result = inp.result.pwrep.result;
        } else {
            *result = NULL;
        }
    }

    return ret;
}

int sss_nss_getgrnam_timeout(const char *name, struct group *grp,
                             char *buffer, size_t buflen, struct group **result,
                             uint32_t flags, unsigned int timeout)
{
    int ret;
    struct nss_input inp = {
        .input.name = name,
        .cmd = SSS_NSS_GETGRNAM_EX,
        .result.grrep.result = grp,
        .result.grrep.buffer = buffer,
        .result.grrep.buflen = buflen};

    ret = make_name_flag_req_data(name, flags, &inp.rd);
    if (ret != 0) {
        return ret;
    }

    ret = sss_get_ex(&inp, flags, timeout);
    free(discard_const(inp.rd.data));

    if (result != NULL) {
        if (ret == 0) {
            *result = inp.result.grrep.result;
        } else {
            *result = NULL;
        }
    }

    return ret;
}

int sss_nss_getgrgid_timeout(gid_t gid, struct group *grp,
                             char *buffer, size_t buflen, struct group **result,
                             uint32_t flags, unsigned int timeout)
{
    int ret;
    uint32_t req_data[2];
    struct nss_input inp = {
        .input.gid = gid,
        .cmd = SSS_NSS_GETGRGID_EX,
        .rd.len = 2 * sizeof(uint32_t),
        .rd.data = &req_data,
        .result.grrep.result = grp,
        .result.grrep.buffer = buffer,
        .result.grrep.buflen = buflen};

    SAFEALIGN_COPY_UINT32(&req_data[0], &gid, NULL);
    SAFEALIGN_COPY_UINT32(&req_data[1], &flags, NULL);

    ret = sss_get_ex(&inp, flags, timeout);

    if (result != NULL) {
        if (ret == 0) {
            *result = inp.result.grrep.result;
        } else {
            *result = NULL;
        }
    }

    return ret;
}

int sss_nss_getgrouplist_timeout(const char *name, gid_t group,
                                 gid_t *groups, int *ngroups,
                                 uint32_t flags, unsigned int timeout)
{
    int ret;
    long int new_ngroups;
    long int start = 1;
    struct nss_input inp = {
        .input.name = name,
        .cmd = SSS_NSS_INITGR_EX};

    ret = make_name_flag_req_data(name, flags, &inp.rd);
    if (ret != 0) {
        return ret;
    }

    new_ngroups = MAX(1, *ngroups);
    inp.result.initgrrep.groups = malloc(new_ngroups * sizeof(gid_t));
    if (inp.result.initgrrep.groups == NULL) {
        free(discard_const(inp.rd.data));
        return ENOMEM;
    }
    inp.result.initgrrep.groups[0] = group;

    inp.result.initgrrep.ngroups = &new_ngroups;
    inp.result.initgrrep.start = &start;

    /* inp.result.initgrrep.groups, inp.result.initgrrep.ngroups and
     * inp.result.initgrrep.start might be modified by sss_get_ex() */
    ret = sss_get_ex(&inp, flags, timeout);
    free(discard_const(inp.rd.data));
    if (ret != 0) {
        free(inp.result.initgrrep.groups);
        return ret;
    }

    memcpy(groups, inp.result.initgrrep.groups,
           MIN(*ngroups, start) * sizeof(gid_t));
    free(inp.result.initgrrep.groups);

    if (start > *ngroups) {
        ret = ERANGE;
    } else {
        ret = 0;
    }
    *ngroups = start;

    return ret;
}
