/*
   SSSD

   NFS Client

   Copyright (C) Noam Meltzer <noam@primarydata.com>    2013-2014
   Copyright (C) Noam Meltzer <tsnoam@gmail.com>        2014-

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

#include "config.h"

#include <stddef.h>
#include <stdlib.h>
#include <sys/types.h>
#include <errno.h>
#include <string.h>

#include <nfsidmap.h>

#ifdef HAVE_NFSIDMAP_PLUGIN_H
#include <nfsidmap_plugin.h>
#else /* fallback to internal header file with older version of libnfsidmap */
#include "nfsidmap_internal.h"
#define nfsidmap_config_get conf_get_str
#endif

#include "sss_client/sss_cli.h"
#include "sss_client/nss_mc.h"


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
#define PLUGIN_NAME                 "sss_nfs"
#define CONF_SECTION                "sss_nfs"
#define CONF_USE_MC                 "memcache"
#define REPLY_ID_OFFSET             (8)
#define REPLY_NAME_OFFSET           (REPLY_ID_OFFSET + 8)
#define BUF_LEN                     (4096)
#define USE_MC_DEFAULT              true


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
static char sss_nfs_plugin_name[]   = PLUGIN_NAME;
static char nfs_conf_sect[]         = CONF_SECTION;
static char nfs_conf_use_mc[]       = CONF_USE_MC;

static bool nfs_use_mc              = USE_MC_DEFAULT;


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/* Forward declarations */
static int send_recv(uint8_t **repp, size_t *rep_lenp, enum sss_cli_command cmd,
                     const void *req, size_t req_len);
static int reply_to_id(id_t *idp, uint8_t *rep, size_t rep_len);
static int reply_to_name(char *name, size_t len, uint8_t *rep, size_t rep_len);


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/* get from memcache functions */
static int get_uid_from_mc(id_t *uid, const char *name)
{
    int rc = 0;
    struct passwd pwd;
    char *buf = NULL;
    char *p = NULL;
    size_t buflen = 0;
    size_t len = 0;

    if (!nfs_use_mc) {
        return -1;
    }

    rc = sss_strnlen(name, SSS_NAME_MAX, &len);
    if (rc != 0) {
        IDMAP_LOG(0, ("%s: no-strnlen; rc=%i", __func__, rc));
        return rc;
    }

    do {
        buflen += BUF_LEN;
        if ((p = realloc(buf, buflen)) == NULL) {
            rc = ENOMEM;
            goto done;
        }
        buf = p;
        rc = sss_nss_mc_getpwnam(name, len, &pwd, buf, buflen);
    } while (rc == ERANGE);

    if (rc == 0) {
        IDMAP_LOG(1, ("found user %s in memcache", name));
        *uid = pwd.pw_uid;
    } else {
        IDMAP_LOG(1, ("user %s not in memcache", name));
    }

done:
    free(buf);
    return rc;
}

static int get_gid_from_mc(id_t *gid, const char *name)
{
    int rc = 0;
    struct group grp;
    char *buf = NULL;
    char *p = NULL;
    size_t buflen = 0;
    size_t len;

    if (!nfs_use_mc) {
        return -1;
    }

    rc = sss_strnlen(name, SSS_NAME_MAX, &len);
    if (rc != 0) {
        IDMAP_LOG(0, ("%s: no-strnlen; rc=%i", __func__, rc));
        return rc;
    }

    do {
        buflen += BUF_LEN;
        if ((p = realloc(buf, buflen)) == NULL) {
            rc = ENOMEM;
            goto done;
        }
        buf = p;
        rc = sss_nss_mc_getgrnam(name, len, &grp, buf, buflen);
    } while (rc == ERANGE);

    if (rc == 0) {
        IDMAP_LOG(1, ("found group %s in memcache", name));
        *gid = grp.gr_gid;
    } else {
        IDMAP_LOG(1, ("group %s not in memcache", name));
    }

done:
    free(buf);
    return rc;
}

static int get_user_from_mc(char *name, size_t len, uid_t uid)
{
    int rc;
    struct passwd pwd;
    char *buf = NULL;
    char *p = NULL;
    size_t buflen = 0;
    size_t pw_name_len;

    if (!nfs_use_mc) {
        return -1;
    }

    do {
        buflen += BUF_LEN;
        if ((p = realloc(buf, buflen)) == NULL) {
            rc = ENOMEM;
            goto done;
        }
        buf = p;
        rc = sss_nss_mc_getpwuid(uid, &pwd, buf, buflen);
    } while (rc == ERANGE);

    if (rc == 0) {
        pw_name_len = strlen(pwd.pw_name) + 1;
        if (pw_name_len > len) {
            IDMAP_LOG(0, ("%s: reply too long; pw_name_len=%lu, len=%lu",
                          __func__, pw_name_len, len));
            rc = ENOBUFS;
        }
        IDMAP_LOG(1, ("found uid %i in memcache", uid));
        memcpy(name, pwd.pw_name, pw_name_len);
    } else {
        IDMAP_LOG(1, ("uid %i not in memcache", uid));
    }

done:
    free(buf);
    return rc;
}

static int get_group_from_mc(char *name, size_t len, id_t gid)
{
    int rc;
    struct group grp;
    char *buf = NULL;
    char *p = NULL;
    size_t buflen = 0;
    size_t gr_name_len;

    if (!nfs_use_mc) {
        return -1;
    }

    do {
        buflen += BUF_LEN;
        if ((p = realloc(buf, buflen)) == NULL) {
            rc = ENOMEM;
            goto done;
        }
        buf = p;
        rc = sss_nss_mc_getgrgid(gid, &grp, buf, buflen);
    } while (rc == ERANGE);

    if (rc == 0) {
        gr_name_len = strlen(grp.gr_name) + 1;
        if (gr_name_len > len) {
            IDMAP_LOG(0, ("%s: reply too long; gr_name_len=%lu, len=%lu",
                          __func__, gr_name_len, len));
            rc = ENOBUFS;
        }
        IDMAP_LOG(1, ("found gid %i in memcache", gid));
        memcpy(name, grp.gr_name, gr_name_len);
    } else {
        IDMAP_LOG(1, ("gid %i not in memcache", gid));
    }

done:
    free(buf);
    return rc;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
static int name_to_id(const char *name, id_t *id, enum sss_cli_command cmd)
{
    int rc;
    uint8_t *rep = NULL;
    size_t rep_len = 0;
    size_t name_len;

    rc = sss_strnlen(name, SSS_NAME_MAX, &name_len);
    if (rc != 0) {
        IDMAP_LOG(0, ("%s: no-strnlen; rc=%i", __func__, rc));
        return rc;
    }

    rc = send_recv(&rep, &rep_len, cmd, name, name_len + 1);
    if (rc == 0) {
        rc = reply_to_id(id, rep, rep_len);
    }

    free(rep);

    return rc;
}

static int id_to_name(char *name, size_t len, id_t id,
                      enum sss_cli_command cmd)
{
    int rc;
    size_t rep_len = 0;
    size_t req_len = sizeof(id_t);
    uint8_t *rep = NULL;
    uint8_t req[req_len];

    memcpy(req, &id, req_len);
    rc = send_recv(&rep, &rep_len, cmd, &req, req_len);
    if (rc == 0) {
        rc = reply_to_name(name, len, rep, rep_len);
    }

    free(rep);

    return rc;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
static int send_recv(uint8_t **rep, size_t *rep_len, enum sss_cli_command cmd,
                     const void *req, size_t req_len)
{
    int err = 0;
    enum nss_status req_rc;
    struct sss_cli_req_data rd;

    rd.data = req;
    rd.len = req_len;

    sss_nss_lock();
    req_rc = sss_nss_make_request(cmd, &rd, rep, rep_len, &err);
    sss_nss_unlock();

    if (req_rc == NSS_STATUS_NOTFOUND) {
        return ENOENT;
    }
    if (req_rc != NSS_STATUS_SUCCESS) {
        IDMAP_LOG(0, ("no-make-request; err=%i", err));
        return EPIPE;
    }

    return 0;
}

static int reply_to_id(id_t *idp, uint8_t *rep, size_t rep_len)
{
    int rc = 0;
    id_t id;
    uint32_t num_results = 0;

    if (rep_len < sizeof(uint32_t)) {
        IDMAP_LOG(0, ("%s: reply too small; rep_len=%lu", __func__, rep_len));
        rc = EBADMSG;
        goto done;
    }

    SAFEALIGN_COPY_UINT32(&num_results, rep, NULL);
    if (num_results > 1) {
        IDMAP_LOG(0, ("%s: too many results (%lu)", __func__, num_results));
        rc = EBADMSG;
        goto done;
    }
    if (num_results == 0) {
        rc = ENOENT;
        goto done;
    }
    if (rep_len < sizeof(uint32_t) + REPLY_ID_OFFSET) {
        IDMAP_LOG(0, ("%s: reply too small(2); rep_len=%lu", __func__,
                      rep_len));
        rc = EBADMSG;
        goto done;
    }

    SAFEALIGN_COPY_UINT32(&id, rep + REPLY_ID_OFFSET, NULL);
    *idp = id;

done:
    return rc;
}

static int reply_to_name(char *name, size_t len, uint8_t *rep, size_t rep_len)
{
    int rc = 0;
    uint32_t num_results = 0;
    const char *buf;
    size_t buf_len;
    size_t offset;

    if (rep_len < sizeof(uint32_t)) {
        IDMAP_LOG(0, ("%s: reply too small; rep_len=%lu", __func__, rep_len));
        rc = EBADMSG;
        goto done;
    }

    SAFEALIGN_COPY_UINT32(&num_results, rep, NULL);
    if (num_results > 1) {
        IDMAP_LOG(0, ("%s: too many results (%lu)", __func__, num_results));
        rc = EBADMSG;
        goto done;
    }
    if (num_results == 0) {
        rc = ENOENT;
        goto done;
    }
    if (rep_len < sizeof(uint32_t) + REPLY_NAME_OFFSET) {
        IDMAP_LOG(0, ("%s: reply too small(2); rep_len=%lu", __func__,
                      rep_len));
        rc = EBADMSG;
        goto done;
    }

    buf = (const char *)(rep + REPLY_NAME_OFFSET);
    buf_len = rep_len - REPLY_NAME_OFFSET;
    offset = 0;
    rc = sss_readrep_copy_string(buf, &offset, &buf_len, &len, &name, NULL);
    if (rc != 0) {
        rc = -rc;
    }

done:
    return rc;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/* configuration parsing aids */
static bool str_equal(const char *s1, const char *s2)
{
    bool res = false;
    size_t len1;
    size_t len2;

    len1 = strlen(s1);
    len2 = strlen(s2);

    if (len1 == len2) {
        res = (strncasecmp(s1, s2, len1) == 0);
    }

    return res;
}

static int nfs_conf_get_bool(const char *sect, const char *attr, int def)
{
    int res;
    const char *val;

    res = def;
    val = nfsidmap_config_get(sect, attr);
    if (val) {
        res = (str_equal("1", val) ||
               str_equal("yes", val) ||
               str_equal("true", val) ||
               str_equal("on", val));
    }

    return res;
}


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/* libnfsidmap return-code aids */

/*
 * we only want to return 0 or ENOENT; otherwise libnfsidmap will stop
 * translation instead of proceeding to the next translation plugin
 */
int normalise_rc(int rc) {
    int res;

    res = rc;
    if (res != 0 && res != ENOENT) {
        res = ENOENT;
    }

    return res;
}

/* log the actual rc from our code (to be used before normalising the rc) */
void log_actual_rc(const char *trans_name, int rc) {
    char tmp[80];
    IDMAP_LOG(1, ("%s: rc=%i msg=%s", trans_name, rc,
                  strerror_r(rc, tmp, sizeof(tmp))));
}


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/* The external interface */
static int sss_nfs_init(void)
{
    nfs_use_mc = nfs_conf_get_bool(nfs_conf_sect, nfs_conf_use_mc,
                                   USE_MC_DEFAULT);
    IDMAP_LOG(1, ("%s: use memcache: %i", __func__, nfs_use_mc));

    return 0;
}

static int sss_nfs_princ_to_ids(char *secname, char *princ, uid_t *uid,
                                gid_t *gid, extra_mapping_params **ex)
{
    IDMAP_LOG(0, ("%s: not implemented", __func__));
    return -ENOENT;
}

static int sss_nfs_name_to_uid(char *name, uid_t *uid)
{
    int rc;
    size_t name_len = 0;

    if (name == NULL) {
        IDMAP_LOG(0, ("%s: name is null", __func__));
        return -EINVAL;
    }
    if (uid == NULL) {
        IDMAP_LOG(0, ("%s: uid is null", __func__));
        return -EINVAL;
    }

    rc = sss_strnlen(name, SSS_NAME_MAX, &name_len);
    if (rc != 0) {
        IDMAP_LOG(0, ("%s: no-strnlen; rc=%i", __func__, rc));
        return -rc;
    }

    rc = get_uid_from_mc(uid, name);
    if (rc != 0) {
        rc = name_to_id(name, uid, SSS_NSS_GETPWNAM);
    }

    log_actual_rc(__func__, rc);
    rc = normalise_rc(rc);

    return -rc;
}

static int sss_nfs_name_to_gid(char *name, gid_t *gid)
{
    int rc;
    size_t name_len = 0;

    if (name == NULL) {
        IDMAP_LOG(0, ("%s: name is null", __func__));
        return -EINVAL;
    }
    if (gid == NULL) {
        IDMAP_LOG(0, ("%s: gid is null", __func__));
        return -EINVAL;
    }

    rc = sss_strnlen(name, SSS_NAME_MAX, &name_len);
    if (rc != 0) {
        IDMAP_LOG(0, ("%s: no-strnlen; rc=%i", __func__, rc));
        return -rc;
    }

    rc = get_gid_from_mc(gid, name);
    if (rc != 0) {
        rc = name_to_id(name, gid, SSS_NSS_GETGRNAM);
    }

    log_actual_rc(__func__, rc);
    rc = normalise_rc(rc);

    return -rc;
}

static int sss_nfs_uid_to_name(uid_t uid, char *domain, char *name, size_t len)
{
    int rc;

    if (name == NULL) {
        IDMAP_LOG(0, ("%s: name is null", __func__));
        return -EINVAL;
    }

    rc = get_user_from_mc(name, len, uid);
    if (rc != 0) {
        rc = id_to_name(name, len, uid, SSS_NSS_GETPWUID);
    }

    log_actual_rc(__func__, rc);
    rc = normalise_rc(rc);

    return -rc;
}

static int sss_nfs_gid_to_name(gid_t gid, char *domain, char *name, size_t len)
{
    int rc;

    if (name == NULL) {
        IDMAP_LOG(0, ("%s: name is null", __func__));
        return -EINVAL;
    }

    rc = get_group_from_mc(name, len, gid);
    if (rc != 0) {
        rc = id_to_name(name, len, gid, SSS_NSS_GETGRGID);
    }

    log_actual_rc(__func__, rc);
    rc = normalise_rc(rc);

    return -rc;
}

static int sss_nfs_gss_princ_to_grouplist(
    char *secname, char *princ, gid_t *groups, int *ngroups,
    extra_mapping_params **ex)
{
    IDMAP_LOG(0, ("%s: not implemented", __func__));
    return -ENOENT;
}

static struct trans_func s_sss_nfs_trans = {
    .name = sss_nfs_plugin_name,
    .init = sss_nfs_init,
    .princ_to_ids = sss_nfs_princ_to_ids,
    .name_to_uid = sss_nfs_name_to_uid,
    .name_to_gid = sss_nfs_name_to_gid,
    .uid_to_name = sss_nfs_uid_to_name,
    .gid_to_name = sss_nfs_gid_to_name,
    .gss_princ_to_grouplist = sss_nfs_gss_princ_to_grouplist,
};

struct trans_func *libnfsidmap_plugin_init(void)
{
    return (&s_sss_nfs_trans);
}
