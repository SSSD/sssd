/*
    SSSD

    Kerberos 5 Backend Module -- tgt_req child

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2009 Red Hat

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
#include <krb5/krb5.h>
#include <sys/types.h>

#include <security/pam_modules.h>

#include "util/util.h"
#include "providers/dp_backend.h"
#include "providers/krb5/krb5_auth.h"

static int pack_response_packet(uint8_t *buf, int status, int type,
                                const char *data)
{
    int len;
    int p=0;

    if ((3*sizeof(int32_t) + strlen(data)+1) > MAX_CHILD_MSG_SIZE) {
        return -1;
    }

    ((int32_t *)(&buf[p]))[0] = status;
    p += sizeof(int32_t);

    ((int32_t *)(&buf[p]))[0] = type;
    p += sizeof(int32_t);

    len = strlen(data)+1;
    ((int32_t *)(&buf[p]))[0] = len;
    p += sizeof(int32_t);

    memcpy(&buf[p], data, len);
    p += len;

    return p;
}

void tgt_req_child(int fd, struct krb5_req *kr)
{
    int ret;
    krb5_error_code kerr = 0;
    char *pass_str = NULL;
    uint8_t buf[MAX_CHILD_MSG_SIZE];
    int size = 0;
    const char *cc_name;
    char *env;
    const char *krb5_error_msg;

    ret = setgid(kr->pd->gr_gid);
    if (ret == -1) {
        DEBUG(1, ("setgid failed [%d][%s].\n", errno, strerror(errno)));
        _exit(-1);
    }

    ret = setuid(kr->pd->pw_uid);
    if (ret == -1) {
        DEBUG(1, ("setuid failed [%d][%s].\n", errno, strerror(errno)));
        _exit(-1);
    }

    ret = setegid(kr->pd->gr_gid);
    if (ret == -1) {
        DEBUG(1, ("setegid failed [%d][%s].\n", errno, strerror(errno)));
        _exit(-1);
    }

    ret = seteuid(kr->pd->pw_uid);
    if (ret == -1) {
        DEBUG(1, ("seteuid failed [%d][%s].\n", errno, strerror(errno)));
        _exit(-1);
    }

    pass_str = talloc_strndup(kr, (const char *) kr->pd->authtok,
                              kr->pd->authtok_size);
    if (pass_str == NULL) {
        DEBUG(1, ("talloc_strndup failed.\n"));
        _exit(-1);
    }

    kerr = krb5_get_init_creds_password(kr->ctx, kr->creds, kr->princ,
                                        pass_str, NULL, NULL, 0, NULL,
                                        kr->options);
    if (kerr != 0) {
        KRB5_DEBUG(1, kerr);
        goto childfailed;
    }

    memset(pass_str, 0, kr->pd->authtok_size);
    talloc_free(pass_str);
    memset(kr->pd->authtok, 0, kr->pd->authtok_size);

    kerr = krb5_cc_default(kr->ctx, &kr->cc);
    if (kerr != 0) {
        KRB5_DEBUG(1, kerr);
        goto childfailed;
    }

    kerr = krb5_cc_initialize(kr->ctx, kr->cc, kr->princ);
    if (kerr != 0) {
        KRB5_DEBUG(1, kerr);
        goto childfailed;
    }

    kerr = krb5_cc_store_cred(kr->ctx, kr->cc, kr->creds);
    if (kerr != 0) {
        KRB5_DEBUG(1, kerr);
        krb5_cc_destroy(kr->ctx, kr->cc);
        goto childfailed;
    }

    cc_name = krb5_cc_get_name(kr->ctx, kr->cc);
    if (cc_name == NULL) {
        DEBUG(1, ("krb5_cc_get_name failed.\n"));
        krb5_cc_destroy(kr->ctx, kr->cc);
        _exit(-1);
    }

    env = talloc_asprintf(kr, "%s=%s",CCACHE_ENV_NAME, cc_name);
    if (env == NULL) {
        DEBUG(1, ("talloc_asprintf failed.\n"));
        krb5_cc_destroy(kr->ctx, kr->cc);
        _exit(-1);
    }

    size = pack_response_packet(buf, PAM_SUCCESS, PAM_ENV_ITEM, env);
    if (size < 0) {
        DEBUG(1, ("failed to create response message.\n"));
        krb5_cc_destroy(kr->ctx, kr->cc);
        _exit(-1);
    }

    kerr = 0;

childfailed:
    if (kerr != 0 ) {
        krb5_error_msg = krb5_get_error_message(krb5_error_ctx, kerr);
        size = pack_response_packet(buf, PAM_SYSTEM_ERR, PAM_USER_INFO,
                                    krb5_error_msg);
        if (size < 0) {
            DEBUG(1, ("failed to create response message.\n"));
            krb5_cc_destroy(kr->ctx, kr->cc);
            _exit(-1);
        }
        krb5_free_error_message(krb5_error_ctx, krb5_error_msg);
    }

    ret = write(fd, buf, size);
    if (ret == -1) {
        DEBUG(1, ("write failed [%d][%s].\n", errno, strerror(errno)));
        krb5_cc_destroy(kr->ctx, kr->cc);
        _exit(ret);
    }

    krb5_cc_close(kr->ctx, kr->cc);


    _exit(0);
}
