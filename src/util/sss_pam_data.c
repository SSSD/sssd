/*
    SSSD

    Utilities to for tha pam_data structure

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

#include <security/pam_modules.h>

#include "util/sss_pam_data.h"
#include "util/sss_cli_cmd.h"

#define PAM_SAFE_ITEM(item) item ? item : "not set"

int pam_data_destructor(void *ptr)
{
    struct pam_data *pd = talloc_get_type(ptr, struct pam_data);

    /* make sure to wipe any password from memory before freeing */
    sss_authtok_wipe_password(pd->authtok);
    sss_authtok_wipe_password(pd->newauthtok);

    return 0;
}

struct pam_data *create_pam_data(TALLOC_CTX *mem_ctx)
{
    struct pam_data *pd;

    pd = talloc_zero(mem_ctx, struct pam_data);
    if (pd == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero failed.\n");
        goto failed;
    }

    pd->pam_status = PAM_SYSTEM_ERR;

    pd->authtok = sss_authtok_new(pd);
    if (pd->authtok == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero failed.\n");
        goto failed;
    }

    pd->newauthtok = sss_authtok_new(pd);
    if (pd->newauthtok == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero failed.\n");
        goto failed;
    }

    talloc_set_destructor((TALLOC_CTX *) pd, pam_data_destructor);

    return pd;

failed:
    talloc_free(pd);
    return NULL;
}

errno_t copy_pam_data(TALLOC_CTX *mem_ctx, struct pam_data *src,
                      struct pam_data **dst)
{
    struct pam_data *pd = NULL;
    errno_t ret;

    pd = create_pam_data(mem_ctx);
    if (pd == NULL) {
        ret =  ENOMEM;
        goto failed;
    }

    pd->cmd  = src->cmd;
    pd->priv = src->priv;

    pd->domain = talloc_strdup(pd, src->domain);
    if (pd->domain == NULL && src->domain != NULL) {
        ret =  ENOMEM;
        goto failed;
    }
    pd->user = talloc_strdup(pd, src->user);
    if (pd->user == NULL && src->user != NULL) {
        ret =  ENOMEM;
        goto failed;
    }
    pd->service = talloc_strdup(pd, src->service);
    if (pd->service == NULL && src->service != NULL) {
        ret =  ENOMEM;
        goto failed;
    }
    pd->tty = talloc_strdup(pd, src->tty);
    if (pd->tty == NULL && src->tty != NULL) {
        ret =  ENOMEM;
        goto failed;
    }
    pd->ruser = talloc_strdup(pd, src->ruser);
    if (pd->ruser == NULL && src->ruser != NULL) {
        ret =  ENOMEM;
        goto failed;
    }
    pd->rhost = talloc_strdup(pd, src->rhost);
    if (pd->rhost == NULL && src->rhost != NULL) {
        ret =  ENOMEM;
        goto failed;
    }

    pd->cli_pid = src->cli_pid;
    pd->client_id_num = src->client_id_num;

    /* if structure pam_data was allocated on stack and zero initialized,
     * than src->authtok and src->newauthtok are NULL, therefore
     * instead of copying, new empty authtok will be created.
     */
    if (src->authtok) {
        ret = sss_authtok_copy(src->authtok, pd->authtok);
        if (ret) {
            goto failed;
        }
    } else {
        pd->authtok = sss_authtok_new(pd);
        if (pd->authtok == NULL) {
            ret = ENOMEM;
            goto failed;
        }
    }

    if (src->newauthtok) {
        ret = sss_authtok_copy(src->newauthtok, pd->newauthtok);
        if (ret) {
            goto failed;
        }
    } else {
        pd->newauthtok = sss_authtok_new(pd);
        if (pd->newauthtok == NULL) {
            ret = ENOMEM;
            goto failed;
        }
    }

    *dst = pd;

    return EOK;

failed:
    talloc_free(pd);
    DEBUG(SSSDBG_CRIT_FAILURE,
          "copy_pam_data failed: (%d) %s.\n", ret, strerror(ret));
    return ret;
}

void pam_print_data(int l, struct pam_data *pd)
{
    DEBUG(l, "command: %s\n", sss_cmd2str(pd->cmd));
    DEBUG(l, "domain: %s\n", PAM_SAFE_ITEM(pd->domain));
    DEBUG(l, "user: %s\n", PAM_SAFE_ITEM(pd->user));
    DEBUG(l, "service: %s\n", PAM_SAFE_ITEM(pd->service));
    DEBUG(l, "tty: %s\n", PAM_SAFE_ITEM(pd->tty));
    DEBUG(l, "ruser: %s\n", PAM_SAFE_ITEM(pd->ruser));
    DEBUG(l, "rhost: %s\n", PAM_SAFE_ITEM(pd->rhost));
    DEBUG(l, "authtok type: %d (%s)\n",
          sss_authtok_get_type(pd->authtok),
          sss_authtok_type_to_str(sss_authtok_get_type(pd->authtok)));
    DEBUG(l, "newauthtok type: %d (%s)\n",
          sss_authtok_get_type(pd->newauthtok),
          sss_authtok_type_to_str(sss_authtok_get_type(pd->newauthtok)));
    DEBUG(l, "priv: %d\n", pd->priv);
    DEBUG(l, "cli_pid: %d\n", pd->cli_pid);
    DEBUG(l, "child_pid: %d\n", pd->child_pid);
    DEBUG(l, "logon name: %s\n", PAM_SAFE_ITEM(pd->logon_name));
    DEBUG(l, "flags: %d\n", pd->cli_flags);
}

int pam_add_response(struct pam_data *pd, enum response_type type,
                     int len, const uint8_t *data)
{
    struct response_data *new;

    new = talloc(pd, struct response_data);
    if (new == NULL) return ENOMEM;

    new->type = type;
    new->len = len;
    new->data = talloc_memdup(new, data, len);
    if (new->data == NULL) return ENOMEM;
    new->do_not_send_to_client = false;
    new->next = pd->resp_list;
    pd->resp_list = new;

    return EOK;
}
