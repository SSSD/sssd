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

#include "providers/data_provider.h"

#define PD_STR_COPY(el) do { \
    if (old_pd->el != NULL) { \
        pd->el = talloc_strdup(pd, old_pd->el); \
        if (pd->el == NULL) { \
            DEBUG(1, ("talloc_strdup failed.\n")); \
            goto failed; \
        } \
    } \
} while(0);

#define PD_MEM_COPY(el, size) do { \
    if (old_pd->el != NULL) { \
        pd->el = talloc_memdup(pd, old_pd->el, (size)); \
        if (pd->el == NULL) { \
            DEBUG(1, ("talloc_memdup failed.\n")); \
            goto failed; \
        } \
    } \
} while(0);

int pam_data_destructor(void *ptr)
{
    struct pam_data *pd = talloc_get_type(ptr, struct pam_data);

    if (pd->authtok_size != 0 && pd->authtok != NULL) {
        memset(pd->authtok, 0, pd->authtok_size);
        pd->authtok_size = 0;
    }

    if (pd->newauthtok_size != 0 && pd->newauthtok != NULL) {
        memset(pd->newauthtok, 0, pd->newauthtok_size);
        pd->newauthtok_size = 0;
    }

    return EOK;
}

struct pam_data *create_pam_data(TALLOC_CTX *mem_ctx)
{
    struct pam_data *pd;

    pd = talloc_zero(mem_ctx, struct pam_data);
    if (pd == NULL) {
        DEBUG(1, ("talloc_zero failed.\n"));
        return NULL;
    }

    talloc_set_destructor((TALLOC_CTX *) pd, pam_data_destructor);

    return pd;
}

errno_t copy_pam_data(TALLOC_CTX *mem_ctx, struct pam_data *old_pd,
                      struct pam_data **new_pd)
{
    struct pam_data *pd = NULL;

    pd = create_pam_data(mem_ctx);
    if (pd == NULL) {
        DEBUG(1, ("create_pam_data failed.\n"));
        return ENOMEM;
    }

    pd->cmd  = old_pd->cmd;
    pd->authtok_type = old_pd->authtok_type;
    pd->authtok_size = old_pd->authtok_size;
    pd->newauthtok_type = old_pd->newauthtok_type;
    pd->newauthtok_size = old_pd->newauthtok_size;

    PD_STR_COPY(domain);
    PD_STR_COPY(user);
    PD_STR_COPY(service);
    PD_STR_COPY(tty);
    PD_STR_COPY(ruser);
    PD_STR_COPY(rhost);
    PD_MEM_COPY(authtok, old_pd->authtok_size);
    PD_MEM_COPY(newauthtok, old_pd->newauthtok_size);
    pd->cli_pid = old_pd->cli_pid;

    *new_pd = pd;

    return EOK;

failed:
    talloc_free(pd);
    return ENOMEM;
}

static const char *pamcmd2str(int cmd) {
    switch (cmd) {
    case SSS_PAM_AUTHENTICATE:
        return "PAM_AUTHENTICATE";
    case SSS_PAM_SETCRED:
        return "PAM_SETCRED";
    case SSS_PAM_ACCT_MGMT:
        return "PAM_ACCT_MGMT";
    case SSS_PAM_OPEN_SESSION:
        return "PAM_OPEN_SESSION";
    case SSS_PAM_CLOSE_SESSION:
        return "PAM_CLOSE_SESSION";
    case SSS_PAM_CHAUTHTOK:
        return "PAM_CHAUTHTOK";
    case SSS_PAM_CHAUTHTOK_PRELIM:
        return "PAM_CHAUTHTOK_PRELIM";
    default:
        return "UNKNOWN";
    }
}

void pam_print_data(int l, struct pam_data *pd)
{
    DEBUG(l, ("command: %s\n", pamcmd2str(pd->cmd)));
    DEBUG(l, ("domain: %s\n", pd->domain));
    DEBUG(l, ("user: %s\n", pd->user));
    DEBUG(l, ("service: %s\n", pd->service));
    DEBUG(l, ("tty: %s\n", pd->tty));
    DEBUG(l, ("ruser: %s\n", pd->ruser));
    DEBUG(l, ("rhost: %s\n", pd->rhost));
    DEBUG(l, ("authtok type: %d\n", pd->authtok_type));
    DEBUG(l, ("authtok size: %d\n", pd->authtok_size));
    DEBUG(l, ("newauthtok type: %d\n", pd->newauthtok_type));
    DEBUG(l, ("newauthtok size: %d\n", pd->newauthtok_size));
    DEBUG(l, ("priv: %d\n", pd->priv));
    DEBUG(l, ("cli_pid: %d\n", pd->cli_pid));
}

int pam_add_response(struct pam_data *pd, enum response_type type,
                     int len, const uint8_t *data)
{
    struct response_data *new;

    new = talloc(pd, struct response_data);
    if (new == NULL) return ENOMEM;

    new->type = type;
    new->len = len;
    new->data = talloc_memdup(pd, data, len);
    if (new->data == NULL) return ENOMEM;
    new->next = pd->resp_list;
    pd->resp_list = new;

    return EOK;
}
