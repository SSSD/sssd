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
