#include "util/util.h"
#include "responder/pam/pamsrv.h"

void pam_print_data(int l, struct pam_data *pd)
{
    DEBUG(l, ("command: %d\n", pd->cmd));
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
}

int pam_add_response(struct pam_data *pd, enum response_type type,
                     int len, uint8_t *data)
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
