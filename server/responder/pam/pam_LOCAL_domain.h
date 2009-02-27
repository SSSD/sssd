#ifndef __PAM_LOCAL_DOMAIN_H__
#define __PAM_LOCAL_DOMAIN_H__

#include "responder/pam/pamsrv.h"

int LOCAL_schedule_request(struct cli_ctx *cctx, pam_dp_callback_t callback,
                           struct pam_data *pd);

#endif /* __PAM_LOCAL_DOMAIN_H__ */
