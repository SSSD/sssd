#ifndef __PAMSRV_H__
#define __PAMSRV_H__

#include <security/pam_appl.h>
#include "util/util.h"
#include "sbus/sssd_dbus.h"
#include "responder/common/responder.h"

#define PAM_DP_TIMEOUT 5000

struct pam_auth_req;

typedef void (pam_dp_callback_t)(struct pam_auth_req *preq);

struct pam_auth_req {
    struct cli_ctx *cctx;
    struct sss_domain_info *domain;

    struct pam_data *pd;

    pam_dp_callback_t *callback;

    bool check_provider;
    void *data;
};

struct sbus_method *register_pam_dp_methods(void);
struct sss_cmd_table *register_sss_cmds(void);

int pam_dp_send_req(struct pam_auth_req *preq, int timeout);

int pam_cache_credentials(struct pam_auth_req *preq);
int pam_cache_auth(struct pam_auth_req *preq);

int LOCAL_pam_handler(struct pam_auth_req *preq);

#endif /* __PAMSRV_H__ */
