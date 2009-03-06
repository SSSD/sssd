#ifndef __PAMSRV_H__
#define __PAMSRV_H__


#include "util/util.h"
#include "sbus/sssd_dbus.h"
#include "responder/common/responder_cmd.h"

#define PAM_DP_TIMEOUT 5000

#define DEBUG_PAM_DATA(level, pd) do { \
    if (level <= debug_level) pam_print_data(level, pd); \
} while(0);

struct response_data {
    int32_t type;
    int32_t len;
    uint8_t *data;
    struct response_data *next;
};

struct pam_data {
    int cmd;
    uint32_t authtok_type;
    uint32_t authtok_size;
    uint32_t newauthtok_type;
    uint32_t newauthtok_size;
    char *domain;
    char *user;
    char *service;
    char *tty;
    char *ruser;
    char *rhost;
    uint8_t *authtok;
    uint8_t *newauthtok;

    int pam_status;
    int response_delay;
    struct response_data *resp_list;
    struct cli_ctx *cctx;
};

int pam_add_response(struct pam_data *pd, enum response_type type,
                     int len, uint8_t *data);
void pam_print_data(int l, struct pam_data *pd);

typedef void (*pam_dp_callback_t)(struct pam_data *pd);

struct sbus_method *register_pam_dp_methods(void);
struct sss_cmd_table *register_sss_cmds(void);
int pam_dp_send_req(struct cli_ctx *cctx, pam_dp_callback_t callback,
                    int timeout, struct pam_data *pd);

#endif /* __PAMSRV_H__ */
