
#include <sys/time.h>
#include <time.h>
#include "responder/nss/nsssrv.h"
#include "util/util.h"
#include "responder/common/responder_packet.h"
#include "responder/common/responder_common.h"
#include "providers/data_provider.h"
#include "sbus/sbus_client.h"
#include "providers/dp_sbus.h"

struct sss_dp_pvt_ctx {
    struct nss_ctx *nctx;
    struct sbus_method *methods;
    time_t last_retry;
    int retries;
};

static int sss_dp_conn_destructor(void *data);
static void sss_dp_reconnect(struct tevent_context *ev,
                             struct tevent_timer *te,
                             struct timeval tv, void *data);

static void sss_dp_conn_reconnect(struct sss_dp_pvt_ctx *pvt)
{
    struct nss_ctx *nctx;
    struct tevent_timer *te;
    struct timeval tv;
    struct sbus_method_ctx *sm_ctx;
    char *sbus_address;
    time_t now;
    int ret;

    now = time(NULL);

    /* reset retry if last reconnect was > 60 sec. ago */
    if (pvt->last_retry + 60 < now) pvt->retries = 0;
    if (pvt->retries >= 3) {
        DEBUG(4, ("Too many reconnect retries! Giving up\n"));
        return;
    }

    pvt->last_retry = now;
    pvt->retries++;

    nctx = pvt->nctx;

    ret = dp_get_sbus_address(nctx, nctx->cdb, &sbus_address);
    if (ret != EOK) {
        DEBUG(0, ("Could not locate data provider address.\n"));
        return;
    }

    ret = dp_init_sbus_methods(nctx, pvt->methods, &sm_ctx);
    if (ret != EOK) {
        DEBUG(0, ("Could not initialize SBUS methods.\n"));
        return;
    }

    ret = sbus_client_init(nctx, nctx->ev,
                           sbus_address, sm_ctx,
                           pvt, sss_dp_conn_destructor,
                           &nctx->dp_ctx);
    if (ret != EOK) {
        DEBUG(4, ("Failed to reconnect [%d(%s)]!\n", ret, strerror(ret)));

        tv.tv_sec = now +5;
        tv.tv_usec = 0;
        te = tevent_add_timer(nctx->ev, nctx, tv, sss_dp_reconnect, pvt);
        if (te == NULL) {
            DEBUG(4, ("Failed to add timed event! Giving up\n"));
        } else {
            DEBUG(4, ("Retrying in 5 seconds\n"));
        }
    }
}

static void sss_dp_reconnect(struct tevent_context *ev,
                             struct tevent_timer *te,
                             struct timeval tv, void *data)
{
    struct sss_dp_pvt_ctx *pvt;

    pvt = talloc_get_type(data, struct sss_dp_pvt_ctx);

    sss_dp_conn_reconnect(pvt);
}

int sss_dp_conn_destructor(void *data)
{
    struct sss_dp_pvt_ctx *pvt;
    struct sbus_conn_ctx *scon;

    scon = talloc_get_type(data, struct sbus_conn_ctx);
    if (!scon) return 0;

    /* if this is a regular disconnect just quit */
    if (sbus_conn_disconnecting(scon)) return 0;

    pvt = talloc_get_type(sbus_conn_get_private_data(scon),
                          struct sss_dp_pvt_ctx);
    if (pvt) return 0;

    sss_dp_conn_reconnect(pvt);

    return 0;
}

int sss_dp_init(struct nss_ctx *nctx, struct sbus_method *dp_methods)
{
    struct sss_dp_pvt_ctx *pvt;

    pvt = talloc_zero(nctx, struct sss_dp_pvt_ctx);
    if (!pvt) return ENOMEM;

    pvt->nctx = nctx;
    pvt->methods = dp_methods;

    sss_dp_conn_reconnect(pvt);

    return EOK;
}

