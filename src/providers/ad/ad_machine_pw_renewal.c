/*
    SSSD

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2016 Red Hat

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


#include "util/child_common.h"
#include "util/util.h"
#include "util/strtonum.h"
#include "providers/be_ptask.h"
#include "providers/ad/ad_common.h"

#ifndef RENEWAL_PROG_PATH_ADCLI
#define RENEWAL_PROG_PATH_ADCLI "/usr/sbin/adcli"
#endif

#ifndef RENEWAL_PROG_PATH_REALM
#define RENEWAL_PROG_PATH_REALM "/usr/sbin/realm"
#endif

enum renew_helper {
    RENEW_HELPER_UNDEFINED = 0,
    RENEW_HELPER_ADCLI,
    RENEW_HELPER_REALM
};

struct renewal_data {
    struct be_ctx *be_ctx;
    char *prog_path;
    const char **extra_args;
    enum renew_helper renew_helper;
};

static errno_t get_adcli_extra_args(const char *ad_domain,
                                    const char *ad_hostname,
                                    const char *ad_keytab,
                                    bool ad_use_ldaps,
                                    size_t pw_lifetime_in_days,
                                    bool add_samba_data,
                                    size_t period,
                                    size_t initial_delay,
                                    struct renewal_data *renewal_data)
{
    const char **args;
    size_t c = 0;

    if (ad_domain == NULL || ad_hostname == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing AD domain or hostname.\n");
        return EINVAL;
    }

    renewal_data->prog_path = talloc_strdup(renewal_data,
                                            RENEWAL_PROG_PATH_ADCLI);
    if (renewal_data->prog_path == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
        return ENOMEM;
    }

    args = talloc_array(renewal_data, const char *, 10);
    if (args == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_array failed.\n");
        return ENOMEM;
    }

    /* extra_args are added in revers order */
    /* first add NULL as a placeholder for the server name which is determined
     * at runtime */
    args[c++] = NULL;
    args[c++] = talloc_asprintf(args, "--computer-password-lifetime=%zu",
                                pw_lifetime_in_days);
    if (add_samba_data) {
        args[c++] = talloc_strdup(args, "--add-samba-data");
    }
    args[c++] = talloc_asprintf(args, "--host-fqdn=%s", ad_hostname);
    if (ad_keytab != NULL) {
        args[c++] = talloc_asprintf(args, "--host-keytab=%s", ad_keytab);
    }
    args[c++] = talloc_asprintf(args, "--domain=%s", ad_domain);
    if (ad_use_ldaps) {
        args[c++] = talloc_strdup(args, "--use-ldaps");
    }
    if (DEBUG_IS_SET(SSSDBG_TRACE_LIBS)) {
        args[c++] = talloc_strdup(args, "--verbose");
    }
    args[c++] = talloc_strdup(args, "update");
    args[c] = NULL;

    do {
        if (args[--c] == NULL) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "talloc failed while copying  arguments.\n");
            talloc_free(args);
            return ENOMEM;
        }
    } while (c != 1); /* it is expected that the first element is NULL */

    renewal_data->extra_args = args;

    return EOK;
}

static errno_t get_realm_extra_args(const char *ad_domain,
                                    const char *ad_hostname,
                                    const char *ad_keytab,
                                    bool ad_use_ldaps,
                                    size_t pw_lifetime_in_days,
                                    bool add_samba_data,
                                    size_t period,
                                    size_t initial_delay,
                                    struct renewal_data *renewal_data)
{
    const char **args;
    size_t c = 0;

    if (ad_domain == NULL || ad_hostname == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing AD domain or hostname.\n");
        return EINVAL;
    }

    renewal_data->prog_path = talloc_strdup(renewal_data, RENEWAL_PROG_PATH_REALM);
    if (renewal_data->prog_path == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
        return ENOMEM;
    }

    args = talloc_array(renewal_data, const char *, 10);
    if (args == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_array failed.\n");
        return ENOMEM;
    }

    /* extra_args are added in revers order */
    /* first add NULL as a placeholder for the server name which is determined
     * at runtime */
    args[c++] = NULL;
    args[c++] = talloc_asprintf(args, "--computer-password-lifetime=%zu",
                                pw_lifetime_in_days);
    if (add_samba_data) {
        args[c++] = talloc_strdup(args, "--add-samba-data");
    }
    args[c++] = talloc_asprintf(args, "--host-fqdn=%s", ad_hostname);
    if (ad_keytab != NULL) {
        args[c++] = talloc_asprintf(args, "--host-keytab=%s", ad_keytab);
    }
    if (ad_use_ldaps) {
        args[c++] = talloc_strdup(args, "--use-ldaps");
    }
    if (DEBUG_IS_SET(SSSDBG_TRACE_LIBS)) {
        args[c++] = talloc_strdup(args, "--verbose");
    }
    args[c++] = talloc_strdup(args, ad_domain);
    args[c++] = talloc_strdup(args, "renew");
    args[c] = NULL;

    do {
        if (args[--c] == NULL) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "talloc failed while copying  arguments.\n");
            talloc_free(args);
            return ENOMEM;
        }
    } while (c != 1); /* it is expected that the first element is NULL */

    renewal_data->extra_args = args;

    return EOK;
}

struct renewal_state {
    struct child_io_fds *io;
};

static void ad_machine_account_password_renewal_done(struct tevent_req *subreq);

static struct tevent_req *
ad_machine_account_password_renewal_send(TALLOC_CTX *mem_ctx,
                                  struct tevent_context *ev,
                                  struct be_ctx *be_ctx,
                                  struct be_ptask *be_ptask,
                                  void *pvt)
{
    struct renewal_data *renewal_data;
    struct renewal_state *state;
    struct tevent_req *req;
    struct tevent_req *subreq;
    int ret;
    const char **extra_args;
    const char *server_name;

    req = tevent_req_create(mem_ctx, &state, struct renewal_state);
    if (req == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "tevent_req_create failed.\n");
        return NULL;
    }

    renewal_data = talloc_get_type(pvt, struct renewal_data);

    server_name = be_fo_get_active_server_name(be_ctx, AD_SERVICE_NAME);
    talloc_zfree(renewal_data->extra_args[0]);
    if ((renewal_data->renew_helper == RENEW_HELPER_ADCLI)
            && (server_name != NULL)) {
        renewal_data->extra_args[0] = talloc_asprintf(renewal_data->extra_args,
                                                      "--domain-controller=%s",
                                                      server_name);
        /* if talloc_asprintf() fails we let adcli try to find a server */
    }

    extra_args = renewal_data->extra_args;
    if (extra_args[0] == NULL) {
        extra_args = &renewal_data->extra_args[1];
    }

    ret = sss_child_start(state, ev,
                          renewal_data->prog_path, extra_args, true,
                          /* no log file */ NULL, STDERR_FILENO,
                          /* no SIGCHLD cb */ NULL, NULL,
                          (unsigned)(be_ptask_get_timeout(be_ptask)),
                          sss_child_handle_timeout,
                          sss_child_create_timeout_cb_pvt(req, ERR_RENEWAL_CHILD),
                          true,
                          &(state->io));
    if (ret != EOK) {
        goto done;
    }

    subreq = read_pipe_non_blocking_send(state, ev,
                                         state->io->read_from_child_fd);
    if (subreq == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "read_pipe_send failed.\n");
        ret = ERR_RENEWAL_CHILD;
        goto done;
    }
    tevent_req_set_callback(subreq,
                            ad_machine_account_password_renewal_done, req);

    /* Now either wait for the timeout to fire or the child
     * to finish
     */
    ret = EOK;

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }
    return req;
}

static void ad_machine_account_password_renewal_done(struct tevent_req *subreq)
{
    uint8_t *buf;
    ssize_t buf_len;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct renewal_state *state = tevent_req_data(req, struct renewal_state);
    int ret;

    talloc_zfree(state->io->timeout_handler);

    ret = read_pipe_recv(subreq, state, &buf, &buf_len);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    DEBUG(SSSDBG_TRACE_LIBS, "--- adcli output start---\n"
                             "%.*s"
                             "---adcli output end---\n",
                             (int) buf_len, buf);

    tevent_req_done(req);
    return;
}

static errno_t
ad_machine_account_password_renewal_recv(struct tevent_req *req)
{

    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

errno_t ad_machine_account_password_renewal_init(struct be_ctx *be_ctx,
                                                 struct ad_options *ad_opts)
{
    int ret;
    struct renewal_data *renewal_data;
    int lifetime;
    size_t period;
    size_t offset;
    size_t initial_delay;
    const char *dummy;
    char **opt_list;
    int opt_list_size;
    char *endptr;

    lifetime = dp_opt_get_int(ad_opts->basic,
                              AD_MAXIMUM_MACHINE_ACCOUNT_PASSWORD_AGE);

    if (lifetime == 0) {
        DEBUG(SSSDBG_CONF_SETTINGS, "Automatic machine account renewal disabled.\n");
        return EOK;
    }

    if (lifetime < 0) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Illegal value [%d] for password lifetime.\n", lifetime);
        return EINVAL;
    }

    renewal_data = talloc_zero(be_ctx, struct renewal_data);
    if (renewal_data == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc failed.\n");
        return ENOMEM;
    }

    dummy = dp_opt_get_cstring(ad_opts->basic,
                               AD_MACHINE_ACCOUNT_PASSWORD_RENEWAL_OPTS);
    ret = split_on_separator(renewal_data, dummy, ':', true, false,
                             &opt_list, &opt_list_size);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "split_on_separator failed.\n");
        goto done;
    }

    if (opt_list_size < 2 || opt_list_size > 4) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Wrong number of renewal options %d\n",
              opt_list_size);
        ret = EINVAL;
        goto done;
    }

    period = strtouint32(opt_list[0], &endptr, 10);
    if (errno != 0 || *endptr != '\0' || opt_list[0] == endptr) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to parse first renewal option.\n");
        ret = EINVAL;
        goto done;
    }

    initial_delay = strtouint32(opt_list[1], &endptr, 10);
    if (errno != 0 || *endptr != '\0' || opt_list[1] == endptr) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to parse second renewal option.\n");
        ret = EINVAL;
        goto done;
    }

    if (opt_list_size >= 3 && opt_list[2] != NULL && *(opt_list[2]) != '\0') {
        offset = strtouint32(opt_list[2], &endptr, 10);
        if (errno != 0 || *endptr != '\0' || opt_list[2] == endptr) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to parse third renewal option.\n");
            ret = EINVAL;
            goto done;
        }
    } else {
        offset = 0;
    }

    renewal_data->renew_helper = RENEW_HELPER_REALM;
    if (opt_list_size == 4 && opt_list[3] != NULL && *(opt_list[3]) != '\0') {
        if (strcasecmp(opt_list[3], "adcli") == 0) {
            renewal_data->renew_helper = RENEW_HELPER_ADCLI;
        } else if (strcasecmp(opt_list[3], "realm") == 0) {
            renewal_data->renew_helper = RENEW_HELPER_REALM;
        } else {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Unsupported keytab renewal helper program [%s].\n",
                  opt_list[3]);
            ret = EINVAL;
            goto done;
        }
    }

    if (renewal_data->renew_helper == RENEW_HELPER_ADCLI) {
        ret = get_adcli_extra_args(dp_opt_get_cstring(ad_opts->basic, AD_DOMAIN),
                   dp_opt_get_cstring(ad_opts->basic, AD_HOSTNAME),
                   dp_opt_get_cstring(ad_opts->id_ctx->sdap_id_ctx->opts->basic,
                                      SDAP_KRB5_KEYTAB),
                   dp_opt_get_bool(ad_opts->basic, AD_USE_LDAPS), lifetime,
                   dp_opt_get_bool(ad_opts->basic,
                                   AD_UPDATE_SAMBA_MACHINE_ACCOUNT_PASSWORD),
                   period, initial_delay, renewal_data);
    } else if (renewal_data->renew_helper == RENEW_HELPER_REALM) {
        ret = get_realm_extra_args(dp_opt_get_cstring(ad_opts->basic, AD_DOMAIN),
                   dp_opt_get_cstring(ad_opts->basic, AD_HOSTNAME),
                   dp_opt_get_cstring(ad_opts->id_ctx->sdap_id_ctx->opts->basic,
                                      SDAP_KRB5_KEYTAB),
                   dp_opt_get_bool(ad_opts->basic, AD_USE_LDAPS), lifetime,
                   dp_opt_get_bool(ad_opts->basic,
                                   AD_UPDATE_SAMBA_MACHINE_ACCOUNT_PASSWORD),
                   period, initial_delay, renewal_data);
    } else {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Unsupported keytab renewal helper program.\n");
        ret = EINVAL;
        goto done;
    }
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to generate argument for helper program [%s].\n",
              renewal_data->prog_path);
        goto done;
    }

    ret = access(renewal_data->prog_path, X_OK);
    if (ret != 0) {
        ret = errno;
        DEBUG(SSSDBG_CONF_SETTINGS,
              "The helper program [%s] for renewal doesn't exist [%d]: %s\n",
              renewal_data->prog_path, ret, strerror(ret));
        return EOK;
    }


    ret = be_ptask_create(be_ctx, be_ctx, period, initial_delay, 0, offset,
                          60, 0,
                          ad_machine_account_password_renewal_send,
                          ad_machine_account_password_renewal_recv,
                          renewal_data,
                          "AD machine account password renewal",
                          BE_PTASK_OFFLINE_DISABLE |
                          BE_PTASK_SCHEDULE_FROM_LAST,
                          NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "be_ptask_create failed.\n");
        goto done;
    }

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(renewal_data);
    }

    return ret;
}
