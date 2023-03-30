/*
   SSSD

   PAM Responder - certificate related requests

   Copyright (C) Sumit Bose <sbose@redhat.com> 2015

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

#include <time.h>

#include "util/util.h"
#include "providers/data_provider.h"
#include "util/child_common.h"
#include "util/strtonum.h"
#include "responder/pam/pamsrv.h"
#include "responder/pam/pam_helpers.h"
#include "lib/certmap/sss_certmap.h"
#include "util/crypto/sss_crypto.h"
#include "util/sss_chain_id.h"
#include "db/sysdb.h"


struct cert_auth_info {
    char *cert;
    char *token_name;
    char *module_name;
    char *key_id;
    char *label;
    struct ldb_result *cert_user_objs;
    struct cert_auth_info *prev;
    struct cert_auth_info *next;
};

const char *sss_cai_get_cert(struct cert_auth_info *i)
{
    return i != NULL ? i->cert : NULL;
}

const char *sss_cai_get_token_name(struct cert_auth_info *i)
{
    return i != NULL ? i->token_name : NULL;
}

const char *sss_cai_get_module_name(struct cert_auth_info *i)
{
    return i != NULL ? i->module_name : NULL;
}

const char *sss_cai_get_key_id(struct cert_auth_info *i)
{
    return i != NULL ? i->key_id : NULL;
}

const char *sss_cai_get_label(struct cert_auth_info *i)
{
    return i != NULL ? i->label : NULL;
}

struct cert_auth_info *sss_cai_get_next(struct cert_auth_info *i)
{
    return i != NULL ? i->next : NULL;
}

struct ldb_result *sss_cai_get_cert_user_objs(struct cert_auth_info *i)
{
    return i != NULL ? i->cert_user_objs : NULL;
}

void sss_cai_set_cert_user_objs(struct cert_auth_info *i,
                                struct ldb_result *cert_user_objs)
{
    if (i->cert_user_objs != NULL) {
        talloc_free(i->cert_user_objs);
    }
    i->cert_user_objs = talloc_steal(i, cert_user_objs);
}

void sss_cai_check_users(struct cert_auth_info **list, size_t *_cert_count,
                         size_t *_cert_user_count)
{
    struct cert_auth_info *c;
    struct cert_auth_info *tmp;
    size_t cert_count = 0;
    size_t cert_user_count = 0;
    struct ldb_result *user_objs;

    DLIST_FOR_EACH_SAFE(c, tmp, *list) {
        user_objs = sss_cai_get_cert_user_objs(c);
        if (user_objs != NULL) {
            cert_count++;
            cert_user_count += user_objs->count;
        } else {
            DLIST_REMOVE(*list, c);
        }
    }

    if (_cert_count != NULL) {
        *_cert_count = cert_count;
    }

    if (_cert_user_count != NULL) {
        *_cert_user_count = cert_user_count;
    }

    return;
}

struct priv_sss_debug {
    int level;
};

static void ext_debug(void *private, const char *file, long line,
                      const char *function, const char *format, ...)
{
    va_list ap;
    struct priv_sss_debug *data = private;
    int level = SSSDBG_OP_FAILURE;

    if (data != NULL) {
        level = data->level;
    }

    va_start(ap, format);
    sss_vdebug_fn(file, line, function, level, APPEND_LINE_FEED,
                  format, ap);
    va_end(ap);
}

errno_t p11_refresh_certmap_ctx(struct pam_ctx *pctx,
                                struct sss_domain_info *domains)
{
    int ret;
    struct sss_certmap_ctx *sss_certmap_ctx = NULL;
    size_t c;
    struct sss_domain_info *dom;
    bool certmap_found = false;
    struct certmap_info **certmap_list;

    ret = sss_certmap_init(pctx, ext_debug, NULL, &sss_certmap_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_certmap_init failed.\n");
        goto done;
    }

    DLIST_FOR_EACH(dom, domains) {
        certmap_list = dom->certmaps;
        if (certmap_list != NULL && *certmap_list != NULL) {
            certmap_found = true;
            break;
        }
    }

    if (!certmap_found) {
        /* Try to add default matching rule */
        ret = sss_certmap_add_rule(sss_certmap_ctx, SSS_CERTMAP_MIN_PRIO,
                                   CERT_AUTH_DEFAULT_MATCHING_RULE, NULL, NULL);
        if (ret != 0) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to add default matching rule.\n");
        }

        goto done;
    }

    DLIST_FOR_EACH(dom, domains) {
        certmap_list = dom->certmaps;
        if (certmap_list == NULL || *certmap_list == NULL) {
            continue;
        }

        for (c = 0; certmap_list[c] != NULL; c++) {
            DEBUG(SSSDBG_TRACE_ALL,
                  "Trying to add rule [%s][%d][%s][%s].\n",
                  certmap_list[c]->name, certmap_list[c]->priority,
                  certmap_list[c]->match_rule, certmap_list[c]->map_rule);

            ret = sss_certmap_add_rule(sss_certmap_ctx,
                                       certmap_list[c]->priority,
                                       certmap_list[c]->match_rule,
                                       certmap_list[c]->map_rule,
                                       certmap_list[c]->domains);
            if (ret != 0) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "sss_certmap_add_rule failed for rule [%s] "
                      "with error [%d][%s], skipping. "
                      "Please check for typos and if rule syntax is supported.\n",
                      certmap_list[c]->name, ret, sss_strerror(ret));
                continue;
            }
        }
    }

    ret = EOK;

done:
    if (ret == EOK) {
        sss_certmap_free_ctx(pctx->sss_certmap_ctx);
        pctx->sss_certmap_ctx = sss_certmap_ctx;
    } else {
        sss_certmap_free_ctx(sss_certmap_ctx);
    }

    return ret;
}

errno_t p11_child_init(struct pam_ctx *pctx)
{
    int ret;
    struct certmap_info **certmaps;
    bool user_name_hint;
    struct sss_domain_info *dom;

    DLIST_FOR_EACH(dom, pctx->rctx->domains) {
        ret = sysdb_get_certmap(dom, dom->sysdb, &certmaps, &user_name_hint);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_get_certmap failed.\n");
            return ret;
        }

        dom->user_name_hint = user_name_hint;
        talloc_free(dom->certmaps);
        dom->certmaps = certmaps;
    }

    ret = p11_refresh_certmap_ctx(pctx, pctx->rctx->domains);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "p11_refresh_certmap_ctx failed.\n");
        return ret;
    }

    return EOK;
}

static inline bool
service_in_list(char **list, size_t nlist, const char *str)
{
    size_t i;

    for (i = 0; i < nlist; i++) {
        if (strcasecmp(list[i], str) == 0) {
            break;
        }
    }

    return (i < nlist) ? true : false;
}

static errno_t get_sc_services(TALLOC_CTX *mem_ctx, struct pam_ctx *pctx,
                               char ***_sc_list)
{
    TALLOC_CTX *tmp_ctx;
    errno_t ret;
    char *conf_str;
    char **conf_list;
    int conf_list_size;
    char **add_list;
    char **remove_list;
    int ai = 0;
    int ri = 0;
    int j = 0;
    char **sc_list;
    int expected_sc_list_size;

    const char *default_sc_services[] = {
        "login", "su", "su-l", "gdm-smartcard", "gdm-password", "kdm", "sudo",
        "sudo-i", "gnome-screensaver", "polkit-1", NULL,
    };
    const int default_sc_services_size =
        sizeof(default_sc_services) / sizeof(default_sc_services[0]);

    tmp_ctx = talloc_new(mem_ctx);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = confdb_get_string(pctx->rctx->cdb, tmp_ctx, CONFDB_PAM_CONF_ENTRY,
                            CONFDB_PAM_P11_ALLOWED_SERVICES, NULL,
                            &conf_str);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "confdb_get_string failed %d [%s]\n", ret, sss_strerror(ret));
        goto done;
    }

    if (conf_str != NULL) {
        ret = split_on_separator(tmp_ctx, conf_str, ',', true, true,
                                 &conf_list, &conf_list_size);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Cannot parse list of service names '%s': %d [%s]\n",
                  conf_str, ret, sss_strerror(ret));
            goto done;
        }
    } else {
        conf_list = talloc_zero_array(tmp_ctx, char *, 1);
        conf_list_size = 0;
    }

    add_list = talloc_zero_array(tmp_ctx, char *, conf_list_size + 1);
    remove_list = talloc_zero_array(tmp_ctx, char *, conf_list_size + 1);

    if (add_list == NULL || remove_list == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (int i = 0; conf_list[i] != NULL; ++i) {
        switch (conf_list[i][0]) {
        case '+':
            add_list[ai] = conf_list[i] + 1;
            ++ai;
            break;
        case '-':
            remove_list[ri] = conf_list[i] + 1;
            ++ri;
            break;
        default:
            DEBUG(SSSDBG_OP_FAILURE,
                  "The option "CONFDB_PAM_P11_ALLOWED_SERVICES" must start"
                  "with either '+' (for adding service) or '-' (for "
                  "removing service) got '%s'\n", conf_list[i]);
            ret = EINVAL;
            goto done;
        }
    }

    expected_sc_list_size = default_sc_services_size + ai + 1;

    sc_list = talloc_zero_array(tmp_ctx, char *, expected_sc_list_size);
    if (sc_list == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (int i = 0; add_list[i] != NULL; ++i) {
        if (service_in_list(remove_list, ri, add_list[i])) {
            continue;
        }

        sc_list[j] = talloc_strdup(sc_list, add_list[i]);
        if (sc_list[j] == NULL) {
            ret = ENOMEM;
            goto done;
        }
        ++j;
    }

    for (int i = 0; default_sc_services[i] != NULL; ++i) {
        if (service_in_list(remove_list, ri, default_sc_services[i])) {
            continue;
        }

        sc_list[j] = talloc_strdup(sc_list, default_sc_services[i]);
        if (sc_list[j] == NULL) {
            ret = ENOMEM;
            goto done;
        }
        ++j;
    }

    if (_sc_list != NULL) {
        *_sc_list = talloc_steal(mem_ctx, sc_list);
    }

done:
    talloc_zfree(tmp_ctx);

    return ret;
}

bool may_do_cert_auth(struct pam_ctx *pctx, struct pam_data *pd)
{
    size_t c;
    errno_t ret;

    if (!pctx->cert_auth) {
        return false;
    }

    if (pd->cmd != SSS_PAM_PREAUTH && pd->cmd != SSS_PAM_AUTHENTICATE) {
        return false;
    }

    if (pd->cmd == SSS_PAM_AUTHENTICATE
           && sss_authtok_get_type(pd->authtok) != SSS_AUTHTOK_TYPE_SC_PIN
           && sss_authtok_get_type(pd->authtok) != SSS_AUTHTOK_TYPE_SC_KEYPAD) {
        return false;
    }

    if (pd->service == NULL || *pd->service == '\0') {
        return false;
    }

    /* Initialize smartcard allowed services just once */
    if (pctx->smartcard_services == NULL) {
        ret = get_sc_services(pctx, pctx, &pctx->smartcard_services);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to get p11 allowed services %d[%s]",
                  ret, sss_strerror(ret));
            sss_log(SSS_LOG_ERR,
                    "Failed to evaluate pam_p11_allowed_services option, "
                    "please check for typos in the SSSD configuration");
            return false;
        }
    }

    for (c = 0; pctx->smartcard_services[c] != NULL; c++) {
        if (strcmp(pd->service, pctx->smartcard_services[c]) == 0) {
            break;
        }
    }
    if (pctx->smartcard_services[c] == NULL) {
        DEBUG(SSSDBG_CONF_SETTINGS,
              "Smartcard authentication for service [%s] not supported.\n",
              pd->service);
        return false;
    }

    return true;
}

static errno_t get_p11_child_write_buffer(TALLOC_CTX *mem_ctx,
                                          struct pam_data *pd,
                                          uint8_t **_buf, size_t *_len)
{
    int ret;
    uint8_t *buf;
    size_t len;
    const char *pin = NULL;

    if (pd == NULL || pd->authtok == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing authtok.\n");
        return EINVAL;
    }

    switch (sss_authtok_get_type(pd->authtok)) {
    case SSS_AUTHTOK_TYPE_SC_PIN:
        ret = sss_authtok_get_sc_pin(pd->authtok, &pin, &len);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sss_authtok_get_sc_pin failed.\n");
            return ret;
        }
        if (pin == NULL || len == 0) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Missing PIN.\n");
            return EINVAL;
        }

        buf = talloc_size(mem_ctx, len);
        if (buf == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_size failed.\n");
            return ENOMEM;
        }

        safealign_memcpy(buf, pin, len, NULL);

        break;
    case SSS_AUTHTOK_TYPE_SC_KEYPAD:
        /* Nothing to send */
        len = 0;
        buf = NULL;
        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE, "Unsupported authtok type [%d].\n",
                                   sss_authtok_get_type(pd->authtok));
        return EINVAL;
    }

    *_len = len;
    *_buf = buf;

    return EOK;
}

static errno_t parse_p11_child_response(TALLOC_CTX *mem_ctx, uint8_t *buf,
                                        ssize_t buf_len,
                                        struct sss_certmap_ctx *sss_certmap_ctx,
                                        struct cert_auth_info **_cert_list)
{
    int ret;
    TALLOC_CTX *tmp_ctx = NULL;
    uint8_t *p;
    uint8_t *pn;
    struct cert_auth_info *cert_list = NULL;
    struct cert_auth_info *cert_auth_info;
    unsigned char *der = NULL;
    size_t der_size;

    if (buf_len <= 0) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Error occurred while reading data from p11_child (len = %ld)\n",
              buf_len);
        return EIO;
    }

    p = memchr(buf, '\n', buf_len);
    if ((p == NULL) || (p == buf)) {
        DEBUG(SSSDBG_OP_FAILURE, "Missing status in p11_child response.\n");
        return EINVAL;
    }
    errno = 0;
    ret = strtol((char *)buf, (char **)&pn, 10);
    if ((errno != 0) || (pn == buf)) {
        DEBUG(SSSDBG_OP_FAILURE, "Invalid status in p11_child response.\n");
        return EINVAL;
    }

    if (ret != 0) {
        if (ret == ERR_P11_PIN_LOCKED) {
            DEBUG(SSSDBG_OP_FAILURE, "PIN locked\n");
            return ret;
        } else {
            *_cert_list = NULL;
            return EOK; /* other errors are treated as "no cert found" */
        }
    }

    if ((p - buf + 1) == buf_len) {
        DEBUG(SSSDBG_TRACE_LIBS, "No certificate found.\n");
        *_cert_list = NULL;
        return EOK;
    }

    p++;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    do {
        cert_auth_info = talloc_zero(tmp_ctx, struct cert_auth_info);
        if (cert_auth_info == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_zero failed.\n");
            ret = ENOMEM;
            goto done;
        }

        pn = memchr(p, '\n', buf_len - (p - buf));
        if (pn == NULL) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Missing new-line in p11_child response.\n");
            ret = EINVAL;
            goto done;
        }
        if (pn == p) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Missing token name in p11_child response.\n");
            ret = EINVAL;
            goto done;
        }

        cert_auth_info->token_name = talloc_strndup(cert_auth_info, (char *)p,
                                                    (pn - p));
        if (cert_auth_info->token_name == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_strndup failed.\n");
            ret = ENOMEM;
            goto done;
        }
        DEBUG(SSSDBG_TRACE_ALL, "Found token name [%s].\n",
              cert_auth_info->token_name);

        p = ++pn;
        pn = memchr(p, '\n', buf_len - (p - buf));
        if (pn == NULL) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Missing new-line in p11_child response.\n");
            ret = EINVAL;
            goto done;
        }

        if (pn == p) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Missing module name in p11_child response.\n");
            ret = EINVAL;
            goto done;
        }

        cert_auth_info->module_name = talloc_strndup(cert_auth_info, (char *)p,
                                                     (pn - p));
        if (cert_auth_info->module_name == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_strndup failed.\n");
            ret = ENOMEM;
            goto done;
        }
        DEBUG(SSSDBG_TRACE_ALL, "Found module name [%s].\n",
              cert_auth_info->module_name);

        p = ++pn;
        pn = memchr(p, '\n', buf_len - (p - buf));
        if (pn == NULL) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Missing new-line in p11_child response.\n");
            ret = EINVAL;
            goto done;
        }

        if (pn == p) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Missing key id in p11_child response.\n");
            ret = EINVAL;
            goto done;
        }

        cert_auth_info->key_id = talloc_strndup(cert_auth_info, (char *)p,
                                                (pn - p));
        if (cert_auth_info->key_id == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_strndup failed.\n");
            ret = ENOMEM;
            goto done;
        }
        DEBUG(SSSDBG_TRACE_ALL, "Found key id [%s].\n", cert_auth_info->key_id);

        p = ++pn;
        pn = memchr(p, '\n', buf_len - (p - buf));
        if (pn == NULL) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Missing new-line in p11_child response.\n");
            ret = EINVAL;
            goto done;
        }

        if (pn == p) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Missing label in p11_child response.\n");
            ret = EINVAL;
            goto done;
        }

        cert_auth_info->label = talloc_strndup(cert_auth_info, (char *) p,
                                               (pn - p));
        if (cert_auth_info->label == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_strndup failed.\n");
            ret = ENOMEM;
            goto done;
        }
        DEBUG(SSSDBG_TRACE_ALL, "Found label [%s].\n", cert_auth_info->label);

        p = ++pn;
        pn = memchr(p, '\n', buf_len - (p - buf));
        if (pn == NULL) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Missing new-line in p11_child response.\n");
            ret = EINVAL;
            goto done;
        }

        if (pn == p) {
            DEBUG(SSSDBG_OP_FAILURE, "Missing cert in p11_child response.\n");
            ret = EINVAL;
            goto done;
        }

        cert_auth_info->cert = talloc_strndup(cert_auth_info, (char *)p,
                                              (pn - p));
        if (cert_auth_info->cert == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_strndup failed.\n");
            ret = ENOMEM;
            goto done;
        }
        DEBUG(SSSDBG_TRACE_ALL, "Found cert [%s].\n", cert_auth_info->cert);

        der = sss_base64_decode(tmp_ctx, cert_auth_info->cert, &der_size);
        if (der == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "sss_base64_decode failed.\n");
            ret = EIO;
            goto done;
        }

        ret = sss_certmap_match_cert(sss_certmap_ctx, der, der_size);
        if (ret == 0) {
            DLIST_ADD(cert_list, cert_auth_info);
        } else {
            DEBUG(SSSDBG_TRACE_LIBS,
                  "Cert [%s] does not match matching rules and is ignored.\n",
                  cert_auth_info->cert);
            talloc_free(cert_auth_info);
        }

        p = ++pn;
    } while ((pn - buf) < buf_len);

    ret = EOK;

done:
    if (ret == EOK) {
        DLIST_FOR_EACH(cert_auth_info, cert_list) {
            talloc_steal(mem_ctx, cert_auth_info);
        }

        *_cert_list = cert_list;
    }

    talloc_free(tmp_ctx);

    return ret;
}

struct pam_check_cert_state {
    int child_status;
    struct sss_child_ctx_old *child_ctx;
    struct tevent_timer *timeout_handler;
    struct tevent_context *ev;
    struct sss_certmap_ctx *sss_certmap_ctx;

    struct child_io_fds *io;

    struct cert_auth_info *cert_list;
    struct pam_data *pam_data;
};

static void p11_child_write_done(struct tevent_req *subreq);
static void p11_child_done(struct tevent_req *subreq);
static void p11_child_timeout(struct tevent_context *ev,
                              struct tevent_timer *te,
                              struct timeval tv, void *pvt);

struct tevent_req *pam_check_cert_send(TALLOC_CTX *mem_ctx,
                                       struct tevent_context *ev,
                                       const char *ca_db,
                                       time_t timeout,
                                       const char *verify_opts,
                                       struct sss_certmap_ctx *sss_certmap_ctx,
                                       const char *uri,
                                       struct pam_data *pd)
{
    errno_t ret;
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct pam_check_cert_state *state;
    pid_t child_pid;
    struct timeval tv;
    int pipefd_to_child[2] = PIPE_INIT;
    int pipefd_from_child[2] = PIPE_INIT;
    const char *extra_args[20] = { NULL };
    uint8_t *write_buf = NULL;
    size_t write_buf_len = 0;
    size_t arg_c;
    uint64_t chain_id;
    const char *module_name = NULL;
    const char *token_name = NULL;
    const char *key_id = NULL;
    const char *label = NULL;

    req = tevent_req_create(mem_ctx, &state, struct pam_check_cert_state);
    if (req == NULL) {
        return NULL;
    }

    if (ca_db == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing CA DB path.\n");
        ret = EINVAL;
        goto done;
    }

    if (sss_certmap_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing certificate matching context.\n");
        ret = EINVAL;
        goto done;
    }

    state->pam_data = pd;

    /* extra_args are added in revers order */
    arg_c = 0;

    chain_id = sss_chain_id_get();

    extra_args[arg_c++] = talloc_asprintf(mem_ctx, "%lu", chain_id);
    extra_args[arg_c++] = "--chain-id";

    if (uri != NULL) {
        DEBUG(SSSDBG_TRACE_ALL, "Adding PKCS#11 URI [%s].\n", uri);
        extra_args[arg_c++] = uri;
        extra_args[arg_c++] = "--uri";
    }

    if ((pd->cli_flags & PAM_CLI_FLAGS_REQUIRE_CERT_AUTH) && pd->priv == 1) {
        extra_args[arg_c++] = "--wait_for_card";
    }
    extra_args[arg_c++] = ca_db;
    extra_args[arg_c++] = "--ca_db";
    if (verify_opts != NULL) {
        extra_args[arg_c++] = verify_opts;
        extra_args[arg_c++] = "--verify";
    }

    if (sss_authtok_get_type(pd->authtok) == SSS_AUTHTOK_TYPE_SC_PIN
            || sss_authtok_get_type(pd->authtok) == SSS_AUTHTOK_TYPE_SC_KEYPAD) {
        ret = sss_authtok_get_sc(pd->authtok, NULL, NULL, &token_name, NULL,
                                 &module_name, NULL, &key_id, NULL,
                                 &label, NULL);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sss_authtok_get_sc failed.\n");
            goto done;
        }

        if (module_name != NULL && *module_name != '\0') {
            extra_args[arg_c++] = module_name;
            extra_args[arg_c++] = "--module_name";
        }
        if (token_name != NULL && *token_name != '\0') {
            extra_args[arg_c++] = token_name;
            extra_args[arg_c++] = "--token_name";
        }
        if (key_id != NULL && *key_id != '\0') {
            extra_args[arg_c++] = key_id;
            extra_args[arg_c++] = "--key_id";
        }
        if (label != NULL && *label != '\0') {
            extra_args[arg_c++] = label;
            extra_args[arg_c++] = "--label";
        }
    }

    if (pd->cmd == SSS_PAM_AUTHENTICATE) {
        extra_args[arg_c++] = "--auth";
        switch (sss_authtok_get_type(pd->authtok)) {
        case SSS_AUTHTOK_TYPE_SC_PIN:
            extra_args[arg_c++] = "--pin";
            break;
        case SSS_AUTHTOK_TYPE_SC_KEYPAD:
            extra_args[arg_c++] = "--keypad";
            break;
        default:
            DEBUG(SSSDBG_OP_FAILURE, "Unsupported authtok type.\n");
            ret = EINVAL;
            goto done;
        }

    } else if (pd->cmd == SSS_PAM_PREAUTH) {
        extra_args[arg_c++] = "--pre";
    } else {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unexpected PAM command [%d].\n", pd->cmd);
        ret = EINVAL;
        goto done;
    }

    state->ev = ev;
    state->sss_certmap_ctx = sss_certmap_ctx;
    state->child_status = EFAULT;
    state->io = talloc(state, struct child_io_fds);
    if (state->io == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc failed.\n");
        ret = ENOMEM;
        goto done;
    }
    state->io->write_to_child_fd = -1;
    state->io->read_from_child_fd = -1;
    talloc_set_destructor((void *) state->io, child_io_destructor);

    ret = pipe(pipefd_from_child);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "pipe failed [%d][%s].\n", ret, strerror(ret));
        goto done;
    }
    ret = pipe(pipefd_to_child);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "pipe failed [%d][%s].\n", ret, strerror(ret));
        goto done;
    }

    child_pid = fork();
    if (child_pid == 0) { /* child */
        exec_child_ex(state, pipefd_to_child, pipefd_from_child,
                      P11_CHILD_PATH, P11_CHILD_LOG_FILE, extra_args, false,
                      STDIN_FILENO, STDOUT_FILENO);

        /* We should never get here */
        DEBUG(SSSDBG_CRIT_FAILURE, "BUG: Could not exec p11 child\n");
    } else if (child_pid > 0) { /* parent */

        state->io->read_from_child_fd = pipefd_from_child[0];
        PIPE_FD_CLOSE(pipefd_from_child[1]);
        sss_fd_nonblocking(state->io->read_from_child_fd);

        state->io->write_to_child_fd = pipefd_to_child[1];
        PIPE_FD_CLOSE(pipefd_to_child[0]);
        sss_fd_nonblocking(state->io->write_to_child_fd);

        /* Set up SIGCHLD handler */
        ret = child_handler_setup(ev, child_pid, NULL, NULL, &state->child_ctx);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Could not set up child handlers [%d]: %s\n",
                ret, sss_strerror(ret));
            ret = ERR_P11_CHILD;
            goto done;
        }

        /* Set up timeout handler */
        tv = sss_tevent_timeval_current_ofs_time_t(timeout);
        state->timeout_handler = tevent_add_timer(ev, req, tv,
                                                  p11_child_timeout, req);
        if(state->timeout_handler == NULL) {
            ret = ERR_P11_CHILD;
            goto done;
        }

        if (pd->cmd == SSS_PAM_AUTHENTICATE) {
            ret = get_p11_child_write_buffer(state, pd, &write_buf,
                                             &write_buf_len);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "get_p11_child_write_buffer failed.\n");
                goto done;
            }
        }

        if (write_buf_len != 0) {
            subreq = write_pipe_send(state, ev, write_buf, write_buf_len,
                                     state->io->write_to_child_fd);
            if (subreq == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "write_pipe_send failed.\n");
                ret = ERR_P11_CHILD;
                goto done;
            }
            tevent_req_set_callback(subreq, p11_child_write_done, req);
        } else {
            subreq = read_pipe_send(state, ev, state->io->read_from_child_fd);
            if (subreq == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "read_pipe_send failed.\n");
                ret = ERR_P11_CHILD;
                goto done;
            }
            tevent_req_set_callback(subreq, p11_child_done, req);
        }

        /* Now either wait for the timeout to fire or the child
         * to finish
         */
    } else { /* error */
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE, "fork failed [%d][%s].\n",
                                   ret, sss_strerror(ret));
        goto done;
    }

    ret = EOK;

done:
    if (ret != EOK) {
        PIPE_CLOSE(pipefd_from_child);
        PIPE_CLOSE(pipefd_to_child);
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }
    return req;
}

static void p11_child_write_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct pam_check_cert_state *state = tevent_req_data(req,
                                                   struct pam_check_cert_state);
    int ret;

    ret = write_pipe_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    PIPE_FD_CLOSE(state->io->write_to_child_fd);

    subreq = read_pipe_send(state, state->ev, state->io->read_from_child_fd);
    if (subreq == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, p11_child_done, req);
}

static void p11_child_done(struct tevent_req *subreq)
{
    uint8_t *buf;
    ssize_t buf_len;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct pam_check_cert_state *state = tevent_req_data(req,
                                                   struct pam_check_cert_state);
    uint32_t user_info_type;
    int ret;

    talloc_zfree(state->timeout_handler);

    ret = read_pipe_recv(subreq, state, &buf, &buf_len);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    PIPE_FD_CLOSE(state->io->read_from_child_fd);

    ret = parse_p11_child_response(state, buf, buf_len, state->sss_certmap_ctx,
                                   &state->cert_list);
    if (ret != EOK) {
        if (ret == ERR_P11_PIN_LOCKED) {
            DEBUG(SSSDBG_MINOR_FAILURE, "PIN locked\n");
            user_info_type = SSS_PAM_USER_INFO_PIN_LOCKED;
            pam_add_response(state->pam_data, SSS_PAM_USER_INFO,
                             sizeof(uint32_t), (const uint8_t *) &user_info_type);
        } else {
            DEBUG(SSSDBG_OP_FAILURE, "parse_p11_child_response failed.\n");
        }
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
    return;
}

static void p11_child_timeout(struct tevent_context *ev,
                              struct tevent_timer *te,
                              struct timeval tv, void *pvt)
{
    struct tevent_req *req = talloc_get_type(pvt, struct tevent_req);
    struct pam_check_cert_state *state =
                              tevent_req_data(req, struct pam_check_cert_state);

    DEBUG(SSSDBG_CRIT_FAILURE,
          "Timeout reached for p11_child, "
          "consider increasing p11_child_timeout.\n");
    child_handler_destroy(state->child_ctx);
    state->child_ctx = NULL;
    state->child_status = ETIMEDOUT;
    tevent_req_error(req, ERR_P11_CHILD_TIMEOUT);
}

errno_t pam_check_cert_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
                            struct cert_auth_info **cert_list)
{
    struct cert_auth_info *tmp_cert_auth_info;
    struct pam_check_cert_state *state =
                              tevent_req_data(req, struct pam_check_cert_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (cert_list != NULL) {
        DLIST_FOR_EACH(tmp_cert_auth_info, state->cert_list) {
            talloc_steal(mem_ctx, tmp_cert_auth_info);
        }

        *cert_list = state->cert_list;
    }

    return EOK;
}

static char *get_cert_prompt(TALLOC_CTX *mem_ctx,
                             struct cert_auth_info *cert_info)
{
    int ret;
    struct sss_certmap_ctx *ctx = NULL;
    unsigned char *der = NULL;
    size_t der_size;
    char *prompt = NULL;
    char *filter = NULL;
    char **domains = NULL;

    ret = sss_certmap_init(mem_ctx, NULL, NULL, &ctx);
    if (ret != 0) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_certmap_init failed.\n");
        return NULL;
    }

    ret = sss_certmap_add_rule(ctx, 10, "KRB5:<ISSUER>.*",
                               "LDAP:{subject_dn!nss}", NULL);
    if (ret != 0) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_certmap_add_rule failed.\n");
        goto done;
    }

    der = sss_base64_decode(mem_ctx, sss_cai_get_cert(cert_info), &der_size);
    if (der == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_base64_decode failed.\n");
        goto done;
    }

    ret = sss_certmap_expand_mapping_rule(ctx, der, der_size,
                                          &filter, &domains);
    if (ret != 0) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_certmap_expand_mapping_rule failed.\n");
        goto done;
    }

    prompt = talloc_asprintf(mem_ctx, "%s\n%s", sss_cai_get_label(cert_info),
                                                filter);
    if (prompt == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
    }

done:
    sss_certmap_free_filter_and_domains(filter, domains);
    sss_certmap_free_ctx(ctx);
    talloc_free(der);

    return prompt;
}

static errno_t pack_cert_data(TALLOC_CTX *mem_ctx, const char *sysdb_username,
                              struct cert_auth_info *cert_info,
                              const char *nss_name,
                              uint8_t **_msg, size_t *_msg_len)
{
    uint8_t *msg = NULL;
    size_t msg_len;
    const char *token_name;
    const char *module_name;
    const char *key_id;
    const char *label;
    char *prompt;
    size_t user_len;
    size_t token_len;
    size_t module_len;
    size_t key_id_len;
    size_t label_len;
    size_t prompt_len;
    size_t nss_name_len;
    const char *username = "";
    const char *nss_username = "";

    if (sysdb_username != NULL) {
        username = sysdb_username;
    }

    if (nss_name != NULL) {
        nss_username = nss_name;
    }

    prompt = get_cert_prompt(mem_ctx, cert_info);
    if (prompt == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "get_cert_prompt failed.\n");
        return EIO;
    }

    token_name = sss_cai_get_token_name(cert_info);
    module_name = sss_cai_get_module_name(cert_info);
    key_id = sss_cai_get_key_id(cert_info);
    label = sss_cai_get_label(cert_info);

    user_len = strlen(username) + 1;
    token_len = strlen(token_name) + 1;
    module_len = strlen(module_name) + 1;
    key_id_len = strlen(key_id) + 1;
    label_len = strlen(label) + 1;
    prompt_len = strlen(prompt) + 1;
    nss_name_len = strlen(nss_username) +1;

    msg_len = user_len + token_len + module_len + key_id_len + label_len
                       + prompt_len + nss_name_len;

    msg = talloc_zero_size(mem_ctx, msg_len);
    if (msg == NULL) {
        talloc_free(prompt);
        DEBUG(SSSDBG_OP_FAILURE, "talloc_zero_size failed.\n");
        return ENOMEM;
    }

    memcpy(msg, username, user_len);
    memcpy(msg + user_len, token_name, token_len);
    memcpy(msg + user_len + token_len, module_name, module_len);
    memcpy(msg + user_len + token_len + module_len, key_id, key_id_len);
    memcpy(msg + user_len + token_len + module_len + key_id_len,
           label, label_len);
    memcpy(msg + user_len + token_len + module_len + key_id_len + label_len,
           prompt, prompt_len);
    memcpy(msg + user_len + token_len + module_len + key_id_len + label_len
               + prompt_len,
           nss_username, nss_name_len);
    talloc_free(prompt);

    if (_msg != NULL) {
        *_msg = msg;
    }

    if (_msg_len != NULL) {
        *_msg_len = msg_len;
    }

    return EOK;
}

/* The PKCS11_LOGIN_TOKEN_NAME environment variable is e.g. used by the Gnome
 * Settings Daemon to determine the name of the token used for login but it
 * should be only set if SSSD is called by gdm-smartcard. Otherwise desktop
 * components might assume that gdm-smartcard PAM stack is configured
 * correctly which might not be the case e.g. if Smartcard authentication was
 * used when running gdm-password. */
#define PKCS11_LOGIN_TOKEN_ENV_NAME "PKCS11_LOGIN_TOKEN_NAME"

errno_t add_pam_cert_response(struct pam_data *pd, struct sss_domain_info *dom,
                              const char *sysdb_username,
                              struct cert_auth_info *cert_info,
                              enum response_type type)
{
    uint8_t *msg = NULL;
    char *env = NULL;
    size_t msg_len;
    int ret;
    char *short_name = NULL;
    char *domain_name = NULL;
    const char *cert_info_name = sysdb_username;
    struct sss_domain_info *user_dom;
    char *nss_name = NULL;


    if (type != SSS_PAM_CERT_INFO && type != SSS_PAM_CERT_INFO_WITH_HINT) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid response type [%d].\n", type);
        return EINVAL;
    }

    if ((type == SSS_PAM_CERT_INFO && sysdb_username == NULL)
            || cert_info == NULL
            || sss_cai_get_token_name(cert_info) == NULL
            || sss_cai_get_module_name(cert_info) == NULL
            || sss_cai_get_key_id(cert_info) == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing mandatory user or slot name.\n");
        return EINVAL;
    }

    /* sysdb_username is a fully-qualified name which is used by pam_sss when
     * prompting the user for the PIN and as login name if it wasn't set by
     * the PAM caller but has to be determined based on the inserted
     * Smartcard. If this type of name is irritating at the PIN prompt or the
     * re_expression config option was set in a way that user@domain cannot be
     * handled anymore some more logic has to be added here. But for the time
     * being I think using sysdb_username is fine.
     */

    if (sysdb_username != NULL) {
        ret = sss_parse_internal_fqname(pd, sysdb_username,
                                        &short_name, &domain_name);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to parse name '%s' [%d]: %s, "
                                       "using full name.\n",
                                        sysdb_username, ret, sss_strerror(ret));
        } else {
            if (domain_name != NULL) {
                user_dom = find_domain_by_name(dom, domain_name, false);

                if (user_dom != NULL) {
                    ret = sss_output_fqname(short_name, user_dom,
                                            sysdb_username, false, &nss_name);
                    if (ret != EOK) {
                        nss_name = NULL;
                    }
                }
            }

        }
    }

    ret = pack_cert_data(pd, cert_info_name, cert_info,
                         nss_name != NULL ? nss_name : sysdb_username,
                         &msg, &msg_len);
    talloc_free(short_name);
    talloc_free(domain_name);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "pack_cert_data failed.\n");
        return ret;
    }

    ret = pam_add_response(pd, type, msg_len, msg);
    talloc_free(msg);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "pam_add_response failed to add certificate info.\n");
        return ret;
    }

    if (strcmp(pd->service, "gdm-smartcard") == 0) {
        env = talloc_asprintf(pd, "%s=%s", PKCS11_LOGIN_TOKEN_ENV_NAME,
                              sss_cai_get_token_name(cert_info));
        if (env == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf failed.\n");
            return ENOMEM;
        }

        ret = pam_add_response(pd, SSS_PAM_ENV_ITEM, strlen(env) + 1,
                               (uint8_t *)env);
        talloc_free(env);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "pam_add_response failed to add environment variable.\n");
            return ret;
        }
    }

    return ret;
}
