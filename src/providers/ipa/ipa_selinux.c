/*
    SSSD

    IPA Backend Module -- selinux loading

    Authors:
        Jan Zeleny <jzeleny@redhat.com>

    Copyright (C) 2012 Red Hat

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

#include "db/sysdb_selinux.h"
#include "util/child_common.h"
#include "util/sss_selinux.h"
#include "providers/ldap/sdap_async.h"
#include "providers/ipa/ipa_common.h"
#include "providers/ipa/ipa_config.h"
#include "providers/ipa/ipa_selinux.h"
#include "providers/ipa/ipa_hosts.h"
#include "providers/ipa/ipa_hbac_rules.h"
#include "providers/ipa/ipa_hbac_private.h"
#include "providers/ipa/ipa_access.h"
#include "providers/ipa/ipa_selinux_maps.h"
#include "providers/ipa/ipa_subdomains.h"

#if defined HAVE_SELINUX && defined HAVE_SELINUX_LOGIN_DIR

#ifndef SELINUX_CHILD_DIR
#ifndef SSSD_LIBEXEC_PATH
#error "SSSD_LIBEXEC_PATH not defined"
#endif  /* SSSD_LIBEXEC_PATH */

#define SELINUX_CHILD_DIR SSSD_LIBEXEC_PATH
#endif /* SELINUX_CHILD_DIR */

#define SELINUX_CHILD SELINUX_CHILD_DIR"/selinux_child"
#define SELINUX_CHILD_LOG_FILE "selinux_child"

#include <selinux/selinux.h>

/* fd used by the selinux_child process for logging */
int selinux_child_debug_fd = -1;

static struct tevent_req *
ipa_get_selinux_send(TALLOC_CTX *mem_ctx,
                     struct be_ctx *be_ctx,
                     struct sysdb_attrs *user,
                     struct sysdb_attrs *host,
                     struct ipa_selinux_ctx *selinux_ctx);
static errno_t ipa_get_selinux_recv(struct tevent_req *req,
                                    TALLOC_CTX *mem_ctx,
                                    size_t *count,
                                    struct sysdb_attrs ***maps,
                                    size_t *hbac_count,
                                    struct sysdb_attrs ***hbac_rules,
                                    char **default_user,
                                    char **map_order);

static struct ipa_selinux_op_ctx *
ipa_selinux_create_op_ctx(TALLOC_CTX *mem_ctx, struct sysdb_ctx *sysdb,
                          struct sss_domain_info *ipa_domain,
                          struct sss_domain_info *user_domain,
                          struct be_req *be_req, const char *username,
                          const char *hostname,
                          struct ipa_selinux_ctx *selinux_ctx);
static void ipa_selinux_handler_done(struct tevent_req *subreq);

static void ipa_get_selinux_connect_done(struct tevent_req *subreq);
static void ipa_get_selinux_hosts_done(struct tevent_req *subreq);
static void ipa_get_config_step(struct tevent_req *req);
static void ipa_get_selinux_config_done(struct tevent_req *subreq);
static void ipa_get_selinux_maps_done(struct tevent_req *subreq);
static void ipa_get_selinux_hbac_done(struct tevent_req *subreq);
static errno_t ipa_selinux_process_maps(TALLOC_CTX *mem_ctx,
                                        struct sysdb_attrs *user,
                                        struct sysdb_attrs *host,
                                        struct sysdb_attrs **selinux_maps,
                                        size_t selinux_map_count,
                                        struct sysdb_attrs **hbac_rules,
                                        size_t hbac_rule_count,
                                        struct sysdb_attrs ***usermaps);

struct ipa_selinux_op_ctx {
    struct be_req *be_req;
    struct sss_domain_info *user_domain;
    struct sss_domain_info *ipa_domain;
    struct ipa_selinux_ctx *selinux_ctx;

    struct sysdb_attrs *user;
    struct sysdb_attrs *host;
};

void ipa_selinux_handler(struct be_req *be_req)
{
    struct be_ctx *be_ctx = be_req_get_be_ctx(be_req);
    struct ipa_selinux_ctx *selinux_ctx;
    struct ipa_selinux_op_ctx *op_ctx;
    struct tevent_req *req;
    struct pam_data *pd;
    const char *hostname;
    struct sss_domain_info *user_domain;
    struct be_ctx *subdom_be_ctx;

    pd = talloc_get_type(be_req_get_data(be_req), struct pam_data);

    selinux_ctx = talloc_get_type(be_ctx->bet_info[BET_SELINUX].pvt_bet_data,
                                  struct ipa_selinux_ctx);

    hostname = dp_opt_get_string(selinux_ctx->id_ctx->ipa_options->basic,
                                 IPA_HOSTNAME);
    if (!hostname) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot determine this machine's host name\n");
        goto fail;
    }

    if (strcasecmp(pd->domain, be_ctx->domain->name) != 0) {
        subdom_be_ctx = ipa_get_subdomains_be_ctx(be_ctx);
        if (subdom_be_ctx == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Subdomains are not configured, " \
                                      "cannot lookup domain [%s].\n",
                                       pd->domain);
            goto fail;
        } else {
            user_domain = find_domain_by_name(subdom_be_ctx->domain,
                                              pd->domain, true);
            if (user_domain == NULL) {
                DEBUG(SSSDBG_MINOR_FAILURE, "No domain entry found " \
                                             "for [%s].\n", pd->domain);
                goto fail;
            }
        }
    } else {
        user_domain = be_ctx->domain;
    }

    op_ctx = ipa_selinux_create_op_ctx(be_req, user_domain->sysdb,
                                       be_ctx->domain,
                                       user_domain,
                                       be_req, pd->user, hostname,
                                       selinux_ctx);
    if (op_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot create op context\n");
        goto fail;
    }

    req = ipa_get_selinux_send(be_req, be_ctx,
                               op_ctx->user, op_ctx->host, selinux_ctx);
    if (req == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot initiate the search\n");
        goto fail;
    }

    tevent_req_set_callback(req, ipa_selinux_handler_done, op_ctx);
    return;

fail:
    be_req_terminate(be_req, DP_ERR_FATAL, PAM_SYSTEM_ERR, NULL);
}

static errno_t
ipa_save_user_maps(struct sysdb_ctx *sysdb,
                   struct sss_domain_info *domain,
                   size_t map_count,
                   struct sysdb_attrs **maps)
{
    errno_t ret;
    errno_t sret;
    bool in_transaction = false;
    int i;

    ret = sysdb_transaction_start(sysdb);
    if (ret) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to start transaction\n");
        goto done;
    }
    in_transaction = true;

    for (i = 0; i < map_count; i++) {
        ret = sysdb_store_selinux_usermap(domain, maps[i]);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to store user map %d. "
                                      "Ignoring.\n", i);
        } else {
            DEBUG(SSSDBG_TRACE_FUNC, "User map %d processed.\n", i);
        }
    }

    ret = sysdb_transaction_commit(sysdb);
    if (ret) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to commit transaction!\n");
        goto done;
    }
    in_transaction = false;
    ret = EOK;

done:
    if (in_transaction) {
        sret = sysdb_transaction_cancel(sysdb);
        if (sret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Failed to cancel transaction\n");
        }
    }
    return ret;
}

static struct ipa_selinux_op_ctx *
ipa_selinux_create_op_ctx(TALLOC_CTX *mem_ctx, struct sysdb_ctx *sysdb,
                          struct sss_domain_info *ipa_domain,
                          struct sss_domain_info *user_domain,
                          struct be_req *be_req, const char *username,
                          const char *hostname,
                          struct ipa_selinux_ctx *selinux_ctx)
{
    struct ipa_selinux_op_ctx *op_ctx;
    struct ldb_dn *host_dn;
    const char *attrs[] = { SYSDB_ORIG_DN,
                            SYSDB_ORIG_MEMBEROF,
                            NULL };
    size_t count;
    struct ldb_message **msgs;
    struct sysdb_attrs **hosts;
    errno_t ret;

    op_ctx = talloc_zero(mem_ctx, struct ipa_selinux_op_ctx);
    if (op_ctx == NULL) {
        return NULL;
    }
    op_ctx->be_req = be_req;
    op_ctx->ipa_domain = ipa_domain;
    op_ctx->user_domain = user_domain;
    op_ctx->selinux_ctx = selinux_ctx;

    ret = sss_selinux_extract_user(op_ctx, user_domain, username, &op_ctx->user);
    if (ret != EOK) {
        goto fail;
    }

    host_dn = sysdb_custom_dn(op_ctx, ipa_domain, hostname, HBAC_HOSTS_SUBDIR);
    if (host_dn == NULL) {
        goto fail;
    }

    /* Look up the host to get its originalMemberOf entries */
    ret = sysdb_search_entry(op_ctx, sysdb, host_dn,
                             LDB_SCOPE_BASE, NULL,
                             attrs, &count, &msgs);
    if (ret == ENOENT || count == 0) {
        op_ctx->host = NULL;
        return op_ctx;
    } else if (ret != EOK) {
        goto fail;
    } else if (count > 1) {
        DEBUG(SSSDBG_OP_FAILURE, "More than one result for a BASE search!\n");
        goto fail;
    }

    ret = sysdb_msg2attrs(op_ctx, count, msgs, &hosts);
    talloc_free(msgs);
    if (ret != EOK) {
        goto fail;
    }

    op_ctx->host = hosts[0];
    return op_ctx;

fail:
    talloc_free(op_ctx);
    return NULL;
}

struct map_order_ctx {
    char *order;
    char **order_array;
    size_t order_count;
};

static errno_t init_map_order_ctx(TALLOC_CTX *mem_ctx, const char *map_order,
                                  struct map_order_ctx **_mo_ctx);

struct selinux_child_input {
    const char *seuser;
    const char *mls_range;
    const char *username;
};

static errno_t choose_best_seuser(TALLOC_CTX *mem_ctx,
                                  struct sysdb_attrs **usermaps,
                                  struct pam_data *pd,
                                  struct sss_domain_info *user_domain,
                                  struct map_order_ctx *mo_ctx,
                                  const char *default_user,
                                  struct selinux_child_input **_sci);

static struct tevent_req *selinux_child_send(TALLOC_CTX *mem_ctx,
                                             struct tevent_context *ev,
                                             struct selinux_child_input *sci);
static errno_t selinux_child_recv(struct tevent_req *req);

static void ipa_selinux_child_done(struct tevent_req *child_req);

static void ipa_selinux_handler_done(struct tevent_req *req)
{
    struct ipa_selinux_op_ctx *op_ctx = tevent_req_callback_data(req, struct ipa_selinux_op_ctx);
    struct be_req *breq = op_ctx->be_req;
    struct be_ctx *be_ctx = be_req_get_be_ctx(breq);
    struct sysdb_ctx *sysdb = op_ctx->ipa_domain->sysdb;
    errno_t ret, sret;
    size_t map_count = 0;
    struct sysdb_attrs **maps = NULL;
    bool in_transaction = false;
    char *default_user = NULL;
    struct pam_data *pd =
                    talloc_get_type(be_req_get_data(breq), struct pam_data);
    char *map_order = NULL;
    size_t hbac_count = 0;
    struct sysdb_attrs **hbac_rules = 0;
    struct sysdb_attrs **best_match_maps;
    struct map_order_ctx *map_order_ctx;
    struct selinux_child_input *sci = NULL;
    struct tevent_req *child_req;

    ret = ipa_get_selinux_recv(req, breq, &map_count, &maps,
                               &hbac_count, &hbac_rules,
                               &default_user, &map_order);
    if (ret != EOK) {
        goto fail;
    }

    ret = sysdb_transaction_start(sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to start transaction\n");
        goto fail;
    }
    in_transaction = true;

    ret = sysdb_delete_usermaps(op_ctx->ipa_domain);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Cannot delete existing maps from sysdb\n");
        goto fail;
    }

    ret = sysdb_store_selinux_config(op_ctx->ipa_domain,
                                     default_user, map_order);
    if (ret != EOK) {
        goto fail;
    }

    if (map_count > 0) {
        ret = ipa_save_user_maps(sysdb, op_ctx->ipa_domain, map_count, maps);
        if (ret != EOK) {
            goto fail;
        }
    }

    ret = sysdb_transaction_commit(sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Could not commit transaction\n");
        goto fail;
    }
    in_transaction = false;

    /* Process the maps and return list of best matches (maps with
     * highest priority). The input maps are also parent memory
     * context for the output list of best matches. The best match
     * maps should never be freed explicitly but always through
     * their parent (or any indirect parent) */
    ret = ipa_selinux_process_maps(maps, op_ctx->user, op_ctx->host,
                                   maps, map_count,
                                   hbac_rules, hbac_count, &best_match_maps);
    if (ret != EOK) {
        goto fail;
    }

    ret = init_map_order_ctx(op_ctx, map_order, &map_order_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to create ordered SELinux users array.\n");
        goto fail;
    }

    ret = choose_best_seuser(breq,
                             best_match_maps, pd, op_ctx->user_domain,
                             map_order_ctx, default_user, &sci);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to evaluate ordered SELinux users array.\n");
        goto fail;
    }

    /* Update the SELinux context in a privileged child as the back end is
     * running unprivileged
     */
    child_req = selinux_child_send(breq, be_ctx->ev, sci);
    if (child_req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "selinux_child_send() failed\n");
        ret = ENOMEM;
        goto fail;
    }
    tevent_req_set_callback(child_req, ipa_selinux_child_done, op_ctx);
    return;

fail:
    if (in_transaction) {
        sret = sysdb_transaction_cancel(sysdb);
        if (sret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Could not cancel transaction\n");
        }
    }
    if (ret == EAGAIN) {
        be_req_terminate(breq, DP_ERR_OFFLINE, EAGAIN, "Offline");
    } else {
        be_req_terminate(breq, DP_ERR_FATAL, ret, NULL);
    }
}

static void ipa_selinux_child_done(struct tevent_req *child_req)
{
    errno_t ret;
    struct ipa_selinux_op_ctx *op_ctx;
    struct be_req *breq;
    struct pam_data *pd;
    struct be_ctx *be_ctx;

    op_ctx = tevent_req_callback_data(child_req, struct ipa_selinux_op_ctx);
    breq = op_ctx->be_req;
    pd = talloc_get_type(be_req_get_data(breq), struct pam_data);
    be_ctx = be_req_get_be_ctx(breq);

    ret = selinux_child_recv(child_req);
    talloc_free(child_req);
    if (ret != EOK) {
        be_req_terminate(breq, DP_ERR_FATAL, ret, NULL);
        return;
    }

    /* If we got here in online mode, set last_update to current time */
    if (!be_is_offline(be_ctx)) {
        op_ctx->selinux_ctx->last_update = time(NULL);
    }

    pd->pam_status = PAM_SUCCESS;
    be_req_terminate(breq, DP_ERR_OK, EOK, "Success");
}

static errno_t
ipa_selinux_process_seealso_maps(struct sysdb_attrs *user,
                                 struct sysdb_attrs *host,
                                 struct sysdb_attrs **seealso_rules,
                                 size_t seealso_rules_count,
                                 struct sysdb_attrs **hbac_rules,
                                 size_t hbac_rule_count,
                                 uint32_t top_priority,
                                 struct sysdb_attrs **usermaps,
                                 size_t best_match_maps_cnt);
static errno_t
ipa_selinux_process_maps(TALLOC_CTX *mem_ctx,
                         struct sysdb_attrs *user,
                         struct sysdb_attrs *host,
                         struct sysdb_attrs **selinux_maps,
                         size_t selinux_map_count,
                         struct sysdb_attrs **hbac_rules,
                         size_t hbac_rule_count,
                         struct sysdb_attrs ***_usermaps)
{
    TALLOC_CTX *tmp_ctx;
    int i;
    errno_t ret;
    uint32_t priority = 0;
    uint32_t top_priority = 0;
    struct sysdb_attrs **seealso_rules;
    size_t num_seealso_rules = 0;
    const char *seealso_str;
    struct sysdb_attrs **usermaps;
    size_t best_match_maps_cnt = 0;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        return ENOMEM;
    }

    seealso_rules = talloc_zero_array(tmp_ctx, struct sysdb_attrs *,
                                      selinux_map_count + 1);
    if (seealso_rules == NULL) {
        ret = ENOMEM;
        goto done;
    }

    usermaps = talloc_zero_array(tmp_ctx, struct sysdb_attrs *, selinux_map_count + 1);
    if (usermaps == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (i = 0; i < selinux_map_count; i++) {
        if (sss_selinux_match(selinux_maps[i], user, host, &priority)) {
            if (priority < top_priority) {
                /* This rule has lower priority than what we already have,
                 * skip it. */
                continue;
            } else if (priority > top_priority) {
                /* This rule has higher priority, drop what we already have */
                while (best_match_maps_cnt > 0) {
                    best_match_maps_cnt--;
                    usermaps[best_match_maps_cnt] = NULL;
                }
                top_priority = priority;
            }

            usermaps[best_match_maps_cnt] = selinux_maps[i];
            best_match_maps_cnt++;

            continue;
        }

        /* SELinux map did not matched -> check sealso attribute for
         * possible HBAC match */
        ret = sysdb_attrs_get_string(selinux_maps[i],
                                     SYSDB_SELINUX_SEEALSO, &seealso_str);
        if (ret == ENOENT) {
            continue;
        } else if (ret != EOK) {
            goto done;
        }

        seealso_rules[num_seealso_rules] = selinux_maps[i];
        num_seealso_rules++;
    }

    ret = ipa_selinux_process_seealso_maps(user, host,
                                           seealso_rules, num_seealso_rules,
                                           hbac_rules, hbac_rule_count,
                                           top_priority, usermaps, best_match_maps_cnt);
    if (ret != EOK) {
        goto done;
    }

    *_usermaps = talloc_steal(mem_ctx, usermaps);

    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t
ipa_selinux_process_seealso_maps(struct sysdb_attrs *user,
                                 struct sysdb_attrs *host,
                                 struct sysdb_attrs **seealso_rules,
                                 size_t seealso_rules_count,
                                 struct sysdb_attrs **hbac_rules,
                                 size_t hbac_rule_count,
                                 uint32_t top_priority,
                                 struct sysdb_attrs **usermaps,
                                 size_t best_match_maps_cnt)
{
    int i, j;
    errno_t ret;
    struct ldb_message_element *el;
    struct sysdb_attrs *usermap;
    const char *seealso_dn;
    const char *hbac_dn;
    uint32_t priority;

    for (i = 0; i < hbac_rule_count; i++) {
        ret = sysdb_attrs_get_string(hbac_rules[i], SYSDB_ORIG_DN, &hbac_dn);
        if (ret != EOK) {
            return ret;
        }

        /* We need to do this translation for further processing. We have to
         * do it manually because no map was used to retrieve HBAC rules.
         */
        ret = sysdb_attrs_get_el(hbac_rules[i], IPA_MEMBER_HOST, &el);
        if (ret != EOK) return ret;
        el->name = SYSDB_ORIG_MEMBER_HOST;

        ret = sysdb_attrs_get_el(hbac_rules[i], IPA_MEMBER_USER, &el);
        if (ret != EOK) return ret;
        el->name = SYSDB_ORIG_MEMBER_USER;

        DEBUG(SSSDBG_TRACE_ALL,
              "Matching HBAC rule %s with SELinux mappings\n", hbac_dn);

        if (!sss_selinux_match(hbac_rules[i], user, host, &priority)) {
            DEBUG(SSSDBG_TRACE_ALL, "Rule did not match\n");
            continue;
        }

        /* HBAC rule matched, find if it is in the "possible" list */
        for (j = 0; j < seealso_rules_count; j++) {
            usermap = seealso_rules[j];
            if (usermap == NULL) {
                continue;
            }

            ret = sysdb_attrs_get_string(usermap, SYSDB_SELINUX_SEEALSO, &seealso_dn);
            if (ret != EOK) {
                return ret;
            }

            if (strcasecmp(hbac_dn, seealso_dn) == 0) {
                DEBUG(SSSDBG_TRACE_FUNC, "HBAC rule [%s] matched, copying its"
                                          "attributes to SELinux user map [%s]\n",
                                          hbac_dn, seealso_dn);

                /* Selinux maps priority evaluation removed --DELETE this comment before pushing*/
                if (priority < top_priority) {
                    /* This rule has lower priority than what we already have,
                     * skip it. */
                    continue;
                } else if (priority > top_priority) {
                    /* This rule has higher priority, drop what we already have */
                    while (best_match_maps_cnt > 0) {
                        best_match_maps_cnt--;
                        usermaps[best_match_maps_cnt] = NULL;
                    }
                    top_priority = priority;
                }

                usermaps[best_match_maps_cnt] = usermap;
                best_match_maps_cnt++;

                ret = sysdb_attrs_copy_values(hbac_rules[i], usermap, SYSDB_ORIG_MEMBER_USER);
                if (ret != EOK) {
                    return ret;
                }

                ret = sysdb_attrs_copy_values(hbac_rules[i], usermap, SYSDB_USER_CATEGORY);
                if (ret != EOK) {
                    return ret;
                }

                /* Speed up the next iteration */
                seealso_rules[j] = NULL;
            }
        }
    }

    return EOK;
}

static errno_t init_map_order_ctx(TALLOC_CTX *mem_ctx, const char *map_order,
                                  struct map_order_ctx **_mo_ctx)
{
    TALLOC_CTX *tmp_ctx;
    errno_t ret;
    int i;
    int len;
    struct map_order_ctx *mo_ctx;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    mo_ctx = talloc(tmp_ctx, struct map_order_ctx);
    if (mo_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* The "order" string contains one or more SELinux user records
     * separated by $. Now we need to create an array of string from
     * this one string. First find out how many elements in the array
     * will be. This way only one alloc will be necessary for the array
     */
    mo_ctx->order_count = 1;
    len = strlen(map_order);
    for (i = 0; i < len; i++) {
        if (map_order[i] == '$') mo_ctx->order_count++;
    }

    mo_ctx->order_array = talloc_array(mo_ctx, char *, mo_ctx->order_count);
    if (mo_ctx->order_array == NULL) {
        ret = ENOMEM;
        goto done;
    }

    mo_ctx->order = talloc_strdup(mo_ctx, map_order);
    if (mo_ctx->order == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* Now fill the array with pointers to the original string. Also
     * use binary zeros to make multiple string out of the one.
     */
    mo_ctx->order_array[0] = mo_ctx->order;
    mo_ctx->order_count = 1;
    for (i = 0; i < len; i++) {
        if (mo_ctx->order[i] == '$') {
            mo_ctx->order[i] = '\0';
            mo_ctx->order_array[mo_ctx->order_count] = &mo_ctx->order[i+1];
            mo_ctx->order_count++;
        }
    }

    *_mo_ctx = talloc_steal(mem_ctx, mo_ctx);
    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t selinux_child_setup(TALLOC_CTX *mem_ctx,
                                   const char *orig_name,
                                   struct sss_domain_info *dom,
                                   const char *seuser_mls_string,
                                   struct selinux_child_input **_sci);

/* Choose best selinux user based on given order and write
 * the user to selinux login file. */
static errno_t choose_best_seuser(TALLOC_CTX *mem_ctx,
                                  struct sysdb_attrs **usermaps,
                                  struct pam_data *pd,
                                  struct sss_domain_info *user_domain,
                                  struct map_order_ctx *mo_ctx,
                                  const char *default_user,
                                  struct selinux_child_input **_sci)
{
    TALLOC_CTX *tmp_ctx;
    char *seuser_mls_str = NULL;
    const char *tmp_str;
    errno_t ret;
    int i, j;
    struct selinux_child_input *sci;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed\n");
        return ENOMEM;
    }

    /* If no maps match, we'll use the default SELinux user from the
     * config */
    seuser_mls_str = talloc_strdup(tmp_ctx, default_user ? default_user : "");
    if (seuser_mls_str == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* Iterate through the order array and try to find SELinux users
     * in fetched maps. The order array contains all SELinux users
     * allowed in the domain in the same order they should appear
     * in the SELinux config file. If any user from the order array
     * is not in fetched user maps, it means it should not be allowed
     * for the user who is just logging in.
     *
     * Right now we have empty content of the SELinux config file,
     * we shall add only those SELinux users that are present both in
     * the order array and user maps applicable to the user who is
     * logging in.
     */
    for (i = 0; i < mo_ctx->order_count; i++) {
        for (j = 0; usermaps[j] != NULL; j++) {
            tmp_str = sss_selinux_map_get_seuser(usermaps[j]);

            if (tmp_str && !strcasecmp(tmp_str, mo_ctx->order_array[i])) {
                /* If seuser_mls_str contained something, overwrite it.
                 * This record has higher priority.
                 */
                talloc_zfree(seuser_mls_str);
                seuser_mls_str = talloc_strdup(tmp_ctx, tmp_str);
                if (seuser_mls_str == NULL) {
                    ret = ENOMEM;
                    goto done;
                }
                break;
            }
        }
    }

    ret = selinux_child_setup(tmp_ctx, pd->user, user_domain, seuser_mls_str, &sci);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot set up child input buffer\n");
        goto done;
    }

    *_sci = talloc_steal(mem_ctx, sci);
    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t
selinux_child_setup(TALLOC_CTX *mem_ctx,
                    const char *orig_name,
                    struct sss_domain_info *dom,
                    const char *seuser_mls_string,
                    struct selinux_child_input **_sci)
{
    errno_t ret;
    char *seuser;
    const char *mls_range;
    char *ptr;
    char *username;
    char *username_final;
    char *domain_name = NULL;
    TALLOC_CTX *tmp_ctx;
    struct selinux_child_input *sci;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    /* Split seuser and mls_range */
    seuser = talloc_strdup(tmp_ctx, seuser_mls_string);
    if (seuser == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ptr = seuser;
    while (*ptr != ':' && *ptr != '\0') {
        ptr++;
    }
    if (*ptr == '\0') {
        /* No mls_range specified */
        mls_range = "";
    } else {
        *ptr = '\0'; /* split */
        mls_range = ptr + 1;
    }

    /* pam_selinux needs the username in the same format getpwnam() would
     * return it
     */
    username = sss_get_cased_name(tmp_ctx, orig_name, dom->case_preserve);
    if (username == NULL) {
        ret = ENOMEM;
        goto done;
    }

    if (dom->fqnames) {
        ret = sss_parse_name(tmp_ctx, dom->names, username, &domain_name,
                             NULL);
        if (ret == EOK && domain_name != NULL) {
            /* username is already a fully qualified name */
            username_final = username;
        } else if ((ret == EOK && domain_name == NULL)
                   || ret == ERR_REGEX_NOMATCH) {
            username_final = talloc_asprintf(tmp_ctx, dom->names->fq_fmt,
                                             username, dom->name);
            if (username_final == NULL) {
                ret = ENOMEM;
                goto done;
            }
        } else {
            DEBUG(SSSDBG_OP_FAILURE,
                  "sss_parse_name failed: [%d] %s\n", ret, sss_strerror(ret));
            goto done;
        }
    } else {
        username_final = username;
    }

    sci = talloc(tmp_ctx, struct selinux_child_input);
    if (sci == NULL) {
        ret = ENOMEM;
        goto done;
    }

    sci->seuser = talloc_strdup(sci, seuser);
    sci->mls_range = talloc_strdup(sci, mls_range);
    sci->username = talloc_strdup(sci, username_final);
    if (sci->seuser == NULL || sci->mls_range == NULL
        || sci->username == NULL) {
        ret = ENOMEM;
        goto done;
    }

    *_sci = talloc_steal(mem_ctx, sci);
    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}

struct selinux_child_state {
    struct selinux_child_input *sci;
    struct tevent_context *ev;
    struct io_buffer *buf;
    struct child_io_fds *io;
};

static errno_t selinux_child_init(void);
static errno_t selinux_child_create_buffer(struct selinux_child_state *state);
static errno_t selinux_fork_child(struct selinux_child_state *state);
static void selinux_child_step(struct tevent_req *subreq);
static void selinux_child_done(struct tevent_req *subreq);
static errno_t selinux_child_parse_response(uint8_t *buf, ssize_t len,
                                            uint32_t *_child_result);

static struct tevent_req *selinux_child_send(TALLOC_CTX *mem_ctx,
                                             struct tevent_context *ev,
                                             struct selinux_child_input *sci)
{
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct selinux_child_state *state;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct selinux_child_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->sci = sci;
    state->ev = ev;
    state->io = talloc(state, struct child_io_fds);
    state->buf = talloc(state, struct io_buffer);
    if (state->io == NULL || state->buf == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc failed.\n");
        ret = ENOMEM;
        goto immediately;
    }

    state->io->write_to_child_fd = -1;
    state->io->read_from_child_fd = -1;
    talloc_set_destructor((void *) state->io, child_io_destructor);

    ret = selinux_child_init();
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to init the child\n");
        goto immediately;
    }

    ret = selinux_child_create_buffer(state);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to create the send buffer\n");
        ret = ENOMEM;
        goto immediately;
    }

    ret = selinux_fork_child(state);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to fork the child\n");
        goto immediately;
    }

    subreq = write_pipe_send(state, ev, state->buf->data, state->buf->size,
                             state->io->write_to_child_fd);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediately;
    }
    tevent_req_set_callback(subreq, selinux_child_step, req);

    ret = EOK;
immediately:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }
    return req;
}

static errno_t selinux_child_init(void)
{
    return child_debug_init(SELINUX_CHILD_LOG_FILE, &selinux_child_debug_fd);
}

static errno_t selinux_child_create_buffer(struct selinux_child_state *state)
{
    size_t rp;
    size_t seuser_len;
    size_t mls_range_len;
    size_t username_len;

    seuser_len = strlen(state->sci->seuser);
    mls_range_len = strlen(state->sci->mls_range);
    username_len = strlen(state->sci->username);

    state->buf->size = 3 * sizeof(uint32_t);
    state->buf->size += seuser_len + mls_range_len + username_len;

    DEBUG(SSSDBG_TRACE_ALL, "buffer size: %zu\n", state->buf->size);

    state->buf->data = talloc_size(state->buf, state->buf->size);
    if (state->buf->data == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_size failed.\n");
        return ENOMEM;
    }

    rp = 0;

    /* seuser */
    SAFEALIGN_SET_UINT32(&state->buf->data[rp], seuser_len, &rp);
    safealign_memcpy(&state->buf->data[rp], state->sci->seuser,
                     seuser_len, &rp);

    /* mls_range */
    SAFEALIGN_SET_UINT32(&state->buf->data[rp], mls_range_len, &rp);
    safealign_memcpy(&state->buf->data[rp], state->sci->mls_range,
                     mls_range_len, &rp);

    /* username */
    SAFEALIGN_SET_UINT32(&state->buf->data[rp], username_len, &rp);
    safealign_memcpy(&state->buf->data[rp], state->sci->username,
                     username_len, &rp);

    return EOK;
}

static errno_t selinux_fork_child(struct selinux_child_state *state)
{
    int pipefd_to_child[2] = PIPE_INIT;
    int pipefd_from_child[2] = PIPE_INIT;
    pid_t pid;
    errno_t ret;

    ret = pipe(pipefd_from_child);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "pipe failed [%d][%s].\n", errno, sss_strerror(errno));
        goto fail;
    }

    ret = pipe(pipefd_to_child);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "pipe failed [%d][%s].\n", errno, sss_strerror(errno));
        goto fail;
    }

    pid = fork();

    if (pid == 0) { /* child */
        exec_child(state,
                   pipefd_to_child, pipefd_from_child,
                   SELINUX_CHILD, selinux_child_debug_fd);

        /* We should never get here */
        DEBUG(SSSDBG_CRIT_FAILURE, "BUG: Could not exec selinux_child\n");
    } else if (pid > 0) { /* parent */
        state->io->read_from_child_fd = pipefd_from_child[0];
        PIPE_FD_CLOSE(pipefd_from_child[1]);
        state->io->write_to_child_fd = pipefd_to_child[1];
        PIPE_FD_CLOSE(pipefd_to_child[0]);
        sss_fd_nonblocking(state->io->read_from_child_fd);
        sss_fd_nonblocking(state->io->write_to_child_fd);

        ret = child_handler_setup(state->ev, pid, NULL, NULL, NULL);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Could not set up child signal handler\n");
            goto fail;
        }
    } else { /* error */
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "fork failed [%d][%s].\n", errno, sss_strerror(errno));
        goto fail;
    }

    return EOK;

fail:
    PIPE_CLOSE(pipefd_from_child);
    PIPE_CLOSE(pipefd_to_child);
    return ret;
}

static void selinux_child_step(struct tevent_req *subreq)
{
    struct tevent_req *req;
    errno_t ret;
    struct selinux_child_state *state;


    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct selinux_child_state);

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
    tevent_req_set_callback(subreq, selinux_child_done, req);
}

static void selinux_child_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct selinux_child_state *state;
    uint32_t child_result;
    errno_t ret;
    ssize_t len;
    uint8_t *buf;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct selinux_child_state);

    ret = read_pipe_recv(subreq, state, &buf, &len);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    PIPE_FD_CLOSE(state->io->read_from_child_fd);

    ret = selinux_child_parse_response(buf, len, &child_result);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "selinux_child_parse_response failed: [%d][%s]\n",
              ret, strerror(ret));
        tevent_req_error(req, ret);
        return;
    } else if (child_result != 0){
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Error in selinux_child: [%d][%s]\n",
              child_result, strerror(child_result));
        tevent_req_error(req, ERR_SELINUX_CONTEXT);
        return;
    }

    tevent_req_done(req);
    return;
}

static errno_t selinux_child_parse_response(uint8_t *buf,
                                            ssize_t len,
                                            uint32_t *_child_result)
{
    size_t p = 0;
    uint32_t child_result;

    /* semanage retval */
    SAFEALIGN_COPY_UINT32_CHECK(&child_result, buf + p, len, &p);

    *_child_result = child_result;
    return EOK;
}

static errno_t selinux_child_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}

/* A more generic request to gather all SELinux and HBAC rules. Updates
 * cache if necessary
 */
struct ipa_get_selinux_state {
    struct be_ctx *be_ctx;
    struct ipa_selinux_ctx *selinux_ctx;
    struct sdap_id_op *op;

    struct sysdb_attrs *host;
    struct sysdb_attrs *user;

    struct sysdb_attrs *defaults;
    struct sysdb_attrs **selinuxmaps;
    size_t nmaps;

    struct sysdb_attrs **hbac_rules;
    size_t hbac_rule_count;
};

static errno_t
ipa_get_selinux_maps_offline(struct tevent_req *req);

static struct tevent_req *
ipa_get_selinux_send(TALLOC_CTX *mem_ctx,
                     struct be_ctx *be_ctx,
                     struct sysdb_attrs *user,
                     struct sysdb_attrs *host,
                     struct ipa_selinux_ctx *selinux_ctx)
{
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct ipa_get_selinux_state *state;
    bool offline;
    int ret = EOK;
    time_t now;
    time_t refresh_interval;
    struct ipa_options *ipa_options = selinux_ctx->id_ctx->ipa_options;

    DEBUG(SSSDBG_TRACE_FUNC, "Retrieving SELinux user mapping\n");
    req = tevent_req_create(mem_ctx, &state, struct ipa_get_selinux_state);
    if (req == NULL) {
        return NULL;
    }

    state->be_ctx = be_ctx;
    state->selinux_ctx = selinux_ctx;
    state->user = user;
    state->host = host;

    offline = be_is_offline(be_ctx);
    DEBUG(SSSDBG_TRACE_INTERNAL, "Connection status is [%s].\n",
                                  offline ? "offline" : "online");

    if (!offline) {
        refresh_interval = dp_opt_get_int(ipa_options->basic,
                                          IPA_SELINUX_REFRESH);
        now = time(NULL);
        if (now < selinux_ctx->last_update + refresh_interval) {
            /* SELinux maps were recently updated -> force offline */
            DEBUG(SSSDBG_TRACE_INTERNAL,
                  "Performing cached SELinux processing\n");
            offline = true;
        }
    }

    if (!offline) {
        state->op = sdap_id_op_create(state,
                        selinux_ctx->id_ctx->sdap_id_ctx->conn->conn_cache);
        if (!state->op) {
            DEBUG(SSSDBG_OP_FAILURE, "sdap_id_op_create failed\n");
            ret = ENOMEM;
            goto immediate;
        }

        subreq = sdap_id_op_connect_send(state->op, state, &ret);
        if (!subreq) {
            DEBUG(SSSDBG_CRIT_FAILURE, "sdap_id_op_connect_send failed: "
                                        "%d(%s).\n", ret, strerror(ret));
            talloc_zfree(state->op);
            goto immediate;
        }

        tevent_req_set_callback(subreq, ipa_get_selinux_connect_done, req);
    } else {
        ret = ipa_get_selinux_maps_offline(req);
        goto immediate;
    }

    return req;

immediate:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, be_ctx->ev);
    return req;
}

static void ipa_get_selinux_connect_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                  struct tevent_req);
    struct ipa_get_selinux_state *state = tevent_req_data(req,
                                                  struct ipa_get_selinux_state);
    int dp_error = DP_ERR_FATAL;
    int ret;
    struct ipa_id_ctx *id_ctx = state->selinux_ctx->id_ctx;

    const char *access_name;
    const char *selinux_name;
    const char *hostname;

    ret = sdap_id_op_connect_recv(subreq, &dp_error);
    talloc_zfree(subreq);

    if (dp_error == DP_ERR_OFFLINE) {
        talloc_zfree(state->op);
        ret = ipa_get_selinux_maps_offline(req);
        if (ret == EOK) {
            tevent_req_done(req);
            return;
        }
        goto fail;
    }

    if (ret != EOK) {
        goto fail;
    }

    access_name = state->be_ctx->bet_info[BET_ACCESS].mod_name;
    selinux_name = state->be_ctx->bet_info[BET_SELINUX].mod_name;
    if (strcasecmp(access_name, selinux_name) == 0 && state->host != NULL) {
        /* If the access control module is the same as the selinux module
         * and the access control had already discovered the host
         */
        return ipa_get_config_step(req);
    }

    hostname = dp_opt_get_string(state->selinux_ctx->id_ctx->ipa_options->basic,
                                        IPA_HOSTNAME);
    if (hostname == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot determine the host name\n");
        goto fail;
    }

    subreq = ipa_host_info_send(state, state->be_ctx->ev,
                                sdap_id_op_handle(state->op),
                                id_ctx->sdap_id_ctx->opts,
                                hostname,
                                id_ctx->ipa_options->host_map,
                                NULL,
                                state->selinux_ctx->host_search_bases);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto fail;
    }

    tevent_req_set_callback(subreq, ipa_get_selinux_hosts_done, req);
    return;

fail:
    tevent_req_error(req, ret);
}

static errno_t
ipa_get_selinux_maps_offline(struct tevent_req *req)
{
    errno_t ret;
    size_t nmaps;
    struct ldb_message **maps;
    struct ldb_message *defaults;
    const char *attrs[] = { SYSDB_NAME,
                            SYSDB_USER_CATEGORY,
                            SYSDB_HOST_CATEGORY,
                            SYSDB_ORIG_MEMBER_USER,
                            SYSDB_ORIG_MEMBER_HOST,
                            SYSDB_SELINUX_SEEALSO,
                            SYSDB_SELINUX_USER,
                            NULL };
    const char *default_user;
    const char *order;

    struct ipa_get_selinux_state *state = tevent_req_data(req,
                                                  struct ipa_get_selinux_state);

    /* read the config entry */
    ret = sysdb_search_selinux_config(state, state->be_ctx->domain,
                                      NULL, &defaults);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_search_selinux_config failed [%d]: %s\n",
                                  ret, strerror(ret));
        return ret;
    }

    default_user = ldb_msg_find_attr_as_string(defaults,
                                               SYSDB_SELINUX_DEFAULT_USER,
                                               NULL);
    order = ldb_msg_find_attr_as_string(defaults, SYSDB_SELINUX_DEFAULT_ORDER,
                                        NULL);

    state->defaults = sysdb_new_attrs(state);
    if (state->defaults == NULL) {
        return ENOMEM;
    }

    if (default_user) {
        ret = sysdb_attrs_add_string(state->defaults,
                                    IPA_CONFIG_SELINUX_DEFAULT_USER_CTX,
                                    default_user);
        if (ret != EOK) {
            return ret;
        }
    }

    ret = sysdb_attrs_add_string(state->defaults,
                                 IPA_CONFIG_SELINUX_MAP_ORDER, order);
    if (ret != EOK) {
        return ret;
    }

    /* read all the SELinux rules */
    ret = sysdb_get_selinux_usermaps(state, state->be_ctx->domain,
                                     attrs, &nmaps, &maps);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_get_selinux_usermaps failed [%d]: %s\n",
                                  ret, strerror(ret));
        return ret;
    }

    ret = sysdb_msg2attrs(state, nmaps, maps, &state->selinuxmaps);
    if (ret != EOK) {
        return ret;
    }
    state->nmaps = nmaps;

    /* read all the HBAC rules */
    ret = hbac_get_cached_rules(state, state->be_ctx->domain,
                                &state->hbac_rule_count, &state->hbac_rules);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "hbac_get_cached_rules failed [%d]: %s\n",
                                  ret, strerror(ret));
        return ret;
    }

    return EOK;
}

static void ipa_get_selinux_hosts_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                  struct tevent_req);
    struct ipa_get_selinux_state *state = tevent_req_data(req,
                                                  struct ipa_get_selinux_state);
    size_t host_count, hostgroup_count;
    struct sysdb_attrs **hostgroups;
    struct sysdb_attrs **host;

    ret = ipa_host_info_recv(subreq, state, &host_count, &host,
                             &hostgroup_count, &hostgroups);
    talloc_free(subreq);
    if (ret != EOK) {
        goto done;
    }
    state->host = host[0];

    return ipa_get_config_step(req);

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
    }
}

static void ipa_get_config_step(struct tevent_req *req)
{
    const char *domain;
    struct tevent_req *subreq;
    struct ipa_get_selinux_state *state = tevent_req_data(req,
                                                  struct ipa_get_selinux_state);
    struct ipa_id_ctx *id_ctx = state->selinux_ctx->id_ctx;

    domain = dp_opt_get_string(state->selinux_ctx->id_ctx->ipa_options->basic,
                               IPA_KRB5_REALM);
    subreq = ipa_get_config_send(state, state->be_ctx->ev,
                                 sdap_id_op_handle(state->op),
                                 id_ctx->sdap_id_ctx->opts,
                                 domain, NULL);
    if (subreq == NULL) {
        tevent_req_error(req, ENOMEM);
    }
    tevent_req_set_callback(subreq, ipa_get_selinux_config_done, req);
}

static void ipa_get_selinux_config_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                  struct tevent_req);
    struct ipa_get_selinux_state *state = tevent_req_data(req,
                                                  struct ipa_get_selinux_state);
    struct sdap_id_ctx *id_ctx = state->selinux_ctx->id_ctx->sdap_id_ctx;
    errno_t ret;

    ret = ipa_get_config_recv(subreq, state, &state->defaults);
    talloc_free(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Could not get IPA config\n");
        goto done;
    }

    subreq = ipa_selinux_get_maps_send(state, state->be_ctx->ev,
                                       state->be_ctx->domain->sysdb,
                                     sdap_id_op_handle(state->op),
                                     id_ctx->opts,
                                     state->selinux_ctx->id_ctx->ipa_options,
                                     state->selinux_ctx->selinux_search_bases);
    if (!subreq) {
        ret = ENOMEM;
        goto done;
    }
    tevent_req_set_callback(subreq, ipa_get_selinux_maps_done, req);
    return;

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
    } else {
        tevent_req_done(req);
    }
}

static void ipa_get_selinux_maps_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct ipa_get_selinux_state *state;

    struct ipa_id_ctx *id_ctx;

    char *selinux_name;
    char *access_name;

    const char *tmp_str;
    bool check_hbac;
    errno_t ret;
    int i;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ipa_get_selinux_state);
    id_ctx = state->selinux_ctx->id_ctx;

    ret = ipa_selinux_get_maps_recv(subreq, state,
                                    &state->nmaps, &state->selinuxmaps);
    talloc_free(subreq);
    if (ret != EOK) {
        if (ret == ENOENT) {
            /* This is returned if no SELinux mapping
             * rules were found. In that case no error
             * occurred, but we don't want any more processing.*/
            ret = EOK;
        }
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
         "Found %zu SELinux user maps\n", state->nmaps);

    check_hbac = false;
    for (i = 0; i < state->nmaps; i++) {
        ret = sysdb_attrs_get_string(state->selinuxmaps[i],
                                     SYSDB_SELINUX_SEEALSO, &tmp_str);
        if (ret == EOK) {
            check_hbac = true;
            break;
        }
    }

    if (check_hbac) {
        access_name = state->be_ctx->bet_info[BET_ACCESS].mod_name;
        selinux_name = state->be_ctx->bet_info[BET_SELINUX].mod_name;
        if (strcasecmp(access_name, selinux_name) == 0) {
            ret = hbac_get_cached_rules(state, state->be_ctx->domain,
                                        &state->hbac_rule_count,
                                        &state->hbac_rules);
            /* Terminates the request */
            goto done;
        }

        DEBUG(SSSDBG_TRACE_FUNC, "SELinux maps referenced an HBAC rule. "
              "Need to refresh HBAC rules\n");
        subreq = ipa_hbac_rule_info_send(state, state->be_ctx->ev,
                                         sdap_id_op_handle(state->op),
                                         id_ctx->sdap_id_ctx->opts,
                                         state->selinux_ctx->hbac_search_bases,
                                         state->host);
        if (subreq == NULL) {
            ret = ENOMEM;
            goto done;
        }

        tevent_req_set_callback(subreq, ipa_get_selinux_hbac_done, req);
        return;
    }

    ret = EOK;
done:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
}

static void ipa_get_selinux_hbac_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct ipa_get_selinux_state *state = tevent_req_data(req,
                                                  struct ipa_get_selinux_state);
    errno_t ret;

    ret = ipa_hbac_rule_info_recv(subreq, state, &state->hbac_rule_count,
                                  &state->hbac_rules);
    DEBUG(SSSDBG_TRACE_INTERNAL,
          "Received %zu HBAC rules\n", state->hbac_rule_count);
    talloc_free(subreq);

    if (ret != EOK) {
        tevent_req_error(req, ret);
    } else {
        tevent_req_done(req);
    }
}

static errno_t
ipa_get_selinux_recv(struct tevent_req *req,
                     TALLOC_CTX *mem_ctx,
                     size_t *count,
                     struct sysdb_attrs ***maps,
                     size_t *hbac_count,
                     struct sysdb_attrs ***hbac_rules,
                     char **default_user,
                     char **map_order)
{
    struct ipa_get_selinux_state *state =
            tevent_req_data(req, struct ipa_get_selinux_state);
    const char *tmp_str;
    errno_t ret;

    TEVENT_REQ_RETURN_ON_ERROR(req);

    ret = sysdb_attrs_get_string(state->defaults,
                                 IPA_CONFIG_SELINUX_DEFAULT_USER_CTX,
                                 &tmp_str);
    if (ret != EOK && ret != ENOENT) {
        return ret;
    }

    if (ret == EOK) {
        *default_user = talloc_strdup(mem_ctx, tmp_str);
        if (*default_user == NULL) {
            return ENOMEM;
        }
    }

    ret = sysdb_attrs_get_string(state->defaults, IPA_CONFIG_SELINUX_MAP_ORDER,
                                 &tmp_str);
    if (ret != EOK) {
        return ret;
    }

    *map_order = talloc_strdup(mem_ctx, tmp_str);
    if (*map_order == NULL) {
        talloc_zfree(*default_user);
        return ENOMEM;
    }

    *count = state->nmaps;
    *maps = talloc_steal(mem_ctx, state->selinuxmaps);

    *hbac_count = state->hbac_rule_count;
    *hbac_rules = talloc_steal(mem_ctx, state->hbac_rules);

    return EOK;
}

/*end of #if defined HAVE_SELINUX && defined HAVE_SELINUX_LOGIN_DIR */
#else
/* Simply return success if HAVE_SELINUX_LOGIN_DIR is not defined. */
void ipa_selinux_handler(struct be_req *be_req)
{
    struct pam_data *pd;

    pd = talloc_get_type(be_req_get_data(be_req), struct pam_data);

    pd->pam_status = PAM_SUCCESS;
    be_req_terminate(be_req, DP_ERR_OK, EOK, "Success");
}
#endif
