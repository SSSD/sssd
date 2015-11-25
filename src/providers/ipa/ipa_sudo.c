/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2015 Red Hat

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

#include "providers/ipa/ipa_common.h"
#include "providers/ldap/sdap_sudo.h"

enum sudo_schema {
    SUDO_SCHEMA_IPA,
    SUDO_SCHEMA_LDAP
};

static errno_t
ipa_sudo_choose_schema(struct dp_option *ipa_opts,
                       struct dp_option *sdap_opts,
                       enum sudo_schema *_schema)
{
    TALLOC_CTX *tmp_ctx;
    char *ipa_search_base;
    char *search_base;
    char *basedn;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed\n");
        return ENOMEM;
    }

    ret = domain_to_basedn(tmp_ctx, dp_opt_get_string(ipa_opts,
                           IPA_KRB5_REALM), &basedn);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to obtain basedn\n");
        goto done;
    }

    ipa_search_base = talloc_asprintf(tmp_ctx, "cn=sudo,%s", basedn);
    if (ipa_search_base == NULL) {
        ret = ENOMEM;
        goto done;
    }

    search_base = dp_opt_get_string(sdap_opts, SDAP_SUDO_SEARCH_BASE);
    if (search_base == NULL) {
        ret = dp_opt_set_string(sdap_opts, SDAP_SUDO_SEARCH_BASE,
                                ipa_search_base);
        if (ret != EOK) {
            goto done;
        }

        DEBUG(SSSDBG_TRACE_FUNC, "Option %s set to %s\n",
              sdap_opts[SDAP_SUDO_SEARCH_BASE].opt_name, ipa_search_base);

        search_base = ipa_search_base;
    }

    /* Use IPA schema only if search base is cn=sudo,$dc. */
    if (strcmp(ipa_search_base, search_base) == 0) {
        *_schema = SUDO_SCHEMA_IPA;
    } else {
        *_schema = SUDO_SCHEMA_LDAP;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

int ipa_sudo_init(struct be_ctx *be_ctx,
                  struct ipa_id_ctx *id_ctx,
                  struct bet_ops **ops,
                  void **pvt_data)
{
    enum sudo_schema schema;
    errno_t ret;

    DEBUG(SSSDBG_TRACE_INTERNAL, "Initializing IPA sudo back end\n");

    ret = ipa_sudo_choose_schema(id_ctx->ipa_options->basic,
                                 id_ctx->ipa_options->id->basic,
                                 &schema);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to choose sudo schema [%d]: %s\n",
                                   ret, sss_strerror(ret));
        return ret;
    }

    switch (schema) {
    case SUDO_SCHEMA_IPA:
        DEBUG(SSSDBG_TRACE_FUNC, "Using IPA schema for sudo\n");
        break;
    case SUDO_SCHEMA_LDAP:
        DEBUG(SSSDBG_TRACE_FUNC, "Using LDAP schema for sudo\n");
        ret = sdap_sudo_init(be_ctx, id_ctx->sdap_id_ctx, ops, pvt_data);
        break;
    }

    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to initialize sudo provider"
              "[%d]: %s\n", ret, sss_strerror(ret));
        return ret;
    }

    return EOK;
}
