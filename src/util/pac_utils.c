/*
    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2022 Red Hat

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
#include <errno.h>
#include <talloc.h>

#include "config.h"

#include "util/util.h"

static errno_t check_check_pac_opt(const char *inp, uint32_t *check_pac_flags)
{
    int ret;
    size_t c;
    char **list = NULL;
    uint32_t flags = 0;

    if (strcasecmp(inp, CHECK_PAC_NO_CHECK_STR) == 0) {
        flags = 0;
        ret = EOK;
        goto done;
    }

    ret = split_on_separator(NULL, inp, ',', true, true, &list, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to split pac_check value.\n");
        goto done;
    }

    for (c = 0; list[c] != NULL; c++) {
        if (strcasecmp(list[c], CHECK_PAC_NO_CHECK_STR) == 0) {
            DEBUG(SSSDBG_CONF_SETTINGS,
                  "pac_check option [%s] can be only used alone.\n",
                  CHECK_PAC_NO_CHECK_STR);
            ret = EINVAL;
            goto done;
        } else if (strcasecmp(list[c], CHECK_PAC_PRESENT_STR) == 0) {
            flags |= CHECK_PAC_PRESENT;
        } else if (strcasecmp(list[c], CHECK_PAC_CHECK_UPN_STR) == 0) {
            flags |= CHECK_PAC_CHECK_UPN;
        } else if (strcasecmp(list[c], CHECK_PAC_UPN_DNS_INFO_PRESENT_STR) == 0) {
            flags |= CHECK_PAC_UPN_DNS_INFO_PRESENT;
            flags |= CHECK_PAC_CHECK_UPN;
        } else if (strcasecmp(list[c], CHECK_PAC_CHECK_UPN_DNS_INFO_EX_STR) == 0) {
            flags |= CHECK_PAC_CHECK_UPN_DNS_INFO_EX;
        } else if (strcasecmp(list[c], CHECK_PAC_UPN_DNS_INFO_EX_PRESENT_STR) == 0) {
            flags |= CHECK_PAC_UPN_DNS_INFO_EX_PRESENT;
            flags |= CHECK_PAC_CHECK_UPN_DNS_INFO_EX;
            flags |= CHECK_PAC_UPN_DNS_INFO_PRESENT;
            flags |= CHECK_PAC_CHECK_UPN;
        } else if (strcasecmp(list[c], CHECK_PAC_CHECK_UPN_ALLOW_MISSING_STR) == 0) {
            flags |= CHECK_PAC_CHECK_UPN_ALLOW_MISSING;
        } else {
            DEBUG(SSSDBG_OP_FAILURE, "Unknown value [%s] for pac_check.\n",
                                     list[c]);
            ret = EINVAL;
            goto done;
        }
    }

    if ((flags & CHECK_PAC_CHECK_UPN_ALLOW_MISSING)
                && !(flags & CHECK_PAC_CHECK_UPN)) {
        DEBUG(SSSDBG_CONF_SETTINGS,
              "pac_check option '%s' is set but '%s' is not set, this means "
              "the UPN is not checked.\n",
              CHECK_PAC_CHECK_UPN_ALLOW_MISSING_STR, CHECK_PAC_CHECK_UPN_STR);
    }

    ret = EOK;

done:
    talloc_free(list);
#ifndef HAVE_PAC_RESPONDER
    if (ret == EOK && flags != 0) {
        DEBUG(SSSDBG_IMPORTANT_INFO,
              "pac_check is configured but SSSD is build without PAC "
              "responder, not all checks will be available.\n");
    }
#endif
    if (ret == EOK && check_pac_flags != NULL) {
        *check_pac_flags = flags;
    }

    return ret;
}

errno_t get_pac_check_config(struct confdb_ctx *cdb, uint32_t *pac_check_opts)
{
    int ret;
    char *dummy;
    struct sss_domain_info *dom;
    struct sss_domain_info *domains = NULL;

    ret = confdb_get_string(cdb, NULL, CONFDB_PAC_CONF_ENTRY,
                            CONFDB_PAC_CHECK, NULL, &dummy);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to get pac_check config option [%d][%s].\n",
              ret, sss_strerror(ret));
        return ret;
    }

    if (dummy == NULL) {
        ret = confdb_get_domains(cdb, &domains);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Failed to get domain list, cannot "
                                       "determine pac_check defaults.\n");
            return ret;
        }

        for (dom = domains; dom != NULL;
                            dom = get_next_domain(dom, SSS_GND_DESCEND
                                                   |SSS_GND_INCLUDE_DISABLED)) {
            if (strcasecmp(dom->provider, "ad") == 0
                    || strcasecmp(dom->provider, "ipa") == 0) {
                break;
            }
        }

        if (dom == NULL) {
            /* No AD or IPA provider found */
            dummy = talloc_strdup(NULL, CONFDB_PAC_CHECK_DEFAULT);
        } else {
            dummy = talloc_strdup(NULL, CONFDB_PAC_CHECK_IPA_AD_DEFAULT);
        }
        if (dummy == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to copy pac_check defaults.\n");
            return ENOMEM;
        }
    }

    ret = check_check_pac_opt(dummy, pac_check_opts);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "pac_check option [%s] is invalid.\n",
              dummy);
    }
    talloc_free(dummy);

    return ret;
}
