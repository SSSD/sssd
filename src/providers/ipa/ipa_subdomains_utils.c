/*
    SSSD

    IPA Subdomains Module - utilities

    Authors:
        Sumit Bose <sbose@redhat.com>

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

#include "providers/ipa/ipa_subdomains.h"
#include "providers/ipa/ipa_common.h"
#include "providers/ipa/ipa_id.h"

struct ldb_dn *ipa_subdom_ldb_dn(TALLOC_CTX *mem_ctx,
                                 struct ldb_context *ldb_ctx,
                                 struct sysdb_attrs *attrs)
{
    int ret;
    const char *orig_dn;
    struct ldb_dn *dn = NULL;

    if (attrs == NULL || ldb_ctx == NULL) {
        return NULL;
    }

    ret = sysdb_attrs_get_string(attrs, SYSDB_ORIG_DN, &orig_dn);
    if (ret) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_string failed: %d\n", ret);
        return NULL;
    }

    dn = ldb_dn_new(mem_ctx, ldb_ctx, orig_dn);
    if (dn == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "ldb_dn_new failed.\n");
        return NULL;
    }

    if (!ldb_dn_validate(dn)) {
        DEBUG(SSSDBG_OP_FAILURE, "Original DN [%s] is not a valid DN.\n",
                                  orig_dn);
        talloc_free(dn);
        return NULL;
    }

    return dn;
}

bool ipa_subdom_is_member_dom(struct ldb_dn *dn)
{
    const struct ldb_val *val;

    if (dn == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Wrong input!\n");
        return false;
    }

    if (ldb_dn_get_comp_num(dn) < 5) {
        /* We are only interested in the member domain objects. In IPA the
         * forest root object is stored as e.g.
         * cn=AD.DOM,cn=ad,cn=trusts,dc=example,dc=com. Member domains in the
         * forest are children of the forest root object e.g.
         * cn=SUB.AD.DOM,cn=AD.DOM,cn=ad,cn=trusts,dc=example,dc=com. Since
         * the forest name is not stored in the member objects we derive it
         * from the RDN of the forest root object. */
        DEBUG(SSSDBG_TRACE_FUNC,
              "DN too short, not a member domain\n");
        return false;
    }

    val = ldb_dn_get_component_val(dn, 3);
    if (strncasecmp("trusts", (const char *) val->data, val->length) != 0) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "4th component is not 'trust', not a member domain\n");
        return false;
    }

    val = ldb_dn_get_component_val(dn, 2);
    if (strncasecmp("ad", (const char *) val->data, val->length) != 0) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "3rd component is not 'ad', not a member domain\n");
        return false;
    }

    return true;
}
