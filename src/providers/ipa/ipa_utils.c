/*
    SSSD

    IPA Module utility functions

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2014 Red Hat

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

#include "util/util.h"

#define OVERRIDE_ANCHOR_IPA_PREFIX ":IPA:"
#define OVERRIDE_ANCHOR_IPA_PREFIX_LEN (sizeof(OVERRIDE_ANCHOR_IPA_PREFIX) -1 )

errno_t split_ipa_anchor(TALLOC_CTX *mem_ctx, const char *anchor,
                         char **_anchor_domain, char **_ipa_uuid)
{
    const char *sep;

    if (anchor == NULL) {
        return EINVAL;
    }
    if (strncmp(OVERRIDE_ANCHOR_IPA_PREFIX, anchor,
                OVERRIDE_ANCHOR_IPA_PREFIX_LEN) != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "No IPA anchor [%s].\n", anchor);
        return ENOMSG;
    }

    sep = strchr(anchor + OVERRIDE_ANCHOR_IPA_PREFIX_LEN, ':');
    if (sep == NULL || sep[1] == '\0') {
        DEBUG(SSSDBG_CRIT_FAILURE, "Broken IPA anchor [%s].\n", anchor);
        return EINVAL;
    }

    *_anchor_domain = talloc_strndup(mem_ctx,
                                 anchor + OVERRIDE_ANCHOR_IPA_PREFIX_LEN,
                                 sep - anchor - OVERRIDE_ANCHOR_IPA_PREFIX_LEN);
    *_ipa_uuid = talloc_strdup(mem_ctx, sep + 1);

    if (*_anchor_domain == NULL || *_ipa_uuid == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_strndup failed.\n");
        talloc_free(*_anchor_domain);
        talloc_free(*_ipa_uuid);
        return ENOMEM;
    }

    return EOK;
}
