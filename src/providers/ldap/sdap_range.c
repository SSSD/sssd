/*
    SSSD

    Authors:
        Stephen Gallagher <sgallagh@redhat.com>

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

#include "providers/ldap/sdap_range.h"
#include "util/util.h"
#include "util/strtonum.h"

#define SDAP_RANGE_STRING "range="

errno_t sdap_parse_range(TALLOC_CTX *mem_ctx,
                         const char *attr_desc,
                         char **base_attr,
                         uint32_t *range_offset,
                         bool disable_range_retrieval)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx;
    char *endptr;
    char *end_range;
    char *base;
    size_t rangestringlen = sizeof(SDAP_RANGE_STRING) - 1;

    *range_offset = 0;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    /* The base_attr is the portion before the semicolon (if it exists) */
    endptr = strchr(attr_desc, ';');
    if (endptr == NULL) {
        /* Not a ranged attribute. Just copy the attribute desc */
        *base_attr = talloc_strdup(mem_ctx, attr_desc);
        if (!*base_attr) {
            ret = ENOMEM;
        } else {
            ret = EOK;
        }
        DEBUG(SSSDBG_TRACE_ALL,
              "No sub-attributes for [%s]\n", attr_desc);
        goto done;
    }

    /* This is a complex attribute. First get the base attribute name */
    base = talloc_strndup(tmp_ctx, attr_desc,
                          endptr - attr_desc);
    if (!base) {
        ret = ENOMEM;
        goto done;
    }
    DEBUG(SSSDBG_TRACE_LIBS,
          "Base attribute of [%s] is [%s]\n",
           attr_desc, base);

    /* Next, determine if this is a ranged attribute */
    if (strncmp(endptr+1, SDAP_RANGE_STRING, rangestringlen) != 0) {
        /* This is some other sub-attribute. We'll just return the whole
         * thing in case it's dealt with elsewhere.
         */
        *base_attr = talloc_strdup(mem_ctx, attr_desc);
        if (!*base_attr) {
            ret = ENOMEM;
        } else {
            ret = EOK;
        }
        DEBUG(SSSDBG_TRACE_LIBS,
              "[%s] contains sub-attribute other than a range, returning whole\n",
               attr_desc);
        goto done;
    } else if (disable_range_retrieval) {
        /* This is range sub-attribute, but we want to ignore it.
         */
        *base_attr = talloc_strdup(mem_ctx, attr_desc);
        if (!*base_attr) {
            ret = ENOMEM;
        } else {
            ret = ECANCELED;
        }
        goto done;
    }

    /* Get the end of the range */
    end_range = strchr(endptr + rangestringlen +1, '-');
    if (!end_range) {
        ret = EINVAL;
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Cannot find hyphen in [%s]\n",
               endptr + rangestringlen +1);
        goto done;
    }
    end_range++; /* advance past the hyphen */

    if (*end_range == '*') {
        /* this was the last iteration of range retrievals */
        *base_attr = talloc_steal(mem_ctx, base);
        *range_offset = 0;
        DEBUG(SSSDBG_TRACE_LIBS,
              "[%s] contained the last set of values for this attribute\n",
               attr_desc);
        ret = EOK;
        goto done;
    }

    *range_offset = strtouint32(end_range, &endptr, 10);
    if ((errno != 0) || (*endptr != '\0') || (end_range == endptr)) {
        *range_offset = 0;
        ret = errno;
        DEBUG(SSSDBG_MINOR_FAILURE,
              "[%s] did not parse as an unsigned integer: [%s]\n",
               end_range, strerror(ret));
        goto done;
    }
    (*range_offset)++;

    *base_attr = talloc_steal(mem_ctx, base);
    DEBUG(SSSDBG_TRACE_LIBS,
          "Parsed range values: [%s][%d]\n",
           base, *range_offset);

    ret = EAGAIN;
done:
    talloc_free(tmp_ctx);
    return ret;
}
