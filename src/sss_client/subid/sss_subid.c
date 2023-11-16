/*
    Copyright (C) 2021 Red Hat

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

#include <stdlib.h>
#include <string.h>
#include <shadow/subid.h>
#include "sss_cli.h"

/* This shadow-utils plugin contains partial SSSD implementation
 * of `subid_nss_ops` API as described in
 * https://github.com/shadow-maint/shadow/blob/d4b6d1549b2af48ce3cb6ff78d9892095fb8fdd9/lib/prototypes.h#L271
 */

/* Find all subid ranges delegated to a user.
 *
 * Usage in shadow-utils:
 *      libsubid: get_sub?id_ranges() -> list_owner_ranges()
 *
 * SUBID_RANGES Reply:
 *
 * 0-3: 32bit unsigned number of UID results
 * 4-7: 32bit unsigned number of GID results
 * For each result (sub-uid ranges first):
 * 0-3: 32bit number with "start" id
 * 4-7: 32bit number with "count" (range size)
 */
enum subid_status shadow_subid_list_owner_ranges(const char *user,
                                                 enum subid_type id_type,
                                                 struct subid_range **ranges,
                                                 int *count)
{
    size_t user_len;
    enum sss_status ret;
    uint8_t *repbuf = NULL;
    size_t index = 0;
    size_t replen;
    int errnop;
    struct sss_cli_req_data rd;
    uint32_t num_results = 0;
    uint32_t val;

    if ( !user || !ranges || !count ||
          ((id_type != ID_TYPE_UID) && (id_type != ID_TYPE_GID)) ) {
        return SUBID_STATUS_ERROR;
    }

    ret = sss_strnlen(user, SSS_NAME_MAX, &user_len);
    if (ret != 0) {
        return SUBID_STATUS_UNKNOWN_USER;
    }
    rd.len = user_len + 1;
    rd.data = user;

    sss_nss_lock();
    /* Anticipated workflow will always request both
     * sub-uid and sub-gid ranges anyway.
     * So don't bother with dedicated commands -
     * just request everything in one shot.
     * The second request will get data from the cache.
     */
    ret = sss_cli_make_request_with_checks(SSS_NSS_GET_SUBID_RANGES, &rd,
                                           SSS_CLI_SOCKET_TIMEOUT,
                                           &repbuf, &replen, &errnop,
                                           SSS_NSS_SOCKET_NAME,
                                           false, false);
    sss_nss_unlock();

    if ( (ret != SSS_STATUS_SUCCESS) || (errnop != EOK)
        /* response must contain at least the "payload header" */
        || (replen < 2*sizeof(uint32_t))
        /* and even number of 'uint32_t' */
        || (replen % (2*sizeof(uint32_t)) != 0) ) {
        free(repbuf);
        if (ret == SSS_STATUS_UNAVAIL) {
            return SUBID_STATUS_ERROR_CONN;
        }
        return SUBID_STATUS_ERROR;
    }

    SAFEALIGN_COPY_UINT32(&num_results, repbuf, NULL);
    if (num_results > (replen/sizeof(uint32_t) - 2)/2) {
        free(repbuf);
        return SUBID_STATUS_ERROR;
    }

    if (id_type == ID_TYPE_UID) {
        index = 2 * sizeof(uint32_t);
    } else {
        index = (2 + 2*num_results) * sizeof(uint32_t);
        SAFEALIGN_COPY_UINT32(&num_results, repbuf + sizeof(uint32_t), NULL);
        if (num_results > ((replen - index)/sizeof(uint32_t)/2)) {
            free(repbuf);
            return SUBID_STATUS_ERROR;
        }
    }
    if (num_results == 0) {
        /* TODO: how to distinguish "user not found" vs "user doesn't have ranges defined" here?
         * Options:
         *  - special "fake" entry in the cache
         *  - provide 'nss_protocol_done_fn' to 'nss_getby_name' to avoid "ENOENT -> "empty packet" logic
         *  - add custom error code for this case and handle in generic 'nss_protocol_done'
         *
         * Note: at the moment this is not important, since shadow-utils doesn't use return code internally
         * and returns -1 from libsubid on any error  anyway.
         */
        free(repbuf);
        return SUBID_STATUS_UNKNOWN_USER;
    }

    *count = num_results;
    if (*count < 0) {
        free(repbuf);
        return SUBID_STATUS_ERROR;
    }

    *ranges = malloc(num_results * sizeof(struct subid_range));
    if (!*ranges) {
        free(repbuf);
        return SUBID_STATUS_ERROR;
    }

    for (uint32_t c = 0; c < num_results; ++c) {
        SAFEALIGN_COPY_UINT32(&val, repbuf + index, &index);
        (*ranges)[c].start = val;
        SAFEALIGN_COPY_UINT32(&val, repbuf + index, &index);
        (*ranges)[c].count = val;
    }
    free(repbuf);

    return SUBID_STATUS_SUCCESS;
}

/* Does a user own a given subid range?
 *
 * Usage in shadow-utils:
 *      newuidmap/user busy : have_sub_uids() -> has_range()
 */
enum subid_status shadow_subid_has_range(const char *owner,
                                         unsigned long start,
                                         unsigned long count,
                                         enum subid_type id_type,
                                         bool *result)
{
    enum subid_status ret;
    struct subid_range *range;
    int amount;
    unsigned long end = start + count;

    if (!result || (end < start)) {
        return SUBID_STATUS_ERROR;
    }

    if (count == 0) {
        *result = true;
        return SUBID_STATUS_SUCCESS;
    }

    /* Anticipated workflow is the following:
     *
     * 1) Podman figures out ranges available for a user:
     *     libsubid::get_subid_ranges() -> ... -> list_owner_ranges()
     *
     * 2) Podman maps available ranges:
     *     newuidmap -> have_sub_uids() -> has_range()
     * At this point all ranges are available in a cache from step (1)
     * so it doesn't make sense to try "smart" LDAP searches (even if possible)
     * Let's just reuse list_owner_ranges() and do a check.
     *
     * It might have some sense to do a check at responder's side (i.e. without
     * fetching all ranges), but range is just a couple of numbers (and FreeIPA
     * only supports a single range per user anyway), so this optimization
     * wouldn't save much traffic anyway, but would introduce new
     * `sss_cli_command`/responder handler.
     */

    ret = shadow_subid_list_owner_ranges(owner, id_type, &range, &amount);
    if (ret != SUBID_STATUS_SUCCESS) {
        return ret;
    }

    *result = false;

    for (int i = 0; i < amount; ++i) {
        if ((range[i].start <= start) &&
            (range[i].start + range[i].count >= end)) {
            *result = true;
        }
        /* TODO: handle coverage via multiple ranges (once IPA supports this) */
    }

    free(range);
    return ret;
}

/* Find uids who own a given subid.
 *
 * Usage in shadow-utils:
 *      libsubid: get_sub?id_owners() -> find_subid_owners()
 */
enum subid_status shadow_subid_find_subid_owners(unsigned long subid,
                                                 enum subid_type id_type,
                                                 uid_t **uids,
                                                 int *count)
{
    /* Not yet implemented.
     * Currently there are no users of this function.
     */
    return SUBID_STATUS_ERROR;
}
