/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

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

#include "db/sysdb.h"
#include "db/sysdb_services.h"
#include "responder/nss/nss_protocol.h"

static errno_t
sss_nss_get_svcent(TALLOC_CTX *mem_ctx,
                   struct sss_domain_info *domain,
                   struct ldb_message *msg,
                   const char *requested_protocol,
                   struct sized_string *_name,
                   struct sized_string *_protocol,
                   uint16_t *_port)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_message_element *el;
    const char *protocol;
    const char *name;
    uint16_t port;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    /* Get name. */
    name = ldb_msg_find_attr_as_string(msg, SYSDB_NAME, NULL);
    if (name == NULL) {
        ret = ERR_INTERNAL;
        goto done;
    }

    name = sss_get_cased_name(tmp_ctx, name, domain->case_preserve);
    if (name == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* Get port. */
    port = (uint16_t)ldb_msg_find_attr_as_uint(msg, SYSDB_SVC_PORT, 0);
    if (port == 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "No port for service [%s]\n", name);
        ret = EINVAL;
        goto done;
    }

    /* Get protocol.
     *
     * Use the requested protocol if present, otherwise take the
     * first protocol returned by the sysdb. */
    if (requested_protocol != NULL) {
        protocol = requested_protocol;
    } else {
        el = ldb_msg_find_element(msg, SYSDB_SVC_PROTO);
        if (el == NULL || el->num_values == 0) {
            ret = EINVAL;
            goto done;
        }

        protocol = (const char *)el->values[0].data;
        if (protocol == NULL) {
            ret = ERR_INTERNAL;
            goto done;
        }
    }

    protocol = sss_get_cased_name(tmp_ctx, protocol, domain->case_preserve);
    if (protocol == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* Set output variables. */

    talloc_steal(mem_ctx, name);
    talloc_steal(mem_ctx, protocol);

    to_sized_string(_name, name);
    to_sized_string(_protocol, protocol);
    *_port = port;

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}

static errno_t
sss_nss_get_svc_aliases(TALLOC_CTX *mem_ctx,
                        struct sss_domain_info *domain,
                        struct ldb_message *msg,
                        const char *name,
                        struct sized_string **_aliases,
                        uint32_t *_num_aliases)
{
    struct ldb_message_element *el;
    struct sized_string *aliases = NULL;
    uint32_t num_aliases;
    const char *alias;
    errno_t ret;
    int i;

    el = ldb_msg_find_element(msg, SYSDB_NAME_ALIAS);
    if (el == NULL) {
        *_num_aliases = 0;
        *_aliases = NULL;
        ret = EOK;
        goto done;
    }

    aliases = talloc_zero_array(mem_ctx, struct sized_string,
                                el->num_values + 1);
    if (aliases == NULL) {
        ret = ENOMEM;
        goto done;
    }

    num_aliases = 0;
    for (i = 0; i < el->num_values; i++) {
        alias = (const char *)el->values[i].data;

        if (sss_string_equal(domain->case_sensitive, alias, name)) {
            continue;
        }

        /* Element value remains in the message, we don't need to strdup it. */
        to_sized_string(&aliases[num_aliases], alias);
        num_aliases++;
    }

    *_aliases = aliases;
    *_num_aliases = num_aliases;

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(aliases);
    }

    return ret;
}

errno_t
sss_nss_protocol_fill_svcent(struct sss_nss_ctx *nss_ctx,
                             struct sss_nss_cmd_ctx *cmd_ctx,
                             struct sss_packet *packet,
                             struct cache_req_result *result)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_message *msg;
    struct sized_string name;
    struct sized_string protocol;
    struct sized_string *aliases;
    uint32_t num_aliases;
    uint16_t port;
    uint32_t num_results;
    size_t rp;
    size_t body_len;
    uint8_t *body;
    int i;
    int j;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    /* First two fields (length and reserved), filled up later. */
    ret = sss_packet_grow(packet, 2 * sizeof(uint32_t));
    if (ret != EOK) {
        return ret;
    }

    rp = 2 * sizeof(uint32_t);

    num_results = 0;
    for (i = 0; i < result->count; i++) {
        talloc_free_children(tmp_ctx);
        msg = result->msgs[i];

        ret = sss_nss_get_svcent(tmp_ctx, result->domain, msg,
                             cmd_ctx->svc_protocol, &name, &protocol, &port);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Unable to get service information, skipping... [%d]: %s\n",
                  ret, sss_strerror(ret));
            continue;
        }

        ret = sss_nss_get_svc_aliases(tmp_ctx, result->domain, msg, name.str,
                                  &aliases, &num_aliases);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Unable to get service aliases, skipping... [%d]: %s\n",
                  ret, sss_strerror(ret));
            continue;
        }

        /* Adjust packet size. */

        ret = sss_packet_grow(packet, 2 * sizeof(uint16_t) + sizeof(uint32_t)
                                          + name.len + protocol.len);
        if (ret != EOK) {
            goto done;
        }

        sss_packet_get_body(packet, &body, &body_len);

        /* Fill packet. */

        SAFEALIGN_SET_UINT32(&body[rp], (uint32_t)htons(port), &rp);
        SAFEALIGN_SET_UINT32(&body[rp], num_aliases, &rp);
        SAFEALIGN_SET_STRING(&body[rp], name.str, name.len, &rp);
        SAFEALIGN_SET_STRING(&body[rp], protocol.str, protocol.len, &rp);

        /* Store aliases. */
        for (j = 0; j < num_aliases; j++) {
            ret = sss_packet_grow(packet, aliases[j].len);
            if (ret != EOK) {
                goto done;
            }
            sss_packet_get_body(packet, &body, &body_len);

            SAFEALIGN_SET_STRING(&body[rp], aliases[j].str, aliases[j].len,
                                 &rp);
        }

        num_results++;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    if (ret != EOK) {
        sss_packet_set_size(packet, 0);
        return ret;
    }

    sss_packet_get_body(packet, &body, &body_len);
    SAFEALIGN_COPY_UINT32(body, &num_results, NULL);
    SAFEALIGN_SETMEM_UINT32(body + sizeof(uint32_t), 0, NULL); /* reserved */

    return EOK;
}
