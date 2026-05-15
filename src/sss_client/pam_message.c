/*
    Authors:
        Sumit Bose <sbose@redhat.com>

    PAM client - create message blob

    Copyright (C) 2015 Red Hat

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdlib.h>
#include <security/pam_modules.h>

#include "sss_pam_compat.h"
#include "sss_pam_macros.h"

#include "pam_message.h"

#include "sss_cli.h"

static size_t add_authtok_item(enum pam_item_type type,
                               enum sss_authtok_type authtok_type,
                               const char *tok, const size_t size,
                               uint8_t *buf)
{
    size_t rp = 0;
    uint32_t c;

    if (tok == NULL) return 0;

    c = type;
    memcpy(&buf[rp], &c, sizeof(uint32_t));
    rp += sizeof(uint32_t);

    c = size + sizeof(uint32_t);
    memcpy(&buf[rp], &c, sizeof(uint32_t));
    rp += sizeof(uint32_t);

    c = authtok_type;
    memcpy(&buf[rp], &c, sizeof(uint32_t));
    rp += sizeof(uint32_t);

    memcpy(&buf[rp], tok, size);
    rp += size;

    return rp;
}

static size_t add_uint32_t_item(enum pam_item_type type, const uint32_t val,
                                uint8_t *buf)
{
    size_t rp = 0;
    uint32_t c;

    c = type;
    memcpy(&buf[rp], &c, sizeof(uint32_t));
    rp += sizeof(uint32_t);

    c = sizeof(uint32_t);
    memcpy(&buf[rp], &c, sizeof(uint32_t));
    rp += sizeof(uint32_t);

    c = val;
    memcpy(&buf[rp], &c, sizeof(uint32_t));
    rp += sizeof(uint32_t);

    return rp;
}

static size_t add_string_item(enum pam_item_type type, const char *str,
                              const size_t size, uint8_t *buf)
{
    size_t rp = 0;
    uint32_t c;

    if (str == NULL || *str == '\0') return 0;

    c = type;
    memcpy(&buf[rp], &c, sizeof(uint32_t));
    rp += sizeof(uint32_t);

    c = size;
    memcpy(&buf[rp], &c, sizeof(uint32_t));
    rp += sizeof(uint32_t);

    memcpy(&buf[rp], str, size);
    rp += size;

    return rp;
}

int pack_message_v3(struct pam_items *pi, size_t *size, uint8_t **buffer)
{
    int len;
    uint8_t *buf;
    size_t rp;

    len = sizeof(uint32_t) + sizeof(uint32_t);

    len +=  *pi->pam_user != '\0' ?
                2*sizeof(uint32_t) + pi->pam_user_size : 0;
    len += *pi->pam_service != '\0' ?
                2*sizeof(uint32_t) + pi->pam_service_size : 0;
    len += *pi->pam_tty != '\0' ?
                2*sizeof(uint32_t) + pi->pam_tty_size : 0;
    len += *pi->pam_ruser != '\0' ?
                2*sizeof(uint32_t) + pi->pam_ruser_size : 0;
    len += *pi->pam_rhost != '\0' ?
                2*sizeof(uint32_t) + pi->pam_rhost_size : 0;
    len += pi->pam_authtok != NULL ?
                3*sizeof(uint32_t) + pi->pam_authtok_size : 0;
    len += pi->pam_newauthtok != NULL ?
                3*sizeof(uint32_t) + pi->pam_newauthtok_size : 0;
    len += 3*sizeof(uint32_t); /* cli_pid */

    len += *pi->requested_domains != '\0' ?
                2*sizeof(uint32_t) + pi->requested_domains_size : 0;
    len += 3*sizeof(uint32_t); /* flags */
    len += *pi->json_auth_msg != '\0' ?
            2*sizeof(uint32_t) + pi->json_auth_msg_size : 0;
    len += *pi->json_auth_selected != '\0' ?
            2*sizeof(uint32_t) + pi->json_auth_selected_size : 0;

    /* optional child_pid */
    if(pi->child_pid > 0) {
        len += 3*sizeof(uint32_t);
    }

    buf = malloc(len);
    if (buf == NULL) {
        D(("malloc failed."));
        return PAM_BUF_ERR;
    }

    rp = 0;
    SAFEALIGN_SETMEM_UINT32(buf, SSS_START_OF_PAM_REQUEST, &rp);

    rp += add_string_item(SSS_PAM_ITEM_USER, pi->pam_user, pi->pam_user_size,
                          &buf[rp]);

    rp += add_string_item(SSS_PAM_ITEM_SERVICE, pi->pam_service,
                          pi->pam_service_size, &buf[rp]);

    rp += add_string_item(SSS_PAM_ITEM_TTY, pi->pam_tty, pi->pam_tty_size,
                          &buf[rp]);

    rp += add_string_item(SSS_PAM_ITEM_RUSER, pi->pam_ruser, pi->pam_ruser_size,
                          &buf[rp]);

    rp += add_string_item(SSS_PAM_ITEM_RHOST, pi->pam_rhost, pi->pam_rhost_size,
                          &buf[rp]);

    rp += add_string_item(SSS_PAM_ITEM_REQUESTED_DOMAINS, pi->requested_domains, pi->requested_domains_size,
                          &buf[rp]);

    rp += add_uint32_t_item(SSS_PAM_ITEM_CLI_PID, (uint32_t) pi->cli_pid,
                            &buf[rp]);

    if (pi->child_pid > 0) {
        rp += add_uint32_t_item(SSS_PAM_ITEM_CHILD_PID,
                                (uint32_t) pi->child_pid, &buf[rp]);
    }

    rp += add_authtok_item(SSS_PAM_ITEM_AUTHTOK, pi->pam_authtok_type,
                           pi->pam_authtok, pi->pam_authtok_size, &buf[rp]);

    rp += add_authtok_item(SSS_PAM_ITEM_NEWAUTHTOK, pi->pam_newauthtok_type,
                           pi->pam_newauthtok, pi->pam_newauthtok_size,
                           &buf[rp]);

    rp += add_uint32_t_item(SSS_PAM_ITEM_FLAGS, (uint32_t) pi->flags,
                            &buf[rp]);
    rp += add_string_item(SSS_PAM_ITEM_JSON_AUTH_INFO, pi->json_auth_msg,
                          pi->json_auth_msg_size, &buf[rp]);
    rp += add_string_item(SSS_PAM_ITEM_JSON_AUTH_SELECTED, pi->json_auth_selected,
                          pi->json_auth_selected_size, &buf[rp]);

    SAFEALIGN_SETMEM_UINT32(buf + rp, SSS_END_OF_PAM_REQUEST, &rp);

    if (rp != len) {
        D(("error during packet creation."));
        free(buf);
        return PAM_BUF_ERR;
    }

    *size = len;
    *buffer = buf;

    return 0;
}
