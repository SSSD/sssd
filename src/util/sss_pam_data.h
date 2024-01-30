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

#ifndef _SSS_PAM_DATA_H_
#define _SSS_PAM_DATA_H_

#include "config.h"
#include <stdbool.h>
#include <stdint.h>
#ifdef USE_KEYRING
#include <sys/types.h>
#include <keyutils.h>
#endif

#include "util/util_errors.h"
#include "util/debug.h"
#include "util/authtok.h"

#define DEBUG_PAM_DATA(level, pd) do { \
    pam_print_data(level, pd); \
} while(0)

struct response_data {
    int32_t type;
    int32_t len;
    uint8_t *data;
    bool do_not_send_to_client;
    struct response_data *next;
};

struct pam_data {
    int cmd;
    char *domain;
    char *user;
    char *service;
    char *tty;
    char *ruser;
    char *rhost;
    char **requested_domains;
    struct sss_auth_token *authtok;
    struct sss_auth_token *newauthtok;
    uint32_t cli_pid;
    uint32_t child_pid;
    char *logon_name;
    uint32_t cli_flags;

    int pam_status;
    int response_delay;
    struct response_data *resp_list;

    bool offline_auth;
    bool last_auth_saved;
    int priv;
    int account_locked;

    uint32_t client_id_num;
#ifdef USE_KEYRING
    key_serial_t key_serial;
#endif
    bool passkey_local_done;
    char *json_auth_msg;
    char *json_auth_selected;
};

/**
 * @brief Create new zero initialized struct pam_data.
 *
 * @param mem_ctx    A memory context use to allocate the internal data
 * @return           A pointer to new struct pam_data
 *                   NULL on error
 *
 * NOTE: This function should be the only way, how to create new empty
 * struct pam_data, because this function automatically initialize sub
 * structures and set destructor to created object.
 */
struct pam_data *create_pam_data(TALLOC_CTX *mem_ctx);
errno_t copy_pam_data(TALLOC_CTX *mem_ctx, struct pam_data *old_pd,
                      struct pam_data **new_pd);
void pam_print_data(int l, struct pam_data *pd);
int pam_add_response(struct pam_data *pd,
                     enum response_type type,
                     int len, const uint8_t *data);

/**
 * @brief Get the selected response type data from the response_data linked
 *        list
 *
 * @param[in] mem_ctx Memory context
 * @param[in] pd Data structure containing the response_data linked list
 * @param[in] type Response type
 * @param[out] _buf Data wrapped inside response_data structure
 * @param[out] _len Data length
 *
 * @return 0 if the data was obtained properly,
 *         error code otherwise.
 */
errno_t
pam_get_response_data(TALLOC_CTX *mem_ctx, struct pam_data *pd, int32_t type,
                      uint8_t **_buf, int32_t *_len);

#endif /* _SSS_PAM_DATA_H_ */
