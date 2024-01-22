/*
    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2015 Red Hat

    PAM client - create message blob

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

#ifndef _PAM_MESSAGE_H_
#define _PAM_MESSAGE_H_

#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>

#include "sss_client/sss_cli.h"

struct cert_auth_info;

struct pam_items {
    const char *pam_service;
    const char *pam_user;
    const char *pam_tty;
    const char *pam_ruser;
    const char *pam_rhost;
    char *pam_authtok;
    char *pam_newauthtok;
    const char *pamstack_authtok;
    const char *pamstack_oldauthtok;
    size_t pam_service_size;
    size_t pam_user_size;
    size_t pam_tty_size;
    size_t pam_ruser_size;
    size_t pam_rhost_size;
    enum sss_authtok_type pam_authtok_type;
    size_t pam_authtok_size;
    enum sss_authtok_type pam_newauthtok_type;
    size_t pam_newauthtok_size;
    pid_t cli_pid;
    pid_t child_pid;
    uint32_t flags;
    const char *login_name;
    char *domain_name;
    const char *requested_domains;
    size_t requested_domains_size;
    char *otp_vendor;
    char *otp_token_id;
    char *otp_challenge;
    char *oauth2_url;
    char *oauth2_url_complete;
    char *oauth2_pin;
    char *first_factor;
    char *passkey_key;
    char *passkey_prompt_pin;
    char *json_auth_msg;
    size_t json_auth_msg_size;
    const char *json_auth_selected;
    size_t json_auth_selected_size;
    bool password_prompting;

    bool user_name_hint;
    struct cert_auth_info *cert_list;
    struct cert_auth_info *selected_cert;

    struct prompt_config **pc;
};

int pack_message_v3(struct pam_items *pi, size_t *size, uint8_t **buffer);

#endif /* _PAM_MESSAGE_H_ */
