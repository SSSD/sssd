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

#ifndef _DP_CUSTOM_DATA_H_
#define _DP_CUSTOM_DATA_H_

#include "providers/data_provider/dp.h"

/* Request handler private data. */

struct dp_sudo_data {
    uint32_t type;
    const char **rules;
};

struct dp_hostid_data {
    const char *name;
    const char *alias;
};

struct dp_autofs_data {
    const char *mapname;
    const char *entryname;
};

struct dp_subdomains_data {
    const char *domain_hint;
};

struct dp_get_acct_domain_data {
    uint32_t entry_type;
    uint32_t filter_type;
    const char *filter_value;
};

struct dp_id_data {
    uint32_t entry_type;
    uint32_t filter_type;
    const char *filter_value;
    const char *extra_value;
    const char *domain;
};

struct dp_resolver_data {
    uint32_t filter_type;
    const char *filter_value;
};

/* Reply private data. */

struct dp_reply_std {
    int dp_error;
    int error;
    const char *message;
};

void dp_reply_std_set(struct dp_reply_std *reply,
                      int dp_error,
                      int error,
                      const char *msg);

void dp_req_reply_std(const char *request_name,
                      struct dp_reply_std *reply,
                      uint16_t *_dp_error,
                      uint32_t *_error,
                      const char **_message);

/* Convert pair of ret and dp_error to single ret value. */
errno_t dp_error_to_ret(errno_t ret, int dp_error);

#endif /* _DP_CUSTOM_DATA_H_ */
