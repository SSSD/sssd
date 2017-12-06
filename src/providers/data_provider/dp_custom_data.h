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
    char **rules;
};

struct dp_hostid_data {
    const char *name;
    const char *alias;
};

struct dp_autofs_data {
    const char *mapname;
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

/* Reply callbacks. */

void dp_req_reply_std(const char *request_name,
                      struct sbus_request *sbus_req,
                      struct dp_reply_std *reply);

#endif /* _DP_CUSTOM_DATA_H_ */
