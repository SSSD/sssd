/*
    SSSD

    IdP Provider Options

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2024 Red Hat

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

#include "src/providers/data_provider.h"

struct dp_option default_idp_opts[] = {
    { "idp_request_timeout", DP_OPT_NUMBER, { .number = 10 }, NULL_NUMBER },
    { "idp_type", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "idp_client_id", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { CONFDB_IDP_CLIENT_SECRET, DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "idp_token_endpoint", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "idp_device_auth_endpoint", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "idp_userinfo_endpoint", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "idp_id_scope", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "idp_auth_scope", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "idmap_range_min", DP_OPT_NUMBER, { .number = 200000 }, NULL_NUMBER },
    { "idmap_range_max", DP_OPT_NUMBER, { .number = 2000200000LL }, NULL_NUMBER },
    { "idmap_range_size", DP_OPT_NUMBER, { .number = 200000 }, NULL_NUMBER },
    DP_OPTION_TERMINATOR
};
