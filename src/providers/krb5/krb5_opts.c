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

#include "src/providers/data_provider.h"

struct dp_option default_krb5_opts[] = {
    { "krb5_server", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_backup_server", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_realm", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_ccachedir", DP_OPT_STRING, { DEFAULT_CCACHE_DIR }, NULL_STRING },
    { "krb5_ccname_template", DP_OPT_STRING, NULL_STRING, NULL_STRING},
    { "krb5_auth_timeout", DP_OPT_NUMBER, { .number = 6 }, NULL_NUMBER },
    { "krb5_keytab", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_validate", DP_OPT_BOOL, BOOL_FALSE, BOOL_FALSE },
    { "krb5_kpasswd", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_backup_kpasswd", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_store_password_if_offline", DP_OPT_BOOL, BOOL_FALSE, BOOL_FALSE },
    { "krb5_renewable_lifetime", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_lifetime", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_renew_interval", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_use_fast", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_fast_principal", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_fast_use_anonymous_pkinit", DP_OPT_BOOL, BOOL_FALSE, BOOL_FALSE },
    { "krb5_canonicalize", DP_OPT_BOOL, BOOL_FALSE, BOOL_FALSE },
    { "krb5_use_enterprise_principal", DP_OPT_BOOL, BOOL_FALSE, BOOL_FALSE },
    { "krb5_use_kdcinfo", DP_OPT_BOOL, BOOL_TRUE, BOOL_TRUE },
    { "krb5_kdcinfo_lookahead", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_map_user", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "krb5_use_subdomain_realm", DP_OPT_BOOL, BOOL_FALSE, BOOL_FALSE },
    DP_OPTION_TERMINATOR
};
