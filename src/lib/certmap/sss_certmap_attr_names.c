/*
    SSSD

    Library for rule based certificate to user mapping - Attribute name
    mapping for different implementations

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2017 Red Hat

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

/* NSS data taken from nss-utils:nss/lib/util/secoid.c and
 * nss:nss/lib/certdb/alg1485.c */

/* AD data taken from
 * https://msdn.microsoft.com/en-us/library/windows/desktop/aa376556%28v=vs.85%29.aspx
 * and wine source code dlls/crypt32/oid.c  and include/wincrypt.h . */

#include <stdbool.h>
#include <string.h>
#include <talloc.h>

struct oid_attr_name_map {
    bool nss_ad_differ;
    const char *oid;
    const char *nss;
    const char *ad;
} oid_attr_name_map[] = {
    { false, "2.5.4.3",                    "CN",                  "CN"},
    { true,  "2.5.4.8",                    "ST",                  "S"},
    { false, "2.5.4.10",                   "O",                   "O"},
    { false, "2.5.4.11",                   "OU",                  "OU"},
    { false, "2.5.4.46",                   "dnQualifier",         "dnQualifier"},
    { false, "2.5.4.6",                    "C",                   "C"},
    { true,  "2.5.4.5",                    "serialNumber",        "SERIALNUMBER"},
    { false, "2.5.4.7",                    "L",                   "L"},
    { true,  "2.5.4.12",                   "title",               "T"},
    { false, "2.5.4.4",                    "SN",                  "SN"},
    { true,  "2.5.4.42",                   "givenName",           "G"},
    { true,  "2.5.4.43",                   "initials",            "I"},
    { true,  "2.5.4.44",                   "generationQualifier", "OID.2.5.4.44"},
    { false, "0.9.2342.19200300.100.1.25", "DC",                  "DC"},
    { true,  "0.9.2342.19200300.100.1.3",  "MAIL",                "OID,0.9.2342.19200300.100.1.3"},
    { true,  "0.9.2342.19200300.100.1.1",  "UID",                 "OID.0.9.2342.19200300.100.1.1"},
    { true,  "2.5.4.13",                    "OID.2.5.4.13",       "Description"},
    { true,  "2.5.4.16",                   "postalAddress",       "OID.2.5.4.16"},
    { true,  "2.5.4.17",                   "postalCode",          "PostalCode"},
    { true,  "2.5.4.18",                   "postOfficeBox",       "POBox"},
    { true,  "2.5.4.51",                   "houseIdentifier",     "OID.2.5.4.51"},
    { false, "1.2.840.113549.1.9.1",       "E",                   "E"},
    { false, "2.5.4.9",                    "STREET",              "STREET"},
    { true,  "2.5.4.65",                   "pseudonym",           "OID.2.5.4.65"},
    { true,  "2.5.4.15",                   "businessCategory",    "OID.2.5.4.15"},
    { true,  "2.5.4.41",                   "name",                "OID.2.5.4.41"},

    { false, NULL, NULL, NULL}
};

char *check_ad_attr_name(TALLOC_CTX *mem_ctx, const char *rdn)
{
    char *p;
    size_t c;
    size_t len;

    if (rdn == NULL) {
        return NULL;
    }

    p = strchr(rdn, '=');
    if (p == NULL) {
        return NULL;
    }

    len = p - rdn;
    if (len == 0) {
        return NULL;
    }

    for (c = 0; oid_attr_name_map[c].oid != NULL; c++) {
        if (!oid_attr_name_map[c].nss_ad_differ) {
            continue;
        }

        if (strlen(oid_attr_name_map[c].nss) != len
                    || strncmp(rdn, oid_attr_name_map[c].nss, len) != 0) {
            continue;
        }

        return talloc_asprintf(mem_ctx, "%s%s", oid_attr_name_map[c].ad, p);
    }

    return NULL;
}
