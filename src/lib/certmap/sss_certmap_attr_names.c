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

/* OpenSSL data taken from include/openssl/obj_mac.h */

#include <stdbool.h>
#include <string.h>
#include <talloc.h>

struct oid_attr_name_map {
    bool nss_ad_differ;
    bool nss_openssl_differ;
    const char *oid;
    const char *nss;
    const char *ad;
    const char *openssl;
} oid_attr_name_map[] = {
    { false, false, "2.5.4.3",                    "CN",                  "CN",                            "CN"},
    { true,  false, "2.5.4.8",                    "ST",                  "S",                             "ST"},
    { false, false, "2.5.4.10",                   "O",                   "O",                             "O"},
    { false, false, "2.5.4.11",                   "OU",                  "OU",                            "OU"},
    { false, false, "2.5.4.46",                   "dnQualifier",         "dnQualifier",                   "dnQualifier"},
    { false, false, "2.5.4.6",                    "C",                   "C",                             "C"},
    { true,  false, "2.5.4.5",                    "serialNumber",        "SERIALNUMBER",                  "serialNumber"},
    { false, false, "2.5.4.7",                    "L",                   "L",                             "L"},
    { true,  false, "2.5.4.12",                   "title",               "T",                             "title"},
    { false, false, "2.5.4.4",                    "SN",                  "SN",                            "SN"},
    { true,  true,  "2.5.4.42",                   "givenName",           "G",                             "GN"},
    { true,  false, "2.5.4.43",                   "initials",            "I",                             "initials"},
    { true,  false, "2.5.4.44",                   "generationQualifier", "OID.2.5.4.44",                  "generationQualifier"},
    { false, false, "0.9.2342.19200300.100.1.25", "DC",                  "DC",                            "DC"},
    { true,  true,  "0.9.2342.19200300.100.1.3",  "MAIL",                "OID,0.9.2342.19200300.100.1.3", "mail"},
    { true,  false, "0.9.2342.19200300.100.1.1",  "UID",                 "OID.0.9.2342.19200300.100.1.1", "UID"},
    { true,  true,  "2.5.4.13",                   "OID.2.5.4.13",        "Description",                   "description"},
    { true,  false, "2.5.4.16",                   "postalAddress",       "OID.2.5.4.16",                  "postalAddress"},
    { true,  false, "2.5.4.17",                   "postalCode",          "PostalCode",                    "postalCode"},
    { true,  false, "2.5.4.18",                   "postOfficeBox",       "POBox",                         "postOfficeBox"},
    { true,  false, "2.5.4.51",                   "houseIdentifier",     "OID.2.5.4.51",                  "houseIdentifier"},
    { false, true,  "1.2.840.113549.1.9.1",       "E",                   "E",                             "emailAddress"},
    { false, true,  "2.5.4.9",                    "STREET",              "STREET",                        "street"},
    { true,  false, "2.5.4.65",                   "pseudonym",           "OID.2.5.4.65",                  "pseudonym"},
    { true,  false, "2.5.4.15",                   "businessCategory",    "OID.2.5.4.15",                  "businessCategory"},
    { true,  false, "2.5.4.41",                   "name",                "OID.2.5.4.41",                  "name"},

    { false, false, NULL, NULL, NULL, NULL}
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

const char *openssl_2_nss_attr_name(const char *attr)
{
    size_t c;

    if (attr == NULL) {
        return NULL;
    }

    for (c = 0; oid_attr_name_map[c].oid != NULL; c++) {
        if (!oid_attr_name_map[c].nss_openssl_differ) {
            continue;
        }

        if (strcmp(attr, oid_attr_name_map[c].openssl) != 0) {
            continue;
        }

        return oid_attr_name_map[c].nss;
    }

    return attr;
}
