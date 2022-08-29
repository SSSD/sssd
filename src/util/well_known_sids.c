/*
    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2013 Red Hat

    Translate well-known SIDs to domains and names

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

#include <ctype.h>
#include "util/util.h"
#include "util/strtonum.h"

/* Well-Known SIDs are documented in section 2.4.2.4 "Well-Known SID
 * Structures" of the "[MS-DTYP]: Windows Data Types" document. */

#define DOM_SID_PREFIX "S-1-5-21-"
#define DOM_SID_PREFIX_LEN (sizeof(DOM_SID_PREFIX) - 1)

#define BUILTIN_SID_PREFIX "S-1-5-32-"
#define BUILTIN_SID_PREFIX_LEN (sizeof(BUILTIN_SID_PREFIX) - 1)
#define BUILTIN_DOM_NAME "BUILTIN"

#define NT_SID_PREFIX "S-1-5-"
#define NT_SID_PREFIX_LEN (sizeof(NT_SID_PREFIX) - 1)
#define NT_DOM_NAME "NT AUTHORITY"

#define NT_AUTH_SID_PREFIX "S-1-5-64-"
#define NT_AUTH_SID_PREFIX_LEN (sizeof(NT_AUTH_SID_PREFIX) - 1)
#define NT_AUTH_DOM_NAME NT_DOM_NAME

#define NT_THIS_SID_PREFIX "S-1-5-65-"
#define NT_THIS_SID_PREFIX_LEN (sizeof(NT_THIS_SID_PREFIX) - 1)
#define NT_THIS_DOM_NAME NT_DOM_NAME

#define SPECIAL_SID_PREFIX "S-1-"
#define SPECIAL_SID_PREFIX_LEN (sizeof(SPECIAL_SID_PREFIX) - 1)
#define NULL_DOM_NAME "NULL AUTHORITY"
#define WORLD_DOM_NAME "WORLD AUTHORITY"
#define LOCAL_DOM_NAME "LOCAL AUTHORITY"
#define CREATOR_DOM_NAME "CREATOR AUTHORITY"
#define MANDATORY_DOM_NAME "MANDATORY LABEL AUTHORITY"
#define AUTHENTICATION_DOM_NAME "AUTHENTICATION AUTHORITY"

#define NT_MAP_ENTRY(rid, name) {rid, NT_SID_PREFIX #rid, name}
#define NT_AUTH_MAP_ENTRY(rid, name) {rid, NT_AUTH_SID_PREFIX #rid, name}
#define NT_THIS_MAP_ENTRY(rid, name) {rid, NT_THIS_SID_PREFIX #rid, name}
#define BUILTIN_MAP_ENTRY(rid, name) {rid, BUILTIN_SID_PREFIX #rid, name}
#define SPECIAL_MAP_ENTRY(id_auth, rid, dom, name) \
   {id_auth, rid, SPECIAL_SID_PREFIX #id_auth "-" #rid, dom, name}

struct rid_sid_name {
    uint32_t rid;
    const char *sid;
    const char *name;
};

struct special_map {
    uint32_t id_auth;
    uint32_t rid;
    const char *sid;
    const char *dom;
    const char *name;
};

struct rid_sid_name builtin_map[] = {
    BUILTIN_MAP_ENTRY(544, "Administrators"),
    BUILTIN_MAP_ENTRY(545, "Users"),
    BUILTIN_MAP_ENTRY(546, "Guests"),
    BUILTIN_MAP_ENTRY(547, "Power Users"),
    BUILTIN_MAP_ENTRY(548, "Account Operators"),
    BUILTIN_MAP_ENTRY(549, "Server Operators"),
    BUILTIN_MAP_ENTRY(550, "Print Operators"),
    BUILTIN_MAP_ENTRY(551, "Backup Operators"),
    BUILTIN_MAP_ENTRY(552, "Replicator"),
    BUILTIN_MAP_ENTRY(554, "Pre-Windows 2000 Compatible Access"),
    BUILTIN_MAP_ENTRY(555, "Remote Desktop Users"),
    BUILTIN_MAP_ENTRY(556, "Network Configuration Operators"),
    BUILTIN_MAP_ENTRY(557, "Incoming Forest Trust Builders"),
    BUILTIN_MAP_ENTRY(558, "Performance Monitor Users"),
    BUILTIN_MAP_ENTRY(559, "Performance Log Users"),
    BUILTIN_MAP_ENTRY(560, "Windows Authorization Access Group"),
    BUILTIN_MAP_ENTRY(561, "Terminal Server License Servers"),
    BUILTIN_MAP_ENTRY(562, "Distributed COM Users"),
    BUILTIN_MAP_ENTRY(568, "IIS Users"),
    BUILTIN_MAP_ENTRY(569, "Cryptographic Operators"),
    BUILTIN_MAP_ENTRY(573, "Event Log Readers"),
    BUILTIN_MAP_ENTRY(574, "Certificate Service DCOM Access"),
    BUILTIN_MAP_ENTRY(575, "RDS Remote Access Servers"),
    BUILTIN_MAP_ENTRY(576, "RDS Endpoint Servers"),
    BUILTIN_MAP_ENTRY(577, "RDS Management Servers"),
    BUILTIN_MAP_ENTRY(578, "Hyper-V Admins"),
    BUILTIN_MAP_ENTRY(579, "Access Control Assistance OPS"),
    BUILTIN_MAP_ENTRY(580, "Remote Management Users"),

    {UINT32_MAX, NULL, NULL}
};

#define LOGON_ID_NAME  "LOGON ID"
#define LOGON_ID_MODEL "S-1-5-5-0-0"
struct rid_sid_name nt_map[] = {
    NT_MAP_ENTRY(1, "DIALUP"),
    NT_MAP_ENTRY(2, "NETWORK"),
    NT_MAP_ENTRY(3, "BATCH"),
    NT_MAP_ENTRY(4, "INTERACTIVE"),
    /* NT_MAP_ENTRY(5-x-y, "LOGON ID"),  special case treated separately */
    NT_MAP_ENTRY(6, "SERVICE"),
    NT_MAP_ENTRY(7, "ANONYMOUS LOGON"),
    NT_MAP_ENTRY(8, "PROXY"),
    NT_MAP_ENTRY(9, "ENTERPRISE DOMAIN CONTROLLERS"),
    NT_MAP_ENTRY(10, "SELF"),
    NT_MAP_ENTRY(11, "Authenticated Users"),
    NT_MAP_ENTRY(12, "RESTRICTED CODE"),
    NT_MAP_ENTRY(13, "TERMINAL SERVER USER"),
    NT_MAP_ENTRY(14, "REMOTE INTERACTIVE LOGON"),
    NT_MAP_ENTRY(15, "This Organization"),
    NT_MAP_ENTRY(17, "IUSR"),
    NT_MAP_ENTRY(18, "LOCAL SYSTEM"),
    NT_MAP_ENTRY(19, "LOCAL SERVICE"),
    NT_MAP_ENTRY(20, "NETWORK SERVICE"),
    NT_MAP_ENTRY(33, "WRITE_RESTRICTED_CODE"),
    NT_MAP_ENTRY(80, "NT_SERVICE"),
    NT_MAP_ENTRY(113, "LOCAL_ACCOUNT"),
    NT_MAP_ENTRY(114, "LOCAL MEMBER OF ADMINISTRATORS GROUP"),
    NT_MAP_ENTRY(1000, "OTHER_ORGANIZATIONS"),

    {UINT32_MAX, NULL, NULL}
};

struct rid_sid_name nt_auth_map[] = {
    NT_AUTH_MAP_ENTRY(10, "NTLM AUTHENTICATION"),
    NT_AUTH_MAP_ENTRY(14, "SCHANNEL AUTHENTICATION"),
    NT_AUTH_MAP_ENTRY(21, "DIGEST AUTHENTICATION"),

    {UINT32_MAX, NULL, NULL}
};

struct rid_sid_name nt_this_map[] = {
    NT_THIS_MAP_ENTRY(1, "THIS ORGANIZATION CERTIFICATE"),

    {UINT32_MAX, NULL, NULL}
};

struct special_map sp_map[] = {
    SPECIAL_MAP_ENTRY(0, 0, NULL_DOM_NAME, "NULL SID"),
    SPECIAL_MAP_ENTRY(1, 0, WORLD_DOM_NAME, "Everyone"),
    SPECIAL_MAP_ENTRY(2, 0, LOCAL_DOM_NAME, "LOCAL"),
    SPECIAL_MAP_ENTRY(2, 1, LOCAL_DOM_NAME, "CONSOLE LOGON"),
    SPECIAL_MAP_ENTRY(3, 0, CREATOR_DOM_NAME, "CREATOR OWNER"),
    SPECIAL_MAP_ENTRY(3, 1, CREATOR_DOM_NAME, "CREATOR GROUP"),
    SPECIAL_MAP_ENTRY(3, 2, CREATOR_DOM_NAME, "CREATOR OWNER SERVER"),
    SPECIAL_MAP_ENTRY(3, 3, CREATOR_DOM_NAME, "CREATOR GROUP SERVER"),
    SPECIAL_MAP_ENTRY(3, 4, CREATOR_DOM_NAME, "OWNER RIGHTS"),
    SPECIAL_MAP_ENTRY(16, 0, MANDATORY_DOM_NAME, "UNTRUSTED"),
    SPECIAL_MAP_ENTRY(16, 4096, MANDATORY_DOM_NAME, "LOW"),
    SPECIAL_MAP_ENTRY(16, 8192, MANDATORY_DOM_NAME, "MEDIUM"),
    SPECIAL_MAP_ENTRY(16, 8448, MANDATORY_DOM_NAME, "MEDIUM_PLUS"),
    SPECIAL_MAP_ENTRY(16, 12288, MANDATORY_DOM_NAME, "HIGH"),
    SPECIAL_MAP_ENTRY(16, 16384, MANDATORY_DOM_NAME, "SYSTEM"),
    SPECIAL_MAP_ENTRY(16, 20480, MANDATORY_DOM_NAME, "PROTECTED_PROCESS"),
    SPECIAL_MAP_ENTRY(16, 28672, MANDATORY_DOM_NAME, "SECURE_PROCESS"),
    SPECIAL_MAP_ENTRY(18, 1, AUTHENTICATION_DOM_NAME, "AUTHENTICATION ASSERTION"),
    SPECIAL_MAP_ENTRY(18, 2, AUTHENTICATION_DOM_NAME, "SERVICE ASSERTION"),
    SPECIAL_MAP_ENTRY(18, 3, AUTHENTICATION_DOM_NAME, "FRESH_PUBLIC_KEY_IDENTITY"),
    SPECIAL_MAP_ENTRY(18, 4, AUTHENTICATION_DOM_NAME, "KEY_TRUST_IDENTITY"),
    SPECIAL_MAP_ENTRY(18, 5, AUTHENTICATION_DOM_NAME, "KEY_PROPERTY_MFA"),
    SPECIAL_MAP_ENTRY(18, 6, AUTHENTICATION_DOM_NAME, "KEY_PROPERTY_ATTESTATION"),

    {'\0', '\0', NULL, NULL, NULL}
};

static errno_t handle_special_sids(const char *sid, const char **dom,
                                   const char **name)
{
    size_t c;
    uint32_t rid;
    uint32_t id_auth;
    char *endptr;

    id_auth = strtouint32(sid + SPECIAL_SID_PREFIX_LEN, &endptr, 10);
    if (errno != 0 || *endptr != '-' || *(endptr + 1) == '\0') {
        return EINVAL;
    }

    rid = strtouint32(endptr + 1, &endptr, 10);
    if (errno != 0 || *endptr != '\0') {
        return EINVAL;
    }

    for (c = 0; sp_map[c].name != NULL; c++) {
        if (id_auth == sp_map[c].id_auth && rid == sp_map[c].rid) {
            *name = sp_map[c].name;
            *dom = sp_map[c].dom;
            return EOK;
        }
    }

    return EINVAL;
}

static errno_t handle_special_names(const char *dom, const char *name,
                                    const char **sid)
{
    size_t c;

    for (c = 0; sp_map[c].name != NULL; c++) {
        if (strcmp(name, sp_map[c].name) == 0
                && strcmp(dom, sp_map[c].dom) == 0) {
            *sid = sp_map[c].sid;
            return EOK;
        }
    }

    return EINVAL;
}

static errno_t handle_rid_to_name_map(const char *sid, size_t prefix_len,
                                      struct rid_sid_name *map,
                                      const char* dom_name, const char **dom,
                                      const char **name)
{
    uint32_t rid;
    char *endptr;
    size_t c;

    rid = (uint32_t) strtouint32(sid + prefix_len, &endptr, 10);
    if (errno != 0 || *endptr != '\0') {
        return EINVAL;
    }

    for (c = 0; map[c].name != NULL; c++) {
        if (rid == map[c].rid) {
            *name = map[c].name;
            *dom = dom_name;
            return EOK;
        }
    }

    return EINVAL;
}

static errno_t handle_name_to_sid_map(const char *name,
                                      struct rid_sid_name *map,
                                      const char **sid)
{
    size_t c;

    for (c = 0; map[c].name != NULL; c++) {
        if (strcmp(name, map[c].name) == 0) {
            *sid = map[c].sid;
            return EOK;
        }
    }

    return EINVAL;
}

/* This function treats a particular case that does not fit in the normal table */
static errno_t handle_nt_sids_particular_cases(const char *sid,
                                               const char **dom,
                                               const char **name)
{
    uint32_t rid;
    char *endptr;
    char *startptr;
    int i;

    rid = (uint32_t) strtouint32(sid + NT_SID_PREFIX_LEN, &endptr, 10);
    if (errno != 0) {
        return EINVAL;
    }

    if (rid == 5) {
        /* S-1-5-5-x-y, we can ignore x and y, but they must be present.
         * The x and y values for these SIDs are different for each logon
         * session and are recycled when the operating system is restarted. */
        for (i = 1; i <= 2; i++) {
            if (*endptr != '-') {
                return EINVAL;
            }

            startptr = endptr + 1;
            (void) strtouint32(startptr, &endptr, 10);
            if (errno != 0 || startptr == endptr) {
                return EINVAL;
            }
        }
        if (*endptr != '\0') {
            return EINVAL;
        }

        *dom = NT_DOM_NAME;
        *name = LOGON_ID_NAME;
        return EOK;
    }

    return EINVAL;
}

static errno_t handle_nt_particular_cases(const char *name, const char **sid)
{


    if (strcmp(name, LOGON_ID_NAME) == 0) {
        /* We return a model because the SID includes variable data */
        *sid = LOGON_ID_MODEL;
        return EOK;
    }

    return EINVAL;
}

static errno_t handle_nt_auth_sids(const char *sid, const char **dom,
                                   const char **name)
{
    return handle_rid_to_name_map(sid, NT_AUTH_SID_PREFIX_LEN, nt_auth_map,
                                  NT_AUTH_DOM_NAME, dom, name);
}

static errno_t handle_nt_auth_names(const char *name, const char **sid)
{
    return handle_name_to_sid_map(name, nt_auth_map, sid);
}

static errno_t handle_nt_this_sids(const char *sid, const char **dom,
                                   const char **name)
{
    return handle_rid_to_name_map(sid, NT_THIS_SID_PREFIX_LEN, nt_this_map,
                                  NT_THIS_DOM_NAME, dom, name);
}

static errno_t handle_nt_this_names(const char *name, const char **sid)
{
    return handle_name_to_sid_map(name, nt_this_map, sid);
}

static errno_t handle_nt_sids(const char *sid, const char **dom,
                              const char **name)
{
    errno_t ret;

    ret = handle_rid_to_name_map(sid, NT_SID_PREFIX_LEN, nt_map, NT_DOM_NAME,
                                 dom, name);
    if (ret == EINVAL) {
        // These are a particular cases that need to be treated separately
        ret = handle_nt_sids_particular_cases(sid, dom, name);
    }

    return ret;
}

static errno_t handle_nt_names(const char *name, const char **sid)
{
    return handle_name_to_sid_map(name, nt_map, sid);
}

static errno_t handle_builtin_sids(const char *sid, const char **dom,
                                   const char **name)
{
    return handle_rid_to_name_map(sid, BUILTIN_SID_PREFIX_LEN, builtin_map,
                                  BUILTIN_DOM_NAME, dom, name);
}

static errno_t handle_builtin_names(const char *name, const char **sid)
{
    return handle_name_to_sid_map(name, builtin_map, sid);
}

errno_t well_known_sid_to_name(const char *sid, const char **dom,
                               const char **name)
{
    int ret;

    if (sid == NULL || dom == NULL || name == NULL) {
        return EINVAL;
    }

    if (strncmp(sid, DOM_SID_PREFIX, DOM_SID_PREFIX_LEN) == 0) {
        ret = ENOENT;
    } else if (strncmp(sid, BUILTIN_SID_PREFIX, BUILTIN_SID_PREFIX_LEN) == 0) {
        ret = handle_builtin_sids(sid, dom, name);
        if (ret != EOK) {
            DEBUG(SSSDBG_IMPORTANT_INFO,
                  "handle_builtin_sids failed for SID: %s\n", sid);
        }
    } else if (strncmp(sid, NT_AUTH_SID_PREFIX, NT_AUTH_SID_PREFIX_LEN) == 0) {
        ret = handle_nt_auth_sids(sid, dom, name);
        if (ret != EOK) {
            DEBUG(SSSDBG_IMPORTANT_INFO,
                  "handle_nt_auth_sids failed for SID: %s\n", sid);
        }
    } else if (strncmp(sid, NT_THIS_SID_PREFIX, NT_THIS_SID_PREFIX_LEN) == 0) {
        ret = handle_nt_this_sids(sid, dom, name);
        if (ret != EOK) {
            DEBUG(SSSDBG_IMPORTANT_INFO,
                  "handle_nt_this_sids failed for SID: %s\n", sid);
        }
    } else if (strncmp(sid, NT_SID_PREFIX, NT_SID_PREFIX_LEN) == 0) {
        ret = handle_nt_sids(sid, dom, name);
        if (ret != EOK) {
            DEBUG(SSSDBG_IMPORTANT_INFO,
                  "handle_nt_sids failed for SID: %s\n", sid);
        }
    } else if (strncmp(sid, SPECIAL_SID_PREFIX, SPECIAL_SID_PREFIX_LEN) == 0) {
        ret = handle_special_sids(sid, dom, name);
        if (ret != EOK) {
            DEBUG(SSSDBG_IMPORTANT_INFO,
                  "handle_special_sids failed for SID: %s\n", sid);
        }
    } else {
        ret = EINVAL;
    }

    return ret;
}

errno_t name_to_well_known_sid(const char *dom, const char *name,
                               const char **sid)
{
    int ret;

    if (sid == NULL || dom == NULL || name == NULL) {
        return EINVAL;
    }

    if (strcmp(dom, NT_DOM_NAME) == 0) {
        /* NT_DOM_NAME == NT_AUTH_DOM_NAME == NT_THIS_DOM_NAME */
        ret = handle_nt_names(name, sid);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "handle_nt_name failed.\n");
            ret = handle_nt_auth_names(name, sid);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "handle_nt_auth_names failed.\n");
                ret = handle_nt_this_names(name, sid);
                if (ret != EOK) {
                    DEBUG(SSSDBG_OP_FAILURE, "handle_nt_this_names failed.\n");
                    ret = handle_nt_particular_cases(name, sid);
                    if (ret != EOK) {
                        DEBUG(SSSDBG_OP_FAILURE,
                              "handle_nt_particular_cases failed.\n");
                    }
                }
            }
        }
    } else if (strcmp(dom, BUILTIN_DOM_NAME) == 0) {
        ret = handle_builtin_names(name, sid);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "handle_builtin_name failed.\n");
        }
    } else if (strcmp(dom, NULL_DOM_NAME) == 0
                || strcmp(dom, WORLD_DOM_NAME) == 0
                || strcmp(dom, LOCAL_DOM_NAME) == 0
                || strcmp(dom, CREATOR_DOM_NAME) == 0
                || strcmp(dom, MANDATORY_DOM_NAME) == 0
                || strcmp(dom, AUTHENTICATION_DOM_NAME) == 0) {
        ret = handle_special_names(dom, name, sid);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "handle_special_name failed.\n");
        }
    } else {
        ret = ENOENT;
    }

    return ret;
}
