/*
   Unix SMB/CIFS implementation.

   Winbind client API - SSSD version

   Copyright (C) Sumit Bose <sbose@redhat.com> 2014

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
/* Required Headers */

#include "libwbclient.h"
#include "wbc_sssd_internal.h"

#define WINBIND_INTERFACE_VERSION 27

/** @brief Ping winbindd to see if the daemon is running
 *
 * @return #wbcErr
 **/
wbcErr wbcPing(void)
{
    /* TODO: add real check */
    return WBC_ERR_SUCCESS;
}

static void wbcInterfaceDetailsDestructor(void *ptr)
{
    struct wbcInterfaceDetails *i = (struct wbcInterfaceDetails *)ptr;
    free(i->winbind_version);
    free(i->netbios_name);
    free(i->netbios_domain);
    free(i->dns_domain);
}

/**
 * @brief Query useful information about the winbind service
 *
 * @param *_details    pointer to hold the struct wbcInterfaceDetails
 *
 * @return #wbcErr
 */

wbcErr wbcInterfaceDetails(struct wbcInterfaceDetails **_details)
{
    wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
    struct wbcInterfaceDetails *info;
    info = (struct wbcInterfaceDetails *)wbcAllocateMemory(
        1, sizeof(struct wbcInterfaceDetails),
        wbcInterfaceDetailsDestructor);
    if (info == NULL) {
        return WBC_ERR_NO_MEMORY;
    }

    /* TODO: currently this call just returns a suitable winbind_separator
     * for wbinfo. */

    info->interface_version = WINBIND_INTERFACE_VERSION;
    info->winbind_version = strdup("libwbclient for SSSD");
    if (info->winbind_version == NULL) {
        wbc_status = WBC_ERR_NO_MEMORY;
        goto done;
    }

    info->winbind_separator = '\\';

    info->netbios_name = strdup("-not available-");
    if (info->netbios_name == NULL) {
        wbc_status = WBC_ERR_NO_MEMORY;
        goto done;
    }

    info->netbios_domain = strdup("-not available-");
    if (info->netbios_domain == NULL) {
        wbc_status = WBC_ERR_NO_MEMORY;
        goto done;
    }

    info->dns_domain = strdup("-not available-");
    if (info->dns_domain == NULL) {
        wbc_status = WBC_ERR_NO_MEMORY;
        goto done;
    }

    *_details = info;
    info = NULL;
    wbc_status = WBC_ERR_SUCCESS;
done:
    wbcFreeMemory(info);
    return wbc_status;
}

/** @brief Lookup the current status of a trusted domain, sync wrapper
 *
 * @param domain      Domain to query
 * @param *dinfo       Pointer to returned struct wbcDomainInfo
 *
 * @return #wbcErr
 */

wbcErr wbcDomainInfo(const char *domain, struct wbcDomainInfo **dinfo)
{
    WBC_SSSD_NOT_IMPLEMENTED;
}

/* Get the list of current DCs */
wbcErr wbcDcInfo(const char *domain, size_t *num_dcs,
         const char ***dc_names, const char ***dc_ips)
{
    WBC_SSSD_NOT_IMPLEMENTED;
}

/* Resolve a NetbiosName via WINS */
wbcErr wbcResolveWinsByName(const char *name, char **ip)
{
    /* SSSD does not support WINS */
    WBC_SSSD_NOT_IMPLEMENTED;
}

/* Resolve an IP address via WINS into a NetbiosName */
wbcErr wbcResolveWinsByIP(const char *ip, char **name)
{
    /* SSSD does not support WINS */
    WBC_SSSD_NOT_IMPLEMENTED;
}

/* Enumerate the domain trusts known by Winbind */
wbcErr wbcListTrusts(struct wbcDomainInfo **domains, size_t *num_domains)
{
    WBC_SSSD_NOT_IMPLEMENTED;
}

/* Enumerate the domain trusts known by Winbind */
wbcErr wbcLookupDomainController(const char *domain,
                 uint32_t flags,
                struct wbcDomainControllerInfo **dc_info)
{
    WBC_SSSD_NOT_IMPLEMENTED;
}

/* Get extended domain controller information */
wbcErr wbcLookupDomainControllerEx(const char *domain,
                   struct wbcGuid *guid,
                   const char *site,
                   uint32_t flags,
                   struct wbcDomainControllerInfoEx **dc_info)
{
    WBC_SSSD_NOT_IMPLEMENTED;
}
