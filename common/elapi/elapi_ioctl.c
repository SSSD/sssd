/*
    ELAPI

    Special platform specific functions related to networking

    Copyright (C) Dmitri Pal <dpal@redhat.com> 2009

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

#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <errno.h>

#include "elapi_ioctl.h"
#include "trace.h"
#include "config.h"

#ifndef HAVE_GETIFADDRS

/* These functions are taken form Stevens's
 * UNIX Network Programming Volume 1
 */

int elapi_get_addrlist(struct ifconf *ifc)
{
    int sockfd;
    int length, lastlen;
    int error;
    char *buffer;

    TRACE_FLOW_STRING("elapi_get_addrlist", "Entry");

    /* Open socket */
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    lastlen = 0;
    length = INTERFACE_NUM_GUESS * sizeof(struct ifreq);

    /* Allocate right amount of memory */
    /* This is a trick from Stevens book */
    /* Search web for "get_ifi_info" to get original code */
    for ( ; ; ) {

        buffer = malloc(length);
        ifc->ifc_len = length;
        ifc->ifc_buf = buffer;

        /* Read list */
        if (ioctl(sockfd, SIOCGIFCONF, ifc) < 0) {
            error = errno;
            TRACE_INFO_NUMBER("Ioctl call failed", error);
            if (error != EINVAL || lastlen != 0) {
                free(buffer);
                TRACE_ERROR_NUMBER("ioctl failed", error);
                return error;
            }
        } else {
            TRACE_INFO_NUMBER("Length returned", ifc->ifc_len);
            TRACE_INFO_NUMBER("Previous length", lastlen);
            /* Break if length is same */
            if (ifc->ifc_len == lastlen) break;
            lastlen = ifc->ifc_len;
        }

        /* Grow length */
        length += INTERFACE_NUM_INC * sizeof(struct ifreq);
        free(buffer);
    }

    TRACE_FLOW_STRING("elapi_get_addrlist", "Exit");
    return EOK;
}

/* Get the variable part of the size of the address */
static int elapi_get_addrlen(struct ifreq *ifr)
{
    int len;

    TRACE_FLOW_STRING("elapi_get_addrlen", "Entry");

#ifdef HAVE_SOCKADDR_SA_LEN
    len = max(sizeof(struct sockaddr), ifr->ifr_addr.sa_len);
#else
    switch (ifr->ifr_addr.sa_family) {
#ifdef IPV6
    case AF_INET6:
        len = sizeof(struct sockaddr_in6);
        break;
#endif
    case AF_INET:
        default:
        len = sizeof(struct sockaddr);
        break;
    }
#endif    /* HAVE_SOCKADDR_SA_LEN */

    TRACE_FLOW_NUMBER("elapi_get_addrlen Returning", len);
    return len;
}

/* Get next address */
struct ifreq *elapi_get_next_addr(struct ifconf *ifc, struct ifreq *current)
{
    char *ifr;

    TRACE_FLOW_STRING("elapi_get_next_addr", "Entry");

    TRACE_INFO_NUMBER("Current ifi", current);
    TRACE_INFO_NUMBER("Address", &current->ifr_addr);

    /* Move to the next item */
    ifr = (char *)current + sizeof(current->ifr_name) + elapi_get_addrlen(current);

    TRACE_INFO_NUMBER("New ifi", ifr);

    /* Check if we are beyond the end of the allocated area */
    /* Have to cast otherwise get warnings */
    if (ifr >= ((char *)ifc->ifc_buf + ifc->ifc_len)) ifr = NULL;

    TRACE_INFO_NUMBER("New ifi adjusted", ifr);

    TRACE_FLOW_STRING("elapi_get_next_addr", "Exit");

    return (struct ifreq *)ifr;
}


#endif /* HAVE_GETIFADDRS */
