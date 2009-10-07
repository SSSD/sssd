/*
    ELAPI

    Header file for the ELAPI handling of netwok interfaces.

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

#ifndef ELAPI_NET_H
#define ELAPI_NET_H

#include "config.h"

#ifdef HAVE_GETIFADDRS
#include <ifaddrs.h>    /* for getifaddrs() */

/* Macros then just wrap the getifaddrs() interface */

/* Type of the variable that stores the list */
#define ELAPI_ADDRLIST struct ifaddrs *

/* Type of the variable that stores the item */
#define ELAPI_ADDRITEM struct ifaddrs *

/* Function to build list of the interfaces */
#define  ELAPI_GET_ADDRLIST getifaddrs

/* Macro to get first item from the list */
#define ELAPI_GET_FIRST_ADDR_ITEM(list, item) \
    do { \
        item = list; \
    } while(0)

/* Macro to get next item from the list */
#define ELAPI_GET_NEXT_ADDR_ITEM(list, item) \
    do { \
        item = item->ifa_next; \
    } while(0)


/* Macro to get address */
#define ELAPI_GET_ADDR(item, addr) \
    do { \
        addr = item->ifa_addr; \
    } while(0)

/* Function to free the list */
#define ELAPI_ADDR_LIST_CLEANUP freeifaddrs

#else
/* Do everything using ioctl yourself... */

#include "elapi_ioctl.h"

/* Type of the variable that stores the list */
#define ELAPI_ADDRLIST struct ifconf

/* Type of valiable that is used as a pointer */
#define ELAPI_ADDRITEM struct ifreq *

/* Function to build list of the interfaces */
#define  ELAPI_GET_ADDRLIST elapi_get_addrlist

/* Macro to get first item from the list */
#define ELAPI_GET_FIRST_ADDR_ITEM(list, item) \
    do { \
        item = (struct ifreq *)list.ifc_buf; \
    } while(0)

/* Macro to get next item from the list */
#define ELAPI_GET_NEXT_ADDR_ITEM(list, item) \
    do { \
        item = elapi_get_next_addr(&list, item); \
    } while(0)


/* Macro to get address */
#define ELAPI_GET_ADDR(item, addr) \
    do { \
        addr = &(item->ifr_addr); \
    } while(0)

/* Function to free the list */
#define ELAPI_ADDR_LIST_CLEANUP(list) \
    do { \
        free(list.ifc_buf); \
    } while(0)


#endif /* HAVE_GETIFADDRS */

#endif
