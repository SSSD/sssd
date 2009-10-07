/*
    ELAPI

    Implementation of the ELAPI event interface.

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
#include <sys/types.h>  /* for getpid() */
#include <unistd.h>     /* for getpid() */
#include <stdlib.h>     /* for realloc() */
#include <syslog.h>     /* for contants releted to severity */
#include <unistd.h>     /* for gethostname() */
#include <errno.h>      /* for errors */
#include <string.h>     /* for memset() and other */
#include <netdb.h>      /* for gethostbyname() */
#include <sys/socket.h> /* for inet_ntop() */
#include <arpa/inet.h>  /* for inet_ntop() */
#include <ctype.h>      /* for isspace() */
#include <stdarg.h>     /* for va_arg() */
#include <string.h>     /* for strndup() */

#include "elapi_priv.h"
#include "elapi_event.h"
#include "elapi_net.h"
#include "trace.h"
#include "config.h"

#include "collection_tools.h"

/* Internal return states from key processing */
#define E_LIST_EMPTY       0
#define E_LIST_ERROR       1
#define E_LIST_LAST        2
#define E_LIST_ADD         3
#define E_LIST_REMOVE      4

#define LOCALHOSTDOMAIN "localhost.localdomain"
#define LOCALHOST       "localhost"
#define LOCALADDRESS    "127.0.0.1"
#define LOCALADDRESSV6  "::1"

const char *undefined = "undefined";
const char *str_yes = "yes";
const char *str_no = "no";
const char *str_true = "true";
const char *str_false = "false";


/* Function to add host identity information to the template */
static int add_host_identity(struct collection_item *tpl, unsigned base)
{
    char hostname[NI_MAXHOST + 1];
    int error = EOK;
    int gai_ret_host = 0;
    int gai_ret_addr = 0;
    char host[NI_MAXHOST];
    char address[NI_MAXHOST];
    char *hnm, *haddr;
    ELAPI_ADDRLIST ifaddr;
    ELAPI_ADDRITEM ifa;
    struct sockaddr *addr;
    int family;
    int set_hostname = 0;
    int set_ip = 0;
    int used_this_ip = 0;

    TRACE_FLOW_STRING("add_host_identity", "Entry");

    /* The goal here to collect information about the host.
     * there is no need to actually use it for establishing
     * any connections.
     * It is a best effort attempt.
     */

    /* If we are not asked for hostname then say we already have it */
    if (!(base & E_HAVE_HOSTNAME)) set_hostname = 1;
    /* If we are not asked for ip then say we already have it */
    if (!(base & E_HAVE_HOSTIP)) set_ip = 1;

    if (ELAPI_GET_ADDRLIST(&ifaddr) == EOK) {

        TRACE_FLOW_STRING("getifaddrs", "Ok");

        /* Walk through linked list, maintaining head pointer so we
            can free list later */
        ELAPI_GET_FIRST_ADDR_ITEM(ifaddr, ifa);

        while (ifa != NULL) {

            TRACE_FLOW_STRING("Top of the loop", "");

            used_this_ip = 0;

            ELAPI_GET_ADDR(ifa, addr);
            if (!addr) {
                ELAPI_GET_NEXT_ADDR_ITEM(ifaddr, ifa);
                continue;
            }

            family = addr->sa_family;

            TRACE_FLOW_NUMBER("Family", family);

            /* For an AF_INET* interface address, display the address */
            if (family == AF_INET || family == AF_INET6) {

                TRACE_FLOW_NUMBER("Got right family", family);

                /* getnameinfo function claims that it returns NULL
                 * terminated strings. Well...
                 * We will trust it here and not clear memory using memset.
                 */

                gai_ret_host = getnameinfo(addr,
                                           (family == AF_INET) ? sizeof(struct sockaddr_in) :
                                                                 sizeof(struct sockaddr_in6),
                                           host,
                                           NI_MAXHOST,
                                           NULL,
                                           0,
                                           0 /* Gets host name */);

                gai_ret_addr = getnameinfo(addr,
                                           (family == AF_INET) ? sizeof(struct sockaddr_in) :
                                                                 sizeof(struct sockaddr_in6),
                                           address,
                                           NI_MAXHOST,
                                           NULL,
                                           0,
                                           NI_NUMERICHOST /* Gets address as string */);

                TRACE_INFO_STRING("Resolved host:", host);
                TRACE_INFO_STRING("Resolved address:", address);
                /* If we have not set host name set it */
                if(!set_hostname) {

                    TRACE_FLOW_STRING("Host name is not set", "");

                    hnm = NULL;
                    /* Use host name returned by gethostname() as main host name */
                    if (gethostname(hostname, NI_MAXHOST) == EOK) {
                        /* Make sure hostname is NULL terminated */
                        hostname[NI_MAXHOST] = '\0';
                        hnm = hostname;
                    }
                    else {
                        /* Were we able to get a host name ? */
                        if (gai_ret_host == EOK) {
                            TRACE_INFO_STRING("getnameinfo returned:", host);
                            hnm = host;
                        }
                    }

                    /* Do we have a host meaningful host name? */
                    if ((hnm) &&
                        ((strcasecmp(hnm, LOCALHOST) == 0 ) ||
                         (strcasecmp(hnm, LOCALHOSTDOMAIN) == 0 ) ||
                         (strcasecmp(hnm, address) == 0))) hnm = NULL;

                    /* If host name is not NULL it would work for us */
                    if (hnm) {
                        TRACE_INFO_STRING("Adding host name:", hnm);
                        error = col_add_str_property(tpl, NULL, E_HOSTNAME, hnm, 0);
                        if (error) {
                            TRACE_ERROR_NUMBER("Failed to add host name. Error", error);
                            ELAPI_ADDR_LIST_CLEANUP(ifaddr);
                            return error;
                        }
                        /* Done with the name */
                        set_hostname = 1;
                    }
                }

                /* If we have not set processed ip address do it */
                if(!set_ip) {

                    TRACE_FLOW_STRING("Address is not set", "");

                    haddr = NULL;
                    if (gai_ret_addr == EOK) {
                        TRACE_INFO_STRING("getnameinfo returned:", address);
                        if ((strcasecmp(address, LOCALADDRESS) != 0 ) &&
                            (strcasecmp(address, LOCALADDRESSV6) != 0 )) {
                            TRACE_INFO_STRING("Not an unhelpful address", "");
                            haddr = address;
                        }
                    }

                    if (haddr) {
                        TRACE_INFO_STRING("Adding host address:", haddr);
                        error = col_add_str_property(tpl, NULL, E_HOSTIP, haddr, 0);
                        if (error) {
                            TRACE_ERROR_NUMBER("Failed to add host name. Error", error);
                            ELAPI_ADDR_LIST_CLEANUP(ifaddr);
                            return error;
                        }
                        set_ip = 1;
                        used_this_ip = 1;
                    }
                }

                /* If we have a name and we are told to deal with alias names */
                if ((set_hostname) && (base & E_HAVE_HOSTALIAS)) {

                    TRACE_INFO_NUMBER("gai_ret_host:", gai_ret_host);
                    TRACE_INFO_STRING("host:", host);
                    TRACE_INFO_STRING("address:", address);
                    TRACE_INFO_STRING("they are:", ((strcasecmp(host, address) != 0) ? "different" : "same"));

                    /* Do we have a host meaningful host name? */
                    if ((gai_ret_host != EOK) ||
                        ((gai_ret_host == EOK) &&
                         ((strcasecmp(host, LOCALHOST) == 0 ) ||
                          (strcasecmp(host, LOCALHOSTDOMAIN) == 0 ) ||
                          (strcasecmp(host, address) == 0)))) hnm = NULL;
                    else hnm = host;

                    if (hnm) {
                        TRACE_INFO_STRING("Adding alias host name:", hnm);
                        error = col_add_str_property(tpl, NULL, E_HOSTALIAS, hnm, 0);
                        if (error) {
                            TRACE_ERROR_NUMBER("Failed to add host name. Error", error);
                            ELAPI_ADDR_LIST_CLEANUP(ifaddr);
                            return error;
                        }
                    }
                }

                /* If we got then main IP and we are told to deal with opther IPs */
                if ((set_ip) && (base & E_HAVE_HOSTIPS) && (!used_this_ip)) {

                    TRACE_INFO_STRING("Considering address:", address);

                    /* Do we have a host meaningful IP */
                    if ((gai_ret_addr != EOK) ||
                        ((gai_ret_addr == EOK) &&
                         ((strcasecmp(address, LOCALADDRESS) == 0 ) ||
                          (strcasecmp(address, LOCALADDRESSV6) == 0 )))) haddr = NULL;
                    else haddr = address;

                    if (haddr) {
                        TRACE_INFO_STRING("Adding alias host IP:", haddr);
                        error = col_add_str_property(tpl, NULL, E_HOSTIPS, haddr, 0);
                        if (error) {
                            TRACE_ERROR_NUMBER("Failed to add host name. Error", error);
                            ELAPI_ADDR_LIST_CLEANUP(ifaddr);
                            return error;
                        }
                    }
                }
            }
            TRACE_INFO_STRING("Moved to next", "");
            ELAPI_GET_NEXT_ADDR_ITEM(ifaddr, ifa);
            TRACE_INFO_NUMBER("Moved to", ifa);
        }

        ELAPI_ADDR_LIST_CLEANUP(ifaddr);
    }

    /* Make sure that we really have the name after all */
    if (!set_hostname) {
        TRACE_INFO_STRING("No host name using default:", undefined);
        error = col_add_str_property(tpl, NULL, E_HOSTNAME, undefined, 0);
        if (error) {
            TRACE_ERROR_NUMBER("Failed to add host name. Error", error);
            return error;
        }
    }

    /* Make sure that we really have the IP after all */
    if (!set_ip) {
        TRACE_INFO_STRING("No host name using default:", undefined);
        error = col_add_str_property(tpl, NULL, E_HOSTIP, undefined, 0);
        if (error) {
            TRACE_ERROR_NUMBER("Failed to add host name. Error", error);
            return error;
        }
    }

    TRACE_FLOW_STRING("add_host_identity", "Exit");
    return error;
}

/* Add base elements to template collection */
static int add_base_elements(struct collection_item *tpl, unsigned base)
{
    int error = EOK;
    unsigned pass_base;

    TRACE_FLOW_STRING("add_base_elements", "Entry");

    /* Populate the template using base */
    if (base & E_HAVE_TIMESTAMP) {
        /* Value is the format string for strftime() */
        error = col_add_str_property(tpl, NULL, E_TIMESTAMP, E_TIMESTAMP_FORMAT, sizeof(E_TIMESTAMP_FORMAT));
        if (error) {
            TRACE_ERROR_NUMBER("Failed to add timestamp. Error", error);
            return error;
        }
    }

    if (base & E_HAVE_UTCTIME) {
        /* Value does not matter */
        error = col_add_int_property(tpl, NULL, E_UTCTIME, 0);
        if (error) {
            TRACE_ERROR_NUMBER("Failed to add UTC time. Error", error);
            return error;
        }
    }

    if (base & E_HAVE_OFFSET) {
        /* Value does not matter */
        error = col_add_int_property(tpl, NULL, E_OFFSET, 0);
        if (error) {
            TRACE_ERROR_NUMBER("Failed to add UTC time. Error", error);
            return error;
        }
    }

    if (base & E_HAVE_PID) {
        /* Value is the current pid */
        error = col_add_long_property(tpl, NULL, E_PID, (long)getpid());
        if (error) {
            TRACE_ERROR_NUMBER("Failed to add pid. Error", error);
            return error;
        }
    }

    if (base & E_HAVE_APPNAME) {
        /* Value does not matter */
        error = col_add_str_property(tpl, NULL, E_APPNAME, "", 1);
        if (error) {
            TRACE_ERROR_NUMBER("Failed to add application name. Error", error);
            return error;
        }
    }

    if (base & E_HAVE_SEVERITY) {
        /* Value is the default severity */
        error = col_add_int_property(tpl, NULL, E_SEVERITY, LOG_USER | LOG_INFO);
        if (error) {
            TRACE_ERROR_NUMBER("Failed to add pid. Error", error);
            return error;
        }
    }

    /* If we need to add aliases or other IPs call the function */
    if ((base & E_HAVE_HOSTNAME) ||
        (base & E_HAVE_HOSTIP) ||
        (base & E_HAVE_HOSTALIAS) ||
        (base & E_HAVE_HOSTIPS))  {

        pass_base = base;

        /* make sure we have extensions on top of the basic data */
        if ((base & E_HAVE_HOSTALIAS) && (!(base & E_HAVE_HOSTNAME))) pass_base |= E_HAVE_HOSTNAME;
        if ((base & E_HAVE_HOSTIPS) && (!(base & E_HAVE_HOSTIP))) pass_base |= E_HAVE_HOSTIP;

        error = add_host_identity(tpl, pass_base);
        if (error) {
            TRACE_ERROR_NUMBER("Failed to add host identity. Error", error);
            return error;
        }
    }

    TRACE_FLOW_STRING("add_base_elements", "Exit");
    return error;
}


/* Internal untility function to tokenize a string */
static int interpret_key(char *key,
                         int *type,
                         char **property,
                         int *prop_len,
                         int *has_len,
                         int *bool_type)
{
    int adjust_by = 0;
    char *start = NULL;
    char *cursor = NULL;
    char *end = NULL;
    int ret = E_LIST_EMPTY;

    TRACE_FLOW_STRING("interpret_key", "Entry");

    TRACE_INFO_STRING("Key", key);

    /* Initialize passed in data */
    *has_len = 0;
    *property = NULL;
    *type = COL_TYPE_STRING;

    cursor = key;

    while (isspace(*cursor)) cursor++;

    /* End of string - we are done */
    if (*cursor == '\0') {
        TRACE_ERROR_STRING("Empty key - end of processing!", "");
        return E_LIST_EMPTY;
    }

    /* This is the beginning of the formatted token */
    if (*cursor == '-') {

        /* This is a remove attribute case */

        cursor++;
        /* Skip spaces if any */
        while (isspace(*cursor)) cursor++;

        /* Mark the start of the actual property */
        start = cursor;

        /* Now we need to extract the name of the property */
        /* We will not be nice here - the add_property will validate if the name is ok */
        while ((*cursor != '\0') && (!isspace(*cursor))) cursor++;

        /* End of string - we are done */
        if (cursor == start) {
            TRACE_ERROR_STRING("Invalid key - end of processing!", "");
            return E_LIST_EMPTY;
        }

        *prop_len = cursor - start;
        *property = start;
        TRACE_INFO_STRING("We are told to remove the property!", *property);
        ret = E_LIST_REMOVE;
    }
    else if (*cursor == '%') {

        /* We got a full key with format string */

        cursor++;
        if ((*cursor == '*') && (*(cursor+1) == 's') && (*(cursor+2) == '(')) {
            *type = COL_TYPE_STRING;
            *has_len = 1;
            adjust_by = 3;
        }
        else if ((*cursor == 's') && (*(cursor+1) == '(')) {
            *type = COL_TYPE_STRING;
            adjust_by = 2;
        }
        else if (((*cursor == 'i')||(*cursor == 'd')) && (*(cursor+1) == '(')) {
            *type = COL_TYPE_INTEGER;
            adjust_by = 2;
        }
        else if ((*cursor == 'u') && (*(cursor+1) == '(')) {
            *type = COL_TYPE_UNSIGNED;
            adjust_by = 2;
        }
        else if ((*cursor == 'l') && ((*(cursor+1) == 'i')||(*(cursor+1) == 'd')) && (*(cursor+2) == '(')) {
            *type = COL_TYPE_LONG;
            adjust_by = 3;
        }
        else if ((*cursor == 'l') && (*(cursor+1) == 'u') && (*(cursor+2) == '(')) {
            *type = COL_TYPE_ULONG;
            adjust_by = 3;
        }
        else if (((*cursor == 'f')||(*cursor == 'e')) && (*(cursor+1) == '(')) {
            *type = COL_TYPE_DOUBLE;
            adjust_by = 2;
        }
        else if (((*cursor == 's') || (*cursor == 'd')) && (*(cursor+1) == 'b') && (*(cursor+2) == '(')) {
            *type = COL_TYPE_BOOL;
            adjust_by = 3;
            if (*cursor == 's') *bool_type = 1;
            else *bool_type = 0;
        }
        else if ((*cursor == 'n') && (*(cursor+1) == '(')) {
            *type = COL_TYPE_BINARY;
            adjust_by = 2;
        }
        else {
            TRACE_ERROR_STRING("Invalid key - end of processing!", key);
            return E_LIST_ERROR;
        }

        cursor += adjust_by;

        /* Skip spaces if any */
        while (isspace(*cursor)) cursor++;

        start = cursor;

        /* Now we need to extract the name of the property */
        /* We will not be nice here - the add_property will validate if the name is ok */
        while ((*cursor != '\0') && (*cursor != ')') && (!isspace(*cursor))) cursor++;

        /* End of string - we are done */
        if ((*cursor == '\0') || (cursor == start)) {
            TRACE_ERROR_STRING("Invalid key - end of processing!", "");
            return E_LIST_EMPTY;
        }

        end = cursor;

        /* Skip spaces if any */
        while (isspace(*cursor)) cursor++;

        /* Check that end of the string is in proper format */
        if ((*cursor != ')') && (*(cursor + 1) != '\0')) {
            TRACE_ERROR_STRING("Invalid key - missing ')' .", key);
            return E_LIST_ERROR;
        }

        *property = start;
        *prop_len = end - start;

        TRACE_INFO_STRING("Property:", *property);
        TRACE_INFO_NUMBER("Property len:", *prop_len);
        ret = E_LIST_ADD;
    }
    else {
        /* Just got a key */
        /* Mark the start of the actual property */
        start = cursor;

        /* Now we need to extract the name of the property */
        /* We will not be nice here - the add_property will validate if the name is ok */
        while ((*cursor != '\0') && (!isspace(*cursor))) cursor++;

        /* End of string - we are done */
        if (cursor == start) {
            TRACE_ERROR_STRING("Invalid key - end of processing!", "");
            return E_LIST_EMPTY;
        }

        *prop_len = cursor - start;
        *property = start;
        TRACE_INFO_STRING("We are told to add/update the property (or last)!", *property);

        if(strncmp(*property, E_EOARG, *prop_len) == 0) ret = E_LIST_LAST;
        else ret = E_LIST_ADD;
    }

    TRACE_INFO_STRING("Returning Property:",*property);
    TRACE_INFO_NUMBER("Returning Property len:", *prop_len);
    TRACE_INFO_NUMBER("Returning Type:", *type);
    TRACE_INFO_NUMBER("Returning Has length:", *has_len);


    TRACE_FLOW_STRING("interpret_key", "Exit");

    return ret;
}

/* Make sure that the right string is given for bool value */
static int convert_bool(char *data_str, unsigned char *data_bool)
{
    TRACE_FLOW_STRING("convert_bool", "Called");
    TRACE_INFO_STRING("Data", data_str);

    if ((strcasecmp(data_str, str_true) == 0) ||
        (strcasecmp(data_str, str_yes) == 0)) {
        TRACE_INFO_STRING("Matched TRUE", "");
        *data_bool = '\1';
        return 1;
    }
    if ((strcasecmp(data_str, str_false) == 0) ||
        (strcasecmp(data_str, str_no) == 0)) {
        TRACE_INFO_STRING("Matched FALSE", "");
        *data_bool = '\0';
        return 1;
    }
    TRACE_INFO_STRING("Matched NOTHING", "");
    return 0;
}


/* Process argument list */
/* Update collection based on the passed in arguments */
static int process_arg_list(struct collection_item *col,
                            va_list args)
{
    int error = EOK;
    char *arg = NULL;
    char *propcopy = NULL;
    int ret = 0;
    int type = 0;
    char *property = NULL;
    int prop_len = 0;
    int has_len = 0;
    int bool_type = 0;
    char *data_str = NULL;
    int data_int = 0;
    unsigned int data_uint = 0;
    long data_long = 0;
    unsigned long data_ulong = 0;
    void *data_bin = NULL;
    double data_dbl = 0.;
    int length = 0;
    void *data = NULL;
    unsigned char data_bool = '\0';

    TRACE_FLOW_STRING("process_arg_list", "Entry.");

    /* We will break from the loop when we find the last item */
    while (1) {

        /* Get next key */
        arg = va_arg(args, char *);

        if (arg == NULL) {
            TRACE_ERROR_STRING("Invalid NULL argument.", "Key can't be NULL");
            return EINVAL;
        }

        /* Interpret the key.
         * It can be just " key ",
         * it can be " - key ",
         * or it can be a formatted string
         * something like " %*s( key )".
         * Function will deal with all cases.
         * Passed in variables initialized and updated inside
         */
        ret = interpret_key(arg,
                            &type,
                            &property,
                            &prop_len,
                            &has_len,
                            &bool_type);

        if (ret == E_LIST_LAST) {
            TRACE_INFO_STRING("Process found last key", arg);
            break;
        }

        if ((ret == E_LIST_ADD) || (ret == E_LIST_REMOVE)) {
            /* We need to create a dup of the string */
            propcopy = malloc(prop_len + 1);
            if (propcopy == NULL) {
                TRACE_ERROR_STRING("Failed to allocate property", arg);
                return ENOMEM;
            }

            /* Copy property */
            memcpy(propcopy, property, prop_len);
            propcopy[prop_len] = '\0';

            TRACE_INFO_STRING("Processing property", propcopy);

            /* Are we supposed to add? */
            if (ret == E_LIST_ADD) {


                /* NOTE: We are not going to check if the key value pairs
                 * are consistent.
                 * It can be made a bit more bullet proof by adding
                 * significant complexity to the code but I do not
                 * think it makes much sense to do so.
                 * There is no way to prevent the argument mismatch
                 * issues 100%. Printf can crash if aguments are
                 * missed or bad, so do we...
                 */

                /* Get data */
                switch(type) {

                case COL_TYPE_STRING:   data_str = va_arg(args, char *);
                                        data = (void *)data_str;
                                        if (has_len) length = va_arg(args, int);
                                        else length = strlen(data_str) + 1;
                                        TRACE_INFO_STRING("Adding string:", data_str);
                                        TRACE_INFO_NUMBER("Length:",length);
                                        break;

                case COL_TYPE_BINARY:   data_bin = va_arg(args, void *);
                                        data = (void *)data_bin;
                                        length = va_arg(args, int);
                                        break;

                case COL_TYPE_INTEGER:  data_int = va_arg(args, int);
                                        data = (void *)(&data_int);
                                        length = sizeof(int);
                                        break;

                case COL_TYPE_UNSIGNED: data_uint = va_arg(args, unsigned int);
                                        data = (void *)(&data_uint);
                                        length = sizeof(unsigned int);
                                        break;

                case COL_TYPE_LONG:     data_long = va_arg(args, long);
                                        data = (void *)(&data_long);
                                        length = sizeof(long);
                                        break;

                case COL_TYPE_ULONG:    data_ulong = va_arg(args, unsigned long);
                                        data = (void *)(&data_ulong);
                                        length = sizeof(unsigned long);
                                        break;

                case COL_TYPE_DOUBLE:   data_dbl = va_arg(args, double);
                                        data = (void *)(&data_dbl);
                                        length = sizeof(double);
                                        break;

                case COL_TYPE_BOOL:     if (bool_type) {
                                            /* It is a string */
                                            data_str = va_arg(args,char *);
                                            /* Check if it is a valid str */
                                            if (!(convert_bool(data_str, &data_bool))) {
                                                TRACE_ERROR_STRING("Failed to to convert bool value", data_str);
                                                free(propcopy);
                                                return EINVAL;
                                            }
                                        }
                                        else {
                                            /* It is an int */
                                            data_int = va_arg(args, int);
                                            if (data_int) data_bool = 1;
                                            else data_bool = 0;
                                        }

                                        data = (void *)(&data_bool);
                                        length = sizeof(unsigned char);
                                        break;

                default:
                                        TRACE_ERROR_STRING("Invalid or unknown type", propcopy);
                                        free(propcopy);
                                        return EINVAL;
                }

                /* Insert or update */
                error = col_insert_property_with_ref(col,
                                                     NULL,
                                                     COL_DSP_END,
                                                     NULL,
                                                     0,
                                                     COL_INSERT_DUPOVER,
                                                     propcopy,
                                                     type,
                                                     data,
                                                     length,
                                                     NULL);
                if (error) {
                    TRACE_ERROR_STRING("Error inserting property", property);
                    free(propcopy);
                    return error;
                }
            }
            else {
                /* Remove case */
                while (error != ENOENT) {
                    error = col_remove_item(col,
                                            NULL,
                                            COL_DSP_FIRSTDUP,
                                            propcopy,
                                            0,
                                            COL_TYPE_ANY);
                    if ((error) && (error != ENOENT)) {
                        TRACE_ERROR_STRING("Error deleting property", propcopy);
                        free(propcopy);
                        return error;
                    }
                }
                error = EOK;
            }
            free(propcopy);
        }
        else {
            /* Errors related to key interpretation are handled here */
            TRACE_ERROR_STRING("Invalid arg", arg);
            return EINVAL;
        }
    } /* end of arg processing loop */

    TRACE_FLOW_STRING("process_arg_list", "Exit");
    return error;
}



/*****************************************************************************/
/* Create event template */
int elapi_create_event_tplt_with_vargs(struct collection_item **tpl,
                                       unsigned base,
                                       va_list args)
{
    int error = EOK;
    struct collection_item *new_tpl = NULL;

    TRACE_FLOW_STRING("elapi_create_event_tplt_with_vargs", "Entry");

    if (tpl == NULL ) {
        TRACE_ERROR_STRING("Template storage must be provided", "");
        return EINVAL;
    }

    *tpl = NULL;

    /* Create collection */
    error = col_create_collection(&new_tpl, E_TEMPLATE_NAME, COL_CLASS_ELAPI_TEMPLATE);
    if (error) {
        TRACE_ERROR_NUMBER("Failed to create collection. Error", error);
        return error;
    }

    /* Add elements using base mask */
    error = add_base_elements(new_tpl, base);
    if (error) {
        TRACE_ERROR_NUMBER("Failed to add base elements. Error", error);
        col_destroy_collection(new_tpl);
        return error;
    }

    /* Process variable argument list */
    error = process_arg_list(new_tpl, args);

    if (error) {
        TRACE_ERROR_NUMBER("Failed to process argument list. Error", error);
        col_destroy_collection(new_tpl);
        return error;
    }

    *tpl = new_tpl;

    TRACE_FLOW_STRING("elapi_create_event_tplt_with_vargs", "Exit");
    return error;
}


/* Create event template */
int elapi_create_event_tplt(struct collection_item **tpl,
                            unsigned base, ...)
{
    int error = EOK;
    va_list args;

    TRACE_FLOW_STRING("elapi_create_event_tplt", "Entry");

    /* Process varible arguments */
    va_start(args, base);

    /* Create template using arguments  */
    error = elapi_create_event_tplt_with_vargs(tpl,
                                               base,
                                               args);

    va_end(args);

    TRACE_FLOW_STRING("elapi_create_event_tplt", "Exit");
    return error;
}

/* Function to destroy event template */
void elapi_destroy_event_tplt(struct collection_item *tpl)
{
    TRACE_FLOW_STRING("elapi_destroy_event_tplt", "Entry");

    col_destroy_collection(tpl);

    TRACE_FLOW_STRING("elapi_destroy_event_tplt", "Exit");
}


/* Create event from template, colection and arguments */
int elapi_create_event_with_vargs(struct collection_item **event,
                                  struct collection_item *tpl,
                                  struct collection_item *collection,
                                  int mode, va_list args)
{
    int error = EOK;
    struct collection_item *evt = NULL;
    const char *alias;

    TRACE_FLOW_STRING("elapi_create_event_with_vargs", "Entry");

    /* Check storage */
    if (event == NULL) {
        TRACE_ERROR_STRING("Event storage must be provided", "");
        return EINVAL;
    }

    *event = NULL;

    /* Create collection */
    error = col_create_collection(&evt, E_EVENT_NAME, COL_CLASS_ELAPI_EVENT);
    if (error) {
        TRACE_ERROR_NUMBER("Failed to create collection. Error", error);
        return error;
    }

    /* Add elements from the template */
    /* Check for template */
    if (tpl != NULL) {
        error = col_add_collection_to_collection(evt, NULL, NULL,
                                                 (struct collection_item *)tpl,
                                                 COL_ADD_MODE_FLAT);
        if (error) {
            TRACE_ERROR_NUMBER("Failed to add elements from the template. Error", error);
            col_destroy_collection(evt);
            return error;
        }
    }

    /* Add elements from the collection */
    if (collection != NULL) {
        /* If we are told to use FLAT DOT mode
         * add collection with prefixing here.
         */
        if (mode == COL_ADD_MODE_FLATDOT) {
            alias = col_get_item_property(collection, NULL);
        }
        else alias = NULL;

        error = col_add_collection_to_collection(evt, NULL, alias, collection, mode);
        if (error) {
            TRACE_ERROR_NUMBER("Failed to add elements from external collection. Error", error);
            col_destroy_collection(evt);
            return error;
        }
    }

    /* Process variable argument list */
    error = process_arg_list(evt, args);

    if (error) {
        TRACE_ERROR_NUMBER("Failed to process argument list. Error", error);
        col_destroy_collection(evt);
        return error;
    }

    *event = evt;

    TRACE_FLOW_STRING("elapi_create_event_with_vargs", "Exit");
    return error;
}


/* Create event a wrapper around a function with arg list */
int elapi_create_event(struct collection_item **event,
                       struct collection_item *tpl,
                       struct collection_item *collection,
                       int mode, ...)
{
    int error = EOK;
    va_list args;

    TRACE_FLOW_STRING("elapi_create_event", "Entry");

    va_start(args, mode);

    error = elapi_create_event_with_vargs(event,
                                          tpl,
                                          collection,
                                          mode,
                                          args);
    va_end(args);


    TRACE_FLOW_STRING("elapi_create_event", "Exit");
    return error;
}

/* Add/Updates/Removes the event attributes based on the and provided key value pairs */
int elapi_modify_event(struct collection_item *event,
                       struct collection_item *collection,
                       int mode, ...)
{
    int error = EOK;
    va_list args;
    const char *alias;

    TRACE_FLOW_STRING("elapi_modify_event", "Entry");

    /* Check event */
    if (event == NULL ) {
        TRACE_ERROR_STRING("Event must be provided", "");
        return EINVAL;
    }

    /* Add elements from the template */
    if (collection != NULL) {
        /* If we are told to use FLAT DOT mode
         * add collection with prefixing here.
         */
        if (mode == COL_ADD_MODE_FLATDOT) {
            alias = col_get_item_property(collection, NULL);
        }
        else alias = NULL;
        error = col_add_collection_to_collection(event, NULL, alias, collection, mode);
        if (error) {
            TRACE_ERROR_NUMBER("Failed to add elements from external collection. Error", error);
            col_destroy_collection(event);
            return error;
        }
    }

    /* Process varible arguments */
    va_start(args, mode);

    /* Process variable argument list */
    error = process_arg_list(event, args);

    va_end(args);

    if (error) {
        TRACE_ERROR_NUMBER("Failed to process argument list. Error", error);
        return error;
    }

    TRACE_FLOW_STRING("elapi_modify_event", "Exit");
    return error;
}

/* Create a copy of the event */
int elapi_copy_event(struct collection_item **new_event,
                     struct collection_item *source_event)
{
    int error = EOK;

    TRACE_FLOW_STRING("elapi_copy_event", "Entry");

    error = col_copy_collection(new_event,
                                source_event,
                                NULL,
                                COL_COPY_NORMAL);

    TRACE_FLOW_NUMBER("elapi_copy_event. Exit Returning", error);
    return error;
}

/* Function to destroy event. */
void elapi_destroy_event(struct collection_item *event)
{
    TRACE_FLOW_STRING("elapi_destroy_event", "Entry");

    col_destroy_collection(event);

    TRACE_FLOW_STRING("elapi_destroy_event", "Exit");
}
