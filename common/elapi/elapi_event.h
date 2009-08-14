/*
    ELAPI

    Header file for the ELAPI event interface.

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

#ifndef ELAPI_EVENT_H
#define ELAPI_EVENT_H

#include "collection.h"

/* Possible predefined elements of the event */
#define E_TIMESTAMP "__stamp__"     /* string - the value is the format for strftime()
                                     * default is standard format for current locale.  */
#define E_UTCTIME   "__time__"      /* int - UTC time as unix time in seconds since 1970 */
#define E_OFFSET    "__loco__"      /* int - local time displacement */
#define E_PID       "__pid__"       /* int - Process ID of the current process */
#define E_APPNAME   "__appnm__"     /* string - Name of the current application */
#define E_HOSTNAME  "__host__"      /* string - Name of the current host */
#define E_HOSTIP    "__ip__"        /* string - IP address */
#define E_SEVERITY  "__sev__"       /* int - Same as "priority" in syslog() */
#define E_HOSTALIAS "__halias__"    /* string - List of alternative host names */
#define E_HOSTIPS   "__iplist__"    /* string - List of alternative IP addresses */

/* There is a special optional attribute of the event named "message".
 * It is a string that contains text specific to each event.
 * This string can contain placeholders that will be automatically
 * replaced by the values that correspond to other attributes in
 * the message. For example message can be:
 * "Connected to remote %(server)".
 * The token %(server) will be replaced by value
 * in the attribute "server" in the event.
 */
#define E_MESSAGE   "__message__"

/* Base argument in the template creation function is a bit mask.
 * Each supported predefined element corresponds to its bit in
 * the mask.
 */
#define E_HAVE_TIMESTAMP    0x00000001
#define E_HAVE_UTCTIME      0x00000002
#define E_HAVE_OFFSET       0x00000004
#define E_HAVE_APPNAME      0x00000010
#define E_HAVE_HOSTNAME     0x00000020
#define E_HAVE_HOSTIP       0x00000040
#define E_HAVE_SEVERITY     0x00000100
#define E_HAVE_HOSTALIAS    0x00000200
#define E_HAVE_HOSTIPS      0x00000400
#define E_HAVE_PID          0x00001000

/* Convenient bitmasks */
#define E_BASE_TIME         ( E_HAVE_TIMESTAMP | E_HAVE_UTCTIME | E_HAVE_OFFSET)
#define E_BASE_HOST         ( E_HAVE_HOSTIP | E_HAVE_HOSTNAME )
#define E_BASE_APP          ( E_HAVE_APPNAME | E_HAVE_PID )
#define E_BASE_HOSTEXT      ( E_HAVE_HOSTALIAS | E_HAVE_HOSTIPS )
#define E_BASE_DEFV1        ( E_BASE_TIME | E_BASE_HOST | E_BASE_APP | E_HAVE_SEVERITY )


/* The default time stamp format */
#define E_TIMESTAMP_FORMAT "%F"

#define TIME_ARRAY_SIZE 100


/* End of arg list special value */
#define E_EOARG "<EOARG>"



/***************************************************************************/
/* TREAD SAFE ELAPI EVENT API                                              */
/***************************************************************************/

/* In the thread safe API the caller is responsible for
 * carrying context information. It is usually allocated
 * when a "create" function is called
 * and should be deleted using "destroy" function.
 */

/* Create an event template.
 * One can create an event template
 * and specify what fields should be
 * populated in the event at its creation.
 * Possible supported fields are listed above.
 * Base parameter specifies the base collection of
 * attributes. See above. The value of 0 will default
 * to the current version of default combination
 * which might change as the API evolves.
 * The variable list can be used to initialize template.
 * It can be initialized by providing key value pairs.
 * ...base, key, value, key, value);
 * If the key does not contain format specifier
 * the value should be a NULL terminated string.
 * See examples for the specific syntax.
 * If key starts with "-" like "-foo"
 * it means that attribute should be removed.
 * In this case the value should not be provided
 * and next argument should be next key.
 * The attributes selected by base argument will
 * be internally and automatically initialized
 * if there is no key - value pair provided.
 * The timestamps will we overwritten each time
 * the event is created so initializing them
 * does not make sense unless you use the base
 * that does not include them.
 * The list of key value pairs should be terminated by special
 * argument E_EOARG.
 */
int elapi_create_event_template(struct collection_item **template,
                                unsigned base, ...);

/* Function to destroy event template */
void elapi_destroy_event_template(struct collection_item *template);

/***************************************************************************/
/* Creates a new event using template (must be provided)
 * and adds additional fields using collection
 * if provided and/or key value pairs if provided.
 * Mode specifies how the collection should be
 * copied into event.
 * See example for details about format specification.
 */
int elapi_create_event(struct collection_item **event,
                       struct collection_item *template,
                       struct collection_item *collection,
                       int mode, ...);

/* Add/Updates/Removes the event attributes based on the and provided key value pairs */
int elapi_modify_event(struct collection_item *event,
                       struct collection_item *collection,
                       int mode, ...);

/* Create a copy of the event */
int elapi_copy_event(struct collection_item **new_event,
                     struct collection_item *source_event);

/* Function to destroy event. */
void elapi_destroy_event(struct collection_item *event);

/***************************************************************************/
/* TREAD UNSAFE ELAPI EVENT API - for simple use cases                     */
/***************************************************************************/
/* Initializes default internal template */
int elapi_set_default_template(unsigned base, ...);

/* Retrieve default template */
int elapi_get_default_template(struct collection_item **template);


/* This function will use internal default template.
 * Hides all complexity from the caller.
 */
int elapi_create_simple_event(struct collection_item **event, ...);


#endif
