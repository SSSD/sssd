/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2014 Red Hat

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

#ifndef SSS_SIFP_H_
#define SSS_SIFP_H_

#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <dhash.h>

/**
 * @defgroup sss_simpleifp Simple interface to SSSD InfoPipe responder.
 * Libsss_simpleifp provides a synchronous interface to simplify basic
 * communication with SSSD InfoPipe responder.
 *
 * This interface is not a full replacement for the complete D-Bus API and it
 * provides only access to the most common tasks like fetching attributes
 * of SSSD objects.
 *
 * If there is a need for a more sophisticated communication with the SSSD
 * InfoPipe responder a D-Bus API of your choice should be used.
 *
 * @{
 */

/** SSSD InfoPipe bus address */
#define SSS_SIFP_ADDRESS "org.freedesktop.sssd.infopipe"

/* Backwards-compatible address */
#define SSS_SIFP_IFP SSS_SIFP_ADDRESS

/* Backwards-compatible interface definitions */
#define SSS_SIFP_IFACE_IFP SSS_SIFP_IFP
#define SSS_SIFP_IFACE_COMPONENTS "org.freedesktop.sssd.infopipe.Components"
#define SSS_SIFP_IFACE_SERVICES "org.freedesktop.sssd.infopipe.Services"
#define SSS_SIFP_IFACE_DOMAINS "org.freedesktop.sssd.infopipe.Domains"
#define SSS_SIFP_IFACE_USERS "org.freedesktop.sssd.infopipe.Users"
#define SSS_SIFP_IFACE_GROUPS "org.freedesktop.sssd.infopipe.Groups"

/**
 * SSSD InfoPipe object path.
 * Look at InfoPipe introspection and SSSD documentation for more objects.
 */
#define SSS_SIFP_PATH "/org/freedesktop/sssd/infopipe"

/**
 * SSSD InfoPipe object path.
 * Look at InfoPipe introspection and SSSD documentation for more interfaces.
 */
#define SSS_SIFP_IFACE "org.freedesktop.sssd.infopipe"

/**
 * Opaque libsss_sifp context. One context shall not be used by multiple
 * threads. Each thread needs to create and use its own context.
 *
 * @see sss_sifp_init
 * @see sss_sifp_init_ex
 */
typedef struct sss_sifp_ctx sss_sifp_ctx;

/**
 * Typedef for memory allocation functions
 */
typedef void (sss_sifp_free_func)(void *ptr, void *pvt);
typedef void *(sss_sifp_alloc_func)(size_t size, void *pvt);

/**
 * Error codes used by libsss_sifp
 */
typedef enum sss_sifp_error {
    /** Success */
    SSS_SIFP_OK = 0,

    /** Ran out of memory during processing */
    SSS_SIFP_OUT_OF_MEMORY,

    /** Invalid argument */
    SSS_SIFP_INVALID_ARGUMENT,

    /**
     * Input/output error
     *
     * @see sss_sifp_get_last_io_error() to get more information
     */
    SSS_SIFP_IO_ERROR,

    /** Internal error */
    SSS_SIFP_INTERNAL_ERROR,

    /** Operation not supported */
    SSS_SIFP_NOT_SUPPORTED,

    /** Attribute does not exist */
    SSS_SIFP_ATTR_MISSING,

    /** Attribute does not have any value set */
    SSS_SIFP_ATTR_NULL,

    /** Incorrect attribute type */
    SSS_SIFP_INCORRECT_TYPE,

    /** Always last */
    SSS_SIFP_ERROR_SENTINEL
} sss_sifp_error;

/**
 * D-Bus object attribute
 */
typedef struct sss_sifp_attr sss_sifp_attr;

/**
 * D-Bus object
 */
typedef struct sss_sifp_object {
    char *name;
    char *object_path;
    char *interface;
    sss_sifp_attr **attrs;
} sss_sifp_object;

/**
 * @brief Initialize sss_sifp context using default allocator (malloc)
 *
 * @param[out] _ctx sss_sifp context
 */
sss_sifp_error
sss_sifp_init(sss_sifp_ctx **_ctx);

/**
 * @brief Initialize sss_sifp context
 *
 * @param[in] alloc_pvt  Private data for allocation routine
 * @param[in] alloc_func Function to allocate memory for the context, if
 *                       NULL malloc() is used
 * @param[in] free_func  Function to free the memory of the context, if
 *                       NULL free() is used
 * @param[out] _ctx      sss_sifp context
 */
sss_sifp_error
sss_sifp_init_ex(void *alloc_pvt,
                 sss_sifp_alloc_func *alloc_func,
                 sss_sifp_free_func *free_func,
                 sss_sifp_ctx **_ctx);

/**
 * @brief Return last error name from underlying D-Bus communication
 *
 * @param[in] ctx sss_sifp context
 * @return Error message or NULL if no error occurred during last D-Bus call.
 */
const char *
sss_sifp_get_last_io_error_name(sss_sifp_ctx *ctx);

/**
 * @brief Return last error message from underlying D-Bus communication
 *
 * @param[in] ctx sss_sifp context
 * @return Error message or NULL if no error occurred during last D-Bus call.
 */
const char *
sss_sifp_get_last_io_error_message(sss_sifp_ctx *ctx);

/**
 * @brief Translate error code into human readable message.
 *
 * @param[in] error sss_sifp error code
 * @return Error message.
 */
const char *
sss_sifp_strerr(sss_sifp_error error);

/**
 * @brief Fetch selected attributes of given object.
 *
 * @param[in] ctx         sss_sifp context
 * @param[in] object_path D-Bus object path
 * @param[in] interface   D-Bus interface
 * @param[in] name        Name of desired attribute
 * @param[out] _attrs     List of acquired attributes
 */
sss_sifp_error
sss_sifp_fetch_attr(sss_sifp_ctx *ctx,
                    const char *object_path,
                    const char *interface,
                    const char *name,
                    sss_sifp_attr ***_attrs);

/**
 * @brief Fetch all attributes of given object.
 *
 * @param[in] ctx         sss_sifp context
 * @param[in] object_path D-Bus object path
 * @param[in] interface   D-Bus interface
 * @param[out] _attrs     Acquired attributes
 */
sss_sifp_error
sss_sifp_fetch_all_attrs(sss_sifp_ctx *ctx,
                         const char *object_path,
                         const char *interface,
                         sss_sifp_attr ***_attrs);

/**
 * @brief Fetch D-Bus object.
 *
 * @param[in] ctx         sss_sifp context
 * @param[in] object_path D-Bus object path
 * @param[in] interface   D-Bus interface
 * @param[out] _object    Object and its attributes
 */
sss_sifp_error
sss_sifp_fetch_object(sss_sifp_ctx *ctx,
                      const char *object_path,
                      const char *interface,
                      sss_sifp_object **_object);

/**
 * @brief Find attribute in list and return its value.
 *
 * @param[in] attrs Attributes
 * @param[in] name Name of the attribute to find
 * @param[out] _value Output value
 */
sss_sifp_error
sss_sifp_find_attr_as_bool(sss_sifp_attr **attrs,
                           const char *name,
                           bool *_value);

/**
 * @brief Find attribute in list and return its value.
 *
 * @param[in] attrs Attributes
 * @param[in] name Name of the attribute to find
 * @param[out] _value Output value
 */
sss_sifp_error
sss_sifp_find_attr_as_int16(sss_sifp_attr **attrs,
                            const char *name,
                            int16_t *_value);

/**
 * @brief Find attribute in list and return its value.
 *
 * @param[in] attrs Attributes
 * @param[in] name Name of the attribute to find
 * @param[out] _value Output value
 */
sss_sifp_error
sss_sifp_find_attr_as_uint16(sss_sifp_attr **attrs,
                             const char *name,
                             uint16_t *_value);

/**
 * @brief Find attribute in list and return its value.
 *
 * @param[in] attrs Attributes
 * @param[in] name Name of the attribute to find
 * @param[out] _value Output value
 */
sss_sifp_error
sss_sifp_find_attr_as_int32(sss_sifp_attr **attrs,
                            const char *name,
                            int32_t *_value);

/**
 * @brief Find attribute in list and return its value.
 *
 * @param[in] attrs Attributes
 * @param[in] name Name of the attribute to find
 * @param[out] _value Output value
 */
sss_sifp_error
sss_sifp_find_attr_as_uint32(sss_sifp_attr **attrs,
                             const char *name,
                             uint32_t *_value);

/**
 * @brief Find attribute in list and return its value.
 *
 * @param[in] attrs Attributes
 * @param[in] name Name of the attribute to find
 * @param[out] _value Output value
 */
sss_sifp_error
sss_sifp_find_attr_as_int64(sss_sifp_attr **attrs,
                            const char *name,
                            int64_t *_value);

/**
 * @brief Find attribute in list and return its value.
 *
 * @param[in] attrs Attributes
 * @param[in] name Name of the attribute to find
 * @param[out] _value Output value
 */
sss_sifp_error
sss_sifp_find_attr_as_uint64(sss_sifp_attr **attrs,
                             const char *name,
                             uint64_t *_value);

/**
 * @brief Find attribute in list and return its value.
 *
 * @param[in] attrs Attributes
 * @param[in] name Name of the attribute to find
 * @param[out] _value Output value
 */
sss_sifp_error
sss_sifp_find_attr_as_string(sss_sifp_attr **attrs,
                             const char *name,
                             const char **_value);

/**
 * @brief Find attribute in list and return its value.
 *
 * The dictionary is stored in dhash table, the values
 * are pointers to NULL-terminated string array.
 *
 * @param[in] attrs Attributes
 * @param[in] name Name of the attribute to find
 * @param[out] _value Output value
 */
sss_sifp_error
sss_sifp_find_attr_as_string_dict(sss_sifp_attr **attrs,
                                  const char *name,
                                  hash_table_t **_value);

/**
 * @brief Find attribute in list and return its values.
 *
 * @param[in] attrs Attributes
 * @param[in] name Name of the attribute to find
 * @param[out] _num_values Number of values in the array
 * @param[out] _value Output array
 */
sss_sifp_error
sss_sifp_find_attr_as_bool_array(sss_sifp_attr **attrs,
                                 const char *name,
                                 unsigned int *_num_values,
                                 bool **_value);

/**
 * @brief Find attribute in list and return its values.
 *
 * @param[in] attrs Attributes
 * @param[in] name Name of the attribute to find
 * @param[out] _num_values Number of values in the array
 * @param[out] _value Output array
 */
sss_sifp_error
sss_sifp_find_attr_as_int16_array(sss_sifp_attr **attrs,
                                  const char *name,
                                  unsigned int *_num_values,
                                  int16_t **_value);

/**
 * @brief Find attribute in list and return its values.
 *
 * @param[in] attrs Attributes
 * @param[in] name Name of the attribute to find
 * @param[out] _num_values Number of values in the array
 * @param[out] _value Output array
 */
sss_sifp_error
sss_sifp_find_attr_as_uint16_array(sss_sifp_attr **attrs,
                                   const char *name,
                                   unsigned int *_num_values,
                                   uint16_t **_value);

/**
 * @brief Find attribute in list and return its values.
 *
 * @param[in] attrs Attributes
 * @param[in] name Name of the attribute to find
 * @param[out] _num_values Number of values in the array
 * @param[out] _value Output array
 */
sss_sifp_error
sss_sifp_find_attr_as_int32_array(sss_sifp_attr **attrs,
                                  const char *name,
                                  unsigned int *_num_values,
                                  int32_t **_value);

/**
 * @brief Find attribute in list and return its values.
 *
 * @param[in] attrs Attributes
 * @param[in] name Name of the attribute to find
 * @param[out] _num_values Number of values in the array
 * @param[out] _value Output array
 */
sss_sifp_error
sss_sifp_find_attr_as_uint32_array(sss_sifp_attr **attrs,
                                   const char *name,
                                   unsigned int *_num_values,
                                   uint32_t **_value);

/**
 * @brief Find attribute in list and return its values.
 *
 * @param[in] attrs Attributes
 * @param[in] name Name of the attribute to find
 * @param[out] _num_values Number of values in the array
 * @param[out] _value Output array
 */
sss_sifp_error
sss_sifp_find_attr_as_int64_array(sss_sifp_attr **attrs,
                                  const char *name,
                                  unsigned int *_num_values,
                                  int64_t **_value);

/**
 * @brief Find attribute in list and return its values.
 *
 * @param[in] attrs Attributes
 * @param[in] name Name of the attribute to find
 * @param[out] _num_values Number of values in the array
 * @param[out] _value Output array
 */
sss_sifp_error
sss_sifp_find_attr_as_uint64_array(sss_sifp_attr **attrs,
                                   const char *name,
                                   unsigned int *_num_values,
                                   uint64_t **_value);

/**
 * @brief Find attribute in list and return its values.
 *
 * @param[in] attrs Attributes
 * @param[in] name Name of the attribute to find
 * @param[out] _num_values Number of values in the array
 * @param[out] _value Output array
 */
sss_sifp_error
sss_sifp_find_attr_as_string_array(sss_sifp_attr **attrs,
                                   const char *name,
                                   unsigned int *_num_values,
                                   const char * const **_value);

/**
 * @brief Free sss_sifp context and set it to NULL.
 *
 * @param[in,out] _ctx sss_sifp context
 */
void
sss_sifp_free(sss_sifp_ctx **_ctx);

/**
 * @brief Free attribute list and set it to NULL.
 *
 * @param[in] ctx sss_sifp context
 * @param[in,out] _attrs Attributes
 */
void
sss_sifp_free_attrs(sss_sifp_ctx *ctx,
                    sss_sifp_attr ***_attrs);

/**
 * @brief Free sss_sifp object and set it to NULL.
 *
 * @param[in] ctx sss_sifp context
 * @param[in,out] _object Object
 */
void
sss_sifp_free_object(sss_sifp_ctx *ctx,
                     sss_sifp_object **_object);

/**
 * @brief Free string and set it to NULL.
 *
 * @param[in] ctx sss_sifp context
 * @param[in,out] _str String
 */
void
sss_sifp_free_string(sss_sifp_ctx *ctx,
                     char **_str);

/**
 * @brief Free array of strings and set it to NULL.
 *
 * @param[in] ctx sss_sifp context
 * @param[in,out] _str_array Array of strings
 */
void
sss_sifp_free_string_array(sss_sifp_ctx *ctx,
                           char ***_str_array);

/**
 * @}
 */

/**
 * @defgroup common Most common use cases of SSSD InfoPipe responder.
 * @{
 */

/**
 * @brief List names of available domains.
 *
 * @param[in] ctx       sss_sifp context
 * @param[out] _domains List of domain names
 */
sss_sifp_error
sss_sifp_list_domains(sss_sifp_ctx *ctx,
                      char ***_domains);

/**
 * @brief Fetch all information about domain by name.
 *
 * @param[in] ctx      sss_sifp context
 * @param[in] name     Domain name
 * @param[out] _domain Domain object
 */
sss_sifp_error
sss_sifp_fetch_domain_by_name(sss_sifp_ctx *ctx,
                              const char *name,
                              sss_sifp_object **_domain);

/**
 * @brief Fetch all information about user by uid.
 *
 * @param[in] ctx    sss_sifp context
 * @param[in] uid    User ID
 * @param[out] _user User object
 */
sss_sifp_error
sss_sifp_fetch_user_by_uid(sss_sifp_ctx *ctx,
                           uid_t uid,
                           sss_sifp_object **_user);

/**
 * @brief Fetch all information about user by name.
 *
 * @param[in] ctx    sss_sifp context
 * @param[in] name   User name
 * @param[out] _user User object
 */
sss_sifp_error
sss_sifp_fetch_user_by_name(sss_sifp_ctx *ctx,
                            const char *name,
                            sss_sifp_object **_user);

/**
 * @}
 */

#endif /* SSS_SIFP_H_ */
