/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

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

#ifndef _SBUS_OPATH_H_
#define _SBUS_OPATH_H_

#include <talloc.h>

#include "util/util.h"

/* @see sbus_opath_compose */
char *
_sbus_opath_compose(TALLOC_CTX *mem_ctx,
                    const char *base,
                    const char *part, ...);

/**
 * Compose an object path from given components. Each component is properly
 * escaped so it does not contain any invalid character and a valid object
 * path is returned.
 *
 * @param mem_ctx       Memory context.
 * @param base          Base object path to begin with.
 * @param ...           Following components as string.
 *
 * @return Constructed object path.
 *
 * @example
 *      sbus_opath_compose(mem_ctx, "/org", "freedesktop", "sssd")
 *      -> "/org/freedesktop/sssd"
 */
#define sbus_opath_compose(mem_ctx, base, ...) \
    _sbus_opath_compose(mem_ctx, base, ##__VA_ARGS__, NULL)


/**
 * Decompose an object path, unescaping its values if needed. Components
 * that follow @prefix are returned.
 *
 * @param mem_ctx           Memory context.
 * @param object_path       Input object path.
 * @param prefix            Beginning of object path that is not returned.
 * @param _components       Output components.
 * @param _num_components   Output number of returned components.
 *
 * @return EOK on success, other error code on failure.
 */
errno_t
sbus_opath_decompose(TALLOC_CTX *mem_ctx,
                     const char *object_path,
                     const char *prefix,
                     char ***_components,
                     size_t *_num_components);

/**
 * Decompose an object path, unescaping its values if needed. This function
 * returns an error if the object path after @prefix does not contain exactly
 * @expected number of component.
 *
 * @param mem_ctx           Memory context.
 * @param object_path       Input object path.
 * @param prefix            Beginning of object path that is not returned.
 * @param expected          Expected number of components.
 * @param _components       Output components.
 *
 * @return EOK on success, other error code on failure.
 */
errno_t
sbus_opath_decompose_expected(TALLOC_CTX *mem_ctx,
                              const char *object_path,
                              const char *prefix,
                              size_t expected,
                              char ***_components);

/**
 * Decompose the object path expecting only a single component after the
 * @prefix path and return this component.
 *
 * @param mem_ctx           Memory context.
 * @param object_path       Input object path.
 * @param prefix            Beginning of object path that is not returned.
 *
 * @return Unescaped component or NULL on error.
 */
char *
sbus_opath_object_name(TALLOC_CTX *mem_ctx,
                       const char *object_path,
                       const char *prefix);

/**
 * Escape a single object path component. Use @sbus_opath_compose
 * if you want to create the whole object path.
 *
 * @param mem_ctx           Memory context.
 * @param component         Component to escape.
 *
 * @return Escaped component or NULL on failure.
 */
char *
sbus_opath_escape(TALLOC_CTX *mem_ctx,
                  const char *component);

/**
 * Unescape a single object path component. Use @sbus_opath_decompose
 * if you want to parse the whole object path.
 *
 * @param mem_ctx           Memory context.
 * @param component         Component to escape.
 *
 * @return Escaped component or NULL on failure.
 */
char *
sbus_opath_unescape(TALLOC_CTX *mem_ctx,
                    const char *component);

/**
 * Remove @prefix from the beginning of @object_path and return the remaining
 * string. The returned pointer points to the original @object_path.
 *
 * @param object_path       Object path.
 * @param prefix            Prefix to strip.
 *
 * @return Remaining object path or NULL if the prefix is not present.
 */
const char *
sbus_opath_strip_prefix(const char *object_path,
                        const char *prefix);

/**
 * Return true if given object path represents a subtree path (ending with
 * asterisk). That is an object path representing all object under this path.
 *
 * @param object_path       Object path.
 *
 * @return True if it is a subtree path, false otherwise.
 */
bool
sbus_opath_is_subtree(const char *object_path);

/**
 * Return subtree base path (removing the ending slash and asterisk).
 *
 * @param mem_ctx           Memory context.
 * @param object_path       Subtree object path.
 *
 * @return Base path or NULL on error.
 */
char *
sbus_opath_subtree_base(TALLOC_CTX *mem_ctx,
                        const char *object_path);

/**
 * Travers up on the subtree object path, returning the parent subtree.
 *
 * @param mem_ctx           Memory context.
 * @param object_path       Subtree object path.
 *
 * @return Parent subtree path or NULL on error.
 */
char *
sbus_opath_subtree_parent(TALLOC_CTX *mem_ctx,
                          const char *object_path);

#endif /* _SBUS_OPATH_H_ */
