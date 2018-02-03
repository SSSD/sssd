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

#include <talloc.h>
#include <string.h>

#include "util/util.h"
#include "sbus/sbus_opath.h"

char *
_sbus_opath_compose(TALLOC_CTX *mem_ctx,
                    const char *base,
                    const char *part, ...)
{
    char *safe_part;
    char *path = NULL;
    va_list va;

    if (base == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Wrong object path base!\n");
        return NULL;
    }

    path = talloc_strdup(mem_ctx, base);
    if (path == NULL) {
        return NULL;
    }

    va_start(va, part);
    while (part != NULL) {
        safe_part = sbus_opath_escape(mem_ctx, part);
        if (safe_part == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Could not add [%s] to objpath\n", part);
            goto fail;
        }

        path = talloc_asprintf_append(path, "/%s", safe_part);
        talloc_free(safe_part);
        if (path == NULL) {
            goto fail;
        }

        part = va_arg(va, const char *);
    }
    va_end(va);

    return path;

fail:
    va_end(va);
    talloc_free(path);
    return NULL;
}

errno_t
sbus_opath_decompose(TALLOC_CTX *mem_ctx,
                     const char *object_path,
                     const char *prefix,
                     char ***_components,
                     size_t *_num_components)
{
    TALLOC_CTX *tmp_ctx;
    const char *path;
    char **decomposed;
    char **unescaped;
    errno_t ret;
    int len;
    int i;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    /* Strip prefix from the path. */
    if (prefix != NULL) {
        path = sbus_opath_strip_prefix(object_path, prefix);
        if (path == NULL) {
            ret = ERR_SBUS_INVALID_PATH;
            goto done;
        }
    } else {
        path = object_path;
    }

    if (path[0] == '\0') {
        *_components = NULL;
        *_num_components = 0;
        ret = EOK;
        goto done;
    }

    /* Split the string using / as delimiter. */
    ret = split_on_separator(tmp_ctx, path, '/', true, true, &decomposed, &len);
    if (ret != EOK) {
        goto done;
    }

    /* Unescape parts. */
    unescaped = talloc_zero_array(tmp_ctx, char *, len + 1);
    if (unescaped == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (i = 0; i < len; i++) {
        unescaped[i] = sbus_opath_unescape(unescaped, decomposed[i]);
        if (unescaped[i] == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    if (_components != NULL) {
        *_components = talloc_steal(mem_ctx, unescaped);
    }

    if (_num_components != NULL) {
        *_num_components = len;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t
sbus_opath_decompose_expected(TALLOC_CTX *mem_ctx,
                              const char *object_path,
                              const char *prefix,
                              size_t expected,
                              char ***_components)
{
    char **components;
    size_t len;
    errno_t ret;

    ret = sbus_opath_decompose(mem_ctx, object_path, prefix,
                               &components, &len);
    if (ret != EOK) {
        return ret;
    }

    if (len != expected) {
        talloc_free(components);
        return ERR_SBUS_INVALID_PATH;
    }

    if (_components != NULL) {
        *_components = components;
    }

    return EOK;
}

char *
sbus_opath_object_name(TALLOC_CTX *mem_ctx,
                       const char *object_path,
                       const char *prefix)
{
    char **components;
    char *name;
    errno_t ret;

    ret = sbus_opath_decompose_expected(mem_ctx, object_path, prefix,
                                        1, &components);
    if (ret != EOK) {
        return NULL;
    }

    name = talloc_steal(mem_ctx, components[0]);
    talloc_free(components);
    return name;
}

char *
sbus_opath_escape(TALLOC_CTX *mem_ctx,
                  const char *component)
{
    size_t n;
    char *safe_path = NULL;
    TALLOC_CTX *tmp_ctx = NULL;

    /* The path must be valid */
    if (component == NULL) {
        return NULL;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return NULL;
    }

    safe_path = talloc_strdup(tmp_ctx, "");
    if (safe_path == NULL) {
        goto done;
    }

    /* Special case for an empty string */
    if (strcmp(component, "") == 0) {
        /* the for loop would just fall through */
        safe_path = talloc_asprintf_append_buffer(safe_path, "_");
        if (safe_path == NULL) {
            goto done;
        }
    }

    for (n = 0; component[n]; n++) {
        int c = component[n];
        /* D-Bus spec says:
         * *
         * * Each element must only contain the ASCII characters
         * "[A-Z][a-z][0-9]_"
         * */
        if ((c >= 'A' && c <= 'Z')
                || (c >= 'a' && c <= 'z')
                || (c >= '0' && c <= '9')) {
            safe_path = talloc_asprintf_append_buffer(safe_path, "%c", c);
            if (safe_path == NULL) {
                goto done;
            }
        } else {
            safe_path = talloc_asprintf_append_buffer(safe_path, "_%02x", c);
            if (safe_path == NULL) {
                goto done;
            }
        }
    }

    safe_path = talloc_steal(mem_ctx, safe_path);

done:
    talloc_free(tmp_ctx);
    return safe_path;
}

static inline int unhexchar(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }

    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }

    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }

    return -1;
}

char *
sbus_opath_unescape(TALLOC_CTX *mem_ctx,
                    const char *component)
{
     TALLOC_CTX *tmp_ctx;
     char *safe_path;
     const char *p;
     int a, b, c;

     tmp_ctx = talloc_new(NULL);
     if (tmp_ctx == NULL) {
         return NULL;
     }

     safe_path = talloc_strdup(tmp_ctx, "");
     if (safe_path == NULL) {
         goto done;
     }

     /* Special case for the empty string */
     if (strcmp(component, "_") == 0) {
         safe_path = talloc_steal(mem_ctx, safe_path);
         goto done;
     }

     for (p = component; *p; p++) {
         if (*p == '_') {
             /* There must be at least two more chars after underscore */
             if (p[1] == '\0' || p[2] == '\0') {
                 safe_path = NULL;
                 goto done;
             }

             if ((a = unhexchar(p[1])) < 0
                     || (b = unhexchar(p[2])) < 0) {
                 /* Invalid escape code, let's take it literal then */
                 c = '_';
             } else {
                 c = ((a << 4) | b);
                 p += 2;
             }
         } else  {
             c = *p;
         }

         safe_path = talloc_asprintf_append_buffer(safe_path, "%c", c);
         if (safe_path == NULL) {
             goto done;
         }
     }

     safe_path = talloc_steal(mem_ctx, safe_path);

 done:
     talloc_free(tmp_ctx);
     return safe_path;
}

const char *
sbus_opath_strip_prefix(const char *object_path,
                        const char *prefix)
{
    size_t len = strlen(prefix);
    if (strncmp(object_path, prefix, len) == 0) {
        return object_path + len;
    }

    return NULL;
}

bool
sbus_opath_is_subtree(const char *object_path)
{
    size_t len;

    len = strlen(object_path);

    /* At least slash and asterisk. */
    if (len < 2) {
        return false;
    }

    return object_path[len - 2] == '/' && object_path[len - 1] == '*';
}

char *
sbus_opath_subtree_base(TALLOC_CTX *mem_ctx,
                        const char *object_path)
{
    char *tree_path;
    size_t len;

    tree_path = talloc_strdup(mem_ctx, object_path);
    if (tree_path == NULL) {
        return NULL;
    }

    if (!sbus_opath_is_subtree(tree_path)) {
        return tree_path;
    }

    /* replace / only if it is not a root path (only slash) */
    len = strlen(tree_path);
    tree_path[len - 1] = '\0';
    tree_path[len - 2] = (len - 2 != 0) ? '\0' : '/';

    return tree_path;
}

char *
sbus_opath_subtree_parent(TALLOC_CTX *mem_ctx,
                          const char *object_path)
{
    char *subtree;
    char *slash;

    /* First remove /~* from the end, stop when we have reached the root i.e.
     * subtree == "/" */
    subtree = sbus_opath_subtree_base(mem_ctx, object_path);
    if (subtree == NULL || subtree[1] == '\0') {
        return NULL;
    }

    /* Find the first separator and replace the part with asterisk. */
    slash = strrchr(subtree, '/');
    if (slash == NULL) {
        /* We cannot continue up. */
        talloc_free(subtree);
        return NULL;
    }

    if (*(slash + 1) == '\0') {
        /* This object path is invalid since it cannot end with slash. */
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid object path '%s'?\n", object_path);
        talloc_free(subtree);
        return NULL;
    }

    /* Because object path cannot end with / there is enough space for
     * asterisk and terminating zero. */
    *(slash + 1) = '*';
    *(slash + 2) = '\0';

    return subtree;
}
