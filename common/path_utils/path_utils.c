/*
    Authors:
        John Dennis <jdennis.redhat.com>

    Copyright (C) 2009 Red Hat

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/*****************************************************************************/
/******************************** Documentation ******************************/
/*****************************************************************************/

/*****************************************************************************/
/******************************* Include Files *******************************/
/*****************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/errno.h>
#include <sys/stat.h>

#include <libgen.h>

#include "path_utils.h"

/*****************************************************************************/
/****************************** Internal Defines *****************************/
/*****************************************************************************/

/*****************************************************************************/
/************************** Internal Type Definitions ************************/
/*****************************************************************************/

/*****************************************************************************/
/**********************  External Function Declarations  *********************/
/*****************************************************************************/

/*****************************************************************************/
/**********************  Internal Function Declarations  *********************/
/*****************************************************************************/

/*****************************************************************************/
/*************************  External Global Variables  ***********************/
/*****************************************************************************/

/*****************************************************************************/
/*************************  Internal Global Variables  ***********************/
/*****************************************************************************/

/*****************************************************************************/
/****************************  Inline Functions  *****************************/
/*****************************************************************************/

/*****************************************************************************/
/***************************  Internal Functions  ****************************/
/*****************************************************************************/

/*****************************************************************************/
/****************************  Exported Functions  ***************************/
/*****************************************************************************/

const char *path_utils_error_string(int error)
{
    switch(error) {
    case SUCCESS:                               return _("Success");
    case PATH_UTILS_ERROR_NOT_FULLY_NORMALIZED: return _("Path could not be fully normalized");
    }
    return NULL;
}

static int dot_to_absolute(char *rel_path, int rel_path_size)
{
    char tmp_path[PATH_MAX];

    if (strcmp(rel_path, ".") == 0) {
        if (getcwd(rel_path, rel_path_size) == NULL) {
            if (errno == ERANGE)
                return ENOBUFS;
            else
                return errno;
        }
    } else if (strcmp(rel_path, "..") == 0) {
        if (getcwd(tmp_path, sizeof(tmp_path)) == NULL)  {
            if (errno == ERANGE)
                return ENOBUFS;
            else
                return errno;
        }
        strncpy(rel_path, dirname(tmp_path), rel_path_size);
        if (rel_path[rel_path_size-1] != 0) return ENOBUFS;
    }

    return SUCCESS;
}

int get_basename(char *base_name, size_t base_name_size, const char *path)
{
    char tmp_path[PATH_MAX];
    int ret;

    if (!path) return EINVAL;
    if (!base_name || base_name_size < 1) return ENOBUFS;

    strncpy(tmp_path, path, sizeof(tmp_path));
    if (tmp_path[sizeof(tmp_path)-1] != 0) return ENOBUFS;
    strncpy(base_name, basename(tmp_path), base_name_size);
    if (base_name[base_name_size-1] != 0) return ENOBUFS;

    ret = dot_to_absolute(base_name, base_name_size);
    if (ret != SUCCESS) {
        return ret;
    }

    return SUCCESS;
}

int get_dirname(char *dir_path, size_t dir_path_size, const char *path)
{
    char tmp_path[PATH_MAX];
    int ret;

    if (!path) return EINVAL;
    if (!dir_path || dir_path_size < 1) return ENOBUFS;

    strncpy(tmp_path, path, sizeof(tmp_path));
    if (tmp_path[sizeof(tmp_path)-1] != 0) return ENOBUFS;
    strncpy(dir_path, dirname(tmp_path), dir_path_size);
    if (dir_path[dir_path_size-1] != 0) return ENOBUFS;

    ret = dot_to_absolute(dir_path, dir_path_size);
    if (ret != SUCCESS) {
        return ret;
    }

    return SUCCESS;
}

int get_directory_and_base_name(char *dir_path, size_t dir_path_size,
                                char *base_name, size_t base_name_size,
                                const char *path)
{
    char tmp_path[PATH_MAX];
    int ret;

    if (!path) return EINVAL;
    if (!dir_path || dir_path_size < 1) return ENOBUFS;
    if (!base_name || base_name_size < 1) return ENOBUFS;

    strncpy(tmp_path, path, sizeof(tmp_path));
    if (tmp_path[sizeof(tmp_path)-1] != 0) return ENOBUFS;
    strncpy(base_name, basename(tmp_path), base_name_size);
    if (base_name[base_name_size-1] != 0) return ENOBUFS;

    strncpy(tmp_path, path, sizeof(tmp_path));
    if (tmp_path[sizeof(tmp_path)-1] != 0) return ENOBUFS;
    strncpy(dir_path, dirname(tmp_path), dir_path_size);
    if (dir_path[dir_path_size-1] != 0) return ENOBUFS;

    ret = dot_to_absolute(dir_path, dir_path_size);
    if (ret != SUCCESS) {
        return ret;
    }

    if (strcmp(base_name, ".") == 0) {
        strncpy(base_name, "", base_name_size);
        if (base_name[base_name_size-1] != 0) return ENOBUFS;
    }

    return SUCCESS;
}

bool is_absolute_path(const char *path)
{
    if (!path) return false;
    return path[0] == '/';
}

int path_concat(char *path, size_t path_size, const char *head, const char *tail)
{
    const char *p, *src;
    char *dst, *dst_end;

    if (!path || path_size < 1) return ENOBUFS;

    dst = path;
    dst_end = path + path_size - 1;             /* -1 allows for NULL terminator */

    if (head && *head) {
        for (p = head; *p; p++);                /* walk to end of head */
        for (p--; p >= head && *p == '/'; p--); /* skip any trailing slashes in head */
        if ((p - head) > path_size-1) return ENOBUFS;
        for (src = head; src <= p && dst < dst_end;) *dst++ = *src++; /* copy head */
    }
    if (tail && *tail) {
        for (p = tail; *p && *p == '/'; p++);   /* skip any leading slashes in tail */
        if (dst > path)
            if (dst < dst_end) *dst++ = '/';    /* insert single slash between head & tail */
        for (src = p; *src && dst <= dst_end;) *dst++ = *src++; /* copy tail */
        if (*src) return ENOBUFS; /* failed to copy everything */
    }
    *dst = 0;
    if (dst > dst_end) {
        return ENOBUFS;
    }
    return SUCCESS;

}

int make_path_absolute(char *absolute_path, size_t absolute_path_size, const char *path)
{
    int result = SUCCESS;
    const char *src;
    char *dst, *dst_end;

    if (!absolute_path || absolute_path_size < 1) return ENOBUFS;

    dst = absolute_path;
    dst_end = absolute_path + absolute_path_size - 1; /* -1 allows for NULL terminator */

    if (is_absolute_path(path)) {
        for (src = path; *src && dst < dst_end;) *dst++ = *src++;
        *dst = 0;
        if (dst > dst_end || *src) result = ENOBUFS;
        return result;
    }

    if ((getcwd(absolute_path, absolute_path_size) == NULL)) {
        if (errno == ERANGE)
            return ENOBUFS;
        else
            return errno;
    }

    for (dst = absolute_path; *dst && dst < dst_end; dst++);
    if (!(path && *path)) return result;
    if (dst > dst_end) {
        *dst = 0;
        return ENOBUFS;
    }

    *dst++ = '/';
    if (dst > dst_end) {
        *dst = 0;
        return ENOBUFS;
    }

    for (src = path; *src && dst < dst_end;) *dst++ = *src++;
    if (*src) return ENOBUFS; /* failed to copy everything */
    *dst = 0;

    return result;
}

char **split_path(const char *path, int *count)
{
    int n_components, component_len, total_component_len, alloc_len;
    const char *start, *end;
    char *mem_block, **array_ptr, *component_ptr;

    if (!path) return NULL;

    /* If path is absolute add in special "/" root component */
    if (*path == '/') {
        n_components = 1;
        total_component_len = 2;
    } else {
        n_components = 0;
        total_component_len = 0;
    }

    /* Scan for components, keep several counts */
    for (start = end = path; *start; start = end) {
        for (start = end; *start && *start == '/'; start++);
        for (end = start; *end && *end != '/'; end++);
        if ((component_len = end - start) == 0) break;
        n_components++;
        total_component_len += component_len + 1;
    }

    /*
     * Allocate a block big enough for component array (with trailing NULL
     * entry, hence n_components+1) and enough room for a copy of each NULL
     * terminated component. We'll copy the components into the same allocation
     * block after the end of the pointer array.
     */
    alloc_len = ((n_components+1) * sizeof(char *)) + total_component_len;

    if ((mem_block = malloc(alloc_len)) == NULL) {
        if (count) *count = -1;
        return NULL;
    }

    /* component array */
    array_ptr = (char **)mem_block;
    /* components copied after end of array */
    component_ptr = mem_block + ((n_components+1)*sizeof(char *));

    /* If path is absolute add in special "/" root component */
    if (*path == '/') {
        *array_ptr++ = component_ptr;
        *component_ptr++ = '/';
        *component_ptr++ = 0;
    }

    for (start = end = path; *start; start = end) {
        for (start = end; *start && *start == '/'; start++);
        for (end = start; *end && *end != '/'; end++);
        if ((component_len = end - start) == 0) break;

        *array_ptr++ = component_ptr;
        while (start < end) *component_ptr++ = *start++;
        *component_ptr++ = 0;
    }
    *array_ptr++ = NULL;
    if (count) *count = n_components;
    return (char **)mem_block;
}

int normalize_path(char *normalized_path, size_t normalized_path_size, const char *path)
{
    int result = SUCCESS;
    int component_len;
    bool is_absolute, can_backup;
    const char *start, *end;
    char *dst, *dst_end, *p, *limit;

    if (!normalized_path || normalized_path_size < 1) return ENOBUFS;

    dst = normalized_path;
    dst_end = normalized_path + normalized_path_size - 1; /* -1 allows for NULL terminator */
    can_backup = true;

    if (!path || !*path) {
        if (dst > dst_end) {
            *dst = 0;
            return ENOBUFS;
        }
        *dst++ = '.';
        *dst = 0;
        return result;
    }

    if ((is_absolute = *path == '/')) {
        if (dst < dst_end) {
            *dst++ = '/';
        } else {
            *dst = 0;
            return ENOBUFS;
        }
    }

    for (start = end = path; *start; start = end) {
        for (start = end; *start && *start == '/'; start++);
        for (end = start; *end && *end != '/'; end++);
        if ((component_len = end - start) == 0) break;
        if (component_len == 1 && start[0] == '.') continue;
        if (component_len == 2 && start[0] == '.' && start[1] == '.' && can_backup) {
            /* back up one level */
            if ((is_absolute && dst == normalized_path+1) || (!is_absolute && dst == normalized_path)) {
                if (is_absolute) continue;
                can_backup = false;
                result = PATH_UTILS_ERROR_NOT_FULLY_NORMALIZED;
            } else {
                if (is_absolute)
                    limit = normalized_path+1;
                else
                    limit = normalized_path;
                for (p = dst-1; p >= limit && *p != '/'; p--);
                if (p <  limit)
                    dst = limit;
                else
                    dst = p;
                continue;
            }
        }

        if ((end-start) > (dst_end-dst)) {
            return ENOBUFS;
        }

        if ((dst > normalized_path) && (dst < dst_end) && (dst[-1] != '/')) *dst++ = '/';
        while ((start < end) && (dst < dst_end)) *dst++ = *start++;
    }

    if (dst == normalized_path) {
        if (is_absolute)
            *dst++ = '/';
        else
            *dst++ = '.';
    }
    *dst = 0;
    return result;
}

int common_path_prefix(char *common_path,
                       size_t common_path_size,
                       int *common_count,
                       const char *path1, const char *path2)
{
    int count1, count2, min_count, i, n_common, result;
    char **split1, **split2;
    char *dst, *dst_end, *src;

    if (!common_path || common_path_size < 1) return ENOBUFS;

    result = SUCCESS;
    n_common = 0;
    split1 = split_path(path1, &count1);
    split2 = split_path(path2, &count2);

    if (count1 <= count2)
        min_count = count1;
    else
        min_count = count2;

    if (min_count <= 0 || !split1 || !split2 ) {
        result = SUCCESS;
        *common_path = 0;
        goto done;
    }

    for (n_common = 0; n_common < min_count; n_common++) {
        if (strcmp(split1[n_common], split2[n_common]) != 0) break;
    }

    if (n_common == 0) {
        result = SUCCESS;
        *common_path = 0;
        goto done;
    }

    dst = common_path;
    dst_end = common_path + common_path_size - 1; /* -1 allows for NULL terminator */
    for (i = 0; i < n_common; i++) {
        for (src = split1[i]; *src && dst < dst_end;) *dst++ = *src++;
        if (dst == dst_end && *src) {
            *dst = 0;
            result = ENOBUFS;
            goto done;
        }
        if (dst[-1] != '/' && i < n_common-1) {   /* insert path separator */
            if (dst == dst_end) {
                *dst = 0;
                result = ENOBUFS;
                goto done;
            }
            *dst++ = '/';
        }
    }
    *dst = 0;

 done:
    free(split1);
    free(split2);
    if (common_count) *common_count = n_common;
    return result;
}

int make_normalized_absolute_path(char *result_path, size_t result_path_size, const char *path)
{
    int error;
    char absolute_path[PATH_MAX];

    if (!result_path || result_path_size < 1) return ENOBUFS;
    *result_path = 0;
    if ((error = make_path_absolute(absolute_path, sizeof(absolute_path), path)) != SUCCESS) return error;
    if ((error = normalize_path(result_path, result_path_size, absolute_path)) != SUCCESS) return error;
    return SUCCESS;
}

int find_existing_directory_ancestor(char *ancestor, size_t ancestor_size, const char *path)
{
    int error;
    char dir_path[PATH_MAX];
    struct stat info;

    if (!ancestor || ancestor_size < 1) return ENOBUFS;
    *ancestor = 0;
    strncpy(dir_path, path, sizeof(dir_path));
    if (dir_path[sizeof(dir_path)-1] != 0) return ENOBUFS;

    while (strcmp(dir_path, "/") != 0) {
        if (lstat(dir_path, &info) < 0) {
            error = errno;
            if (error != ENOENT) return error;
        } else {
            if (S_ISDIR(info.st_mode)) break;
        }
        error = get_dirname(dir_path, sizeof(dir_path), dir_path);
        if (error != SUCCESS) {
            return error;
        }
    }

    strncpy(ancestor, dir_path, ancestor_size);
    if (ancestor[ancestor_size-1] != 0) return ENOBUFS;
    return SUCCESS;
}

int directory_list(const char *path, bool recursive,
                   directory_list_callback_t callback, void *user_data)
{
    DIR *dir;
    struct dirent *entry;
    struct stat info;
    int error = 0;
    char entry_path[PATH_MAX];
    bool prune = false;

    if (!(dir = opendir(path))) {
        error = errno;
        return error;
    }

    for (entry = readdir(dir); entry; entry = readdir(dir)) {
        prune = false;
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        error = path_concat(entry_path, sizeof(entry_path),
                            path, entry->d_name);
        if (error != SUCCESS) {
            return error;
        }

        if (lstat(entry_path, &info) < 0) {
            continue;
        }

        prune = !callback(path, entry->d_name, entry_path, &info, user_data);
        if (S_ISDIR(info.st_mode)) {
            if (recursive && !prune) {
                error = directory_list(entry_path, recursive,
                                       callback, user_data);
                if (error != SUCCESS) {
                    return error;
                }
            }
        }
    }
    error = closedir(dir);
    if (error) {
        return error;
    }
    return SUCCESS;
}

bool is_ancestor_path(const char *ancestor, const char *path)
{
    char **path_components, **ancestor_components;
    int i, path_count, ancestor_count;
    bool result;

    result = false;
    path_components = split_path(path, &path_count);
    ancestor_components = split_path(ancestor, &ancestor_count);

    if (!path_components || !ancestor_components) {
        result = false;
        goto exit;
    }

    if (ancestor_count >= path_count) {
        result = false;
        goto exit;
    }

    for (i = 0; i < ancestor_count; i++) {
        if (strcmp(path_components[i], ancestor_components[i]) != 0) {
            result = false;
            goto exit;
        }
    }

    result = true;

 exit:
    free(path_components);
    free(ancestor_components);
    return result;
}

