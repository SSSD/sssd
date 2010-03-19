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

#ifndef PATH_UTILS_H
#define PATH_UTILS_H

/*****************************************************************************/
/******************************** Documentation ******************************/
/*****************************************************************************/

/** @mainpage Pathname manipulation utilities
 *
 * This library contains a set of utilities designed to extract info from
 * and manipulate path names.
 *
 */

/*****************************************************************************/
/******************************* Include Files *******************************/
/*****************************************************************************/

#include <stdbool.h>
#include <libintl.h>
#include <sys/param.h>
#include <sys/stat.h>

/*****************************************************************************/
/*********************************** Defines *********************************/
/*****************************************************************************/

/**
 * @defgroup constants Constants
 * @{
 */

#ifndef _
#define _(String) gettext(String)
#endif

/**
 * @brief SUCCESS (=0) is returned by all functions in the path_utils
 * library on success.
 */
#ifndef SUCCESS
#define SUCCESS 0
#endif

/**
 * @}
 */

/**
 * @defgroup errors Error codes and macros
 * @{
 */

#define PATH_UTILS_ERROR_BASE -3000
#define PATH_UTILS_ERROR_LIMIT (PATH_UTILS_ERROR_BASE+20)

/**
 * @brief You can use this macro to check if an error code is one of
 * the internal path_utils codes.
 */
#define IS_PATH_UTILS_ERROR(error)  (((error) >= PATH_UTILS_ERROR_BASE) && ((error) < PATH_UTILS_ERROR_LIMIT))

/** @brief A path cannot be normalized due to too many parent links
 *
 * Returned when a relative path contains too many parent (\c "..") links.
 * Please see the documentation of \c normalize_path() for full explanation.
 */
#define PATH_UTILS_ERROR_NOT_FULLY_NORMALIZED   (PATH_UTILS_ERROR_BASE + 1)

/**
 * @}
 */

/*****************************************************************************/
/******************************* Type Definitions ****************************/
/*****************************************************************************/

/*****************************************************************************/
/*************************  External Global Variables  ***********************/
/*****************************************************************************/

/*****************************************************************************/
/****************************  Exported Functions  ***************************/
/*****************************************************************************/

/**
 * @defgroup functions Functions
 * @{
 */

/** @brief Given an error code return the string description.
 *
 * @param[in] error The error code
 *
 * @return Error string. If error code is not recognized \c NULL is returned.
 */
const char *path_utils_error_string(int error);

/** @brief Get the basename component of a path
 *
 * Given a path, copy the basename component (in the usual case, the part
 * following the final "/") into the buffer \c base_name
 * whose length is \c base_name_size. If the path does not contain a slash,
 * \c get_basename() returns a copy of path.
 *
 * @param[out]  base_name       The basename component
 * @param[in]   base_name_size  The size of the base_name buffer
 * @param[in]   path            The full path to parse
 *
 * @return \c SUCCESS if successful, non-zero error code otherwise.
 * Possible errors:
 * \li \c ENOBUFS      if the buffer space is too small
 * \li \c EINVAL       The path was a NULL pointer
 */
int get_basename(char *base_name, size_t base_name_size, const char *path);

/** @brief Copy the directory components of a path
 *
 * Given a path, copy the directory components (in the usual case, the path
 * up to, but not including the final "/") into the buffer \c dir_path whose
 * length is \c dir_path_size. If the path does not contain a slash,
 * \c get_dirname() returns the current working directory.
 *
 * @param[out]  dir_path       The directory component
 * @param[in]   dir_path_size  The size of the dir_path buffer
 * @param[in]   path           The full path to parse
 *
 * @return \c SUCCESS if successful, non-zero error code otherwise.
 * Possible errors:
 * \li \c ENOBUFS      If the buffer space is too small
 * \li \c EACCES       Permission to read or search a component of the filename was denied.
 * \li \c ENAMETOOLONG The size of the null-terminated pathname exceeds PATH_MAX bytes.
 * \li \c ENOENT       The current working directory has been unlinked.
 * \li \c EINVAL       The path was a NULL pointer
 */
int get_dirname(char *dir_path, size_t dir_path_size, const char *path);

/** @brief Get the basaname and directory components of a path
 *
 * Given a path, copy the directory components into the buffer \c dir_path whose
 * length is \c dir_path_size and copy the basename component into the buffer
 * \c base_name whose length is \c base_name_size.
 *
 * @param[out]  base_name       The basename component
 * @param[in]   base_name_size  The size of the base_name buffer
 * @param[out]  dir_path       The directory component
 * @param[in]   dir_path_size  The size of the dir_path buffer
 * @param[in]   path           The full path to parse
 *
 * @return \c SUCCESS if successful, non-zero error code otherwise.
 * Possible errors:
 * \li \c ENOBUFS      If the buffer space is too small
 * \li \c EACCES       Permission to read or search a component of the filename was denied.
 * \li \c ENAMETOOLONG The size of the null-terminated pathname exceeds PATH_MAX bytes.
 * \li \c ENOENT       The current working directory has been unlinked.
 * \li \c EINVAL       The path was a NULL pointer
 */
int get_directory_and_base_name(char *dir_path, size_t dir_path_size,
                                char *base_name, size_t base_name_size,
                                const char *path);

/** @brief Tell if path is absolute or relative
 *
 * @param[in]   path           The path to check
 *
 * @return \c true if the path is absolute, \c false otherwise.
 */
bool is_absolute_path(const char *path);

/** @brief Concatenate two components of a path
 *
 * Given two paths, \c head & \c tail, copy their concatenation into the
 * buffer \c path whose length is \c path_size.
 *
 * @param[out]   path           The full path
 * @param[in]    path_size      The size of the path buffer
 * @param[in]    head           The first component of the path
 * @param[in]    tail           The second component of the path
 *
 * @return \c SUCCESS if successful, non-zero error code otherwise.
 * \li \c ENOBUFS      If the buffer space is too small
 */
int path_concat(char *path, size_t path_size, const char *head, const char *tail);

/** @brief Convert a path into absolute
 *
 * Given a path make it absolute storing the absolute path in into the buffer
 * \c absolute_path whose length is \c absolute_path_size.
 *
 * Returns \c SUCCESS if successful, non-zero error code otherwise. Possible errors:
 * \li \c ENOBUFS      If the buffer space is too small
 * \li \c ENOMEM       If user memory cannot be mapped
 * \li \c ENOENT       If directory does not exist (i.e. it has been deleted)
 * \li \c EFAULT       If memory access violation occurs while copying
 * \li \c EINVAL       The path was a NULL pointer
 */
int make_path_absolute(char *absolute_path, size_t absolute_path_size, const char *path);

/** @brief Split a file system path into individual components.
 *
 * Split a file system path into individual components.  Return a pointer to an
 * array of char pointers, each array entry is a pointer to a copy of the
 * component. As a special case if the path begins with / then the first
 * component is "/" so the caller can identify the pah as absolute with the
 * first component being the root. The last entry in the array is \c NULL serving
 * as a termination sentinel. An optional integer count parameter can be
 * provided, which if non-NULL will have the number of components written into
 * it. Thus the caller can iterate on the array until it sees a \c NULL pointer or
 * iterate count times indexing the array.
 *
 * The caller is responsible for calling \c free() on the returned array.  This
 * frees both the array of component pointers and the copies of each component
 * in one operation because the copy of each component is stored in the same
 * allocation block.
 *
 * The original path parameter is not modified.
 *
 * In the event of an error \c NULL is returned and count (if specified) will be -1.
 *
 * Examples:
 *
 * \code
 * char **components, **component;
 * int i;
 *
 * components = split_path(path, NULL);
 * for (component = components; *component; component++)
 *     printf("\"%s\" ", *component);
 * free(components);
 * \endcode
 *
 * -OR-
 *
 * \code
 * components = split_path(path, &count);
 * for (i = 0; i < count; i++)
 *     printf("\"%s\" ", components[i]);
 * free(components);
 * \endcode
 *
 * @param[in]   path    The original path
 * @param[out]  count   The number of components the path was split into
 *
 * @return An array of char pointers, each array entry is a pointer to a
 * copy of the component or NULL on error.
 */
char **split_path(const char *path, int *count);

/** @brief Normalizes a path
 *
 * Normalizes a path copying the resulting normalized path into the buffer
 * \c normalized_path whose length is \c normalized_size.
 *
 * A path is normalized when:
 * \li only 1 slash separates all path components
 * \li there are no \c . path components (except if \c . is the only component)
 * \li there are no \c .. path components
 *
 * The input path may either be an absolute path or a path fragment.
 *
 * As a special case if the input path is \c NULL, the empty string \c "",
 * or \c "." the returned normalized path will be \c ".".
 *
 * \c ".." path components point to the parent directory which effectively
 * means poping the parent off the path. But what happens when there are
 * more \c ".." path components than ancestors in the path? The answer depends
 * on whether the path is an absolute path or a path fragment. If the path is
 * absolute then the extra \c ".." components which would move above the root
 * (/) are simply ignored. This effectively limits the path to the root.
 * However if the path is not absolute, rather it is a path fragment, and
 * there are more \c ".." components than ancestors which can be "popped off"
 * then as many \c ".." components will be popped off the fragement as
 * possible without changing the meaning of the path fragment. In this case
 * some extra \c ".." components will be left in the path and the function
 * will return the error \c ERROR_COULD_NOT_NORMALIZE_PATH_FULLY. However the
 * function will still normalize as much of the path fragment as is possible.
 * The behavior of \c ".." components when the input path is a fragment is
 * adopted because after normalizing a path fragment then the normalized path
 * fragment if made absolute should reference the same file system name as if
 * the unnormalized fragment were made absolute. Note this also means
 * \c ERROR_COULD_NOT_NORMALIZE_PATH_FULLY will never be returned if the input
 * path is absolute.
 *
 * @returns \c SUCCESS if successful, non-zero error code otherwise. Possible
 * errors:
 * \li \c ENOBUFS      If the buffer space is too small
 * \li \c ERROR_COULD_NOT_NORMALIZE_PATH_FULLY If not all \c ".." path components could be removed
 */
int normalize_path(char *normalized_path, size_t normalized_path_size, const char *path);

/** @brief Find the common prefix between two paths
 *
 * Finds the common prefix between two paths, returns the common prefix and
 * optionally the count of how many path components were common between the
 * two paths (if \c common_count is non-NULL). Please note that for absolute
 * paths, the \c "/" root prefix is treated as a common components, so the
 * paths \c "/usr/lib" and \c "/usr/share" would have two common components -
 * \c "/" and \c "/usr".
 *
 * Contrary to some other implementations, \c common_path_prefix() works on
 * path components, not characters, which guarantees at least some level of
 * sanity of the returned prefixes (for example, the common prefix of
 * \c "/usr/share" and \c "/usr/src" would be \c "/usr")
 *
 * @returns \c SUCCESS if successful, non-zero error code otherwise.
 * Possible errors:
 * \li \c ENOBUFS      if the buffer space is too small
 */
int common_path_prefix(char *common_path,
                       size_t common_path_size,
                       int *common_count,
                       const char *path1, const char *path2);


/** @brief Make the input path absolute if it's not already, then normalize it.
 *
 * @returns \c SUCCESS if successful, non-zero error code otherwise.
 * Possible errors:
 * \li \c ENOBUFS      if the buffer space is too small
 */
int make_normalized_absolute_path(char *result_path, size_t result_path_size, const char *path);

/**
 * Find the first path component which is an existing directory by walking from
 * the tail of the path to it's head, return the path of the existing directory.
 *
 * If the pathname is relative and does not contain a directory, the current
 * directory is returned as parent.
 *
 * @returns \c SUCCESS if successful, non-zero error code otherwise.
 * Possible errors:
 * \li \c ENOBUFS      if the buffer space is too small
 * \li \c EACCES       Search permission is denied for one of the directories.
 * \li \c ELOOP        Too many symbolic links encountered while traversing the path.
 * \li \c ENAMETOOLONG File name too long.
 * \li \c ENOMEM       Out of memory (i.e., kernel memory).
 */
int find_existing_directory_ancestor(char *ancestor, size_t ancestor_size, const char *path);

/** @brief callback for the \c directory_list() function
 *
 * Please see the description of \c directory_list() to see more
 * details about this callback
 *
 * @param[in]   directory   Directory name of the visited path
 * @param[in]   base_name   Base name of the visited path
 * @param[in]   path        Full name of the visited path
 * @param[in]   info        Info about the visited directory
 * @param[in]   user_data   Callback data passed by caller
 *
 * @returns if \c false, do not recursively descend into the directory,
 * descend if \c true
 */
typedef bool (*directory_list_callback_t)(const char *directory, const char *base_name,
                                          const char *path, struct stat *info,
                                          void *user_data);
/** @brief Walk a directory.
 *
 * Walk a directory. If \c recursive is \c true child directories will be
 * descended into. The supplied callback is invoked for each entry in the
 * directory.
 *
 * The callback is provided with the directory name, basename, the full
 * pathname (i.e. directory name + basename) a stat structure for the path
 * item and a pointer to any user supplied data specified in the \c user_data
 * parameter. If the callback returns \c false for a directory the recursive
 * descent into that directory does not occur thus effectively "pruning"
 * the tree.
 *
 * @param[in]   path        The path to examine
 * @param[in]   recursive   Whether to recursively examine entries in the directory 
 * @param[in]   callback    The callback to invoke for each entry
 * @param[in]   user_data   The data to pass into the callback
 *
 * @returns SUCCESS if successfull, an error code if not.
 */
int directory_list(const char *path, bool recursive,
                   directory_list_callback_t callback, void *user_data);

/** @brief  Tell if one path is ancestor of another
 *
 * Test to see if the path passed in the \c ancestor parameter is an ancestor
 * of the path passed in the path parameter returning true if it is, \c false
 * otherwise.
 *
 * The test is "static" as such it is performed on the string components in
 * each path. Live symbolic links in the file system are not taken into
 * consideration. The test operates by splitting each path into it's individual
 * components and then comparing each component pairwise for string
 * equality. Both paths mush share a common root component for the test to be
 * meaningful (e.g. don't attempt to compare an absolute path with a relative
 * path).
 *
 * Example:
 * \code
 * is_ancestor_path("/a/b/c"   "/a/b/c/d") => true
 * is_ancestor_path("/a/b/c/d" "/a/b/c/d") => false // equal, not ancestor
 * is_ancestor_path("/a/x/c"   "/a/b/c/d") => false
 * \endcode
 *
 * @returns \c true if \c ancestor is an ancestor of \c path
 */
bool is_ancestor_path(const char *ancestor, const char *path);

/**
 * @}
 */

#endif /* PATH_UTILS_H */
