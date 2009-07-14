#ifndef PATH_UTILS_H
#define PATH_UTILS_H

/*****************************************************************************/
/******************************** Documentation ******************************/
/*****************************************************************************/

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

#ifndef _
#define _(String) gettext(String)
#endif

#ifndef SUCCESS
#define SUCCESS 0
#endif

#define PATH_UTILS_ERROR_BASE -3000
#define PATH_UTILS_ERROR_LIMIT (PATH_UTILS_ERROR_BASE+20)
#define IS_PATH_UTILS_ERROR(error)  (((error) >= PATH_UTILS_ERROR_BASE) && ((error) < PATH_UTILS_ERROR_LIMIT))

#define PATH_UTILS_ERROR_NOT_FULLY_NORMALIZED   (PATH_UTILS_ERROR_BASE + 1)

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
 * Given an error code return the string description.
 * If error code is not recognized NULL is returned.
 */
const char *path_utils_error_string(int error);

/**
 * Given a path, copy the basename component into the buffer base_name whose
 * length is base_name_size.
 *
 * Returns SUCCESS (0) if successful, non-zero error code otherwise. Possible errors:
 * ENOBUFS      if the buffer space is too small
 */
int get_basename(char *base_name, size_t base_name_size, const char *path);

/**
 * Given a path, copy the directory components into the buffer dir_path whose
 * length is dir_path_size.
 *
 * Returns SUCCESS (0) if successful, non-zero error code otherwise. Possible errors:
 * ENOBUFS      If the buffer space is too small
 * EACCES       Permission to read or search a component of the filename was denied.
 * ENAMETOOLONG The size of the null-terminated pathname exceeds PATH_MAX bytes.
 * ENOENT       The current working directory has been unlinked.
 */
int get_dirname(char *dir_path, size_t dir_path_size, const char *path);

/**
 * Given a path, copy the directory components into the buffer dir_path whose
 * length is dir_path_size and copy the basename component into the buffer
 * base_name whose length is base_name_size.
 *
 * Returns SUCCESS (0) if successful, non-zero error code otherwise. Possible errors:
 * ENOBUFS      If the buffer space is too small
 * EACCES       Permission to read or search a component of the filename was denied.
 * ENAMETOOLONG The size of the null-terminated pathname exceeds PATH_MAX bytes.
 * ENOENT       The current working directory has been unlinked.
 */
int get_directory_and_base_name(char *dir_path, size_t dir_path_size, char *base_name, size_t base_name_size, const char *path);

/**
 * Return true if the path is absolute, false otherwise.
 */
bool is_absolute_path(const char *path);

/**
 * Given two paths, head & tail, copy their concatenation into the buffer path
 * whose length is path_size.
 *
 * Returns SUCCESS (0) if successful, non-zero error code otherwise. Possible errors:
 * ENOBUFS      If the buffer space is too small
 */
int path_concat(char *path, size_t path_size, const char *head, const char *tail);

/**
 * Given a path make it absolute storing the absolute path in into the buffer
 * absolute_path whose length is absolute_path_size.
 *
 * Returns SUCCESS (0) if successful, non-zero error code otherwise. Possible errors:
 * ENOBUFS      If the buffer space is too small
 * ENOMEM       If user memory cannot be mapped
 * ENOENT       If directory does not exist (i.e. it has been deleted)
 * EFAULT       If memory access violation occurs while copying
 */
int make_path_absolute(char *absolute_path, size_t absolute_path_size, const char *path);

/**
 * Split a file system path into individual components.  Return a pointer to an
 * array of char pointers, each array entry is a pointer to a copy of the
 * component. As a special case if the path begins with / then the first
 * component is "/" so the caller can identify the pah as absolute with the
 * first component being the root. The last entry in the array is NULL serving
 * as a termination sentinel. An optional integer count parameter can be
 * provided, which if non-NULL will have the number of components written into
 * it. Thus the caller can iterate on the array until it sees a NULL pointer or
 * iterate count times indexing the array.
 *
 * The caller is responsible for calling free() on the returned array.  This
 * frees both the array of component pointers and the copies of each component
 * in one operation because the copy of each component is stored in the same
 * allocation block.
 *
 * The original path parameter is not modified.
 *
 * In the event of an error NULL is returned and count (if specified) will be -1.
 *
 * Examples:
 *
 * char **components, **component;
 * int i;
 *
 * components = split_path(path, NULL);
 * for (component = components; *component; component++)
 *     printf("\"%s\" ", *component);
 * free(components);
 *
 * -OR-
 *
 * components = split_path(path, &count);
 * for (i = 0; i < count; i++)
 *     printf("\"%s\" ", components[i]);
 * free(components);
 *
 */
char **split_path(const char *path, int *count);

/**
 * Normalizes a path copying the resulting normalized path into the buffer
 * normalized_path whose length is normalized_size.
 *
 * A path is normalized when:
 *     only 1 slash separates all path components
 *     there are no . path components (except if . is the only component)
 *     there are no .. path components
 *
 * The input path may either be an absolute path or a path fragment.
 *
 * As a special case if the input path is NULL, the empty string "", or "." the
 * returned normalized path will be ".".
 *
 * .. path components point to the parent directory which effectively means
 * poping the parent off the path. But what happens when there are more .. path
 * components than ancestors in the path? The answer depends on whether the path
 * is an absolute path or a path fragment. If the path is absolute then the
 * extra .. components which would move above the root (/) are simply
 * ignored. This effectively limits the path to the root. However if the path is
 * not absolute, rather it is a path fragment, and there are more .. components
 * than ancestors which can be "popped off" then as many .. components will be
 * popped off the fragement as possible without changing the meaning of the path
 * fragment. In this case some extra .. components will be left in the path and
 * the function will return the error
 * ERROR_COULD_NOT_NORMALIZE_PATH_FULLY. However the function will still
 * normalize as much of the path fragment as is possible. The behavior of
 * .. components when the input path is a fragment is adopted because after
 * normalizing a path fragment then the normalized path fragment if made
 * absolute should reference the same file system name as if the unnormalized
 * fragment were made absolute. Note this also means
 * ERROR_COULD_NOT_NORMALIZE_PATH_FULLY will never be returned if the input path
 * is absolute.
 *
 * Returns SUCCESS (0) if successful, non-zero error code otherwise. Possible errors:
 * ENOBUFS      If the buffer space is too small
 * ERROR_COULD_NOT_NORMALIZE_PATH_FULLY If not all .. path components could be removed
 */
int normalize_path(char *normalized_path, size_t normalized_path_size, const char *path);

/**
 * Finds the common prefix between two paths, returns the common prefix and
 * optionally the count of how many path components were common between the two
 * paths (if common_count is non-NULL).
 *
 * Returns SUCCESS (0) if successful, non-zero error code otherwise. Possible errors:
 * ENOBUFS      if the buffer space is too small
 */
int common_path_prefix(char *common_path, size_t common_path_size, int *common_count, const char *path1, const char *path2);


/**
 * Make the input path absolute if it's not already, then normalize it.
 *
 * Returns SUCCESS (0) if successful, non-zero error code otherwise. Possible errors:
 * ENOBUFS      if the buffer space is too small
 */
int make_normalized_absolute_path(char *result_path, size_t result_path_size, const char *path);

/**
 * Find the first path component which is an existing directory by walking from
 * the tail of the path to it's head, return the path of the existing directory.
 *
 * Returns SUCCESS (0) if successful, non-zero error code otherwise. Possible errors:
 * ENOBUFS      if the buffer space is too small
 * EACCES       Search permission is denied for one of the directories.
 * ELOOP        Too many symbolic links encountered while traversing the path.
 * ENAMETOOLONG File name too long.
 * ENOMEM       Out of memory (i.e., kernel memory).
 */
int find_existing_directory_ancestor(char *ancestor, size_t ancestor_size, const char *path);

/**
 * Walk a directory. If recursive is true child directories will be descended
 * into. The supplied callback is invoked for each entry in the directory.
 *
 * The callback is provided with the directory name, basename the full pathname
 * (i.e. directory name + basename) a stat sturcture for the path item and a
 * pointer to any user supplied data specified in the user_data parameter. If
 * the callback returns false for a directory the recursive descent into that
 * directory does not occur thus effectively "pruning" the tree.
 */
typedef bool (*directory_list_callback_t)(const char *directory, const char *basename, const char *path,
                                         struct stat *info, void *user_data);
int directory_list(const char *path, bool recursive, directory_list_callback_t callback, void *user_data);

/**
 * Test to see if the path passed in the ancestor parameter is an ancestor of
 * the path passed in the path parameter returning true if it is, false otherwise.
 *
 * The test "static" as such it is performed on the string components in each
 * path. Live symbolic links in the file system are not taken into
 * consideration. The test operates by splitting each path into it's individual
 * components and then comparing each component pairwise for string
 * equality. Both paths mush share a common root component for the test to be
 * meaningful (e.g. don't attempt to compare an absolute path with a relative
 * path).
 *
 * Example:
 * is_ancestor_path("/a/b/c"   "/a/b/c/d") => true
 * is_ancestor_path("/a/b/c/d" "/a/b/c/d") => false // equal, not ancestor
 * is_ancestor_path("/a/x/c"   "/a/b/c/d") => false
 */
bool is_ancestor_path(const char *ancestor, const char *path);
#endif
