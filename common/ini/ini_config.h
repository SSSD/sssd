/*
    INI LIBRARY

    Header file for reading configuration from INI file
    and storing as a collection.

    Copyright (C) Dmitri Pal <dpal@redhat.com> 2009

    INI Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    INI Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with INI Library.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef INI_CONFIG_H
#define INI_CONFIG_H

#include <limits.h>
#include <stdio.h>
#include "collection.h"

/** @mainpage The INI configuration interface
 *
 * The goal of the this interface is to allow applications
 * to read configuration from the INI file.
 *
 * So why yet another library to read data from INI file?
 * As we started the SSSD project we looked around for a
 * open source library that would meet the following
 * requirements:
 * - Is written in C (not C++)
 * - Is lightweight.
 * - Has an live community.
 * - Supported on multiple platforms .
 * - Can evolve as we build SSSD solution.
 * - Can deal with different types of values including arrays.
 * - Can deal with sections that are related to each other
 *   and can form a hierarchy of sections.
 * - Has a compatible license we can use.
 *
 * We have seen several solutions but none was able to address our
 * requirements fully. As a result we started developing our own
 * INI parsing library. It is currently stable, however there is
 * a list of the enhancements that we eventually plan to implement.
 * One of the most interesting future features is the grammar
 * validation utility. It is targeted at helping to diagnose
 * a misconfiguration.
 *
 * Currently INI parser allows reading and merging INI files
 * and getting a resulting configuration in one object.
 *
 * One of the main differences of this interface is that
 * the library is created with the idea of reading the configuration
 * data not managing it. Thus currently you will not find
 * any function that alters the configuration data read from the files.
 * There is a set of proposed enhancements to be able to manipulate
 * the configuration data and save it back but there have been no real
 * driver for it. This API is focused on letting applications read data
 * from a file (or files) and interpret it, not to generate configuration
 * files. There are all sorts of different tools that already do that.
 *
 * The INI configuration interface uses COLLECTION (see libcollection
 * interface) to store data internally.
 *
 * Concepts:
 * - The INI file consists of the key value pairs.
 * - The keys and values are separated by the equal sign.
 *   The spaces around equal sign are trimmed. Everything before the equal
 *   sign is the key, everything after is the value.
 * - Comments are the lines that start with ";" or "#" in the first
 *   position of the line.
 * - Library currently does not support multi-line values.
 * - The keys and values are read and stored in the internal
 *   collection.
 * - More than one file can constitute the configuration for the application.
 *   For example there can be a generic file in the /etc that
 *   contains configuration for all the applications of this class running
 *   on the box and then there might be a special file
 *   with parameters specific for the application in the
 *   /etc/whatever.d directory. Interface allows reading
 *   both files in one call. The specific configuration for application
 *   will overwrite the generic one.
 * - If there is no section in the file or there are key value pairs
 *   declared before the first section those pairs will be placed into
 *   the default section.
 * - The values are treated as strings. Spaces are trimmed at the beginning
 *   and the end of the value. The value ends at the end of the line.
 *   If values is too long an error will be returned.
 * - Parsing of the values happens when the caller tries to interpret
 *   the value. The caller can use different functions to do this.
 *   The value can be treated as numeric, logical, string, binary,
 *   array of strings or array of numbers. In case of arrays the functions
 *   accept separators that will be used to slice the value into the array
 *   elements.
 * - If there is any error parsing the section and key values it can be
 *   intercepted by the caller. There are different modes that the library
 *   supports regarding error handling. See details in the description
 *   of the individual functions.
 */

/**
 * @defgroup ini_config INI configuration interface
 * @{
 */

/**
 * @defgroup constants Constants
 * @{
 */

/**
 * @brief Name of the default section.
 *
 * This is the name of the implied section where orphan key-value
 * pairs will be put.
 */
#define INI_DEFAULT_SECTION "default"

/**
 * @defgroup classes Collection classes
 *
 * INI uses COLLECTION library to store data.
 * It creates different objects with implied internal structure.
 * To be able to validate the objects
 * it is a good practice to define a class for each type of
 * the object.
 *
 * This section contains constants that define
 * internal collection classes used by INI interface.
 * They are exposed so that if you use collection for
 * other purposes you can make sure that the object classes
 * do not overlap. It is a good practice to avoid
 * them overlapping. Non-overlapping class space
 * would make internal type checking more effective
 * so that if an object of the wrong class is passed to
 * some interface the interface would be able to
 * check and detect an error.
 *
 * @{
 */
/** @brief Base for the class definitions. */
#define COL_CLASS_INI_BASE        20000
/**
 * @brief Class for the configuration object.
 *
 * The configuration object consists of the collection
 * of collections where each sub collection is a section.
 * Application however should not assume that this always
 * be the case. Use only INI interface functions
 * get data from the configuration object.
 * Do not use the raw collection interface to get
 * data.
 */
#define COL_CLASS_INI_CONFIG      COL_CLASS_INI_BASE + 0
/**
 * @brief A one level collection of key value pairs
 * where values are always strings.
 */
#define COL_CLASS_INI_SECTION     COL_CLASS_INI_BASE + 1
/**
 * @brief A one level collection of parse errors.
 *
 * Collection stores \ref parse_error structures.
 */
#define COL_CLASS_INI_PERROR      COL_CLASS_INI_BASE + 2
/**
 * @brief Collection of error collections.
 *
 * When multiple files are read during one call
 * each file has its own set of parsing errors
 * and warnings. This is the collection
 * of such sets.
 */
#define COL_CLASS_INI_PESET       COL_CLASS_INI_BASE + 3

/**
 * @brief Collection of metadata.
 *
 * Collection that stores metadata.
 */
#define COL_CLASS_INI_META        COL_CLASS_INI_BASE + 4
/**
 * @}
 */

/**
 * @defgroup errorlevel Error tolerance constants
 *
 * Constants in this section define what to do if
 * error or warning encountered while parsing the INI file.
 *
 * @{
 */
/** @brief Fail if any problem is detected. */
#define INI_STOP_ON_ANY     0
/** @brief Best effort - do not fail. */
#define INI_STOP_ON_NONE    1
/** @brief Fail on errors only. */
#define INI_STOP_ON_ERROR   2

/**
 * @}
 */

/**
 * @defgroup parseerr Parsing errors and warnings
 *
 * @{
 */
/** @brief Line is too long (Error). */
#define ERR_LONGDATA        1
/** @brief No closing bracket in section definition (Error). */
#define ERR_NOCLOSESEC      2
/** @brief Section name is missing (Error). */
#define ERR_NOSECTION       3
/** @brief Section name too long (Error). */
#define ERR_SECTIONLONG     4
/** @brief No equal sign (Warning). */
#define ERR_NOEQUAL         5
/** @brief No key before equal sign (Warning). */
#define ERR_NOKEY           6
/** @brief Key is too long (Warning). */
#define ERR_LONGKEY         7

/** @brief Size of the error array. */
#define ERR_MAXPARSE        ERR_LONGKEY

/**
 * @}
 */

/**
 * @defgroup gramerr Grammar errors and warnings
 *
 * Placeholder for now. Reserved for future use.
 *
 * @{
 */
#define ERR_MAXGRAMMAR      0
/**
 * @}
 */

/**
 * @defgroup valerr Validation errors and warnings
 *
 * Placeholder for now. Reserved for future use.
 *
 * @{
 */
#define ERR_MAXVALID        0


/**
 * @}
 */

/**
 * @}
 */

/**
 * @defgroup structures Structures
 * @{
 */

/** @brief Structure that holds error number and
 *  line number for the encountered error.
 */
struct parse_error {
    unsigned line;
    int error;
};


/**
 * @}
 */

/**
 * @defgroup metadata Meta data
 *
 * Metadata is a collection of a similar structure as any ini file.
 * The difference is that there are some predefined sections
 * and attributes inside these sections.
 * Using meta flags one can specify what section he is interested
 * in including into the meta data. If a flag for a corresponding
 * meta data section is specified the data for this section will
 * be included into the meta data collection. The caller can then
 * use meta data collection to get items from it and then get
 * a specific value using a corresponding conversion function.
 *
 * Think about the meta data as an INI file that looks like this:
 *
 * <b>
 * [ACCESS]
 * - uid = <i>\<ini file owner uid\></i>
 * - gid = <i>\<ini file group gid\></i>
 * - perm = <i>\<permissions word\></i>
 * - name = <i>\<file name\></i>
 * - created = <i>\<time stamp\></i>
 * - modified = <i>\<time stamp\></i>
 * - ...
 *
 * [ERROR]
 * - read_error = <i><file open error if any\></i>
 * - ...
 *
 * [<i>TBD</i>]
 * - ...
 *
 * </b>
 *
 * The names of the keys and sections provide an example
 * of how the meta data is structured. Look information
 * about specific sections and available keys in this manual
 * to get the exact set of currently supported sections
 * and keys.
 *
 * @{
 */

/**
 * @brief Collect only meta data.
 *
 * Special flag that indicates that only meta data
 * needs to be collected. No parsing should be performed.
 *
 */
#define INI_META_ACTION_NOPARSE     0x10000000

/**
 * @defgroup metasection Meta data section names
 *
 * @{
 */

/**
 * @brief Meta data section that stores file access information
 * and ownership.
 */
#define INI_META_SEC_ACCESS     "ACCESS"

/**
 * @brief Meta data "access" section flag to include access section
 * into the output.
 */
#define INI_META_SEC_ACCESS_FLAG     0x00000001


/**
 * @defgroup metaaccesskeys Key names available in the "ACCESS" section
 *
 * @{
 *
 */

/**
 * @brief The value for this key will store user ID of the INI file owner.
 *
 */
#define INI_META_KEY_UID     "uid"

/**
 * @brief The value for this key will store group ID of the INI file owner.
 *
 */
#define INI_META_KEY_GID     "gid"

/**
 * @brief The value for this key will store INI file access permissions.
 *
 */
#define INI_META_KEY_PERM     "perm"

/**
 * @brief The value for this key will store INI file device ID.
 *
 */
#define INI_META_KEY_DEV     "dev"

/**
 * @brief The value for this key will store INI file inode number.
 *
 */
#define INI_META_KEY_INODE     "inode"

/**
 * @brief The value for this key will store INI file modification time stamp.
 *
 */
#define INI_META_KEY_MODIFIED     "modified"

/**
 * @brief The value for this key will store INI file full name.
 *
 */
#define INI_META_KEY_NAME     "name"

/**
 * @}
 */

/**
 * @brief Meta data section that stores error related information.
 */
#define INI_META_SEC_ERROR     "ERROR"

/**
 * @brief Meta data "error" section flag to include access section
 * into the output.
 */
#define INI_META_SEC_ERROR_FLAG     0x00000002


/**
 * @defgroup metaerrorkeys Key names available in the "ERROR" section
 *
 * @{
 *
 */

/**
 * @brief The value for this key will store read error when file was opened.
 *
 * If file was opened by caller first but this section was requested
 * the value will be zero.
 */
#define INI_META_KEY_READ_ERROR     "read_error"


/**
 * @}
 */

/**
 * @}
 */

/**
 * @}
 */


/**
 * @defgroup functions Functions
 * @{
 */

/** @brief Function to return a parsing error as a string.
 *
 * @param[in] parsing_error    Error code for the parsing error.
 *
 * @return Error string.
 */
const char *parsing_error_str(int parsing_error);


/**
 * @brief Read configuration information from a file.
 *
 * @param[in]  application         Name of the application,
 *                                 will be used as name of
 *                                 the collection.
 * @param[in]  config_filename     Name of the config file,
 *                                 if NULL the configuration
 *                                 collection will be empty.
 * @param[out] ini_config          If *ini_config is NULL
 *                                 a new ini object will be
 *                                 allocated, otherwise
 *                                 the one that is pointed to
 *                                 will be updated.
 * @param[in]  error_level         Break for errors, warnings
 *                                 or best effort (don't break).
 * @param[out] error_list          List of errors for the file
 *                                 detected during parsing.
 *
 * @return 0 - Success.
 * @return EINVAL - Invalid parameter.
 * @return Any error returned by fopen().
 *
 */
int config_from_file(const char *application,
                     const char *config_filename,
                     struct collection_item **ini_config,
                     int error_level,
                     struct collection_item **error_list);

/**
 * @brief Read configuration information from a file descriptor.
 *
 * @param[in]  application         Name of the application,
 *                                 will be used as name of
 *                                 the collection.
 * @param[in]  fd                  Previously opened file
 *                                 descriptor for the config file.
 * @param[in]  config_source       Name of the file being parsed,
 *                                 for use when printing the error
 *                                 list.
 * @param[out] ini_config          If *ini_config is NULL
 *                                 a new ini object will be
 *                                 allocated, otherwise
 *                                 the one that is pointed to
 *                                 will be updated.
 * @param[in]  error_level         Break for errors, warnings
 *                                 or best effort (don't break).
 * @param[out] error_list          List of errors for the file
 *                                 detected during parsing.
 *
 * @return 0 - Success.
 * @return EINVAL - Invalid parameter.
 *
 */
int config_from_fd(const char *application,
                   int fd,
                   const char *config_source,
                   struct collection_item **ini_config,
                   int error_level,
                   struct collection_item **error_list);



/**
 * @brief Read configuration information from a file with
 * additional meta data.
 *
 * Meta data consists of addition information about
 * the file for example when it was created
 * or who is the owner. For the detailed description
 * of the meta data content and structure see
 * \ref metadata "meta data" section.
 *
 * If the metadata argument is not NULL
 * the calling function MUST always free meta data since it can
 * be allocated even if the function returned error.
 *
 * @param[in]  application         Name of the application,
 *                                 will be used as name of
 *                                 the collection.
 * @param[in]  config_filename     Name of the config file,
 *                                 if NULL the configuration
 *                                 collection will be empty.
 * @param[out] ini_config          If *ini_config is NULL
 *                                 a new ini object will be
 *                                 allocated, otherwise
 *                                 the one that is pointed to
 *                                 will be updated.
 * @param[in]  error_level         Break for errors, warnings
 *                                 or best effort (don't break).
 * @param[out] error_list          List of errors for the file
 *                                 detected during parsing.
 * @param[in]  metaflags           A bit mask of flags that define
 *                                 what kind of metadata should
 *                                 be collected.
 * @param[out] metadata            Collection of metadata
 *                                 values. See \ref metadata "meta data"
 *                                 section for more details.
 *                                 Can be NULL.
 *
 * @return 0 - Success.
 * @return EINVAL - Invalid parameter.
 * @return Any error returned by fopen().
 *
 *
 */
int config_from_file_with_metadata(
                     const char *application,
                     const char *config_filename,
                     struct collection_item **ini_config,
                     int error_level,
                     struct collection_item **error_list,
                     uint32_t metaflags,
                     struct collection_item **metadata);


/**
 * @brief Read configuration information from a file descriptor
 * with additional meta data.
 *
 * Meta data consists of addition information about
 * the file for example when it was created
 * or who is the owner. For the detailed description
 * of the meta data content and structure see
 * \ref metadata "meta data" section.
 *
 * If the metadata argument is not NULL
 * the calling function MUST always free meta data since it can
 * be allocated even if the function returned error.
 *
 * @param[in]  application         Name of the application,
 *                                 will be used as name of
 *                                 the collection.
 * @param[in]  fd                  Previously opened file
 *                                 descriptor for the config file.
 * @param[in]  config_source       Name of the file being parsed,
 *                                 for use when printing the error
 *                                 list.
 * @param[out] ini_config          If *ini_config is NULL
 *                                 a new ini object will be
 *                                 allocated, otherwise
 *                                 the one that is pointed to
 *                                 will be updated.
 * @param[in]  error_level         Break for errors, warnings
 *                                 or best effort (don't break).
 * @param[out] error_list          List of errors for the file
 *                                 detected during parsing.
 * @param[in]  metaflags           A bit mask of flags that define
 *                                 what kind of metadata should
 *                                 be collected.
 * @param[out] metadata            Collection of metadata
 *                                 values. See \ref metadata "meta data"
 *                                 section for more details.
 *                                 Can be NULL.
 *
 * @return 0 - Success.
 * @return EINVAL - Invalid parameter.
 *
 */
int config_from_fd_with_metadata(
                   const char *application,
                   int fd,
                   const char *config_source,
                   struct collection_item **ini_config,
                   int error_level,
                   struct collection_item **error_list,
                   uint32_t metaflags,
                   struct collection_item **metadata);


/**
 * @brief Read default configuration file and then
 * overwrite it with a specific one from the directory.
 *
 * @param[in]  application         Name of the application,
 *                                 will be used as name of
 *                                 the collection.
 * @param[in]  config_file         Name of the configuration file,
 *                                 with default settings for all
 *                                 appplications.
 * @param[in]  config_dir          Name of the directory where
 *                                 the configuration files for
 *                                 different applications reside.
 *                                 Function will look for file
 *                                 with the name constructed by
 *                                 appending ".ini" to the end of
 *                                 the "application" argument.
 * @param[out] ini_config          A new configuration object.
 * @param[in]  error_level         Break for errors, warnings
 *                                 or best effort (don't break).
 * @param[out] error_set           Collection of error lists.
 *                                 One list per file.
 *
 * @return 0 - Success.
 * @return EINVAL - Invalid parameter.
 * @return Any error returned by fopen().
 */
int config_for_app(const char *application,
                   const char *config_file,
                   const char *config_dir,
                   struct collection_item **ini_config,
                   int error_level,
                   struct collection_item **error_set);

/**
 * @brief Read default configuration file and then
 * overwrite it with a specific one from the directory.
 *
 * If requested collect meta data for both.
 *
 * If the metadata argument is not NULL
 * the calling function MUST always free meta data since it can
 * be allocated even if the function returned error.
 *
 * @param[in]  application         Name of the application,
 *                                 will be used as name of
 *                                 the collection.
 * @param[in]  config_file         Name of the configuration file,
 *                                 with default settings for all
 *                                 appplications.
 * @param[in]  config_dir          Name of the directory where
 *                                 the configuration files for
 *                                 different applications reside.
 *                                 Function will look for file
 *                                 with the name constructed by
 *                                 appending ".ini" to the end of
 *                                 the "application" argument.
 * @param[out] ini_config          A new configuration object.
 * @param[in]  error_level         Break for errors, warnings
 *                                 or best effort (don't break).
 * @param[out] error_set           Collection of error lists.
 *                                 One list per file.
 * @param[in]  metaflags           A bit mask of flags that define
 *                                 what kind of metadata should
 *                                 be collected.
 * @param[out] meta_default        Collection of metadata
 *                                 values for the default common
 *                                 config file for all applications.
 *                                 See \ref metadata "meta data"
 *                                 section for more details.
 *                                 Can be NULL.
 * @param[out] meta_appini         Collection of metadata
 *                                 values for the application
 *                                 specific config file.
 *                                 See \ref metadata "meta data"
 *                                 section for more details.
 *                                 Can be NULL.
 *
 * @return 0 - Success.
 * @return EINVAL - Invalid parameter.
 * @return Any error returned by fopen().
 */
int config_for_app_with_metadata(
                   const char *application,
                   const char *config_file,
                   const char *config_dir,
                   struct collection_item **ini_config,
                   int error_level,
                   struct collection_item **error_set,
                   uint32_t metaflags,
                   struct collection_item **meta_default,
                   struct collection_item **meta_appini);
/**
 * @brief Function to free configuration object.
 *
 * @param[in] ini_config       Configuration object.
 *
 */
void free_ini_config(struct collection_item *ini_config);

/**
 * @brief Function to free configuration errors.
 *
 * @param[in] error_set       Configuration error set object.
 *
 */
void free_ini_config_errors(struct collection_item *error_set);


/**
 * @brief Function to free metadata.
 *
 * @param[in] error_set       Configuration meta data object.
 *
 */
void free_ini_config_metadata(struct collection_item *metadata);


/**
 * @brief Print errors and warnings that were detected while parsing one file.
 *
 * @param[in] file           File descriptor.
 * @param[in] error_list     List of the parsing errors.
 *
 */
void print_file_parsing_errors(FILE *file,
                               struct collection_item *error_list);


/**
 * @brief Print errors and warnings that were detected
 * parsing configuration as a whole.
 *
 * Use this function to print results of the config_for_app() call.
 *
 * @param[in] file           File descriptor.
 * @param[in] error_set      List of lists of the parsing errors.
 *
 */
void print_config_parsing_errors(FILE *file,
                                 struct collection_item *error_set);

/**
 * @brief Get list of sections.
 *
 * Get list of sections from the configuration object
 * as an array of strings.
 * Function allocates memory for the array of the sections.
 * Use \ref free_section_list() to free allocated memory.
 *
 * @param[in]  ini_config       Configuration object.
 * @param[out] size             If not NULL parameter will
 *                              receive number of sections
 *                              in the configuration.
 * @param[out] error            If not NULL parameter will
 *                              receive the error code.
 *                              0 - Success.
 *                              EINVAL - Invalid parameter.
 *                              ENOMEM - No memory.
 *
 * @return Array of strings.
 */
char **get_section_list(struct collection_item *ini_config,
                        int *size,
                        int *error);

/**
 * @brief Free list of sections.
 *
 * The section array created by \ref get_section_list()
 * should be freed using this function.
 *
 * @param[in] section_list       Array of strings returned by
 *                               \ref get_section_list() function.
 */
void free_section_list(char **section_list);

/**
 * @brief Get list of attributes.
 *
 * Get list of attributes in a section as an array of strings.
 * Function allocates memory for the array of attributes.
 * Use \ref free_attribute_list() to free allocated memory.
 *
 * @param[in]  ini_config       Configuration object.
 * @param[in]  section          Section name.
 * @param[out] size             If not NULL parameter will
 *                              receive number of attributes
 *                              in the section.
 * @param[out] error            If not NULL parameter will
 *                              receive the error code.
 *                              0 - Success.
 *                              EINVAL - Invalid parameter.
 *                              ENOMEM - No memory.
 *
 * @return Array of strings.
 */
char **get_attribute_list(struct collection_item *ini_config,
                          const char *section,
                          int *size,
                          int *error);

/**
 * @brief Free list of attributes.
 *
 * The attribute array created by \ref get_attribute_list()
 * should be freed using this function.
 *
 * @param[in] attr_list          Array of strings returned by
 *                               \ref get_attribute_list() function.
 */
void free_attribute_list(char **attr_list);

/**
 * @brief Get a configuration item form the configuration.
 *
 * Check return error code first. If the function returns
 * an error there is a serious problem.
 * Then check if item is found. Function will set
 * item parameter to NULL if no attribute with
 * provided name is found in the collection.
 *
 * @param[in]  section          Section name.
 *                              If NULL assumed default.
 * @param[in]  name             Attribute name to find.
 * @param[in]  ini_config       Configuration object to search.
 * @param[out] item             Element of configuration
 *                              collection.
 *                              Will be set to NULL if
 *                              element with the given name
 *                              is not found.
 * @return 0 - Success.
 * @return EINVAL - Invalid parameter.
 * @return ENOMEM - No memory.
 *
 */
int get_config_item(const char *section,
                    const char *name,
                    struct collection_item *ini_config,
                    struct collection_item **item);

/**
 * @brief Convert item value to integer number.
 *
 * This is a conversion function.
 * It converts the value read from the INI file
 * and stored in the configuration item
 * into an integer number. Any of the conversion
 * functions can be used to try to convert the value
 * stored as a string inside the item.
 * The results can be different depending upon
 * how the caller tries to interpret the value.
 * If "strict" parameter is non zero the function will fail
 * if there are more characters after the last digit.
 * The value range is from INT_MIN to INT_MAX.
 *
 * @param[in]  item             Item to interpret.
 *                              It must be retrieved using
 *                              \ref get_config_item().
 * @param[in]  strict           Fail the function if
 *                              the symbol after last digit
 *                              is not valid.
 * @param[in]  def              Default value to use if
 *                              conversion failed.
 * @param[out] error            Variable will get the value
 *                              of the error code if
 *                              error happened.
 *                              Can be NULL. In this case
 *                              function does not set
 *                              the code.
 *                              Codes:
 *                              - 0 - Success.
 *                              - EINVAL - Argument is invalid.
 *                              - EIO - Conversion failed due
 *                                invalid characters.
 *                              - ERANGE - Value is out of range.
 *
 * @return Converted value.
 * In case of failure the function returns default value and
 * sets error code into the provided variable.
 */
int get_int_config_value(struct collection_item *item,
                         int strict,
                         int def,
                         int *error);

/**
 * @brief Convert item value to long number.
 *
 * This is a conversion function.
 * It converts the value read from the INI file
 * and stored in the configuration item
 * into a long number. Any of the conversion
 * functions can be used to try to convert the value
 * stored as a string inside the item.
 * The results can be different depending upon
 * how the caller tries to interpret the value.
 * If "strict" parameter is non zero the function will fail
 * if there are more characters after the last digit.
 * The value range is from LONG_MIN to LONG_MAX.
 *
 * @param[in]  item             Item to interpret.
 *                              It must be retrieved using
 *                              \ref get_config_item().
 * @param[in]  strict           Fail the function if
 *                              the symbol after last digit
 *                              is not valid.
 * @param[in]  def              Default value to use if
 *                              conversion failed.
 * @param[out] error            Variable will get the value
 *                              of the error code if
 *                              error happened.
 *                              Can be NULL. In this case
 *                              function does not set
 *                              the code.
 *                              Codes:
 *                              - 0 - Success.
 *                              - EINVAL - Argument is invalid.
 *                              - EIO - Conversion failed due
 *                                invalid characters.
 *                              - ERANGE - Value is out of range.
 *
 * @return Converted value.
 * In case of failure the function returns default value and
 * sets error code into the provided variable.
 */
long get_long_config_value(struct collection_item *item,
                           int strict,
                           long def,
                           int *error);

/**
 * @brief Convert item value to unsigned integer number.
 *
 * This is a conversion function.
 * It converts the value read from the INI file
 * and stored in the configuration item
 * into an unsigned integer number. Any of the conversion
 * functions can be used to try to convert the value
 * stored as a string inside the item.
 * The results can be different depending upon
 * how the caller tries to interpret the value.
 * If "strict" parameter is non zero the function will fail
 * if there are more characters after the last digit.
 * The value range is from 0 to UINT_MAX.
 *
 * @param[in]  item             Item to interpret.
 *                              It must be retrieved using
 *                              \ref get_config_item().
 * @param[in]  strict           Fail the function if
 *                              the symbol after last digit
 *                              is not valid.
 * @param[in]  def              Default value to use if
 *                              conversion failed.
 * @param[out] error            Variable will get the value
 *                              of the error code if
 *                              error happened.
 *                              Can be NULL. In this case
 *                              function does not set
 *                              the code.
 *                              Codes:
 *                              - 0 - Success.
 *                              - EINVAL - Argument is invalid.
 *                              - EIO - Conversion failed due
 *                                invalid characters.
 *                              - ERANGE - Value is out of range.
 *
 * @return Converted value.
 * In case of failure the function returns default value and
 * sets error code into the provided variable.
 */
unsigned get_unsigned_config_value(struct collection_item *item,
                                   int strict,
                                   unsigned def,
                                   int *error);

/**
 * @brief Convert item value to unsigned long number.
 *
 * This is a conversion function.
 * It converts the value read from the INI file
 * and stored in the configuration item
 * into an unsigned long number. Any of the conversion
 * functions can be used to try to convert the value
 * stored as a string inside the item.
 * The results can be different depending upon
 * how the caller tries to interpret the value.
 * If "strict" parameter is non zero the function will fail
 * if there are more characters after the last digit.
 * The value range is from 0 to ULONG_MAX.
 *
 * @param[in]  item             Item to interpret.
 *                              It must be retrieved using
 *                              \ref get_config_item().
 * @param[in]  strict           Fail the function if
 *                              the symbol after last digit
 *                              is not valid.
 * @param[in]  def              Default value to use if
 *                              conversion failed.
 * @param[out] error            Variable will get the value
 *                              of the error code if
 *                              error happened.
 *                              Can be NULL. In this case
 *                              function does not set
 *                              the code.
 *                              Codes:
 *                              - 0 - Success.
 *                              - EINVAL - Argument is invalid.
 *                              - EIO - Conversion failed due
 *                                invalid characters.
 *                              - ERANGE - Value is out of range.
 *
 * @return Converted value.
 * In case of failure the function returns default value and
 * sets error code into the provided variable.
 */
unsigned long get_ulong_config_value(struct collection_item *item,
                                     int strict,
                                     unsigned long def,
                                     int *error);

/**
 * @brief Convert item value to floating point number.
 *
 * This is a conversion function.
 * It converts the value read from the INI file
 * and stored in the configuration item
 * into a floating point number. Any of the conversion
 * functions can be used to try to convert the value
 * stored as a string inside the item.
 * The results can be different depending upon
 * how the caller tries to interpret the value.
 * If "strict" parameter is non zero the function will fail
 * if there are more characters after the last digit.
 *
 * @param[in]  item             Item to interpret.
 *                              It must be retrieved using
 *                              \ref get_config_item().
 * @param[in]  strict           Fail the function if
 *                              the symbol after last digit
 *                              is not valid.
 * @param[in]  def              Default value to use if
 *                              conversion failed.
 * @param[out] error            Variable will get the value
 *                              of the error code if
 *                              error happened.
 *                              Can be NULL. In this case
 *                              function does not set
 *                              the code.
 *                              Codes:
 *                              - 0 - Success.
 *                              - EINVAL - Argument is invalid.
 *                              - EIO - Conversion failed due
 *                                invalid characters.
 *
 * @return Converted value.
 * In case of failure the function returns default value and
 * sets error code into the provided variable.
 */
double get_double_config_value(struct collection_item *item,
                               int strict,
                               double def,
                               int *error);

/**
 * @brief Convert item value into a logical value.
 *
 * This is a conversion function.
 * It converts the value read from the INI file
 * and stored in the configuration item
 * into a Boolean. Any of the conversion
 * functions can be used to try to convert the value
 * stored as a string inside the item.
 * The results can be different depending upon
 * how the caller tries to interpret the value.
 *
 * @param[in]  item             Item to interpret.
 *                              It must be retrieved using
 *                              \ref get_config_item().
 * @param[in]  def              Default value to use if
 *                              conversion failed.
 * @param[out] error            Variable will get the value
 *                              of the error code if
 *                              error happened.
 *                              Can be NULL. In this case
 *                              function does not set
 *                              the code.
 *                              Codes:
 *                              - 0 - Success.
 *                              - EINVAL - Argument is invalid.
 *                              - EIO - Conversion failed due
 *                                invalid characters.
 *
 * @return Converted value.
 * In case of failure the function returns default value and
 * sets error code into the provided variable.
 */
unsigned char get_bool_config_value(struct collection_item *item,
                                    unsigned char def,
                                    int *error);

/**
 * @brief Get string configuration value
 *
 * Function creates a copy of the string value stored in the item.
 * Returned value needs to be freed after use.
 * If error occurred the returned value will be NULL.
 *
 * @param[in]  item             Item to use.
 *                              It must be retrieved using
 *                              \ref get_config_item().
 * @param[out] error            Variable will get the value
 *                              of the error code if
 *                              error happened.
 *                              Can be NULL. In this case
 *                              function does not set
 *                              the code.
 *                              Codes:
 *                              - 0 - Success.
 *                              - EINVAL - Argument is invalid.
 *                              - ENOMEM - No memory.
 *
 * @return Copy of the string or NULL.
 */
char *get_string_config_value(struct collection_item *item,
                              int *error);
/**
 * @brief Function returns the string stored in the item.
 *
 * Function returns a reference to the string value
 * stored inside the item. This string can't be altered.
 * The string will go out of scope if the item is deleted.
 *
 * @param[in]  item             Item to use.
 *                              It must be retrieved using
 *                              \ref get_config_item().
 * @param[out] error            Variable will get the value
 *                              of the error code if
 *                              error happened.
 *                              Can be NULL. In this case
 *                              function does not set
 *                              the code.
 *                              Codes:
 *                              - 0 - Success.
 *                              - EINVAL - Argument is invalid.
 *
 * @return String from the item.
 */
const char *get_const_string_config_value(struct collection_item *item,
                                          int *error);

/**
 * @brief Convert item value into a binary sequence.
 *
 * This is a conversion function.
 * It converts the value read from the INI file
 * and stored in the configuration item
 * into a sequence of bytes.
 * Any of the conversion functions
 * can be used to try to convert the value
 * stored as a string inside the item.
 * The results can be different depending upon
 * how the caller tries to interpret the value.
 *
 * The function allocates memory.
 * It is the responsibility of the caller to free it after use.
 * Use \ref free_bin_config_value() for this purpose.
 * Functions will return NULL if conversion failed.
 *
 * Function assumes that the value being interpreted
 * has a special format.
 * The string should be taken in single quotes
 * and consist of hex encoded value represented by
 * two hex digits per byte.
 * Case does not matter.
 *
 * Example: '0a2BFeCc'
 *
 * @param[in]  item             Item to interpret.
 *                              It must be retrieved using
 *                              \ref get_config_item().
 * @param[out] length           Variable that optionally receives
 *                              the length of the binary
 *                              sequence.
 * @param[out] error            Variable will get the value
 *                              of the error code if
 *                              error happened.
 *                              Can be NULL. In this case
 *                              function does not set
 *                              the code.
 *                              Codes:
 *                              - 0 - Success.
 *                              - EINVAL - Argument is invalid.
 *                              - EIO - Conversion failed due
 *                                invalid characters.
 *                              - ENOMEM - No memory.
 *
 * @return Converted value.
 * In case of failure the function returns NULL.
 */
char *get_bin_config_value(struct collection_item *item,
                           int *length,
                           int *error);

/**
 * @brief Free binary buffer
 *
 * Free binary value returned by \ref get_bin_config_value().
 *
 * @param[in] bin              Binary buffer to free.
 *
 */
void free_bin_config_value(char *bin);

/**
 * @brief Convert value to an array of strings.
 *
 * This is a conversion function.
 * It converts the value read from the INI file
 * and stored in the configuration item
 * into an array of strings. Any of the conversion
 * functions can be used to try to convert the value
 * stored as a string inside the item.
 * The results can be different depending upon
 * how the caller tries to interpret the value.
 *
 * Separator string includes up to three different separators.
 * If separator NULL, comma is assumed.
 * The spaces are trimmed automatically around separators
 * in the string.
 * The function drops empty tokens from the list.
 * This means that the string like this: "apple, ,banana, ,orange ,"
 * will be translated into the list of three items:
 * "apple","banana" and "orange".
 *
 * The length of the allocated array is returned in "size".
 * Size and error parameters can be NULL.
 * Use \ref free_string_config_array() to free the array after use.
 *
 * The array is always NULL terminated so
 * it is safe not to get size and just loop until
 * array element is NULL.
 *
 * @param[in]  item             Item to interpret.
 *                              It must be retrieved using
 *                              \ref get_config_item().
 * @param[in]  sep              String cosisting of separator
 *                              symbols. For example: ",.;" would mean
 *                              that comma, dot and semicolon
 *                              should be treated as separators
 *                              in the value.
 * @param[out] size             Variable that optionally receives
 *                              the size of the array.
 * @param[out] error            Variable will get the value
 *                              of the error code if
 *                              error happened.
 *                              Can be NULL. In this case
 *                              function does not set
 *                              the code.
 *                              Codes:
 *                              - 0 - Success.
 *                              - EINVAL - Argument is invalid.
 *                              - EIO - Conversion failed.
 *                              - ENOMEM - No memory.
 *
 * @return Array of strings.
 * In case of failure the function returns NULL.
 */
char **get_string_config_array(struct collection_item *item,
                               const char *sep,
                               int *size,
                               int *error);

/**
 * @brief Convert value to an array of strings.
 *
 * This is a conversion function.
 * It converts the value read from the INI file
 * and stored in the configuration item
 * into an array of strings. Any of the conversion
 * functions can be used to try to convert the value
 * stored as a string inside the item.
 * The results can be different depending upon
 * how the caller tries to interpret the value.
 *
 * Separator string includes up to three different separators.
 * If separator NULL, comma is assumed.
 * The spaces are trimmed automatically around separators
 * in the string.
 * The function does not drop empty tokens from the list.
 * This means that the string like this: "apple, ,banana, ,orange ,"
 * will be translated into the list of five items:
 * "apple", "", "banana", "" and "orange".
 *
 * The length of the allocated array is returned in "size".
 * Size and error parameters can be NULL.
 * Use \ref free_string_config_array() to free the array after use.
 *
 * The array is always NULL terminated so
 * it is safe not to get size and just loop until
 * array element is NULL.
 *
 * @param[in]  item             Item to interpret.
 *                              It must be retrieved using
 *                              \ref get_config_item().
 * @param[in]  sep              String cosisting of separator
 *                              symbols. For example: ",.;" would mean
 *                              that comma, dot and semicolon
 *                              should be treated as separators
 *                              in the value.
 * @param[out] size             Variable that optionally receives
 *                              the size of the array.
 * @param[out] error            Variable will get the value
 *                              of the error code if
 *                              error happened.
 *                              Can be NULL. In this case
 *                              function does not set
 *                              the code.
 *                              Codes:
 *                              - 0 - Success.
 *                              - EINVAL - Argument is invalid.
 *                              - EIO - Conversion failed.
 *                              - ENOMEM - No memory.
 *
 * @return Array of strings.
 * In case of failure the function returns NULL.
 */
char **get_raw_string_config_array(struct collection_item *item,
                                   const char *sep,
                                   int *size,
                                   int *error);

/**
 * @brief Convert value to an array of long values.
 *
 * This is a conversion function.
 * It converts the value read from the INI file
 * and stored in the configuration item
 * into an array of long values. Any of the conversion
 * functions can be used to try to convert the value
 * stored as a string inside the item.
 * The results can be different depending upon
 * how the caller tries to interpret the value.
 *
 * Separators inside the string are detected automatically.
 * The spaces are trimmed automatically around separators
 * in the string.
 *
 * The length of the allocated array is returned in "size".
 * Size parameter can't be NULL.
 *
 * Use \ref free_long_config_array() to free the array after use.
 *
 * @param[in]  item             Item to interpret.
 *                              It must be retrieved using
 *                              \ref get_config_item().
 * @param[out] size             Variable that receives
 *                              the size of the array.
 * @param[out] error            Variable will get the value
 *                              of the error code if
 *                              error happened.
 *                              Can be NULL. In this case
 *                              function does not set
 *                              the code.
 *                              Codes:
 *                              - 0 - Success.
 *                              - EINVAL - Argument is invalid.
 *                              - EIO - Conversion failed.
 *                              - ERANGE - Value is out of range.
 *                              - ENOMEM - No memory.
 *
 * @return Array of long values.
 * In case of failure the function returns NULL.
 */
long *get_long_config_array(struct collection_item *item,
                            int *size,
                            int *error);

/**
 * @brief Convert value to an array of floating point values.
 *
 * This is a conversion function.
 * It converts the value read from the INI file
 * and stored in the configuration item
 * into an array of floating point values. Any of the conversion
 * functions can be used to try to convert the value
 * stored as a string inside the item.
 * The results can be different depending upon
 * how the caller tries to interpret the value.
 *
 * Separators inside the string are detected automatically.
 * The spaces are trimmed automatically around separators
 * in the string.
 *
 * The length of the allocated array is returned in "size".
 * Size parameter can't be NULL.
 *
 * Use \ref free_double_config_array() to free the array after use.
 *
 * @param[in]  item             Item to interpret.
 *                              It must be retrieved using
 *                              \ref get_config_item().
 * @param[out] size             Variable that receives
 *                              the size of the array.
 * @param[out] error            Variable will get the value
 *                              of the error code if
 *                              error happened.
 *                              Can be NULL. In this case
 *                              function does not set
 *                              the code.
 *                              Codes:
 *                              - 0 - Success.
 *                              - EINVAL - Argument is invalid.
 *                              - EIO - Conversion failed.
 *                              - ENOMEM - No memory.
 *
 * @return Array of floating point values.
 * In case of failure the function returns NULL.
 */
double *get_double_config_array(struct collection_item *item,
                                int *size,
                                int *error);

/**
 * @brief Free array of string values.
 *
 * Use this function to free the array returned by
 * \ref get_string_config_array() or by
 * \ref get_raw_string_config_array().
 *
 * @param[in] str_config        Array of string values.
 */
void free_string_config_array(char **str_config);

/**
 * @brief Free array of long values.
 *
 * Use this function to free the array returned by
 * \ref get_long_config_array().
 *
 * @param[in] array         Array of long values.
 */
void free_long_config_array(long *array);
/**
 * @brief Free array of floating pointer values.
 *
 * Use this function to free the array returned by
 * \ref get_double_config_array().
 *
 * @param[in] array         Array of floating pointer values.
 */
void free_double_config_array(double *array);


/**
 * @}
 */

#endif
