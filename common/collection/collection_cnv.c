/*
    COLLECTION LIBRARY

    Convenience wrapper functions are implemented here.
    They take a lot of space but pretty simple so they
    are separated from the core logic.

    Copyright (C) Dmitri Pal <dpal@redhat.com> 2009

    Collection Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Collection Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with Collection Library.  If not, see <http://www.gnu.org/licenses/>.
*/

#define _GNU_SOURCE
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include "trace.h"

/* The collection should use the teal structures */
#include "collection_priv.h"
#include "collection.h"

/* PROPERTIES */
/* Insert string property with positioning */
int col_insert_str_property(struct collection_item *ci,
                            const char *subcollection,
                            int disposition,
                            const char *refprop,
                            int index,
                            unsigned flags,
                            const char *property,
                            char *string,
                            int length)
{
    int error = EOK;

    TRACE_FLOW_STRING("col_insert_string_property", "Entry.");

    if (length == 0) length = strlen(string) + 1;

    error = col_insert_property_with_ref(ci,
                                         subcollection,
                                         disposition,
                                         refprop,
                                         index,
                                         flags,
                                         property,
                                         COL_TYPE_STRING,
                                         (void *)string,
                                         length,
                                         NULL);

    TRACE_FLOW_NUMBER("col_insert_string_property returning", error);
    return error;
}

/* Insert binary property with positioning */
int col_insert_binary_property(struct collection_item *ci,
                               const char *subcollection,
                               int disposition,
                               const char *refprop,
                               int index,
                               unsigned flags,
                               const char *property,
                               void *binary_data,
                               int length)
{
    int error = EOK;

    TRACE_FLOW_STRING("col_insert_binary_property", "Entry.");

    error = col_insert_property_with_ref(ci,
                                         subcollection,
                                         disposition,
                                         refprop,
                                         index,
                                         flags,
                                         property,
                                         COL_TYPE_BINARY,
                                         binary_data,
                                         length,
                                         NULL);

    TRACE_FLOW_NUMBER("col_insert_binary_property returning", error);
    return error;
}


/* Insert integer property with positioning */
int col_insert_int_property(struct collection_item *ci,
                            const char *subcollection,
                            int disposition,
                            const char *refprop,
                            int index,
                            unsigned flags,
                            const char *property,
                            int number)
{
    int error = EOK;

    TRACE_FLOW_STRING("col_insert_int_property", "Entry.");

    error = col_insert_property_with_ref(ci,
                                         subcollection,
                                         disposition,
                                         refprop,
                                         index,
                                         flags,
                                         property,
                                         COL_TYPE_INTEGER,
                                         (void *)&number,
                                         sizeof(int),
                                         NULL);

    TRACE_FLOW_NUMBER("col_insert_int_property returning", error);
    return error;
}


/* Insert unsigned property with positioning */
int col_insert_unsigned_property(struct collection_item *ci,
                                 const char *subcollection,
                                 int disposition,
                                 const char *refprop,
                                 int index,
                                 unsigned flags,
                                 const char *property,
                                 unsigned number)
{
    int error = EOK;

    TRACE_FLOW_STRING("col_insert_unsigned_property", "Entry.");

    error = col_insert_property_with_ref(ci,
                                         subcollection,
                                         disposition,
                                         refprop,
                                         index,
                                         flags,
                                         property,
                                         COL_TYPE_UNSIGNED,
                                         (void *)&number,
                                         sizeof(unsigned),
                                         NULL);

    TRACE_FLOW_NUMBER("col_insert_unsigned_property returning", error);
    return error;
}


/* Insert long property with positioning */
int col_insert_long_property(struct collection_item *ci,
                             const char *subcollection,
                             int disposition,
                             const char *refprop,
                             int index,
                             unsigned flags,
                             const char *property,
                             long number)
{
    int error = EOK;

    TRACE_FLOW_STRING("col_insert_long_property", "Entry.");

    error = col_insert_property_with_ref(ci,
                                         subcollection,
                                         disposition,
                                         refprop,
                                         index,
                                         flags,
                                         property,
                                         COL_TYPE_LONG,
                                         (void *)&number,
                                         sizeof(long),
                                         NULL);

    TRACE_FLOW_NUMBER("col_insert_long_property returning", error);
    return error;
}

/* Insert unsigned long property with positioning */
int col_insert_ulong_property(struct collection_item *ci,
                              const char *subcollection,
                              int disposition,
                              const char *refprop,
                              int index,
                              unsigned flags,
                              const char *property,
                              unsigned long number)
{
    int error = EOK;

    TRACE_FLOW_STRING("col_insert_ulong_property", "Entry.");

    error = col_insert_property_with_ref(ci,
                                         subcollection,
                                         disposition,
                                         refprop,
                                         index,
                                         flags,
                                         property,
                                         COL_TYPE_ULONG,
                                         (void *)&number,
                                         sizeof(unsigned long),
                                         NULL);

    TRACE_FLOW_NUMBER("col_insert_ulong_property returning", error);
    return error;
}

/* Insert double property with positioning */
int col_insert_double_property(struct collection_item *ci,
                               const char *subcollection,
                               int disposition,
                               const char *refprop,
                               int index,
                               unsigned flags,
                               const char *property,
                               double number)
{
    int error = EOK;

    TRACE_FLOW_STRING("col_insert_double_property", "Entry.");

    error = col_insert_property_with_ref(ci,
                                         subcollection,
                                         disposition,
                                         refprop,
                                         index,
                                         flags,
                                         property,
                                         COL_TYPE_DOUBLE,
                                         (void *)&number,
                                         sizeof(double),
                                         NULL);

    TRACE_FLOW_NUMBER("col_insert_double_property returning", error);
    return error;
}

/* Insert bool property with positioning */
int col_insert_bool_property(struct collection_item *ci,
                             const char *subcollection,
                             int disposition,
                             const char *refprop,
                             int index,
                             unsigned flags,
                             const char *property,
                             unsigned char logical)
{
    int error = EOK;

    TRACE_FLOW_STRING("col_insert_bool_property", "Entry.");

    error = col_insert_property_with_ref(ci,
                                         subcollection,
                                         disposition,
                                         refprop,
                                         index,
                                         flags,
                                         property,
                                         COL_TYPE_BOOL,
                                         (void *)&logical,
                                         sizeof(unsigned char),
                                         NULL);

    TRACE_FLOW_NUMBER("col_insert_bool_property returning", error);
    return error;
}


/* Insert string property with positioning and reference. */
int col_insert_str_property_with_ref(struct collection_item *ci,
                                     const char *subcollection,
                                     int disposition,
                                     const char *refprop,
                                     int index,
                                     unsigned flags,
                                     const char *property,
                                     char *string,
                                     int length,
                                     struct collection_item **ret_ref)
{
    int error = EOK;

    TRACE_FLOW_STRING("col_insert_string_property_with_ref", "Entry.");

    if (length == 0) length = strlen(string) + 1;

    error = col_insert_property_with_ref(ci,
                                         subcollection,
                                         disposition,
                                         refprop,
                                         index,
                                         flags,
                                         property,
                                         COL_TYPE_STRING,
                                         (void *)string,
                                         length,
                                         ret_ref);

    TRACE_FLOW_NUMBER("col_insert_string_property_with_ref returning", error);
    return error;
}

/* Insert binary property with positioning and reference. */
int col_insert_binary_property_with_ref(struct collection_item *ci,
                                        const char *subcollection,
                                        int disposition,
                                        const char *refprop,
                                        int index,
                                        unsigned flags,
                                        const char *property,
                                        void *binary_data,
                                        int length,
                                        struct collection_item **ret_ref)
{
    int error = EOK;

    TRACE_FLOW_STRING("col_insert_binary_property_with_ref", "Entry.");

    error = col_insert_property_with_ref(ci,
                                         subcollection,
                                         disposition,
                                         refprop,
                                         index,
                                         flags,
                                         property,
                                         COL_TYPE_BINARY,
                                         (void *)binary_data,
                                         length,
                                         ret_ref);

    TRACE_FLOW_NUMBER("col_insert_binary_property_with_ref returning", error);
    return error;
}

/* Insert int property with positioning and reference. */
int col_insert_int_property_with_ref(struct collection_item *ci,
                                     const char *subcollection,
                                     int disposition,
                                     const char *refprop,
                                     int index,
                                     unsigned flags,
                                     const char *property,
                                     int number,
                                     struct collection_item **ret_ref)
{
    int error = EOK;

    TRACE_FLOW_STRING("col_insert_int_property_with_ref", "Entry.");

    error = col_insert_property_with_ref(ci,
                                         subcollection,
                                         disposition,
                                         refprop,
                                         index,
                                         flags,
                                         property,
                                         COL_TYPE_INTEGER,
                                         (void *)&number,
                                         sizeof(int),
                                         ret_ref);

    TRACE_FLOW_NUMBER("col_insert_int_property_with_ref returning", error);
    return error;
}


/* Insert unsigned property with positioning and reference. */
int col_insert_unsigned_property_with_ref(struct collection_item *ci,
                                          const char *subcollection,
                                          int disposition,
                                          const char *refprop,
                                          int index,
                                          unsigned flags,
                                          const char *property,
                                          unsigned number,
                                          struct collection_item **ret_ref)
{
    int error = EOK;

    TRACE_FLOW_STRING("col_insert_unsigned_property_with_ref", "Entry.");

    error = col_insert_property_with_ref(ci,
                                         subcollection,
                                         disposition,
                                         refprop,
                                         index,
                                         flags,
                                         property,
                                         COL_TYPE_UNSIGNED,
                                         (void *)&number,
                                         sizeof(unsigned),
                                         ret_ref);

    TRACE_FLOW_NUMBER("col_insert_unsigned_property_with_ref returning", error);
    return error;
}

/* Insert long property with positioning and reference. */
int col_insert_long_property_with_ref(struct collection_item *ci,
                                      const char *subcollection,
                                      int disposition,
                                      const char *refprop,
                                      int index,
                                      unsigned flags,
                                      const char *property,
                                      long number,
                                      struct collection_item **ret_ref)
{
    int error = EOK;

    TRACE_FLOW_STRING("col_insert_long_property_with_ref", "Entry.");

    error = col_insert_property_with_ref(ci,
                                         subcollection,
                                         disposition,
                                         refprop,
                                         index,
                                         flags,
                                         property,
                                         COL_TYPE_LONG,
                                         (void *)&number,
                                         sizeof(long),
                                         ret_ref);

    TRACE_FLOW_NUMBER("col_insert_long_property_with_ref returning", error);
    return error;
}

/* Insert unsigned long property with positioning and reference. */
int col_insert_ulong_property_with_ref(struct collection_item *ci,
                                       const char *subcollection,
                                       int disposition,
                                       const char *refprop,
                                       int index,
                                       unsigned flags,
                                       const char *property,
                                       unsigned long number,
                                       struct collection_item **ret_ref)
{
    int error = EOK;

    TRACE_FLOW_STRING("col_insert_ulong_property_with_ref", "Entry.");

    error = col_insert_property_with_ref(ci,
                                         subcollection,
                                         disposition,
                                         refprop,
                                         index,
                                         flags,
                                         property,
                                         COL_TYPE_ULONG,
                                         (void *)&number,
                                         sizeof(unsigned long),
                                         ret_ref);

    TRACE_FLOW_NUMBER("col_insert_ulong_property_with_ref returning", error);
    return error;
}

/* Insert double property with positioning and reference. */
int col_insert_double_property_with_ref(struct collection_item *ci,
                                        const char *subcollection,
                                        int disposition,
                                        const char *refprop,
                                        int index,
                                        unsigned flags,
                                        const char *property,
                                        double number,
                                        struct collection_item **ret_ref)
{
    int error = EOK;

    TRACE_FLOW_STRING("col_insert_double_property_with_ref", "Entry.");

    error = col_insert_property_with_ref(ci,
                                         subcollection,
                                         disposition,
                                         refprop,
                                         index,
                                         flags,
                                         property,
                                         COL_TYPE_DOUBLE,
                                         (void *)&number,
                                         sizeof(double),
                                         ret_ref);

    TRACE_FLOW_NUMBER("col_insert_double_property_with_ref returning", error);
    return error;
}

/* Insert bool property with positioning and reference. */
int col_insert_bool_property_with_ref(struct collection_item *ci,
                                      const char *subcollection,
                                      int disposition,
                                      const char *refprop,
                                      int index,
                                      unsigned flags,
                                      const char *property,
                                      unsigned char logical,
                                      struct collection_item **ret_ref)
{
    int error = EOK;

    TRACE_FLOW_STRING("col_insert_bool_property_with_ref", "Entry.");

    error = col_insert_property_with_ref(ci,
                                         subcollection,
                                         disposition,
                                         refprop,
                                         index,
                                         flags,
                                         property,
                                         COL_TYPE_BOOL,
                                         (void *)&logical,
                                         sizeof(unsigned char),
                                         ret_ref);

    TRACE_FLOW_NUMBER("col_insert_bool_property_with_ref returning", error);
    return error;
}


/* Add a string property. */
int col_add_str_property(struct collection_item *ci,
                         const char *subcollection,
                         const char *property,
                         char *string,
                         int length)
{
    int error = EOK;

    TRACE_FLOW_STRING("col_add_str_property", "Entry.");

    error = col_insert_str_property(ci,
                                    subcollection,
                                    COL_DSP_END,
                                    NULL,
                                    0,
                                    0,
                                    property,
                                    string,
                                    length);

    TRACE_FLOW_NUMBER("col_add_str_property returning", error);
    return error;
}

/* Add a binary property. */
int col_add_binary_property(struct collection_item *ci,
                            const char *subcollection,
                            const char *property,
                            void *binary_data,
                            int length)
{
    int error = EOK;

    TRACE_FLOW_STRING("col_add_binary_property", "Entry.");

    error = col_insert_binary_property(ci,
                                       subcollection,
                                       COL_DSP_END,
                                       NULL,
                                       0,
                                       0,
                                       property,
                                       binary_data,
                                       length);

    TRACE_FLOW_NUMBER("col_add_binary_property returning", error);
    return error;
}

/* Add an int property. */
int col_add_int_property(struct collection_item *ci,
                         const char *subcollection,
                         const char *property,
                         int number)
{
    int error = EOK;

    TRACE_FLOW_STRING("col_add_int_property", "Entry.");

    error = col_insert_int_property(ci,
                                    subcollection,
                                    COL_DSP_END,
                                    NULL,
                                    0,
                                    0,
                                    property,
                                    number);

    TRACE_FLOW_NUMBER("col_add_int_property returning", error);
    return error;
}

/* Add an unsigned int property. */
int col_add_unsigned_property(struct collection_item *ci,
                              const char *subcollection,
                              const char *property,
                              unsigned int number)
{
    int error = EOK;

    TRACE_FLOW_STRING("col_add_unsigned_property", "Entry.");

    error = col_insert_unsigned_property(ci,
                                         subcollection,
                                         COL_DSP_END,
                                         NULL,
                                         0,
                                         0,
                                         property,
                                         number);

    TRACE_FLOW_NUMBER("col_add_unsigned_property returning", error);
    return error;
}

/* Add an long property. */
int col_add_long_property(struct collection_item *ci,
                          const char *subcollection,
                          const char *property,
                          long number)
{
    int error = EOK;

    TRACE_FLOW_STRING("col_add_long_property", "Entry.");


    error = col_insert_long_property(ci,
                                     subcollection,
                                     COL_DSP_END,
                                     NULL,
                                     0,
                                     0,
                                     property,
                                     number);

    TRACE_FLOW_NUMBER("col_add_long_property returning", error);
    return error;
}

/* Add an unsigned long property. */
int col_add_ulong_property(struct collection_item *ci,
                           const char *subcollection,
                           const char *property,
                           unsigned long number)
{
    int error = EOK;

    TRACE_FLOW_STRING("col_add_ulong_property", "Entry.");

    error = col_insert_ulong_property(ci,
                                      subcollection,
                                      COL_DSP_END,
                                      NULL,
                                      0,
                                      0,
                                      property,
                                      number);

    TRACE_FLOW_NUMBER("col_add_ulong_property returning", error);
    return error;
}

/* Add a double property. */
int col_add_double_property(struct collection_item *ci,
                            const char *subcollection,
                            const char *property,
                            double number)
{
    int error = EOK;

    TRACE_FLOW_STRING("col_add_double_property", "Entry.");

    error = col_insert_double_property(ci,
                                       subcollection,
                                       COL_DSP_END,
                                       NULL,
                                       0,
                                       0,
                                       property,
                                       number);

    TRACE_FLOW_NUMBER("col_add_double_property returning", error);
    return error;
}

/* Add a bool property. */
int col_add_bool_property(struct collection_item *ci,
                          const char *subcollection,
                          const char *property,
                          unsigned char logical)
{
    int error = EOK;

    TRACE_FLOW_STRING("col_add_bool_property", "Entry.");

    error = col_insert_bool_property(ci,
                                     subcollection,
                                     COL_DSP_END,
                                     NULL,
                                     0,
                                     0,
                                     property,
                                     logical);

    TRACE_FLOW_NUMBER("col_add_bool_property returning", error);
    return error;
}

/* A function to add a property */
int col_add_any_property(struct collection_item *ci,
                         const char *subcollection,
                         const char *property,
                         int type,
                         void *data,
                         int length)
{
    int error = EOK;

    TRACE_FLOW_STRING("col_add_any_property", "Entry.");

    error = col_insert_property_with_ref(ci,
                                         subcollection,
                                         COL_DSP_END,
                                         NULL,
                                         0,
                                         0,
                                         property,
                                         type,
                                         data,
                                         length,
                                         NULL);

    TRACE_FLOW_NUMBER("col_add_any_property returning", error);
    return error;
}

/* Add a string property with reference */
int col_add_str_property_with_ref(struct collection_item *ci,
                                  const char *subcollection,
                                  const char *property,
                                  char *string, int length,
                                  struct collection_item **ref_ret)
{
    int error = EOK;

    TRACE_FLOW_STRING("col_add_str_property_with_ref", "Entry.");

    error = col_insert_str_property_with_ref(ci,
                                             subcollection,
                                             COL_DSP_END,
                                             NULL,
                                             0,
                                             0,
                                             property,
                                             string,
                                             length,
                                             ref_ret);

    TRACE_FLOW_NUMBER("col_add_str_property_with_ref returning", error);
    return error;
}

/* Add a binary property with reference. */
int col_add_binary_property_with_ref(struct collection_item *ci,
                                     const char *subcollection,
                                     const char *property,
                                     void *binary_data, int length,
                                     struct collection_item **ref_ret)
{
    int error = EOK;

    TRACE_FLOW_STRING("col_add_binary_property_with_ref", "Entry.");

    error = col_insert_binary_property_with_ref(ci,
                                                subcollection,
                                                COL_DSP_END,
                                                NULL,
                                                0,
                                                0,
                                                property,
                                                binary_data,
                                                length,
                                                ref_ret);

    TRACE_FLOW_NUMBER("col_add_binary_property_with_ref returning", error);
    return error;
}

/* Add an int property with reference. */
int col_add_int_property_with_ref(struct collection_item *ci,
                                  const char *subcollection,
                                  const char *property,
                                  int number,
                                  struct collection_item **ref_ret)
{
    int error = EOK;

    TRACE_FLOW_STRING("col_add_int_property_with_ref", "Entry.");

    error = col_insert_int_property_with_ref(ci,
                                             subcollection,
                                             COL_DSP_END,
                                             NULL,
                                             0,
                                             0,
                                             property,
                                             number,
                                             ref_ret);

    TRACE_FLOW_NUMBER("col_add_int_property_with_ref returning", error);
    return error;
}

/* Add an unsigned int property with reference.  */
int col_add_unsigned_property_with_ref(struct collection_item *ci,
                                       const char *subcollection,
                                       const char *property,
                                       unsigned int number,
                                       struct collection_item **ref_ret)
{
    int error = EOK;

    TRACE_FLOW_STRING("col_add_unsigned_property_with_ref", "Entry.");

    error = col_insert_unsigned_property_with_ref(ci,
                                                  subcollection,
                                                  COL_DSP_END,
                                                  NULL,
                                                  0,
                                                  0,
                                                  property,
                                                  number,
                                                  ref_ret);

    TRACE_FLOW_NUMBER("col_add_unsigned_property_with_ref returning", error);
    return error;
}

/* Add an long property with reference. */
int col_add_long_property_with_ref(struct collection_item *ci,
                                   const char *subcollection,
                                   const char *property,
                                   long number,
                                   struct collection_item **ref_ret)
{
    int error = EOK;

    TRACE_FLOW_STRING("col_add_long_property_with_ref", "Entry.");

    error = col_insert_long_property_with_ref(ci,
                                              subcollection,
                                              COL_DSP_END,
                                              NULL,
                                              0,
                                              0,
                                              property,
                                              number,
                                              ref_ret);

    TRACE_FLOW_NUMBER("col_add_long_property_with_ref returning", error);
    return error;
}

/* Add an unsigned long property with reference. */
int col_add_ulong_property_with_ref(struct collection_item *ci,
                                    const char *subcollection,
                                    const char *property,
                                    unsigned long number,
                                    struct collection_item **ref_ret)
{
    int error = EOK;

    TRACE_FLOW_STRING("col_add_ulong_property_with_ref", "Entry.");

    error = col_insert_ulong_property_with_ref(ci,
                                               subcollection,
                                               COL_DSP_END,
                                               NULL,
                                               0,
                                               0,
                                               property,
                                               number,
                                               ref_ret);

    TRACE_FLOW_NUMBER("col_add_ulong_property_with_ref returning", error);
    return error;
}

/* Add a double property with reference. */
int col_add_double_property_with_ref(struct collection_item *ci,
                                     const char *subcollection,
                                     const char *property,
                                     double number,
                                     struct collection_item **ref_ret)
{
    int error = EOK;

    TRACE_FLOW_STRING("col_add_double_property_with_ref", "Entry.");

    error = col_insert_double_property_with_ref(ci,
                                                subcollection,
                                                COL_DSP_END,
                                                NULL,
                                                0,
                                                0,
                                                property,
                                                number,
                                                ref_ret);

    TRACE_FLOW_NUMBER("col_add_double_property_with_ref returning", error);
    return error;
}

/* Add a bool property with reference. */
int col_add_bool_property_with_ref(struct collection_item *ci,
                                   const char *subcollection,
                                   const char *property,
                                   unsigned char logical,
                                   struct collection_item **ref_ret)
{
    int error = EOK;

    TRACE_FLOW_STRING("col_add_bool_property_with_ref", "Entry.");

    error = col_insert_bool_property_with_ref(ci,
                                              subcollection,
                                              COL_DSP_END,
                                              NULL,
                                              0,
                                              0,
                                              property,
                                              logical,
                                              ref_ret);

    TRACE_FLOW_NUMBER("col_add_bool_property_with_ref returning", error);
    return error;
}

/* A function to add a property with reference. */
int col_add_any_property_with_ref(struct collection_item *ci,
                                  const char *subcollection,
                                  const char *property,
                                  int type,
                                  void *data,
                                  int length,
                                  struct collection_item **ref_ret)
{
    int error = EOK;

    TRACE_FLOW_STRING("col_add_any_property_with_ref", "Entry.");

    error = col_insert_property_with_ref(ci,
                                         subcollection,
                                         COL_DSP_END,
                                         NULL,
                                         0,
                                         0,
                                         property,
                                         type,
                                         data,
                                         length,
                                         ref_ret);

    TRACE_FLOW_NUMBER("col_add_any_property_with_ref returning", error);
    return error;
}


/* Update a string property in the collection.
 * Length should include the terminating 0  */
int col_update_str_property(struct collection_item *ci,
                            const char *property,
                            int mode_flags,
                            char *string,
                            int length)
{
    int error = EOK;
    TRACE_FLOW_STRING("col_update_str_property", "Entry.");

    if (length == 0) length = strlen(string) + 1;
    error = col_update_property(ci, property, COL_TYPE_STRING,
                                (void *)string, length, mode_flags);

    TRACE_FLOW_NUMBER("col_update_str_property Returning", error);
    return error;
}

/* Update a binary property in the collection.  */
int col_update_binary_property(struct collection_item *ci,
                               const char *property,
                               int mode_flags,
                               void *binary_data,
                               int length)
{
    int error = EOK;
    TRACE_FLOW_STRING("col_update_binary_property", "Entry.");

    error = col_update_property(ci, property, COL_TYPE_BINARY,
                                binary_data, length, mode_flags);

    TRACE_FLOW_NUMBER("col_update_binary_property Returning", error);
    return error;
}

/* Update an int property in the collection. */
int col_update_int_property(struct collection_item *ci,
                            const char *property,
                            int mode_flags,
                            int number)
{
    int error = EOK;
    TRACE_FLOW_STRING("col_update_int_property", "Entry.");

    error = col_update_property(ci, property, COL_TYPE_INTEGER,
                                (void *)(&number), sizeof(int), mode_flags);

    TRACE_FLOW_NUMBER("col_update_int_property Returning", error);
    return error;
}

/* Update an unsigned int property. */
int col_update_unsigned_property(struct collection_item *ci,
                                 const char *property,
                                 int mode_flags,
                                 unsigned int number)
{
    int error = EOK;
    TRACE_FLOW_STRING("col_update_unsigned_property", "Entry.");

    error = col_update_property(ci, property, COL_TYPE_UNSIGNED,
                                (void *)(&number), sizeof(unsigned int),
                                mode_flags);

    TRACE_FLOW_NUMBER("col_update_unsigned_property Returning", error);
    return error;
}

/* Update a long property. */
int col_update_long_property(struct collection_item *ci,
                             const char *property,
                             int mode_flags,
                             long number)
{
    int error = EOK;
    TRACE_FLOW_STRING("col_update_long_property", "Entry.");

    error = col_update_property(ci, property, COL_TYPE_LONG,
                                (void *)(&number), sizeof(long),
                                mode_flags);

    TRACE_FLOW_NUMBER("col_update_long_property Returning", error);
    return error;

}

/* Update an unsigned long property. */
int col_update_ulong_property(struct collection_item *ci,
                              const char *property,
                              int mode_flags,
                              unsigned long number)
{
    int error = EOK;
    TRACE_FLOW_STRING("col_update_ulong_property", "Entry.");

    error = col_update_property(ci, property, COL_TYPE_ULONG,
                                (void *)(&number), sizeof(unsigned long),
                                mode_flags);

    TRACE_FLOW_NUMBER("col_update_ulong_property Returning", error);
    return error;
}

/* Update a double property. */
int col_update_double_property(struct collection_item *ci,
                               const char *property,
                               int mode_flags,
                               double number)
{
    int error = EOK;
    TRACE_FLOW_STRING("col_update_double_property", "Entry.");

    error = col_update_property(ci, property, COL_TYPE_DOUBLE,
                                (void *)(&number), sizeof(double),
                                mode_flags);

    TRACE_FLOW_NUMBER("col_update_double_property Returning", error);
    return error;
}

/* Update a bool property. */
int col_update_bool_property(struct collection_item *ci,
                             const char *property,
                             int mode_flags,
                             unsigned char logical)
{
    int error = EOK;
    TRACE_FLOW_STRING("col_update_bool_property", "Entry.");

    error = col_update_property(ci, property, COL_TYPE_BOOL,
                             (void *)(&logical), sizeof(unsigned char),
                             mode_flags);

    TRACE_FLOW_NUMBER("col_update_bool_property Returning", error);
    return error;
}

/* Rename item */
int col_modify_item_property(struct collection_item *item,
                             const char *property)
{
    int error;

    TRACE_FLOW_STRING("col_modify_item_property", "Entry");

    error = col_modify_item(item, property, 0, NULL, 0);

    TRACE_FLOW_STRING("col_modify_item_property", "Exit");
    return error;
}

/* Convenience functions that wrap modify_item(). */
/* Modify item data to be str */
int col_modify_str_item(struct collection_item *item,
                        const char *property,
                        char *string,
                        int length)
{
    int len;
    int error;

    TRACE_FLOW_STRING("col_modify_str_item", "Entry");

    if (length != 0) len = length;
    else len = strlen(string) + 1;

    error = col_modify_item(item, property, COL_TYPE_STRING, (void *)string, len);

    TRACE_FLOW_STRING("col_modify_str_item", "Exit");
    return error;
}

/* Modify item data to be binary */
int col_modify_binary_item(struct collection_item *item,
                           const char *property,
                           void *binary_data,
                           int length)
{
    int error;

    TRACE_FLOW_STRING("col_modify_binary_item", "Entry");

    error = col_modify_item(item, property, COL_TYPE_BINARY, binary_data, length);

    TRACE_FLOW_STRING("col_modify_binary_item", "Exit");
    return error;
}

/* Modify item data to be bool */
int col_modify_bool_item(struct collection_item *item,
                         const char *property,
                         unsigned char logical)
{
    int error;

    TRACE_FLOW_STRING("col_modify_bool_item", "Entry");

    error = col_modify_item(item, property, COL_TYPE_BOOL, (void *)(&logical), 1);

    TRACE_FLOW_STRING("col_modify_bool_item", "Exit");
    return error;
}

/* Modify item data to be int */
int col_modify_int_item(struct collection_item *item,
                        const char *property,
                        int number)
{
    int error;

    TRACE_FLOW_STRING("col_modify_int_item","Entry");

    error = col_modify_item(item, property, COL_TYPE_INTEGER,
                            (void *)(&number), sizeof(int));

    TRACE_FLOW_STRING("col_modify_int_item", "Exit");
    return error;
}

/* Modify item data to be long */
int col_modify_long_item(struct collection_item *item,
                         const char *property,
                         long number)
{
    int error;

    TRACE_FLOW_STRING("col_modify_long_item", "Entry");

    error = col_modify_item(item, property, COL_TYPE_LONG,
                            (void *)(&number), sizeof(long));

    TRACE_FLOW_STRING("col_modify_long_item", "Exit");
    return error;
}

/* Modify item data to be unigned long */
int col_modify_ulong_item(struct collection_item *item,
                          const char *property,
                          unsigned long number)
{
    int error;

    TRACE_FLOW_STRING("col_modify_ulong_item", "Entry");

    error = col_modify_item(item, property, COL_TYPE_ULONG,
                            (void *)(&number), sizeof(unsigned long));

    TRACE_FLOW_STRING("col_modify_ulong_item", "Exit");
    return error;
}

int col_modify_unsigned_item(struct collection_item *item,
                             const char *property,
                             unsigned number)
{
    int error;

    TRACE_FLOW_STRING("col_modify_unsigned_item", "Entry");

    error = col_modify_item(item, property, COL_TYPE_UNSIGNED,
                            (void *)(&number), sizeof(unsigned));

    TRACE_FLOW_STRING("col_modify_unsigned_item", "Exit");
    return error;
}

int col_modify_double_item(struct collection_item *item,
                           const char *property,
                           double number)
{
    int error;

    TRACE_FLOW_STRING("col_modify_double_item", "Entry");

    error = col_modify_item(item, property, COL_TYPE_DOUBLE,
                            (void *)(&number), sizeof(double));

    TRACE_FLOW_STRING("col_modify_double_item", "Exit");
    return error;
}
