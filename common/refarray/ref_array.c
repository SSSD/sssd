/*
    REF ARRAY

    Implementation of the dynamic array with reference count.

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
#include <errno.h>  /* for errors */
#include <stdint.h>
#include <malloc.h>
#include <string.h>
#include <stdio.h>

#include "ref_array.h"
#include "config.h"
#include "trace.h"

/* The structure used in referenced array */
struct ref_array {
    void *storage;      /* The storage buffer */
    size_t elsize;      /* Size of one element in the buffer */
    uint32_t size;      /* Size of the storage in items */
    uint32_t grow_by;   /* What increment use to reallocate memory */
    uint32_t len;       /* Number of the elements in the array */
    uint32_t refcount;  /* Reference count */
    ref_array_fn cb;    /* Cleanup callback */
    void *cb_data;      /* Caller's callback data */
};

/****************************************************/
/* INTERNAL FUNCTIONS                               */
/****************************************************/
static int ref_array_grow(struct ref_array *ra)
{
    int error = EOK;
    void *newbuf = NULL;

    TRACE_FLOW_STRING("ref_array_grow", "Entry");

    TRACE_INFO_NUMBER("Current length: ", ra->len);
    TRACE_INFO_NUMBER("Current size: ", ra->size);

    /* Grow buffer if needed */
    newbuf = realloc(ra->storage, (ra->size + ra->grow_by) * ra->elsize);
    if (newbuf == NULL) {
        TRACE_ERROR_NUMBER("Failed to allocate memory.", ENOMEM);
        return ENOMEM;
    }

    ra->storage = newbuf;
    ra->size += ra->grow_by;

    TRACE_INFO_NUMBER("Final size: ", ra->size);
    TRACE_FLOW_NUMBER("elapi_grow_data. Exit. Returning", error);
    return error;

}


/****************************************************/
/* PUBLIC FUNCTIONS                                 */
/****************************************************/

/* Create referenced array */
int ref_array_create(struct ref_array **ra,
                     size_t elemsz,
                     uint32_t grow_by,
                     ref_array_fn cb,
                     void *data)
{
    struct ref_array *new_ra = NULL;

    TRACE_FLOW_STRING("ref_array_create", "Entry");

    if (!ra) {
        TRACE_ERROR_NUMBER("Uninitialized argument.", EINVAL);
        return EINVAL;
    }

    if ((!elemsz) || (!grow_by)) {
        TRACE_ERROR_NUMBER("Invalid argument.", EINVAL);
        return EINVAL;
    }

    new_ra = (struct ref_array *)malloc(sizeof(struct ref_array));

    if (!new_ra) {
        TRACE_ERROR_NUMBER("Failed to allocate memory.", ENOMEM);
        return ENOMEM;
    }

    new_ra->storage = NULL;
    new_ra->elsize = elemsz;
    new_ra->size = 0;
    new_ra->grow_by = grow_by;
    new_ra->len = 0;
    new_ra->refcount = 1;
    new_ra->cb = cb;
    new_ra->cb_data = data;

    *ra = new_ra;

    TRACE_FLOW_STRING("ref_array_create", "Exit");
    return EOK;
}

/* Get new reference to an array */
struct ref_array *ref_array_getref(struct ref_array *ra)
{
    TRACE_FLOW_STRING("ref_array_getref", "Entry");

    /* Check if array is not NULL */
    if (ra) {
        TRACE_INFO_NUMBER("Increasing reference count. Current: ", ra->refcount);
        /* Increase reference count */
        ra->refcount++;
        TRACE_INFO_NUMBER("Increased reference count. New: ", ra->refcount);

    }
    else {
        TRACE_ERROR_STRING("Uninitialized array.", "Returning NULL");
    }

    TRACE_FLOW_STRING("ref_array_getref", "Exit");
    return ra;
}

/* Delete the array */
void ref_array_destroy(struct ref_array *ra)
{
    int idx;

    TRACE_FLOW_STRING("ref_array_destroy", "Entry");

    /* Check if array is not NULL */
    if (!ra) {
        TRACE_ERROR_STRING("Uninitialized array.", "Coding error???");
        return;
    }

    TRACE_INFO_NUMBER("Current reference count: ", ra->refcount);
    if (ra->refcount) {
        /* Decrease reference count */
        ra->refcount--;
        if (ra->refcount == 0) {
            TRACE_INFO_NUMBER("It is time to delete array. Count:", ra->refcount);
            if (ra->cb) {
                for (idx = 0; idx < ra->len; idx++) {
                    ra->cb((unsigned char *)(ra->storage) + idx * ra->elsize,
                            REF_ARRAY_DESTROY, ra->cb_data);
                }
            }
            free(ra->storage);
            free(ra);
        }
    }
    else {
        /* Should never be here...
         * This can happen if the caller by mistake would try to
         * destroy the object from within the callback. Brrr....
         */
        TRACE_ERROR_STRING("Reference count is 0.", "Coding error???");
    }

    TRACE_FLOW_STRING("ref_array_destroy", "Exit");
}

/* Add new element to the array */
int ref_array_append(struct ref_array *ra, void *element)
{
    int error = EOK;

    TRACE_FLOW_STRING("ref_array_append", "Entry");
    if ((!ra) || (!element)) {
        TRACE_ERROR_NUMBER("Uninitialized argument.", EINVAL);
        return EINVAL;
    }

    /* Do we have enough room for a new element? */
    if (ra->size == ra->len) {
        error = ref_array_grow(ra);
        if (error) {
            TRACE_ERROR_NUMBER("Failed to grow array.", error);
            return error;
        }
    }

    /* Copy element */
    memcpy((unsigned char *)(ra->storage) + ra->len * ra->elsize,
           element,
           ra->elsize);

    ra->len++;

    TRACE_FLOW_STRING("ref_array_append", "Exit");
    return error;
}

/* Get element */
void *ref_array_get(struct ref_array *ra, uint32_t idx, void *acptr)
{
    TRACE_FLOW_STRING("ref_array_get", "Entry");

    if (!ra) {
        TRACE_ERROR_STRING("Uninitialized argument.", "");
        return NULL;
    }

    if (idx >= ra->len) {
        TRACE_ERROR_NUMBER("Invalid idx.", idx);
        return NULL;
    }

    TRACE_INFO_NUMBER("Index: ", idx);

    if (acptr) {

        TRACE_INFO_STRING("Copying data.", "");
        memcpy(acptr,
               (unsigned char *)(ra->storage) + idx * ra->elsize,
               ra->elsize);

    }

    TRACE_FLOW_STRING("ref_array_get returning internal storage", "Exit");
    return (unsigned char *)(ra->storage) + idx * ra->elsize;
}


/* Get length */
int ref_array_getlen(struct ref_array *ra, uint32_t *len)
{
    TRACE_FLOW_STRING("ref_array_getlen", "Entry");

    if ((!ra) || (!len)) {
        TRACE_ERROR_STRING("Uninitialized argument.", "");
        return EINVAL;
    }

    *len = ra->len;

    TRACE_FLOW_STRING("ref_array_getlen", "Exit");
    return EOK;
}

/* Alternative function to get length */
uint32_t ref_array_len(struct ref_array *ra)
{
    TRACE_FLOW_STRING("ref_array_len", "Entry");

    if (!ra) {
        TRACE_ERROR_STRING("Uninitialized argument.", "");
        errno = EINVAL;
        return 0;
    }

    TRACE_FLOW_STRING("ref_array_len", "Exit");
    return ra->len;
}


/* Insert a new element into the array */
int ref_array_insert(struct ref_array *ra,
                     uint32_t idx,
                     void *element)
{
    int error = EOK;
    uint32_t i;

    TRACE_FLOW_STRING("ref_array_insert", "Entry");

    if ((!ra) || (!element)) {
        TRACE_ERROR_NUMBER("Uninitialized argument.", EINVAL);
        return EINVAL;
    }

    if (idx > ra->len) {
        TRACE_ERROR_NUMBER("Index is out of range", ERANGE);
        return ERANGE;
    }

    /* Do we have enough room for a new element? */
    if (ra->size == ra->len) {
        error = ref_array_grow(ra);
        if (error) {
            TRACE_ERROR_NUMBER("Failed to grow array.", error);
            return error;
        }
    }

    /* Shift elements right */
    for (i = ra->len; i >= (idx + 1); i--) {
        memcpy((unsigned char *)(ra->storage) + i * ra->elsize,
               (unsigned char *)(ra->storage) + (i - 1) * ra->elsize,
               ra->elsize);
    }

    /* Overwrite element */
    memcpy((unsigned char *)(ra->storage) + idx * ra->elsize,
           element,
           ra->elsize);

    ra->len++;

    TRACE_FLOW_STRING("ref_array_insert", "Exit");
    return error;

}


/* Replace element in the array */
int ref_array_replace(struct ref_array *ra,
                      uint32_t idx,
                      void *element)
{
    int error = EOK;

    TRACE_FLOW_STRING("ref_array_replace", "Entry");

    if ((!ra) || (!element)) {
        TRACE_ERROR_NUMBER("Uninitialized argument.", EINVAL);
        return EINVAL;
    }

    if (idx > ra->len) {
        TRACE_ERROR_NUMBER("Index is out of range", ERANGE);
        return ERANGE;
    }

    /* Clear old element */
    ra->cb((unsigned char *)(ra->storage) + idx * ra->elsize,
           REF_ARRAY_DELETE, ra->cb_data);

    /* Overwrite element */
    memcpy((unsigned char *)(ra->storage) + idx * ra->elsize,
           element,
           ra->elsize);


    TRACE_FLOW_STRING("ref_array_replace", "Exit");
    return error;
}


/* Remove element from the array */
int ref_array_remove(struct ref_array *ra,
                     uint32_t idx)
{
    int error = EOK;
    uint32_t i;

    TRACE_FLOW_STRING("ref_array_remove", "Entry");

    if (!ra) {
        TRACE_ERROR_NUMBER("Uninitialized argument.", EINVAL);
        return EINVAL;
    }

    if (idx >= ra->len) {
        TRACE_ERROR_NUMBER("Index is out of range", ERANGE);
        return ERANGE;
    }

    /* Clear old element */
    ra->cb((unsigned char *)(ra->storage) + idx * ra->elsize,
           REF_ARRAY_DELETE, ra->cb_data);

    /* Shift elements left */
    for (i = idx + 1; i < ra->len; i++) {
        memcpy((unsigned char *)(ra->storage) + (i - 1) * ra->elsize,
               (unsigned char *)(ra->storage) +  i * ra->elsize,
               ra->elsize);
    }

    ra->len--;

    TRACE_FLOW_STRING("ref_array_remove", "Exit");
    return error;
}

/* Reset array */
void ref_array_reset(struct ref_array *ra)
{
    int idx;

    TRACE_FLOW_STRING("ref_array_reset", "Entry");

    /* Check if array is not NULL */
    if (!ra) {
        TRACE_ERROR_STRING("Uninitialized array.", "Coding error???");
        return;
    }

    if (ra->cb) {
        for (idx = 0; idx < ra->len; idx++) {
            ra->cb((unsigned char *)(ra->storage) + idx * ra->elsize,
                    REF_ARRAY_DESTROY, ra->cb_data);
        }
    }

    free(ra->storage);
    ra->storage = NULL;
    ra->size = 0;
    ra->len = 0;

    TRACE_FLOW_STRING("ref_array_reset", "Exit");
}

/* Swap two elements in the array */
int ref_array_swap(struct ref_array *ra,
                   uint32_t idx1,
                   uint32_t idx2)
{
    int error = EOK;
    void *temp = NULL;

    TRACE_FLOW_STRING("ref_array_swap", "Entry");

    if (!ra) {
        TRACE_ERROR_NUMBER("Uninitialized argument.", EINVAL);
        return EINVAL;
    }

    if ((idx1 >= ra->len) ||
        (idx2 >= ra->len)) {
        TRACE_ERROR_NUMBER("Index is out of range", ERANGE);
        return ERANGE;
    }

    if (idx1 == idx2) {
        TRACE_FLOW_STRING("ref_array_swap", "Noop return");
        return EOK;
    }

    temp = malloc(ra->elsize);
    if (!temp) {
        TRACE_FLOW_STRING("Failed to allocate memory for temp storage.", "");
        return ENOMEM;
    }

    memcpy(temp,
           (unsigned char *)(ra->storage) +  idx2 * ra->elsize,
           ra->elsize);
    memcpy((unsigned char *)(ra->storage) +  idx2 * ra->elsize,
           (unsigned char *)(ra->storage) +  idx1 * ra->elsize,
           ra->elsize);
    memcpy((unsigned char *)(ra->storage) +  idx1 * ra->elsize,
           temp,
           ra->elsize);

    free(temp);

    TRACE_FLOW_STRING("ref_array_swap", "Exit");
    return error;
}

/* Debug function */
void ref_array_debug(struct ref_array *ra)
{
    int i,j;

    printf("\nARRAY DUMP START\n");
    printf("Length = %u\n", ra->len);
    printf("Size = %u\n", ra->size);
    printf("Element = %u\n", (unsigned int)(ra->elsize));
    printf("Grow by = %u\n", ra->grow_by);
    printf("Count = %u\n", ra->refcount);
    printf("ARRAY:\n");
    for (i = 0; i < ra->len; i++)  {
        for (j = 0; j < ra->elsize; j++) {
            printf("%x", *((unsigned char *)(ra->storage) + i * ra->elsize + j));
        }
        printf("\n%s\n", *((char **)((unsigned char *)(ra->storage) + i * ra->elsize)));
    }
    printf("\nARRAY DUMP END\n\n");
}
