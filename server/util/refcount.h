#ifndef __REFCOUNT_H__
#define __REFCOUNT_H__

#include <stddef.h>

#define REFCOUNT_MEMBER_NAME DO_NOT_TOUCH_THIS_MEMBER_refcount

/*
 * Include this member in your structure in order to be able to use it with
 * the refcount_* functions.
 */
#define REFCOUNT_COMMON int REFCOUNT_MEMBER_NAME

/*
 * Allocate a new structure that uses reference counting. The resulting pointer
 * returned. You must not free the returned pointer manually. It will be freed
 * when 'ctx' is freed with talloc_free() and no other references are left.
 */
#define rc_alloc(ctx, type) \
 (type *)_rc_alloc(ctx, sizeof(type), offsetof(type, REFCOUNT_MEMBER_NAME), \
                   #type)

/*
 * Increment the reference count of 'src' and return it back if we are
 * successful. The reference count will be decremented after 'ctx' has been
 * released by talloc_free(). The function will return NULL in case of failure.
 */
#define rc_reference(ctx, type, src) \
 (type *)_rc_reference(ctx, offsetof(type, REFCOUNT_MEMBER_NAME), src)

/*
 * These functions should not be used directly. Use the above macros instead.
 */
void *_rc_alloc(const void *context, size_t size, size_t refcount_offset,
                 const char *type_name);
void *_rc_reference(const void *context, size_t refcount_offset, void *source);


#endif /* !__REFCOUNT_H__ */
