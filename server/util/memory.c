#include "util/util.h"

/*
 * talloc_takeover
 * This function will take a non-talloc pointer and add it to a talloc
 * memory context. It will accept a destructor for the original pointer
 * so that when the parent memory context is freed, the non-talloc
 * pointer will also be freed properly.
 */
TALLOC_CTX *talloc_takeover(TALLOC_CTX *mem_ctx, void *ptr, int (*destructor)(void **)) {
    void **handle;

    if (ptr == NULL) {
        return NULL;
    }

    handle = talloc_named_const(mem_ctx, sizeof(void *), "void *");
    if (handle == NULL) {
        return NULL;
    }

    *handle = ptr;
    talloc_set_destructor(handle,destructor);

    return handle;
}