#include "talloc.h"
#include "util/util.h"

/*
 * sssd_mem_attach
 * This function will take a non-talloc pointer and "attach" it to a talloc
 * memory context. It will accept a destructor for the original pointer
 * so that when the parent memory context is freed, the non-talloc
 * pointer will also be freed properly.
 */

int password_destructor(void *memctx)
{
    char *password = (char *)memctx;
    int i;

    /* zero out password */
    for (i = 0; password[i]; i++) password[i] = '\0';

    return 0;
}

static int mem_holder_destructor(void *ptr)
{
    struct mem_holder *h;

    h = talloc_get_type(ptr, struct mem_holder);
    return h->fn(h->mem);
}

void *sss_mem_attach(TALLOC_CTX *mem_ctx,
                     void *ptr,
                     void_destructor_fn_t *fn)
{
    struct mem_holder *h;

    if (!ptr || !fn) return NULL;

    h = talloc(mem_ctx, struct mem_holder);
    if (!h) return NULL;

    h->mem = ptr;
    h->fn = fn;
    talloc_set_destructor((TALLOC_CTX *)h, mem_holder_destructor);

    return h;
}
