#ifndef __TESTS_COMMON_H__
#define __TESTS_COMMON_H__

#include <talloc.h>

extern TALLOC_CTX *global_talloc_context;

#define check_leaks(ctx, bytes) _check_leaks((ctx), (bytes), __location__)
void _check_leaks(TALLOC_CTX *ctx,
                  size_t bytes,
                  const char *location);

void check_leaks_push(TALLOC_CTX *ctx);

#define check_leaks_pop(ctx) _check_leaks_pop((ctx), __location__)
void _check_leaks_pop(TALLOC_CTX *ctx, const char *location);

void leak_check_setup(void);
void leak_check_teardown(void);

#endif /* !__TESTS_COMMON_H__ */
