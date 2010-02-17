/*
 * System Security Services Daemon. Client Interface for NSS and PAM.
 *
 * Copyright (C) Stephen Gallagher 2009
 *
 * You can used this header file in any way you see fit provided copyright
 * notices are preserved.
 *
 */

#ifndef _SSS_PAM_MACROS_H
#define _SSS_PAM_MACROS_H

/* Older versions of the pam development headers do not include the
 * _pam_overwrite_n(n,x) macro. This implementation is copied from
 * the Fedora 11 _pam_macros.h.
 */
#include <security/_pam_macros.h>
#ifndef _pam_overwrite_n
#define _pam_overwrite_n(x,n)   \
do {                             \
     register char *__xx__;      \
     register unsigned int __i__ = 0;    \
     if ((__xx__=(x)))           \
        for (;__i__<n; __i__++) \
            __xx__[__i__] = 0; \
} while (0)
#endif /* _pam_overwrite_n */

#endif /* _SSS_PAM_MACROS_H */
