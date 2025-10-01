/*
    Copyright (C) 2025 Red Hat

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

#ifndef _SSS_TYPEOF_H_
#define _SSS_TYPEOF_H_

/**
 * Provide a compile-time type safety for callbacks and handlers.
 *
 * We use GCC __typeof__ extension to achieve this. We retrieve the private
 * data type and create the expected handler function type with it. If the
 * method accepts parsed D-Bus arguments, they are appended with variadic
 * parameters. We check that the handler type matches the expected type
 * and return the sbus_handler structure value.
 *
 * We also use __attribute__((unused)) to suppress compiler warning about
 * unused __fn.
 *
 * We do not perform this check on platforms where this extension is not
 * available and just create a generic handler. This does not matter since
 * we test compilation with GCC anyway.
 */
#if (__GNUC__ >= 3)

#define SSS_CHECK_FUNCTION_TYPE(fn, return_type, ...) ({                            \
    __attribute__((unused)) return_type (*__fn)(__VA_ARGS__) = (fn);     \
})

#define SSS_TYPEOF(data) __typeof__(data)

#else
#define SSS_CHECK_FUNCTION_TYPE(handler, return_type, ...)
#define SSS_TYPEOF(data) (void*)
#endif

#endif /* _SSS_TYPEOF_H_ */
