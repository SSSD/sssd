#ifndef __SSS_PYTHON_H__
#define __SSS_PYTHON_H__

#include "config.h"

#include <stdbool.h>

#include "util/util.h"

/* Python's headers must be included last due to usage of _POSIX_C_SOURCE=200809
 * that disables Annex K extensions, resulting in undefined 'errno_t' on FreeBSD
 */
#include <Python.h>
#include <structmember.h>


#if PY_VERSION_HEX < 0x02050000
#define sss_py_const_p(type, value) discard_const_p(type, (value))
#else
#define sss_py_const_p(type, value) (value)
#endif

#if PY_MAJOR_VERSION >= 3
#define IS_PY3K

#define MODINITERROR(module) do {                   \
    Py_XDECREF(module);                             \
    return NULL;                                    \
} while(0)

#define PYNUMBER_CHECK(what) PyLong_Check(what)
#define PYNUMBER_FROMLONG(what) PyLong_FromLong(what)
#define PYNUMBER_ASLONG(what) PyLong_AsLong(what)
#else /* PY_MAJOR_VERSION < 3 */
#include <bytesobject.h>

#define MODINITERROR(module) do {                   \
    Py_XDECREF(module);                             \
    return;                                         \
} while(0)

#define PYNUMBER_CHECK(what) PyInt_Check(what)
#define PYNUMBER_FROMLONG(what) PyInt_FromLong(what)
#define PYNUMBER_ASLONG(what) PyInt_AsLong(what)
#endif /* PY_MAJOR_VERSION < 3 */

/* Exceptions compatibility */
PyObject *
sss_exception_with_doc(const char *name, const char *doc, PyObject *base,
                       PyObject *dict);

/* Convenience macros */
#define TYPE_READY(module, type, name) do {         \
    if (PyType_Ready(&type) < 0) {                  \
        MODINITERROR(module);                       \
    }                                               \
    Py_INCREF(&type);                               \
    if (PyModule_AddObject(module,                  \
                       discard_const_p(char, name), \
                       (PyObject *) &type) == -1) { \
        Py_XDECREF(&type);                          \
        MODINITERROR(module);                       \
    }                                               \
} while(0)                                          \

#define SAFE_SET(old, new) do {         \
    PyObject *__simple_set_tmp = NULL;  \
    __simple_set_tmp = old;             \
    Py_INCREF(new);                     \
    old = new;                          \
    Py_XDECREF(__simple_set_tmp);       \
} while(0)

#endif /* __SSS_PYTHON_H__ */
