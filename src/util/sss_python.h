#ifndef __SSS_PYTHON_H__
#define __SSS_PYTHON_H__

#include "config.h"

#include <Python.h>
#include <stdbool.h>

#include "util/util.h"

#if PY_VERSION_HEX < 0x02050000
#define sss_py_const_p(type, value) discard_const_p(type, (value))
#else
#define sss_py_const_p(type, value) (value)
#endif

#if PY_MAJOR_VERSION >= 3
#define IS_PY3K
#define MODINITERROR return NULL
#define PYNUMBER_CHECK(what) PyLong_Check(what)
#define PYNUMBER_FROMLONG(what) PyLong_FromLong(what)
#define PYNUMBER_ASLONG(what) PyLong_AsLong(what)
#else
#include <bytesobject.h>
#define MODINITERROR return
#define PYNUMBER_CHECK(what) PyInt_Check(what)
#define PYNUMBER_FROMLONG(what) PyInt_FromLong(what)
#define PYNUMBER_ASLONG(what) PyInt_AsLong(what)
#endif

/* Exceptions compatibility */
PyObject *
sss_exception_with_doc(const char *name, const char *doc, PyObject *base,
                       PyObject *dict);

/* Convenience macros */
#define TYPE_READY(module, type, name) do {         \
    if (PyType_Ready(&type) < 0) {                  \
        MODINITERROR;                               \
    }                                               \
    Py_INCREF(&type);                               \
    PyModule_AddObject(module,                      \
                       discard_const_p(char, name), \
                       (PyObject *) &type);         \
} while(0)                                          \

#define SAFE_SET(old, new) do {         \
    PyObject *__simple_set_tmp = NULL;  \
    __simple_set_tmp = old;             \
    Py_INCREF(new);                     \
    old = new;                          \
    Py_XDECREF(__simple_set_tmp);       \
} while(0)

#endif /* __SSS_PYTHON_H__ */
