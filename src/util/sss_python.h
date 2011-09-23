#ifndef __SSS_PYTHON_H__
#define __SSS_PYTHON_H__

#include <Python.h>
#include <stdbool.h>
#include "util/util.h"

#if PY_VERSION_HEX < 0x02050000
#define sss_py_const_p(type, value) discard_const_p(type, (value))
#else
#define sss_py_const_p(type, value) (value)
#endif

/* Py_ssize_t compatibility for python < 2.5 as per
 * http://www.python.org/dev/peps/pep-0353/ */
#ifndef HAVE_PY_SSIZE_T
typedef int Py_ssize_t;
#endif

#ifndef PY_SSIZE_T_MAX
#define PY_SSIZE_T_MAX INT_MAX
#endif

#ifndef PY_SSIZE_T_MIN
#define PY_SSIZE_T_MIN INT_MIN
#endif

/* Wrappers providing the subset of C API for python's set objects we use */
PyObject *sss_python_set_new(void);
int sss_python_set_add(PyObject *set, PyObject *key);
bool sss_python_set_check(PyObject *set);

/* Unicode compatibility */
PyObject *sss_python_unicode_from_string(const char *u);

/* Exceptions compatibility */
PyObject *
sss_exception_with_doc(char *name, char *doc, PyObject *base, PyObject *dict);

/* PyModule_AddIntMacro() compatibility */
#if !HAVE_DECL_PYMODULE_ADDINTMACRO
#define PyModule_AddIntMacro(m, c) PyModule_AddIntConstant(m, sss_py_const_p(char, #c), c)
#endif

/* Convenience macros */
#define TYPE_READY(module, type, name) do {         \
    if (PyType_Ready(&type) < 0)                    \
        return;                                     \
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
