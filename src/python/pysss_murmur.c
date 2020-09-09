/*
    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2012 Red Hat

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

#include "config.h"

#define PY_SSIZE_T_CLEAN 1
#include <Python.h>

#include "util/sss_python.h"
#include "shared/murmurhash3.h"

PyDoc_STRVAR(murmurhash3_doc,
"murmurhash3(key, key_len, seed) -> 32bit integer hash\n\
\n\
Calculate the murmur hash version 3 of the first key_len bytes from key\n\
using the given seed."
);

static PyObject * py_murmurhash3(PyObject *module, PyObject *args)
{
    const char *key;
    long key_len;
    long long seed;
    uint32_t hash;
    Py_ssize_t input_len;

    if (!PyArg_ParseTuple(args, sss_py_const_p(char, "z#lL"),
                          &key, &input_len, &key_len, &seed)) {
        PyErr_Format(PyExc_ValueError, "Invalid argument\n");
        return NULL;
    }

    if (seed > UINT32_MAX || key_len > INT_MAX || key_len < 0 ||
        key_len > input_len) {
        PyErr_Format(PyExc_ValueError, "Invalid value\n");
        return NULL;
    }

    hash = murmurhash3(key, key_len, seed);

    return PyLong_FromUnsignedLong((unsigned long) hash);
}

static PyMethodDef methods[] = {
    { sss_py_const_p(char, "murmurhash3"), (PyCFunction) py_murmurhash3,
      METH_VARARGS, murmurhash3_doc },
    { NULL,NULL, 0, NULL }
};

#ifdef IS_PY3K
static struct PyModuleDef pysss_murmurdef = {
    PyModuleDef_HEAD_INIT,
    "pysss_murmur",
    NULL,
    -1,
    methods,
    NULL,
    NULL,
    NULL,
    NULL
};

PyMODINIT_FUNC
PyInit_pysss_murmur(void)
#else
PyMODINIT_FUNC
initpysss_murmur(void)
#endif
{
    PyObject *m;
#ifdef IS_PY3K
    m = PyModule_Create(&pysss_murmurdef);
#else
    m = Py_InitModule3(sss_py_const_p(char, "pysss_murmur"),
                   methods, sss_py_const_p(char, "murmur hash functions"));
#endif
    if (m == NULL) {
        MODINITERROR(NULL);
    }
#ifdef IS_PY3K
    return m;
#endif
}
