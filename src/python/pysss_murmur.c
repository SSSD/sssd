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

#include <Python.h>
#include "util/sss_python.h"

#include "util/murmurhash3.h"

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

    if (!PyArg_ParseTuple(args, sss_py_const_p(char, "slL"),
                          &key, &key_len, &seed)) {
        PyErr_Format(PyExc_ValueError, "Invalid argument\n");
        return NULL;
    }

    if (seed > UINT32_MAX || key_len > INT_MAX || key_len < 0 ||
        key_len > strlen(key)) {
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


PyMODINIT_FUNC
initpysss_murmur(void)
{
    Py_InitModule3(sss_py_const_p(char, "pysss_murmur"),
                   methods, sss_py_const_p(char, "murmur hash functions"));
}
