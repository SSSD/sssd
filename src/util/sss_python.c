/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

    Copyright (C) 2011 Red Hat

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

#include "src/util/sss_python.h"

PyObject *
sss_exception_with_doc(char *name, char *doc, PyObject *base, PyObject *dict)
{
#ifdef HAVE_PYERR_NEWEXCEPTIONWITHDOC
    return PyErr_NewExceptionWithDoc(name, doc, base, dict);
#else
    int result;
    PyObject *ret = NULL;
    PyObject *mydict = NULL; /* points to the dict only if we create it */
    PyObject *docobj;

    if (dict == NULL) {
        dict = mydict = PyDict_New();
        if (dict == NULL) {
            return NULL;
        }
    }

    if (doc != NULL) {
        docobj = PyString_FromString(doc);
        if (docobj == NULL)
            goto failure;
        result = PyDict_SetItemString(dict, "__doc__", docobj);
        Py_DECREF(docobj);
        if (result < 0)
            goto failure;
    }

    ret = PyErr_NewException(name, base, dict);
  failure:
    Py_XDECREF(mydict);
    return ret;
#endif
}
