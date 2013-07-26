/*
    Authors:
        Sumit Bose <sbose@redhat.com>
        Alexander Bokovoy <abokovoy@redhat.com>

    Copyright (C) 2013 Red Hat

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

#include "sss_client/idmap/sss_nss_idmap.h"

#define SSS_NAME_KEY "name"
#define SSS_SID_KEY "sid"
#define SSS_ID_KEY "id"
#define SSS_TYPE_KEY "type"

enum lookup_type {
    SIDBYNAME,
    SIDBYID,
    NAMEBYSID,
    IDBYSID
};

static int add_dict(PyObject *py_result, PyObject *key, PyObject *res_type,
                    PyObject *res, PyObject *id_type)
{
    int ret;
    PyObject *py_dict;

    py_dict =  PyDict_New();
    if (py_dict == NULL) {
        return ENOMEM;
    }

    ret = PyDict_SetItem(py_dict, res_type, res);
    if (ret != 0) {
        Py_XDECREF(py_dict);
        return ret;
    }

    ret = PyDict_SetItem(py_dict, PyString_FromString(SSS_TYPE_KEY), id_type);
    if (ret != 0) {
        Py_XDECREF(py_dict);
        return ret;
    }

    ret = PyDict_SetItem(py_result, key, py_dict);

    return ret;
}

static char *py_string_or_unicode_as_string(PyObject *inp)
{
    PyObject *py_str = NULL;

    if (PyUnicode_Check(inp)) {
        py_str = PyUnicode_AsUTF8String(inp);
    } else if (PyString_Check(inp)) {
        py_str = inp;
    } else {
        PyErr_Format(PyExc_TypeError, "input must be unicode or a string");
        return NULL;
    }

    return PyString_AS_STRING(py_str);
}

static int do_getsidbyname(PyObject *py_result, PyObject *py_name)
{
    int ret;
    const char *name;
    char *sid = NULL;
    enum sss_id_type id_type;

    name = py_string_or_unicode_as_string(py_name);
    if (name == NULL) {
        return EINVAL;
    }

    ret = sss_nss_getsidbyname(name, &sid, &id_type);
    if (ret == 0) {
        ret = add_dict(py_result, py_name, PyString_FromString(SSS_SID_KEY),
                       PyUnicode_FromString(sid), PyInt_FromLong(id_type));
    }
    free(sid);

    return ret;
}

static int do_getnamebysid(PyObject *py_result, PyObject *py_sid)
{
    int ret;
    const char *sid;
    char *name = NULL;
    enum sss_id_type id_type;

    sid = py_string_or_unicode_as_string(py_sid);
    if (sid == NULL) {
        return EINVAL;
    }

    ret = sss_nss_getnamebysid(sid, &name, &id_type);
    if (ret == 0) {
        ret = add_dict(py_result, py_sid, PyString_FromString(SSS_NAME_KEY),
                       PyUnicode_FromString(name), PyInt_FromLong(id_type));
    }
    free(name);

    return ret;
}

static int do_getsidbyid(PyObject *py_result, PyObject *py_id)
{
    long id;
    const char *id_str;
    char *endptr;
    char *sid = NULL;
    int ret;
    enum sss_id_type id_type;

    if (PyInt_Check(py_id)) {
        id = PyInt_AS_LONG(py_id);
    } else if (PyLong_Check(py_id)) {
        id = PyLong_AsLong(py_id);
    } else {
        id_str = py_string_or_unicode_as_string(py_id);
        if (id_str == NULL) {
            return EINVAL;
        }
        errno = 0;
        id = strtol(id_str, &endptr, 10);
        if (errno != 0 || *endptr != '\0') {
            return EINVAL;
        }
    }

    if (id < 0 || id > UINT32_MAX) {
        return EINVAL;
    }

    ret = sss_nss_getsidbyid((uint32_t) id, &sid, &id_type);
    if (ret == 0) {
        ret = add_dict(py_result, py_id, PyString_FromString(SSS_SID_KEY),
                       PyUnicode_FromString(sid), PyInt_FromLong(id_type));
    }
    free(sid);

    return ret;
}

static int do_getidbysid(PyObject *py_result, PyObject *py_sid)
{
    const char *sid;
    uint32_t id;
    enum sss_id_type id_type;
    int ret;

    sid = py_string_or_unicode_as_string(py_sid);
    if (sid == NULL) {
        return EINVAL;
    }

    ret = sss_nss_getidbysid(sid, &id, &id_type);
    if (ret == 0) {
        ret = add_dict(py_result, py_sid, PyString_FromString(SSS_ID_KEY),
                       PyInt_FromLong(id), PyInt_FromLong(id_type));
    }

    return ret;
}

static int do_lookup(enum lookup_type type, PyObject *py_result,
                     PyObject *py_inp)
{
    switch(type) {
    case SIDBYNAME:
        return do_getsidbyname(py_result, py_inp);
        break;
    case NAMEBYSID:
        return do_getnamebysid(py_result, py_inp);
        break;
    case SIDBYID:
        return do_getsidbyid(py_result, py_inp);
        break;
    case IDBYSID:
        return do_getidbysid(py_result, py_inp);
        break;
    default:
        return ENOSYS;
    }

    return ENOSYS;
}

static PyObject *check_args(enum lookup_type type, PyObject *args)
{
    PyObject *obj, *py_value;
    int ret;
    Py_ssize_t len, i;
    PyObject *py_result;

    if (!PyArg_ParseTuple(args, sss_py_const_p(char, "O"), &obj)) {
        PyErr_Format(PyExc_ValueError, "Unable to retrieve argument\n");
        return NULL;
    }

    if (!(PyList_Check(obj) || PyTuple_Check(obj) ||
          PyString_Check(obj) || PyUnicode_Check(obj) ||
          (type == SIDBYID && (PyInt_Check(obj) || PyLong_Check(obj))))) {
        PyErr_Format(PyExc_ValueError,
                     "Only string, long or list or tuples of them " \
                     "are accepted\n");
        return NULL;
    }

    py_result = PyDict_New();
    Py_XINCREF(py_result);
    if (py_result == NULL) {
        PyErr_Format(PyExc_MemoryError,
                     "Unable to allocate resulting dictionary\n");
        return NULL;
    }

    if (PyList_Check(obj) || PyTuple_Check(obj)) {
        len = PySequence_Size(obj);
        for(i=0; i < len; i++) {
            py_value = PySequence_GetItem(obj, i);
            if ((py_value != NULL) &&
                (PyString_Check(py_value) || PyUnicode_Check(py_value) ||
                 (type == SIDBYID &&
                  (PyInt_Check(py_value) || PyLong_Check(py_value))))) {
                ret = do_lookup(type, py_result, py_value);
                if (ret != 0) {
                    /* Skip this name */
                    continue;
                }
            }
        }
    } else {
        ret = do_lookup(type, py_result, obj);
        switch (ret) {
        case 0:
        case ENOENT: /* nothing found, return empty dict */
            break;
        case EINVAL:
            PyErr_Format(PyExc_ValueError, "Unable to retrieve argument\n");
            Py_XDECREF(py_result);
            return NULL;
            break;
        default:
            PyErr_Format(PyExc_IOError, "Operation not supported\n");
            Py_XDECREF(py_result);
            return NULL;
        }
    }

    Py_XDECREF(py_result);
    return py_result;

}

PyDoc_STRVAR(getsidbyname_doc,
"getsidbyname(name or list/tuple of names) -> dict(name => dict(results))\n\
\n\
Returns a dictionary with a dictonary of results for each given name.\n\
The result dictonary contain the SID and the type of the object which can be\n\
accessed with the key constants SID_KEY and TYPE_KEY, respectively.\n\
\n\
The return type can be one of the following constants:\n\
- ID_NOT_SPECIFIED\n\
- ID_USER\n\
- ID_GROUP\n\
- ID_BOTH"
);

static PyObject * py_getsidbyname(PyObject *module, PyObject *args)
{
    return check_args(SIDBYNAME, args);
}

PyDoc_STRVAR(getsidbyid_doc,
"getsidbyid(id or list/tuple of id) -> dict(id => dict(results))\n\
\n\
Returns a dictionary with a dictonary of results for each given POSIX ID.\n\
The result dictonary contain the SID and the type of the object which can be\n\
accessed with the key constants SID_KEY and TYPE_KEY, respectively."
);

static PyObject * py_getsidbyid(PyObject *module, PyObject *args)
{
    return check_args(SIDBYID, args);
}

PyDoc_STRVAR(getnamebysid_doc,
"getnamebysid(sid or list/tuple of sid) -> dict(sid => dict(results))\n\
\n\
Returns a dictionary with a dictonary of results for each given SID.\n\
The result dictonary contain the name and the type of the object which can be\n\
accessed with the key constants NAME_KEY and TYPE_KEY, respectively.\n\
\n\
NOTE: getnamebysid currently works only with id_provider set as \"ad\" or \"ipa\""
);

static PyObject * py_getnamebysid(PyObject *module, PyObject *args)
{
    return check_args(NAMEBYSID, args);
}

PyDoc_STRVAR(getidbysid_doc,
"getidbysid(sid) -> POSIX ID\n\
\n\
Returns the POSIX ID of the object with the given SID."
"getidbysid(sid or list/tuple of sid) -> dict(sid => dict(results))\n\
\n\
Returns a dictionary with a dictonary of results for each given SID.\n\
The result dictonary contain the POSIX ID and the type of the object which\n\
can be accessed with the key constants ID_KEY and TYPE_KEY, respectively."
);

static PyObject * py_getidbysid(PyObject *module, PyObject *args)
{
    return check_args(IDBYSID, args);
}

static PyMethodDef methods[] = {
    { sss_py_const_p(char, "getsidbyname"), (PyCFunction) py_getsidbyname,
      METH_VARARGS, getsidbyname_doc },
    { sss_py_const_p(char, "getsidbyid"), (PyCFunction) py_getsidbyid,
      METH_VARARGS, getsidbyid_doc },
    { sss_py_const_p(char, "getnamebysid"), (PyCFunction) py_getnamebysid,
      METH_VARARGS, getnamebysid_doc },
    { sss_py_const_p(char, "getidbysid"), (PyCFunction) py_getidbysid,
      METH_VARARGS, getidbysid_doc },
    { NULL,NULL, 0, NULL }
};


PyMODINIT_FUNC
initpysss_nss_idmap(void)
{
    PyObject *module;

    module = Py_InitModule3(sss_py_const_p(char, "pysss_nss_idmap"),
                            methods,
                            sss_py_const_p(char, "SSSD ID-mapping functions"));

    PyModule_AddIntConstant(module, "ID_NOT_SPECIFIED",
                            SSS_ID_TYPE_NOT_SPECIFIED);
    PyModule_AddIntConstant(module, "ID_USER", SSS_ID_TYPE_UID);
    PyModule_AddIntConstant(module, "ID_GROUP", SSS_ID_TYPE_GID);
    PyModule_AddIntConstant(module, "ID_BOTH", SSS_ID_TYPE_BOTH);

    PyModule_AddStringConstant(module, "SID_KEY", SSS_SID_KEY);
    PyModule_AddStringConstant(module, "NAME_KEY", SSS_NAME_KEY);
    PyModule_AddStringConstant(module, "ID_KEY", SSS_ID_KEY);
    PyModule_AddStringConstant(module, "TYPE_KEY", SSS_TYPE_KEY);
}
