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

#include "config.h"

#include "sss_client/idmap/sss_nss_idmap.h"

#include "sss_python.h" /* must be last in the includes list */

#define SSS_NAME_KEY "name"
#define SSS_SID_KEY "sid"
#define SSS_ID_KEY "id"
#define SSS_TYPE_KEY "type"

enum lookup_type {
    SIDBYNAME,
    SIDBYUSERNAME,
    SIDBYGROUPNAME,
    SIDBYID,
    SIDBYUID,
    SIDBYGID,
    NAMEBYSID,
    IDBYSID,
    NAMEBYCERT,
    LISTBYCERT
};

static int add_dict_to_list(PyObject *py_list, PyObject *res_type,
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

    ret = PyDict_SetItem(py_dict, PyUnicode_FromString(SSS_TYPE_KEY), id_type);
    if (ret != 0) {
        Py_XDECREF(py_dict);
        return ret;
    }

    ret = PyList_Append(py_list, py_dict);

    return ret;
}
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

    ret = PyDict_SetItem(py_dict, PyUnicode_FromString(SSS_TYPE_KEY), id_type);
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
    } else if (PyBytes_Check(inp)) {
        py_str = inp;
    } else {
        PyErr_Format(PyExc_TypeError, "input must be unicode or a string");
        return NULL;
    }

    return PyBytes_AS_STRING(py_str);
}

static int do_getsidbyname(enum lookup_type type,
                           PyObject *py_result,
                           PyObject *py_name)
{
    int ret;
    const char *name;
    char *sid = NULL;
    enum sss_id_type id_type;

    name = py_string_or_unicode_as_string(py_name);
    if (name == NULL) {
        return EINVAL;
    }

    switch (type) {
    case SIDBYNAME:
        ret = sss_nss_getsidbyname(name, &sid, &id_type);
        break;
    case SIDBYUSERNAME:
        ret = sss_nss_getsidbyusername(name, &sid, &id_type);
        break;
    case SIDBYGROUPNAME:
        ret = sss_nss_getsidbygroupname(name, &sid, &id_type);
        break;
    default:
        return EINVAL;
    }
    if (ret == 0) {
        ret = add_dict(py_result, py_name, PyUnicode_FromString(SSS_SID_KEY),
                       PyUnicode_FromString(sid), PYNUMBER_FROMLONG(id_type));
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
        ret = add_dict(py_result, py_sid, PyUnicode_FromString(SSS_NAME_KEY),
                       PyUnicode_FromString(name), PYNUMBER_FROMLONG(id_type));
    }
    free(name);

    return ret;
}

static int do_getsidbyid(enum lookup_type type, PyObject *py_result,
                         PyObject *py_id)
{
    long id;
    const char *id_str;
    char *endptr;
    char *sid = NULL;
    int ret;
    enum sss_id_type id_type;

#ifndef IS_PY3K
    if (PyInt_Check(py_id)) {
        id = PyInt_AS_LONG(py_id);
    } else
#endif
    if (PyLong_Check(py_id)) {
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

    switch (type) {
    case SIDBYID:
        ret = sss_nss_getsidbyid((uint32_t) id, &sid, &id_type);
        break;
    case SIDBYUID:
        ret = sss_nss_getsidbyuid((uint32_t) id, &sid, &id_type);
        break;
    case SIDBYGID:
        ret = sss_nss_getsidbygid((uint32_t) id, &sid, &id_type);
        break;
    default:
        return EINVAL;
    }
    if (ret == 0) {
        ret = add_dict(py_result, py_id, PyUnicode_FromString(SSS_SID_KEY),
                       PyUnicode_FromString(sid), PYNUMBER_FROMLONG(id_type));
    }
    free(sid);

    return ret;
}

static int do_getnamebycert(PyObject *py_result, PyObject *py_cert)
{
    int ret;
    const char *cert;
    char *name = NULL;
    enum sss_id_type id_type;

    cert = py_string_or_unicode_as_string(py_cert);
    if (cert == NULL) {
        return EINVAL;
    }

    ret = sss_nss_getnamebycert(cert, &name, &id_type);
    if (ret == 0) {
        ret = add_dict(py_result, py_cert, PyUnicode_FromString(SSS_NAME_KEY),
                       PyUnicode_FromString(name), PYNUMBER_FROMLONG(id_type));
    }
    free(name);

    return ret;
}

static int do_getlistbycert(PyObject *py_result, PyObject *py_cert)
{
    int ret;
    const char *cert;
    char **names = NULL;
    enum sss_id_type *id_types = NULL;
    size_t c;

    cert = py_string_or_unicode_as_string(py_cert);
    if (cert == NULL) {
        return EINVAL;
    }

    ret = sss_nss_getlistbycert(cert, &names, &id_types);
    if (ret == 0) {

        PyObject *py_list;

        py_list =  PyList_New(0);
        if (py_list == NULL) {
            return ENOMEM;
        }

        for (c = 0; names[c] != NULL; c++) {
            ret = add_dict_to_list(py_list,
                                   PyUnicode_FromString(SSS_NAME_KEY),
                                   PyUnicode_FromString(names[c]),
                                   PYNUMBER_FROMLONG(id_types[c]));
            if (ret != 0) {
                goto done;
            }
        }
        ret = PyDict_SetItem(py_result, py_cert, py_list);
        if (ret != 0) {
            goto done;
        }
    }

done:
    free(id_types);
    if (names != NULL) {
        for (c = 0; names[c] != NULL; c++) {
            free(names[c]);
        }
        free(names);
    }

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
        ret = add_dict(py_result, py_sid, PyUnicode_FromString(SSS_ID_KEY),
                       PYNUMBER_FROMLONG(id), PYNUMBER_FROMLONG(id_type));
    }

    return ret;
}

static int do_lookup(enum lookup_type type, PyObject *py_result,
                     PyObject *py_inp)
{
    switch(type) {
    case SIDBYNAME:
    case SIDBYUSERNAME:
    case SIDBYGROUPNAME:
        return do_getsidbyname(type, py_result, py_inp);
        break;
    case NAMEBYSID:
        return do_getnamebysid(py_result, py_inp);
        break;
    case SIDBYID:
    case SIDBYUID:
    case SIDBYGID:
        return do_getsidbyid(type, py_result, py_inp);
        break;
    case IDBYSID:
        return do_getidbysid(py_result, py_inp);
        break;
    case NAMEBYCERT:
        return do_getnamebycert(py_result, py_inp);
        break;
    case LISTBYCERT:
        return do_getlistbycert(py_result, py_inp);
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
          PyBytes_Check(obj) || PyUnicode_Check(obj) ||
          ((type == SIDBYID
                || type == SIDBYUID
                || type == SIDBYGID) && (PYNUMBER_CHECK(obj))))) {
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
                (PyBytes_Check(py_value) || PyUnicode_Check(py_value) ||
                 ((type == SIDBYID
                        || type == SIDBYUID
                        || type == SIDBYGID) && PYNUMBER_CHECK(py_value)))) {
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
            PyErr_Format(PyExc_ValueError, "Unable to retrieve result\n");
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
Returns a dictionary with a dictionary of results for each given name.\n\
The result dictionary contain the SID and the type of the object which can be\n\
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

PyDoc_STRVAR(getsidbyusername_doc,
"getsidbyusername(name or list/tuple of names) -> dict(name => dict(results))\n\
\n\
Returns a dictionary with a dictionary of results for each given name.\n\
The result dictionary contain the SID and the type of the object which can be\n\
accessed with the key constants SID_KEY and TYPE_KEY, respectively.\n\
\n\
The return type can be one of the following constants:\n\
- ID_NOT_SPECIFIED\n\
- ID_USER\n\
- ID_GROUP\n\
- ID_BOTH"
);

static PyObject * py_getsidbyusername(PyObject *module, PyObject *args)
{
    return check_args(SIDBYUSERNAME, args);
}

PyDoc_STRVAR(getsidbygroupname_doc,
"getsidbygroupname(name or list/tuple of names) -> dict(name => dict(results))\n\
\n\
Returns a dictionary with a dictionary of results for each given name.\n\
The result dictionary contain the SID and the type of the object which can be\n\
accessed with the key constants SID_KEY and TYPE_KEY, respectively.\n\
\n\
The return type can be one of the following constants:\n\
- ID_NOT_SPECIFIED\n\
- ID_USER\n\
- ID_GROUP\n\
- ID_BOTH"
);

static PyObject * py_getsidbygroupname(PyObject *module, PyObject *args)
{
    return check_args(SIDBYGROUPNAME, args);
}

PyDoc_STRVAR(getsidbyid_doc,
"getsidbyid(id or list/tuple of id) -> dict(id => dict(results))\n\
\n\
Returns a dictionary with a dictionary of results for each given POSIX ID.\n\
The result dictionary contain the SID and the type of the object which can be\n\
accessed with the key constants SID_KEY and TYPE_KEY, respectively."
);

static PyObject * py_getsidbyid(PyObject *module, PyObject *args)
{
    return check_args(SIDBYID, args);
}

PyDoc_STRVAR(getsidbyuid_doc,
"getsidbyuid(uid or list/tuple of uid) -> dict(uid => dict(results))\n\
\n\
Returns a dictionary with a dictionary of results for each given POSIX UID.\n\
The result dictionary contain the SID and the type of the object which can be\n\
accessed with the key constants SID_KEY and TYPE_KEY, respectively. Since \n\
given ID is assumed to be a user ID is not expected that group objects are\n\
returned."
);

static PyObject * py_getsidbyuid(PyObject *module, PyObject *args)
{
    return check_args(SIDBYUID, args);
}

PyDoc_STRVAR(getsidbygid_doc,
"getsidbygid(gid or list/tuple of gid) -> dict(gid => dict(results))\n\
\n\
Returns a dictionary with a dictionary of results for each given POSIX GID.\n\
The result dictionary contain the SID and the type of the object which can be\n\
accessed with the key constants SID_KEY and TYPE_KEY, respectively. Since \n\
given ID is assumed to be a group ID is is not expected that user objects are\n\
returned."
);

static PyObject * py_getsidbygid(PyObject *module, PyObject *args)
{
    return check_args(SIDBYGID, args);
}

PyDoc_STRVAR(getnamebysid_doc,
"getnamebysid(sid or list/tuple of sid) -> dict(sid => dict(results))\n\
\n\
Returns a dictionary with a dictionary of results for each given SID.\n\
The result dictionary contain the name and the type of the object which can be\n\
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
Returns a dictionary with a dictionary of results for each given SID.\n\
The result dictionary contain the POSIX ID and the type of the object which\n\
can be accessed with the key constants ID_KEY and TYPE_KEY, respectively."
);

static PyObject * py_getidbysid(PyObject *module, PyObject *args)
{
    return check_args(IDBYSID, args);
}

PyDoc_STRVAR(getnamebycert_doc,
"getnamebycert(certificate or list/tuple of certificates) -> dict(certificate => dict(results))\n\
\n\
Returns a dictionary with a dictionary of results for each given certificates.\n\
The result dictionary contain the name and the type of the object which can be\n\
accessed with the key constants NAME_KEY and TYPE_KEY, respectively.\n\
\n\
NOTE: getnamebycert currently works only with id_provider set as \"ad\" or \"ipa\""
);

static PyObject * py_getnamebycert(PyObject *module, PyObject *args)
{
    return check_args(NAMEBYCERT, args);
}

PyDoc_STRVAR(getlistbycert_doc,
"getnamebycert(certificate or list/tuple of certificates) -> dict(certificate => dict(results))\n\
\n\
Returns a dictionary with a dictionary of results for each given certificates.\n\
The result dictionary contain the name and the type of the object which can be\n\
accessed with the key constants NAME_KEY and TYPE_KEY, respectively.\n\
\n\
NOTE: getlistbycert currently works only with id_provider set as \"ad\" or \"ipa\""
);

static PyObject * py_getlistbycert(PyObject *module, PyObject *args)
{
    return check_args(LISTBYCERT, args);
}

static PyMethodDef methods[] = {
    { sss_py_const_p(char, "getsidbyname"), (PyCFunction) py_getsidbyname,
      METH_VARARGS, getsidbyname_doc },
    { sss_py_const_p(char, "getsidbyusername"), (PyCFunction) py_getsidbyusername,
      METH_VARARGS, getsidbyusername_doc },
    { sss_py_const_p(char, "getsidbygroupname"), (PyCFunction) py_getsidbygroupname,
      METH_VARARGS, getsidbygroupname_doc },
    { sss_py_const_p(char, "getsidbyid"), (PyCFunction) py_getsidbyid,
      METH_VARARGS, getsidbyid_doc },
    { sss_py_const_p(char, "getsidbyuid"), (PyCFunction) py_getsidbyuid,
      METH_VARARGS, getsidbyuid_doc },
    { sss_py_const_p(char, "getsidbygid"), (PyCFunction) py_getsidbygid,
      METH_VARARGS, getsidbygid_doc },
    { sss_py_const_p(char, "getnamebysid"), (PyCFunction) py_getnamebysid,
      METH_VARARGS, getnamebysid_doc },
    { sss_py_const_p(char, "getidbysid"), (PyCFunction) py_getidbysid,
      METH_VARARGS, getidbysid_doc },
    { sss_py_const_p(char, "getnamebycert"), (PyCFunction) py_getnamebycert,
      METH_VARARGS, getnamebycert_doc },
    { sss_py_const_p(char, "getlistbycert"), (PyCFunction) py_getlistbycert,
      METH_VARARGS, getlistbycert_doc },
    { NULL,NULL, 0, NULL }
};

#ifdef IS_PY3K
static struct PyModuleDef pysss_nss_idmap_def = {
    PyModuleDef_HEAD_INIT,
    "pysss_nss_idmap",
    NULL,
    -1,
    methods,
    NULL,
    NULL,
    NULL,
    NULL
};

PyMODINIT_FUNC
PyInit_pysss_nss_idmap(void)
#else
PyMODINIT_FUNC
initpysss_nss_idmap(void)
#endif
{
    PyObject *module;

#ifdef IS_PY3K
    module = PyModule_Create(&pysss_nss_idmap_def);
#else
    module = Py_InitModule3(sss_py_const_p(char, "pysss_nss_idmap"),
                            methods,
                            sss_py_const_p(char, "SSSD ID-mapping functions"));
#endif
    if (module == NULL) {
        MODINITERROR(NULL);
    }

    if (PyModule_AddIntConstant(module, "ID_NOT_SPECIFIED",
                                SSS_ID_TYPE_NOT_SPECIFIED) == -1) {
        MODINITERROR(module);
    }
    if (PyModule_AddIntConstant(module, "ID_USER", SSS_ID_TYPE_UID) == -1) {
        MODINITERROR(module);
    }
    if (PyModule_AddIntConstant(module, "ID_GROUP", SSS_ID_TYPE_GID) == -1) {
        MODINITERROR(module);
    }
    if (PyModule_AddIntConstant(module, "ID_BOTH", SSS_ID_TYPE_BOTH) == -1) {
        MODINITERROR(module);
    }

    if (PyModule_AddStringConstant(module, "SID_KEY", SSS_SID_KEY) == -1) {
        MODINITERROR(module);
    }
    if (PyModule_AddStringConstant(module, "NAME_KEY", SSS_NAME_KEY) == -1) {
        MODINITERROR(module);
    }
    if (PyModule_AddStringConstant(module, "ID_KEY", SSS_ID_KEY) == -1) {
        MODINITERROR(module);
    }
    if (PyModule_AddStringConstant(module, "TYPE_KEY", SSS_TYPE_KEY) == -1) {
        MODINITERROR(module);
    }

#ifdef IS_PY3K
    return module;
#endif
}
