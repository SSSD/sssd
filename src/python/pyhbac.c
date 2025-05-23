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

#include "config.h"

#include "util/util.h"
#include "lib/ipa_hbac/ipa_hbac.h"

#include "sss_python.h" /* must be last in the includes list */

#define PYTHON_MODULE_NAME  "pyhbac"

#ifndef PYHBAC_ENCODING
#define PYHBAC_ENCODING "UTF-8"
#endif

#define PYHBAC_ENCODING_ERRORS "strict"

#define CHECK_ATTRIBUTE_DELETE(attr, attrname) do {         \
    if (attr == NULL) {                                     \
        PyErr_Format(PyExc_TypeError,                       \
                     "Cannot delete the %s attribute",      \
                      attrname);                            \
        return -1;                                          \
    }                                                       \
} while(0)

static PyObject *PyExc_HbacError;

/* ==================== Utility functions ========================*/
static char *
py_strdup(const char *string)
{
    char *copy;

    copy = PyMem_New(char, strlen(string)+1);
    if (copy ==  NULL) {
        PyErr_NoMemory();
        return NULL;
    }

    return strcpy(copy, string);
}

static char *
py_strcat_realloc(char *first, const char *second)
{
    char *new_first;
    new_first = PyMem_Realloc(first, strlen(first) + strlen(second) + 1);
    if (new_first == NULL) {
        PyErr_NoMemory();
        return NULL;
    }

    return strcat(new_first, second);
}

static PyObject *
get_utf8_string(PyObject *obj, const char *attrname)
{
    const char *a = attrname ? attrname : "attribute";
    PyObject *obj_utf8 = NULL;

    if (PyBytes_Check(obj)) {
        obj_utf8 = obj;
        Py_INCREF(obj_utf8); /* Make sure we can DECREF later */
    } else if (PyUnicode_Check(obj)) {
        if ((obj_utf8 = PyUnicode_AsUTF8String(obj)) == NULL) {
            return NULL;
        }
    } else {
        PyErr_Format(PyExc_TypeError, "%s must be a string", a);
        return NULL;
    }

    return obj_utf8;
}

static void
free_string_list(const char **list)
{
    int i;

    if (!list) return;

    for (i=0; list[i]; i++) {
        PyMem_Free(discard_const_p(char, list[i]));
    }
    PyMem_Free(list);
}

static const char **
sequence_as_string_list(PyObject *seq, const char *paramname)
{
    const char *p = paramname ? paramname : "attribute values";
    const char **ret;
    PyObject *utf_item;
    int i;
    Py_ssize_t len;
    PyObject *item;

    if (!PySequence_Check(seq)) {
        PyErr_Format(PyExc_TypeError,
                     "The object must be a sequence\n");
        return NULL;
    }

    len = PySequence_Size(seq);
    if (len == -1) return NULL;

    ret = PyMem_New(const char *, (len+1));
    if (!ret) {
        PyErr_NoMemory();
        return NULL;
    }

    for (i = 0; i < len; i++) {
        item = PySequence_GetItem(seq, i);
        if (item == NULL) {
            break;
        }

        utf_item = get_utf8_string(item, p);
        if (utf_item == NULL) {
            Py_DECREF(item);
            return NULL;
        }

        ret[i] = py_strdup(PyBytes_AsString(utf_item));
        Py_DECREF(utf_item);
        if (!ret[i]) {
            Py_DECREF(item);
            return NULL;
        }
        Py_DECREF(item);
    }

    ret[i] = NULL;
    return ret;
}

static bool
verify_sequence(PyObject *seq, const char *attrname)
{
    const char *a = attrname ? attrname : "attribute";

    if (!PySequence_Check(seq)) {
        PyErr_Format(PyExc_TypeError, "%s must be a sequence", a);
        return false;
    }

    return true;
}

static int
pyobject_to_category(PyObject *o)
{
    long c;

    c = PYNUMBER_ASLONG(o);
    if (c == -1 && PyErr_Occurred()) {
        PyErr_Format(PyExc_TypeError,
                     "Invalid type for category element - must be an int\n");
        return -1;
    }

    switch (c) {
        case HBAC_CATEGORY_NULL:
        case HBAC_CATEGORY_ALL:
            return c;
    }

    PyErr_Format(PyExc_ValueError, "Invalid value %ld for category\n", c);
    return -1;
}

static int
native_category(PyObject *pycat, uint32_t *_category)
{
    PyObject *iterator;
    PyObject *item;
    uint32_t cat;
    int ret;

    iterator = PyObject_GetIter(pycat);
    if (iterator == NULL) {
        PyErr_Format(PyExc_RuntimeError, "Cannot iterate category\n");
        return -1;
    }

    cat = 0;
    while ((item = PyIter_Next(iterator))) {
        ret = pyobject_to_category(item);
        Py_DECREF(item);
        if (ret == -1) {
            Py_DECREF(iterator);
            return -1;
        }

        cat |= ret;
    }

    Py_DECREF(iterator);

    *_category = cat;
    return 0;
}

static char *
str_concat_sequence(PyObject *seq, const char *delim)
{
    Py_ssize_t size;
    Py_ssize_t i;
    PyObject *item;
    char *s = NULL;
    const char *part;

    size = PySequence_Size(seq);

    if (size == 0) {
        s = py_strdup("");
        if (s == NULL) {
            return NULL;
        }
        return s;
    }

    for (i=0; i < size; i++) {
        item = PySequence_GetItem(seq, i);
        if (item == NULL) goto fail;

#ifdef IS_PY3K
        part = PyUnicode_AsUTF8(item);
#else
        part = PyString_AsString(item);
#endif

        if (s) {
            s = py_strcat_realloc(s, delim);
            if (s == NULL) goto fail;
            s = py_strcat_realloc(s, part);
            if (s == NULL) goto fail;
        } else {
            s = py_strdup(part);
            if (s == NULL) goto fail;
        }
        Py_DECREF(item);
    }

    return s;

fail:
    Py_XDECREF(item);
    PyMem_Free(s);
    return NULL;
}

/* ================= HBAC Exception handling =====================*/
static void
set_hbac_exception(PyObject *exc, struct hbac_info *error)
{
    PyObject *obj;

    obj = Py_BuildValue(sss_py_const_p(char, "(i,s)"), error->code,
                        error->rule_name ? error->rule_name : "no rule");

    PyErr_SetObject(exc, obj);
    Py_XDECREF(obj);
}

/* ==================== HBAC Rule Element ========================*/
typedef struct {
    PyObject_HEAD

    PyObject *category;
    PyObject *names;
    PyObject *groups;
} HbacRuleElement;

static PyObject *
HbacRuleElement_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    HbacRuleElement *self;

    self = (HbacRuleElement *) type->tp_alloc(type, 0);
    if (self == NULL) {
        PyErr_NoMemory();
        return NULL;
    }

    self->category = PySet_New(NULL);
    self->names = PyList_New(0);
    self->groups = PyList_New(0);
    if (!self->names || !self->groups || !self->category) {
        Py_DECREF(self);
        PyErr_NoMemory();
        return NULL;
    }

    return (PyObject *) self;
}

static int
HbacRuleElement_clear(HbacRuleElement *self)
{
    Py_CLEAR(self->names);
    Py_CLEAR(self->groups);
    Py_CLEAR(self->category);
    return 0;
}

static void
HbacRuleElement_dealloc(HbacRuleElement *self)
{
    HbacRuleElement_clear(self);
    Py_TYPE(self)->tp_free((PyObject*) self);
}

static int
HbacRuleElement_traverse(HbacRuleElement *self, visitproc visit, void *arg)
{
    Py_VISIT(self->groups);
    Py_VISIT(self->names);
    Py_VISIT(self->category);
    return 0;
}

static int
hbac_rule_element_set_names(HbacRuleElement *self, PyObject *names,
                            void *closure);
static int
hbac_rule_element_set_groups(HbacRuleElement *self, PyObject *groups,
                             void *closure);
static int
hbac_rule_element_set_category(HbacRuleElement *self, PyObject *category,
                               void *closure);

static int
HbacRuleElement_init(HbacRuleElement *self, PyObject *args, PyObject *kwargs)
{
    const char * const kwlist[] = { "names", "groups", "category", NULL };
    PyObject *names = NULL;
    PyObject *groups = NULL;
    PyObject *category = NULL;
    PyObject *tmp = NULL;

    if (!PyArg_ParseTupleAndKeywords(args, kwargs,
                                     sss_py_const_p(char, "|OOO"),
                                     discard_const_p(char *, kwlist),
                                     &names, &groups, &category)) {
        return -1;
    }

    if (names) {
        if (hbac_rule_element_set_names(self, names, NULL) != 0) {
            return -1;
        }
    }

    if (groups) {
        if (hbac_rule_element_set_groups(self, groups, NULL) != 0) {
            return -1;
        }
    }

    if (category) {
        if (hbac_rule_element_set_category(self, category, NULL) != 0) {
            return -1;
        }
    } else {
        tmp = PYNUMBER_FROMLONG(HBAC_CATEGORY_NULL);
        if (!tmp) {
            return -1;
        }

        if (PySet_Add(self->category, tmp) != 0) {
            Py_DECREF(tmp);
            return -1;
        }
    }

    return 0;
}

static int
hbac_rule_element_set_names(HbacRuleElement *self,
                            PyObject *names,
                            void *closure)
{
    CHECK_ATTRIBUTE_DELETE(names, "names");

    if (!verify_sequence(names, "names")) {
        return -1;
    }

    SAFE_SET(self->names, names);
    return 0;
}

static PyObject *
hbac_rule_element_get_names(HbacRuleElement *self, void *closure)
{
    Py_INCREF(self->names);
    return self->names;
}

static int
hbac_rule_element_set_groups(HbacRuleElement *self,
                             PyObject *groups,
                             void *closure)
{
    CHECK_ATTRIBUTE_DELETE(groups, "groups");

    if (!verify_sequence(groups, "groups")) {
        return -1;
    }

    SAFE_SET(self->groups, groups);
    return 0;
}

static PyObject *
hbac_rule_element_get_groups(HbacRuleElement *self, void *closure)
{
    Py_INCREF(self->groups);
    return self->groups;
}

static int
hbac_rule_element_set_category(HbacRuleElement *self,
                               PyObject *category,
                               void *closure)
{
    PyObject *iterator;
    PyObject *item;
    int ret;

    CHECK_ATTRIBUTE_DELETE(category, "category");

    if (!PySet_Check(category)) {
        PyErr_Format(PyExc_TypeError, "The category must be a set type\n");
        return -1;
    }

    /* Check the values, too */
    iterator = PyObject_GetIter(category);
    if (iterator == NULL) {
        PyErr_Format(PyExc_RuntimeError, "Cannot iterate a set?\n");
        return -1;
    }

    while ((item = PyIter_Next(iterator))) {
        ret = pyobject_to_category(item);
        Py_DECREF(item);
        if (ret == -1) {
            Py_DECREF(iterator);
            return -1;
        }
    }

    SAFE_SET(self->category, category);
    Py_DECREF(iterator);
    return 0;
}

static PyObject *
hbac_rule_element_get_category(HbacRuleElement *self, void *closure)
{
    Py_INCREF(self->category);
    return self->category;
}

static PyObject *
HbacRuleElement_repr(HbacRuleElement *self)
{
    char *strnames = NULL;
    char *strgroups = NULL;
    uint32_t category;
    int ret;
    PyObject *o, *format, *args;

    format = PyUnicode_FromString("<category %lu names [%s] groups [%s]>");
    if (format == NULL) {
        return NULL;
    }

    strnames = str_concat_sequence(self->names,
                                   discard_const_p(char, ","));
    strgroups = str_concat_sequence(self->groups,
                                    discard_const_p(char, ","));
    ret = native_category(self->category, &category);
    if (strnames == NULL || strgroups == NULL || ret == -1) {
        PyMem_Free(strnames);
        PyMem_Free(strgroups);
        Py_DECREF(format);
        return NULL;
    }

    args = Py_BuildValue(sss_py_const_p(char, "Kss"),
                         (unsigned long long ) category,
                         strnames, strgroups);
    if (args == NULL) {
        PyMem_Free(strnames);
        PyMem_Free(strgroups);
        Py_DECREF(format);
        return NULL;
    }

    o = PyUnicode_Format(format, args);
    PyMem_Free(strnames);
    PyMem_Free(strgroups);
    Py_DECREF(format);
    Py_DECREF(args);
    return o;
}

PyDoc_STRVAR(HbacRuleElement_names__doc__,
"(sequence of strings) A list of object names this element applies to");
PyDoc_STRVAR(HbacRuleElement_groups__doc__,
"(sequence of strings) A list of group names this element applies to");
PyDoc_STRVAR(HbacRuleElement_category__doc__,
"(set) A set of categories this rule falls into");

static PyGetSetDef py_hbac_rule_element_getset[] = {
    { discard_const_p(char, "names"),
      (getter) hbac_rule_element_get_names,
      (setter) hbac_rule_element_set_names,
      HbacRuleElement_names__doc__,
      NULL },

    { discard_const_p(char, "groups"),
      (getter) hbac_rule_element_get_groups,
      (setter) hbac_rule_element_set_groups,
      HbacRuleElement_groups__doc__,
      NULL },

    { discard_const_p(char, "category"),
      (getter) hbac_rule_element_get_category,
      (setter) hbac_rule_element_set_category,
      HbacRuleElement_category__doc__,
      NULL },

    { NULL, 0, 0, 0, NULL } /* Sentinel */
};

PyDoc_STRVAR(HbacRuleElement__doc__,
"IPA HBAC Rule Element\n\n"
"HbacRuleElement() -> new empty rule element\n"
"HbacRuleElement([names], [groups], [category]) -> optionally, provide\n"
"names and/or groups and/or category\n");

static PyTypeObject pyhbac_hbacrule_element_type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = sss_py_const_p(char, "pyhbac.HbacRuleElement"),
    .tp_basicsize = sizeof(HbacRuleElement),
    .tp_new = HbacRuleElement_new,
    .tp_dealloc = (destructor) HbacRuleElement_dealloc,
    .tp_traverse = (traverseproc) HbacRuleElement_traverse,
    .tp_clear = (inquiry) HbacRuleElement_clear,
    .tp_init = (initproc) HbacRuleElement_init,
    .tp_repr = (reprfunc) HbacRuleElement_repr,
    .tp_getset = py_hbac_rule_element_getset,
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE | Py_TPFLAGS_HAVE_GC,
    .tp_doc   = HbacRuleElement__doc__
};

static void
free_hbac_rule_element(struct hbac_rule_element *el)
{
    if (!el) return;

    free_string_list(el->names);
    free_string_list(el->groups);
    PyMem_Free(el);
}

struct hbac_rule_element *
HbacRuleElement_to_native(HbacRuleElement *pyel)
{
    struct hbac_rule_element *el = NULL;
    int ret;

    /* check the type, None would wreak havoc here because for some reason
     * it would pass the sequence check */
    if (!PyObject_IsInstance((PyObject *) pyel,
                             (PyObject *) &pyhbac_hbacrule_element_type)) {
        PyErr_Format(PyExc_TypeError,
                     "The element must be of type HbacRuleElement\n");
        goto fail;
    }

    el = PyMem_Malloc(sizeof(struct hbac_rule_element));
    if (!el) {
        PyErr_NoMemory();
        goto fail;
    }

    ret = native_category(pyel->category, &el->category);
    el->names = sequence_as_string_list(pyel->names, "names");
    el->groups = sequence_as_string_list(pyel->groups, "groups");
    if (!el->names || !el->groups || ret == -1) {
        goto fail;
    }

    return el;

fail:
    free_hbac_rule_element(el);
    return NULL;
}

/* ==================== HBAC Rule ========================*/
typedef struct {
    PyObject_HEAD

    PyObject *name;
    bool enabled;

    HbacRuleElement *users;
    HbacRuleElement *services;
    HbacRuleElement *targethosts;
    HbacRuleElement *srchosts;
} HbacRuleObject;

static void
free_hbac_rule(struct hbac_rule *rule);
static struct hbac_rule *
HbacRule_to_native(HbacRuleObject *pyrule);

static PyObject *
HbacRule_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    HbacRuleObject *self;

    self = (HbacRuleObject *) type->tp_alloc(type, 0);
    if (self == NULL) {
        PyErr_NoMemory();
        return NULL;
    }

    self->name = PyUnicode_FromString("");
    if (self->name == NULL) {
        Py_DECREF(self);
        PyErr_NoMemory();
        return NULL;
    }

    self->enabled = false;

    self->services = (HbacRuleElement *) HbacRuleElement_new(
                                                &pyhbac_hbacrule_element_type,
                                                NULL, NULL);
    self->users = (HbacRuleElement *) HbacRuleElement_new(
                                                &pyhbac_hbacrule_element_type,
                                                NULL, NULL);
    self->targethosts = (HbacRuleElement *) HbacRuleElement_new(
                                                &pyhbac_hbacrule_element_type,
                                                NULL, NULL);
    self->srchosts = (HbacRuleElement *) HbacRuleElement_new(
                                                &pyhbac_hbacrule_element_type,
                                                NULL, NULL);
    if (self->services == NULL || self->users == NULL ||
        self->targethosts == NULL || self->srchosts == NULL) {
        Py_XDECREF(self->services);
        Py_XDECREF(self->users);
        Py_XDECREF(self->targethosts);
        Py_XDECREF(self->srchosts);
        Py_DECREF(self->name);
        Py_DECREF(self);
        PyErr_NoMemory();
        return NULL;
    }

    return (PyObject *) self;
}

static int
HbacRule_clear(HbacRuleObject *self)
{
    Py_CLEAR(self->name);
    Py_CLEAR(self->services);
    Py_CLEAR(self->users);
    Py_CLEAR(self->targethosts);
    Py_CLEAR(self->srchosts);
    return 0;
}

static void
HbacRule_dealloc(HbacRuleObject *self)
{
    HbacRule_clear(self);
    Py_TYPE(self)->tp_free((PyObject*) self);
}

static int
HbacRule_traverse(HbacRuleObject *self, visitproc visit, void *arg)
{
    Py_VISIT((PyObject *) self->name);
    Py_VISIT((PyObject *) self->services);
    Py_VISIT((PyObject *) self->users);
    Py_VISIT((PyObject *) self->targethosts);
    Py_VISIT((PyObject *) self->srchosts);
    return 0;
}

static int
hbac_rule_set_enabled(HbacRuleObject *self, PyObject *enabled, void *closure);
static int
hbac_rule_set_name(HbacRuleObject *self, PyObject *name, void *closure);

static int
HbacRule_init(HbacRuleObject *self, PyObject *args, PyObject *kwargs)
{
    const char * const kwlist[] = { "name", "enabled", NULL };
    PyObject *name = NULL;
    PyObject *empty_tuple = NULL;
    PyObject *enabled=NULL;

    if (!PyArg_ParseTupleAndKeywords(args, kwargs,
                                     sss_py_const_p(char, "O|O"),
                                     discard_const_p(char *, kwlist),
                                     &name, &enabled)) {
        return -1;
    }

    if (enabled) {
        if (hbac_rule_set_enabled(self, enabled, NULL) == -1) {
            return -1;
        }
    }

    if (hbac_rule_set_name(self, name, NULL) == -1) {
        return -1;
    }

    empty_tuple = PyTuple_New(0);
    if (!empty_tuple) {
        return -1;
    }

    if (HbacRuleElement_init(self->users, empty_tuple, NULL) == -1 ||
        HbacRuleElement_init(self->services, empty_tuple, NULL) == -1 ||
        HbacRuleElement_init(self->targethosts, empty_tuple, NULL) == -1 ||
        HbacRuleElement_init(self->srchosts, empty_tuple, NULL) == -1) {
        Py_DECREF(empty_tuple);
        return -1;
    }

    Py_DECREF(empty_tuple);
    return 0;
}

static int
hbac_rule_set_enabled(HbacRuleObject *self, PyObject *enabled, void *closure)
{
    CHECK_ATTRIBUTE_DELETE(enabled, "enabled");

    if (PyBytes_Check(enabled) || PyUnicode_Check(enabled)) {
        PyObject *utf8_str;
        char *str;

        utf8_str = get_utf8_string(enabled, "enabled");
        if (!utf8_str) return -1;
        str = PyBytes_AsString(utf8_str);
        if (!str) {
            Py_DECREF(utf8_str);
            return -1;
        }

        if (strcasecmp(str, "true") == 0) {
            self->enabled = true;
        } else if (strcasecmp(str, "false") == 0) {
            self->enabled = false;
        } else {
            PyErr_Format(PyExc_ValueError,
                         "enabled only accepts 'true' of 'false' "
                         "string literals");
            Py_DECREF(utf8_str);
            return -1;
        }

        Py_DECREF(utf8_str);
        return 0;
    } else if (PyBool_Check(enabled) == true) {
        self->enabled = (enabled == Py_True);
        return 0;
    } else if (PYNUMBER_CHECK(enabled)) {
        switch(PYNUMBER_ASLONG(enabled)) {
            case 0:
                self->enabled = false;
                break;
            case 1:
                self->enabled = true;
                break;
            default:
                PyErr_Format(PyExc_ValueError,
                            "enabled only accepts '0' of '1' "
                            "integer constants");
                return -1;
        }
        return 0;
    }

    PyErr_Format(PyExc_TypeError, "enabled must be a boolean, an integer "
                                  "1 or 0 or a string constant true/false");
    return -1;

}

static PyObject *
hbac_rule_get_enabled(HbacRuleObject *self, void *closure)
{
    if (self->enabled) {
        Py_RETURN_TRUE;
    }

    Py_RETURN_FALSE;
}

static int
hbac_rule_set_name(HbacRuleObject *self, PyObject *name, void *closure)
{
    CHECK_ATTRIBUTE_DELETE(name, "name");

    if (!PyBytes_Check(name) && !PyUnicode_Check(name)) {
        PyErr_Format(PyExc_TypeError, "name must be a string or Unicode");
        return -1;
    }

    SAFE_SET(self->name, name);
    return 0;
}

static PyObject *
hbac_rule_get_name(HbacRuleObject *self, void *closure)
{
    if (PyUnicode_Check(self->name)) {
        Py_INCREF(self->name);
        return self->name;
    } else if (PyBytes_Check(self->name)) {
        return PyUnicode_FromEncodedObject(self->name,
                                           PYHBAC_ENCODING, PYHBAC_ENCODING_ERRORS);
    }

    /* setter does typechecking but let us be paranoid */
    PyErr_Format(PyExc_TypeError, "name must be a string or Unicode");
    return NULL;
}

static PyObject *
HbacRule_repr(HbacRuleObject *self)
{
    PyObject *users_repr;
    PyObject *services_repr;
    PyObject *targethosts_repr;
    PyObject *srchosts_repr;
    PyObject *o, *format, *args;

    format = PyUnicode_FromString("<name %s enabled %d "
                                            "users %s services %s "
                                            "targethosts %s srchosts %s>");
    if (format == NULL) {
        return NULL;
    }

    users_repr = HbacRuleElement_repr(self->users);
    services_repr = HbacRuleElement_repr(self->services);
    targethosts_repr = HbacRuleElement_repr(self->targethosts);
    srchosts_repr = HbacRuleElement_repr(self->srchosts);
    if (users_repr == NULL || services_repr == NULL ||
        targethosts_repr == NULL || srchosts_repr == NULL) {
        Py_XDECREF(users_repr);
        Py_XDECREF(services_repr);
        Py_XDECREF(targethosts_repr);
        Py_XDECREF(srchosts_repr);
        Py_DECREF(format);
        return NULL;
    }

    args = Py_BuildValue(sss_py_const_p(char, "OiOOOO"),
                         self->name, self->enabled,
                         users_repr, services_repr,
                         targethosts_repr, srchosts_repr);
    if (args == NULL) {
        Py_DECREF(users_repr);
        Py_DECREF(services_repr);
        Py_DECREF(targethosts_repr);
        Py_DECREF(srchosts_repr);
        Py_DECREF(format);
        return NULL;
    }

    o = PyUnicode_Format(format, args);
    Py_DECREF(users_repr);
    Py_DECREF(services_repr);
    Py_DECREF(targethosts_repr);
    Py_DECREF(srchosts_repr);
    Py_DECREF(format);
    Py_DECREF(args);
    return o;
}

static PyObject *
py_hbac_rule_validate(HbacRuleObject *self, PyObject *args)
{
    struct hbac_rule *rule;
    bool is_valid;
    uint32_t missing;
    uint32_t attr;
    PyObject *ret = NULL;
    PyObject *py_is_valid = NULL;
    PyObject *py_missing = NULL;
    PyObject *py_attr = NULL;

    rule = HbacRule_to_native(self);
    if (!rule) {
        /* Make sure there is at least a generic exception */
        if (!PyErr_Occurred()) {
            PyErr_Format(PyExc_IOError,
                         "Could not convert HbacRule to native type\n");
        }
        goto fail;
    }

    is_valid = hbac_rule_is_complete(rule, &missing);
    free_hbac_rule(rule);

    ret = PyTuple_New(2);
    if (!ret) {
        PyErr_NoMemory();
        goto fail;
    }

    py_is_valid = PyBool_FromLong(is_valid);
    py_missing = PySet_New(NULL);
    if (!py_missing || !py_is_valid) {
        PyErr_NoMemory();
        goto fail;
    }

    for (attr = HBAC_RULE_ELEMENT_USERS;
         attr <= HBAC_RULE_ELEMENT_SOURCEHOSTS;
         attr <<= 1) {
        if (!(missing & attr)) continue;

        py_attr = PYNUMBER_FROMLONG(attr);
        if (!py_attr) {
            PyErr_NoMemory();
            goto fail;
        }

        if (PySet_Add(py_missing, py_attr) != 0) {
            /* If the set-add succeeded, it would steal the reference */
            Py_DECREF(py_attr);
            goto fail;
        }
    }

    PyTuple_SET_ITEM(ret, 0, py_is_valid);
    PyTuple_SET_ITEM(ret, 1, py_missing);
    return ret;

fail:
    Py_XDECREF(ret);
    Py_XDECREF(py_missing);
    Py_XDECREF(py_is_valid);
    return NULL;
}

PyDoc_STRVAR(py_hbac_rule_validate__doc__,
"validate() -> (valid, missing)\n\n"
"Validate an HBAC rule\n"
"Returns a tuple of (bool, set). The boolean value describes whether\n"
"the rule is valid. If it is False, then the set lists all the missing "
"rule elements as HBAC_RULE_ELEMENT_* constants\n");

static PyMethodDef py_hbac_rule_methods[] = {
    { sss_py_const_p(char, "validate"),
      (PyCFunction) py_hbac_rule_validate,
      METH_VARARGS, py_hbac_rule_validate__doc__,
    },
    { NULL, NULL, 0, NULL }        /* Sentinel */
};

PyDoc_STRVAR(HbacRuleObject_users__doc__,
"(HbacRuleElement) Users and user groups for which this rule applies");
PyDoc_STRVAR(HbacRuleObject_services__doc__,
"(HbacRuleElement) Services and service groups for which this rule applies");
PyDoc_STRVAR(HbacRuleObject_targethosts__doc__,
"(HbacRuleElement) Target hosts for which this rule applies");
PyDoc_STRVAR(HbacRuleObject_srchosts__doc__,
"(HbacRuleElement) Source hosts for which this rule applies");

static PyMemberDef py_hbac_rule_members[] = {
    { discard_const_p(char, "users"), T_OBJECT_EX,
      offsetof(HbacRuleObject, users), 0,
      HbacRuleObject_users__doc__ },

    { discard_const_p(char, "services"), T_OBJECT_EX,
      offsetof(HbacRuleObject, services), 0,
      HbacRuleObject_services__doc__ },

    { discard_const_p(char, "targethosts"), T_OBJECT_EX,
      offsetof(HbacRuleObject, targethosts), 0,
      HbacRuleObject_targethosts__doc__},

    { discard_const_p(char, "srchosts"), T_OBJECT_EX,
      offsetof(HbacRuleObject, srchosts), 0,
      HbacRuleObject_srchosts__doc__},

    { NULL, 0, 0, 0, NULL } /* Sentinel */
};

PyDoc_STRVAR(HbacRuleObject_enabled__doc__,
"(bool) Is the rule enabled");
PyDoc_STRVAR(HbacRuleObject_name__doc__,
"(string) The name of the rule");

static PyGetSetDef py_hbac_rule_getset[] = {
    { discard_const_p(char, "enabled"),
      (getter) hbac_rule_get_enabled,
      (setter) hbac_rule_set_enabled,
      HbacRuleObject_enabled__doc__,
      NULL },

    { discard_const_p(char, "name"),
      (getter) hbac_rule_get_name,
      (setter) hbac_rule_set_name,
      HbacRuleObject_name__doc__,
      NULL },

    {NULL, 0, 0, 0, NULL} /* Sentinel */
};

PyDoc_STRVAR(HbacRuleObject__doc__,
"IPA HBAC Rule\n\n"
"HbacRule(name, [enabled]) -> instantiate an empty rule, optionally\n"
"specify whether it is enabled. Rules are created disabled by default and\n"
"contain empty HbacRuleElement instances in services, users, targethosts\n"
"and srchosts attributes.\n");

static PyTypeObject pyhbac_hbacrule_type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = sss_py_const_p(char, "pyhbac.HbacRule"),
    .tp_basicsize = sizeof(HbacRuleObject),
    .tp_new = HbacRule_new,
    .tp_dealloc = (destructor) HbacRule_dealloc,
    .tp_traverse = (traverseproc) HbacRule_traverse,
    .tp_clear = (inquiry) HbacRule_clear,
    .tp_init = (initproc) HbacRule_init,
    .tp_repr = (reprfunc) HbacRule_repr,
    .tp_members = py_hbac_rule_members,
    .tp_methods = py_hbac_rule_methods,
    .tp_getset = py_hbac_rule_getset,
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE | Py_TPFLAGS_HAVE_GC,
    .tp_doc   = HbacRuleObject__doc__
};

static void
free_hbac_rule(struct hbac_rule *rule)
{
    if (!rule) return;

    free_hbac_rule_element(rule->services);
    free_hbac_rule_element(rule->users);
    free_hbac_rule_element(rule->targethosts);
    free_hbac_rule_element(rule->srchosts);

    PyMem_Free(discard_const_p(char, rule->name));
    PyMem_Free(rule);
}

static struct hbac_rule *
HbacRule_to_native(HbacRuleObject *pyrule)
{
    struct hbac_rule *rule = NULL;
    PyObject *utf_name;

    rule = PyMem_Malloc(sizeof(struct hbac_rule));
    if (!rule) {
        PyErr_NoMemory();
        goto fail;
    }

    if (!PyObject_IsInstance((PyObject *) pyrule,
                             (PyObject *) &pyhbac_hbacrule_type)) {
        PyErr_Format(PyExc_TypeError,
                     "The rule must be of type HbacRule\n");
        goto fail;
    }

    utf_name = get_utf8_string(pyrule->name, "name");
    if (utf_name == NULL) {
        return NULL;
    }

    rule->name = py_strdup(PyBytes_AsString(utf_name));
    Py_DECREF(utf_name);
    if (rule->name == NULL) {
        goto fail;
    }

    rule->services = HbacRuleElement_to_native(pyrule->services);
    rule->users = HbacRuleElement_to_native(pyrule->users);
    rule->targethosts = HbacRuleElement_to_native(pyrule->targethosts);
    rule->srchosts =  HbacRuleElement_to_native(pyrule->srchosts);
    if (!rule->services || !rule->users ||
        !rule->targethosts || !rule->srchosts) {
        goto fail;
    }

    rule->enabled = pyrule->enabled;
    return rule;

fail:
    free_hbac_rule(rule);
    return NULL;
}

/* ==================== HBAC Request Element ========================*/
typedef struct {
    PyObject_HEAD

    PyObject *name;
    PyObject *groups;
} HbacRequestElement;

static PyObject *
HbacRequestElement_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    HbacRequestElement *self;

    self = (HbacRequestElement *) type->tp_alloc(type, 0);
    if (self == NULL) {
        PyErr_NoMemory();
        return NULL;
    }

    self->name = PyUnicode_FromString("");
    if (self->name == NULL) {
        PyErr_NoMemory();
        Py_DECREF(self);
        return NULL;
    }

    self->groups = PyList_New(0);
    if (self->groups == NULL) {
        Py_DECREF(self->name);
        Py_DECREF(self);
        PyErr_NoMemory();
        return NULL;
    }

    return (PyObject *) self;
}

static int
HbacRequestElement_clear(HbacRequestElement *self)
{
    Py_CLEAR(self->name);
    Py_CLEAR(self->groups);
    return 0;
}

static void
HbacRequestElement_dealloc(HbacRequestElement *self)
{
    HbacRequestElement_clear(self);
    Py_TYPE(self)->tp_free((PyObject*) self);
}

static int
HbacRequestElement_traverse(HbacRequestElement *self,
                            visitproc visit, void *arg)
{
    Py_VISIT(self->name);
    Py_VISIT(self->groups);
    return 0;
}

static int
hbac_request_element_set_groups(HbacRequestElement *self,
                                PyObject *groups,
                                void *closure);
static int
hbac_request_element_set_name(HbacRequestElement *self,
                              PyObject *name,
                              void *closure);

static int
HbacRequestElement_init(HbacRequestElement *self,
                        PyObject *args,
                        PyObject *kwargs)
{
    const char * const kwlist[] = { "name", "groups", NULL };
    PyObject *name = NULL;
    PyObject *groups = NULL;

    if (!PyArg_ParseTupleAndKeywords(args, kwargs,
                                     sss_py_const_p(char, "|OO"),
                                     discard_const_p(char *, kwlist),
                                     &name, &groups)) {
        return -1;
    }

    if (name) {
        if (hbac_request_element_set_name(self, name, NULL) != 0) {
            return -1;
        }
    }

    if (groups) {
        if (hbac_request_element_set_groups(self, groups, NULL) != 0) {
            return -1;
        }
    }

    return 0;
}

static int
hbac_request_element_set_name(HbacRequestElement *self,
                              PyObject *name,
                              void *closure)
{
    CHECK_ATTRIBUTE_DELETE(name, "name");

    if (!PyBytes_Check(name) && !PyUnicode_Check(name)) {
        PyErr_Format(PyExc_TypeError, "name must be a string or Unicode");
        return -1;
    }

    SAFE_SET(self->name, name);
    return 0;
}

static PyObject *
hbac_request_element_get_name(HbacRequestElement *self, void *closure)
{
    if (PyUnicode_Check(self->name)) {
        Py_INCREF(self->name);
        return self->name;
    } else if (PyBytes_Check(self->name)) {
        return PyUnicode_FromEncodedObject(self->name,
                                           PYHBAC_ENCODING, PYHBAC_ENCODING_ERRORS);
    }

    /* setter does typechecking but let us be paranoid */
    PyErr_Format(PyExc_TypeError, "name must be a string or Unicode");
    return NULL;
}

static int
hbac_request_element_set_groups(HbacRequestElement *self,
                                PyObject *groups,
                                void *closure)
{
    CHECK_ATTRIBUTE_DELETE(groups, "groups");

    if (!verify_sequence(groups, "groups")) {
        return -1;
    }

    SAFE_SET(self->groups, groups);
    return 0;
}

static PyObject *
hbac_request_element_get_groups(HbacRequestElement *self, void *closure)
{
    Py_INCREF(self->groups);
    return self->groups;
}

static PyObject *
HbacRequestElement_repr(HbacRequestElement *self)
{
    char *strgroups;
    PyObject *o, *format, *args;

    format = PyUnicode_FromString("<name %s groups [%s]>");
    if (format == NULL) {
        return NULL;
    }

    strgroups = str_concat_sequence(self->groups, discard_const_p(char, ","));
    if (strgroups == NULL) {
        Py_DECREF(format);
        return NULL;
    }

    args = Py_BuildValue(sss_py_const_p(char, "Os"), self->name, strgroups);
    if (args == NULL) {
        PyMem_Free(strgroups);
        Py_DECREF(format);
        return NULL;
    }

    o = PyUnicode_Format(format, args);
    PyMem_Free(strgroups);
    Py_DECREF(format);
    Py_DECREF(args);
    return o;
}

PyDoc_STRVAR(HbacRequestElement_name__doc__,
"(string) An object name this element applies to");
PyDoc_STRVAR(HbacRequestElement_groups__doc__,
"(list of strings) A list of group names this element applies to");

static PyGetSetDef py_hbac_request_element_getset[] = {
    { discard_const_p(char, "name"),
      (getter) hbac_request_element_get_name,
      (setter) hbac_request_element_set_name,
      HbacRequestElement_name__doc__,
      NULL },

    { discard_const_p(char, "groups"),
      (getter) hbac_request_element_get_groups,
      (setter) hbac_request_element_set_groups,
      HbacRequestElement_groups__doc__,
      NULL },

    { NULL, 0, 0, 0, NULL } /* Sentinel */
};

PyDoc_STRVAR(HbacRequestElement__doc__,
"IPA HBAC Request Element\n\n"
"HbacRequestElement() -> new empty request element\n"
"HbacRequestElement([name], [groups]) -> optionally, provide name and/or "
"groups\n");

static PyTypeObject pyhbac_hbacrequest_element_type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = sss_py_const_p(char, "pyhbac.HbacRequestElement"),
    .tp_basicsize = sizeof(HbacRequestElement),
    .tp_new = HbacRequestElement_new,
    .tp_dealloc = (destructor) HbacRequestElement_dealloc,
    .tp_traverse = (traverseproc) HbacRequestElement_traverse,
    .tp_clear = (inquiry) HbacRequestElement_clear,
    .tp_init = (initproc) HbacRequestElement_init,
    .tp_repr = (reprfunc) HbacRequestElement_repr,
    .tp_getset = py_hbac_request_element_getset,
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE | Py_TPFLAGS_HAVE_GC,
    .tp_doc   = HbacRequestElement__doc__
};

static void
free_hbac_request_element(struct hbac_request_element *el)
{
    if (!el) return;

    PyMem_Free(discard_const_p(char, el->name));
    free_string_list(el->groups);
    PyMem_Free(el);
}

static struct hbac_request_element *
HbacRequestElement_to_native(HbacRequestElement *pyel)
{
    struct hbac_request_element *el = NULL;
    PyObject *utf_name;

    if (!PyObject_IsInstance((PyObject *) pyel,
                             (PyObject *) &pyhbac_hbacrequest_element_type)) {
        PyErr_Format(PyExc_TypeError,
                     "The element must be of type HbacRequestElement\n");
        goto fail;
    }

    el = PyMem_Malloc(sizeof(struct hbac_request_element));
    if (!el) {
        PyErr_NoMemory();
        goto fail;
    }

    utf_name = get_utf8_string(pyel->name, "name");
    if (utf_name == NULL) {
        return NULL;
    }

    el->name = py_strdup(PyBytes_AsString(utf_name));
    Py_DECREF(utf_name);
    if (!el->name) {
        goto fail;
    }

    el->groups = sequence_as_string_list(pyel->groups, "groups");
    if (!el->groups) {
        goto fail;
    }

    return el;

fail:
    free_hbac_request_element(el);
    return NULL;
}

/* ==================== HBAC Request ========================*/
typedef struct {
    PyObject_HEAD

    HbacRequestElement *service;
    HbacRequestElement *user;
    HbacRequestElement *targethost;
    HbacRequestElement *srchost;

    PyObject *rule_name;
} HbacRequest;

static PyObject *
HbacRequest_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    HbacRequest *self;

    self = (HbacRequest *) type->tp_alloc(type, 0);
    if (self == NULL) {
        PyErr_NoMemory();
        return NULL;
    }

    self->service = (HbacRequestElement *) HbacRequestElement_new(
                                            &pyhbac_hbacrequest_element_type,
                                            NULL, NULL);
    self->user = (HbacRequestElement *) HbacRequestElement_new(
                                            &pyhbac_hbacrequest_element_type,
                                            NULL, NULL);
    self->targethost = (HbacRequestElement *) HbacRequestElement_new(
                                            &pyhbac_hbacrequest_element_type,
                                            NULL, NULL);
    self->srchost = (HbacRequestElement *) HbacRequestElement_new(
                                            &pyhbac_hbacrequest_element_type,
                                            NULL, NULL);
    if (self->service == NULL || self->user == NULL ||
        self->targethost == NULL || self->srchost == NULL) {
        Py_XDECREF(self->service);
        Py_XDECREF(self->user);
        Py_XDECREF(self->targethost);
        Py_XDECREF(self->srchost);
        Py_DECREF(self);
        PyErr_NoMemory();
        return NULL;
    }

    return (PyObject *) self;
}

static int
HbacRequest_clear(HbacRequest *self)
{
    Py_CLEAR(self->service);
    Py_CLEAR(self->user);
    Py_CLEAR(self->targethost);
    Py_CLEAR(self->srchost);
    Py_CLEAR(self->rule_name);
    return 0;
}

static void
HbacRequest_dealloc(HbacRequest *self)
{
    HbacRequest_clear(self);
    Py_TYPE(self)->tp_free((PyObject*) self);
}

static int
HbacRequest_traverse(HbacRequest *self, visitproc visit, void *arg)
{
    Py_VISIT((PyObject *) self->service);
    Py_VISIT((PyObject *) self->user);
    Py_VISIT((PyObject *) self->targethost);
    Py_VISIT((PyObject *) self->srchost);
    return 0;
}

static int
HbacRequest_init(HbacRequest *self, PyObject *args, PyObject *kwargs)
{
    PyObject *empty_tuple = NULL;

    empty_tuple = PyTuple_New(0);
    if (!empty_tuple) {
        PyErr_NoMemory();
        return -1;
    }

    self->rule_name = NULL;

    if (HbacRequestElement_init(self->user, empty_tuple, NULL) == -1 ||
        HbacRequestElement_init(self->service, empty_tuple, NULL) == -1 ||
        HbacRequestElement_init(self->targethost, empty_tuple, NULL) == -1 ||
        HbacRequestElement_init(self->srchost, empty_tuple, NULL) == -1) {
        Py_DECREF(empty_tuple);
        return -1;
    }

    Py_DECREF(empty_tuple);
    return 0;
}

PyDoc_STRVAR(py_hbac_evaluate__doc__,
"evaluate(rules) -> int\n\n"
"Evaluate a set of HBAC rules.\n"
"rules is a sequence of HbacRule objects. The returned value describes\n"
"the result of evaluation and will have one of HBAC_EVAL_* values.\n"
"Use hbac_result_string() to get textual representation of the result\n"
"On error, HbacError exception is raised.\n"
"If HBAC_EVAL_ALLOW is returned, the class attribute rule_name would\n"
"contain the name of the rule that matched. Otherwise, the attribute\n"
"contains None\n");

static struct hbac_eval_req *
HbacRequest_to_native(HbacRequest *pyreq);

static void
free_hbac_rule_list(struct hbac_rule **rules)
{
    int i;

    if (!rules) return;

    for(i=0; rules[i]; i++) {
        free_hbac_rule(rules[i]);
    }
    PyMem_Free(rules);
}

static void
free_hbac_eval_req(struct hbac_eval_req *req);

static PyObject *
py_hbac_evaluate(HbacRequest *self, PyObject *args)
{
    PyObject *py_rules_list = NULL;
    PyObject *py_rule = NULL;
    Py_ssize_t num_rules;
    struct hbac_rule **rules = NULL;
    struct hbac_eval_req *hbac_req = NULL;
    enum hbac_eval_result eres;
    struct hbac_info *info = NULL;
    PyObject *ret = NULL;
    long i;

    if (!PyArg_ParseTuple(args, sss_py_const_p(char, "O"), &py_rules_list)) {
        goto fail;
    }

    if (!PySequence_Check(py_rules_list)) {
        PyErr_Format(PyExc_TypeError,
                     "The parameter rules must be a sequence\n");
        goto fail;
    }

    num_rules = PySequence_Size(py_rules_list);
    rules = PyMem_New(struct hbac_rule *, num_rules+1);
    if (!rules) {
        PyErr_NoMemory();
        goto fail;
    }

    for (i=0; i < num_rules; i++) {
        py_rule = PySequence_GetItem(py_rules_list, i);

        if (!PyObject_IsInstance(py_rule,
                                 (PyObject *) &pyhbac_hbacrule_type)) {
            PyErr_Format(PyExc_TypeError,
                         "A rule must be of type HbacRule\n");
            goto fail;
        }

        rules[i] = HbacRule_to_native((HbacRuleObject *) py_rule);
        if (!rules[i]) {
            /* Make sure there is at least a generic exception */
            if (!PyErr_Occurred()) {
                PyErr_Format(PyExc_IOError,
                             "Could not convert HbacRule to native type\n");
            }
            goto fail;
        }
    }
    rules[num_rules] = NULL;

    hbac_req = HbacRequest_to_native(self);
    if (!hbac_req) {
        if (!PyErr_Occurred()) {
            PyErr_Format(PyExc_IOError,
                         "Could not convert HbacRequest to native type\n");
        }
        goto fail;
    }

    Py_XDECREF(self->rule_name);
    self->rule_name = NULL;

    eres = hbac_evaluate(rules, hbac_req, &info);
    switch (eres) {
    case HBAC_EVAL_ALLOW:
        self->rule_name = PyUnicode_FromString(info->rule_name);
        if (!self->rule_name) {
            PyErr_NoMemory();
            goto fail;
        }
        /* FALLTHROUGH */
        SSS_ATTRIBUTE_FALLTHROUGH;
    case HBAC_EVAL_DENY:
        ret = PYNUMBER_FROMLONG(eres);
        break;
    case HBAC_EVAL_ERROR:
        set_hbac_exception(PyExc_HbacError, info);
        goto fail;
    case HBAC_EVAL_OOM:
        PyErr_NoMemory();
        goto fail;
    }

    free_hbac_eval_req(hbac_req);
    free_hbac_rule_list(rules);
    hbac_free_info(info);
    return ret;

fail:
    hbac_free_info(info);
    free_hbac_eval_req(hbac_req);
    free_hbac_rule_list(rules);
    return NULL;
}

static PyObject *
hbac_request_element_get_rule_name(HbacRequest *self, void *closure)
{
    if (self->rule_name == NULL) {
        Py_INCREF(Py_None);
        return Py_None;
    } else if (PyUnicode_Check(self->rule_name)) {
        Py_INCREF(self->rule_name);
        return self->rule_name;
    }

    PyErr_Format(PyExc_TypeError, "rule_name is not Unicode");
    return NULL;
}

static PyObject *
HbacRequest_repr(HbacRequest *self)
{
    PyObject *user_repr;
    PyObject *service_repr;
    PyObject *targethost_repr;
    PyObject *srchost_repr;
    PyObject *o, *format, *args;

    format = PyUnicode_FromString("<user %s service %s "
                                            "targethost %s srchost %s>");
    if (format == NULL) {
        return NULL;
    }

    user_repr = HbacRequestElement_repr(self->user);
    service_repr = HbacRequestElement_repr(self->service);
    targethost_repr = HbacRequestElement_repr(self->targethost);
    srchost_repr = HbacRequestElement_repr(self->srchost);
    if (user_repr == NULL || service_repr == NULL ||
        targethost_repr == NULL || srchost_repr == NULL) {
        Py_XDECREF(user_repr);
        Py_XDECREF(service_repr);
        Py_XDECREF(targethost_repr);
        Py_XDECREF(srchost_repr);
        Py_DECREF(format);
        return NULL;
    }

    args = Py_BuildValue(sss_py_const_p(char, "OOOO"),
                         user_repr, service_repr,
                         targethost_repr, srchost_repr);
    if (args == NULL) {
        Py_DECREF(user_repr);
        Py_DECREF(service_repr);
        Py_DECREF(targethost_repr);
        Py_DECREF(srchost_repr);
        Py_DECREF(format);
        return NULL;
    }

    o = PyUnicode_Format(format, args);
    Py_DECREF(user_repr);
    Py_DECREF(service_repr);
    Py_DECREF(targethost_repr);
    Py_DECREF(srchost_repr);
    Py_DECREF(format);
    Py_DECREF(args);
    return o;
}

static PyMethodDef py_hbac_request_methods[] = {
    { sss_py_const_p(char, "evaluate"),
      (PyCFunction) py_hbac_evaluate,
      METH_VARARGS, py_hbac_evaluate__doc__
    },
    { NULL, NULL, 0, NULL }        /* Sentinel */
};

PyDoc_STRVAR(HbacRequest_service__doc__,
"(HbacRequestElement) This is a list of service DNs to check, it must\n"
"consist of the actual service requested, as well as all parent groups\n"
"containing that service");
PyDoc_STRVAR(HbacRequest_user__doc__,
"(HbacRequestElement) This is a list of user DNs to check, it must consist\n"
"of the actual user requested, as well as all parent groups containing\n"
"that user.");
PyDoc_STRVAR(HbacRequest_targethost__doc__,
"(HbacRequestElement) This is a list of target hosts to check, it must\n"
"consist of the actual target host requested, as well as all parent groups\n"
"containing that target host.");
PyDoc_STRVAR(HbacRequest_srchost__doc__,
"(HbacRequestElement) This is a list of source hosts to check, it must\n"
"consist of the actual source host requested, as well as all parent groups\n"
"containing that source host.");

static PyMemberDef py_hbac_request_members[] = {
    { discard_const_p(char, "service"), T_OBJECT_EX,
      offsetof(HbacRequest, service), 0,
      HbacRequest_service__doc__ },

    { discard_const_p(char, "user"), T_OBJECT_EX,
      offsetof(HbacRequest, user), 0,
      HbacRequest_user__doc__ },

    { discard_const_p(char, "targethost"), T_OBJECT_EX,
      offsetof(HbacRequest, targethost), 0,
      HbacRequest_targethost__doc__ },

    { discard_const_p(char, "srchost"), T_OBJECT_EX,
      offsetof(HbacRequest, srchost), 0,
      HbacRequest_srchost__doc__ },

    { NULL, 0, 0, 0, NULL } /* Sentinel */
};

PyDoc_STRVAR(HbacRequest_rule_name__doc__,
"(string) If result of evaluation was to allow access, this member contains\n"
"the name of the rule that allowed it. Otherwise, this attribute contains \n"
"None. This attribute is read-only.\n");

static PyGetSetDef py_hbac_request_getset[] = {
    { discard_const_p(char, "rule_name"),
      (getter) hbac_request_element_get_rule_name,
      NULL, /* read only */
      HbacRequest_rule_name__doc__,
      NULL },

    { NULL, 0, 0, 0, NULL } /* Sentinel */
};

PyDoc_STRVAR(HbacRequest__doc__,
"IPA HBAC Request\n\n"
"HbacRequest() -> new empty HBAC request");

static PyTypeObject pyhbac_hbacrequest_type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = sss_py_const_p(char, "pyhbac.HbacRequest"),
    .tp_basicsize = sizeof(HbacRequest),
    .tp_new = HbacRequest_new,
    .tp_dealloc = (destructor) HbacRequest_dealloc,
    .tp_traverse = (traverseproc) HbacRequest_traverse,
    .tp_clear = (inquiry) HbacRequest_clear,
    .tp_init = (initproc) HbacRequest_init,
    .tp_repr = (reprfunc) HbacRequest_repr,
    .tp_methods = py_hbac_request_methods,
    .tp_members = py_hbac_request_members,
    .tp_getset = py_hbac_request_getset,
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
    .tp_doc   = HbacRequest__doc__
};

static void
free_hbac_eval_req(struct hbac_eval_req *req)
{
    if (!req) return;

    free_hbac_request_element(req->service);
    free_hbac_request_element(req->user);
    free_hbac_request_element(req->targethost);
    free_hbac_request_element(req->srchost);

    PyMem_Free(req);
}

static struct hbac_eval_req *
HbacRequest_to_native(HbacRequest *pyreq)
{
    struct hbac_eval_req *req = NULL;

    req = PyMem_Malloc(sizeof(struct hbac_eval_req));
    if (!req) {
        PyErr_NoMemory();
        goto fail;
    }

    if (!PyObject_IsInstance((PyObject *) pyreq,
                             (PyObject *) &pyhbac_hbacrequest_type)) {
        PyErr_Format(PyExc_TypeError,
                     "The request must be of type HbacRequest\n");
        goto fail;
    }

    req->service = HbacRequestElement_to_native(pyreq->service);
    req->user = HbacRequestElement_to_native(pyreq->user);
    req->targethost = HbacRequestElement_to_native(pyreq->targethost);
    req->srchost =  HbacRequestElement_to_native(pyreq->srchost);
    if (!req->service || !req->user ||
        !req->targethost || !req->srchost) {
        goto fail;
    }
    return req;

fail:
    free_hbac_eval_req(req);
    return NULL;
}

/* =================== the pyhbac module initialization =====================*/
PyDoc_STRVAR(py_hbac_result_string__doc__,
"hbac_result_string(code) -> string\n"
"Returns a string representation of the HBAC result code");

static PyObject *
py_hbac_result_string(PyObject *module, PyObject *args)
{
    enum hbac_eval_result result;
    const char *str;

    if (!PyArg_ParseTuple(args, sss_py_const_p(char, "i"), &result)) {
        return NULL;
    }

    str = hbac_result_string(result);
    if (str == NULL) {
        /* None needs to be referenced, too */
        Py_INCREF(Py_None);
        return Py_None;
    }

    return PyUnicode_FromString(str);
}

PyDoc_STRVAR(py_hbac_error_string__doc__,
"hbac_error_string(code) -> string\n"
"Returns a string representation of the HBAC error code");

static PyObject *
py_hbac_error_string(PyObject *module, PyObject *args)
{
    enum hbac_error_code code;
    const char *str;

    if (!PyArg_ParseTuple(args, sss_py_const_p(char, "i"), &code)) {
        return NULL;
    }

    str = hbac_error_string(code);
    if (str == NULL) {
        /* None needs to be referenced, too */
        Py_INCREF(Py_None);
        return Py_None;
    }

    return PyUnicode_FromString(str);
}

static PyMethodDef pyhbac_module_methods[] = {
        {  sss_py_const_p(char, "hbac_result_string"),
           (PyCFunction) py_hbac_result_string,
           METH_VARARGS,
           py_hbac_result_string__doc__,
        },

        { sss_py_const_p(char, "hbac_error_string"),
           (PyCFunction) py_hbac_error_string,
           METH_VARARGS,
           py_hbac_error_string__doc__,
        },

        {NULL, NULL, 0, NULL}  /* Sentinel */
};

PyDoc_STRVAR(HbacError__doc__,
"An HBAC processing exception\n\n"
"This exception is raised when there is an internal error during the\n"
"HBAC processing, such as an Out-Of-Memory situation or unparseable\n"
"rule. HbacError.args argument is a tuple that contains error code and\n"
"the name of the rule that was being processed. Use hbac_error_string()\n"
"to get the text representation of the HBAC error");

#ifdef IS_PY3K
static struct PyModuleDef pyhbacdef = {
    PyModuleDef_HEAD_INIT,
    PYTHON_MODULE_NAME,
    NULL,
    -1,
    pyhbac_module_methods,
    NULL,
    NULL,
    NULL,
    NULL
};

PyMODINIT_FUNC
PyInit_pyhbac(void)
#else
PyMODINIT_FUNC
initpyhbac(void)
#endif
{
    PyObject *m;
    int ret;

#ifdef IS_PY3K
    m = PyModule_Create(&pyhbacdef);
#else
    m = Py_InitModule(sss_py_const_p(char, PYTHON_MODULE_NAME),
                      pyhbac_module_methods);
#endif
    if (m == NULL) {
        MODINITERROR(NULL);
    }

    /* The HBAC module exception */
    PyExc_HbacError = sss_exception_with_doc(
                        "hbac.HbacError", HbacError__doc__,
                        PyExc_EnvironmentError, NULL);
    Py_INCREF(PyExc_HbacError);
    ret = PyModule_AddObject(m, sss_py_const_p(char, "HbacError"), PyExc_HbacError);
    if (ret == -1) {
        Py_XDECREF(PyExc_HbacError);
        MODINITERROR(m);
    }

    /* HBAC rule categories */
    ret = PyModule_AddIntMacro(m, HBAC_CATEGORY_NULL);
    if (ret == -1) {
        MODINITERROR(m);
    }
    ret = PyModule_AddIntMacro(m, HBAC_CATEGORY_ALL);
    if (ret == -1) {
        MODINITERROR(m);
    }

    /* HBAC rule elements */
    ret = PyModule_AddIntMacro(m, HBAC_RULE_ELEMENT_USERS);
    if (ret == -1) {
        MODINITERROR(m);
    }
    ret = PyModule_AddIntMacro(m, HBAC_RULE_ELEMENT_SERVICES);
    if (ret == -1) {
        MODINITERROR(m);
    }
    ret = PyModule_AddIntMacro(m, HBAC_RULE_ELEMENT_TARGETHOSTS);
    if (ret == -1) {
        MODINITERROR(m);
    }
    ret = PyModule_AddIntMacro(m, HBAC_RULE_ELEMENT_SOURCEHOSTS);
    if (ret == -1) {
        MODINITERROR(m);
    }

    /* enum hbac_eval_result */
    ret = PyModule_AddIntMacro(m, HBAC_EVAL_ALLOW);
    if (ret == -1) {
        MODINITERROR(m);
    }
    ret = PyModule_AddIntMacro(m, HBAC_EVAL_DENY);
    if (ret == -1) {
        MODINITERROR(m);
    }
    ret = PyModule_AddIntMacro(m, HBAC_EVAL_ERROR);
    if (ret == -1) {
        MODINITERROR(m);
    }

    /* enum hbac_error_code */
    ret = PyModule_AddIntMacro(m, HBAC_ERROR_UNKNOWN);
    if (ret == -1) {
        MODINITERROR(m);
    }
    ret = PyModule_AddIntMacro(m, HBAC_SUCCESS);
    if (ret == -1) {
        MODINITERROR(m);
    }
    ret = PyModule_AddIntMacro(m, HBAC_ERROR_NOT_IMPLEMENTED);
    if (ret == -1) {
        MODINITERROR(m);
    }
    ret = PyModule_AddIntMacro(m, HBAC_ERROR_OUT_OF_MEMORY);
    if (ret == -1) {
        MODINITERROR(m);
    }
    ret = PyModule_AddIntMacro(m, HBAC_ERROR_UNPARSEABLE_RULE);
    if (ret == -1) {
        MODINITERROR(m);
    }

    TYPE_READY(m, pyhbac_hbacrule_type, "HbacRule");
    TYPE_READY(m, pyhbac_hbacrule_element_type, "HbacRuleElement");
    TYPE_READY(m, pyhbac_hbacrequest_element_type, "HbacRequestElement");
    TYPE_READY(m, pyhbac_hbacrequest_type, "HbacRequest");

#ifdef IS_PY3K
    return m;
#endif
}
