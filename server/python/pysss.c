/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

    Copyright (C) 2009 Red Hat

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
#include <structmember.h>
#include <talloc.h>
#include <pwd.h>
#include <grp.h>

#include "util/util.h"
#include "db/sysdb.h"
#include "tools/tools_util.h"
#include "tools/sss_sync_ops.h"

#define TRANSACTION_WAIT(trs, retval) do { \
    while (!trs->transaction_done) { \
        tevent_loop_once(trs->self->ev); \
    } \
    retval = trs->error; \
    if (retval) { \
        PyErr_SetSssError(retval); \
        goto fail; \
    } \
} while(0)

/*
 * function taken from samba sources tree as of Aug 20 2009,
 * file source4/lib/ldb/pyldb.c
 */
static char **PyList_AsStringList(TALLOC_CTX *mem_ctx, PyObject *list,
                                  const char *paramname)
{
    char **ret;
    int i;

    ret = talloc_array(NULL, char *, PyList_Size(list)+1);
    for (i = 0; i < PyList_Size(list); i++) {
        PyObject *item = PyList_GetItem(list, i);
        if (!PyString_Check(item)) {
            PyErr_Format(PyExc_TypeError, "%s should be strings", paramname);
            return NULL;
        }
        ret[i] = talloc_strndup(ret, PyString_AsString(item),
                                PyString_Size(item));
    }

    ret[i] = NULL;
    return ret;
}

/*
 * The sss.local object
 */
typedef struct {
    PyObject_HEAD

    TALLOC_CTX *mem_ctx;
    struct tevent_context *ev;
    struct sysdb_ctx *sysdb;
    struct confdb_ctx *confdb;

    struct sss_domain_info *local;

    int lock;
    int unlock;
} PySssLocalObject;

/*
 * The transaction object
 */
struct py_sss_transaction {
    PySssLocalObject *self;
    struct ops_ctx *ops;

    struct sysdb_handle *handle;
    bool transaction_done;
    int error;
};

/*
 * Error reporting
 */
static void PyErr_SetSssErrorWithMessage(int ret, const char *message)
{
    PyObject *exc = Py_BuildValue(discard_const_p(char, "(is)"),
                                  ret, message);

    PyErr_SetObject(PyExc_IOError, exc);
    Py_XDECREF(exc);
}

static void PyErr_SetSssError(int ret)
{
    PyErr_SetSssErrorWithMessage(ret, strerror(ret));
}

/*
 * Common init of all methods
 */
struct ops_ctx *init_ctx(PySssLocalObject *self)
{
    struct ops_ctx *ops = NULL;

    ops = talloc_zero(self->mem_ctx, struct ops_ctx);
    if (ops == NULL) {
        PyErr_NoMemory();
        return NULL;
    }

    ops->domain = self->local;
    return ops;
}

/*
 * Common transaction finish
 */
static void req_done(struct tevent_req *req)
{
    struct py_sss_transaction *trs = tevent_req_callback_data(req,
                                                   struct py_sss_transaction);

    trs->error = sysdb_transaction_commit_recv(req);
    trs->transaction_done = true;
}

/*
 * Add a user
 */
static void py_sss_useradd_transaction(struct tevent_req *req);

PyDoc_STRVAR(py_sss_useradd__doc__,
    "Add a user named ``username``.\n\n"
    ":param username: name of the user\n\n"
    ":param kwargs: Keyword arguments ro customize the operation\n\n"
    "* useradd can be customized further with keyword arguments:\n"
    "    * ``uid``: The UID of the user\n"
    "    * ``gid``: The GID of the user\n"
    "    * ``gecos``: The comment string\n"
    "    * ``homedir``: Home directory\n"
    "    * ``shell``: Login shell\n"
    "    * ``groups``: List of groups the user is member of\n");


static PyObject *py_sss_useradd(PySssLocalObject *self,
                                PyObject *args,
                                PyObject *kwds)
{
    struct ops_ctx *ops = NULL;
    struct py_sss_transaction *trs = NULL;
    struct tevent_req *req;
    unsigned long uid = 0;
    unsigned long gid = 0;
    const char *gecos = NULL;
    const char *home = NULL;
    const char *shell = NULL;
    char *username = NULL;
    int ret;
    const char * const kwlist[] = { "username", "uid", "gid", "gecos",
                                    "homedir", "shell", "groups", NULL };
    PyObject *py_groups = Py_None;

    /* parse arguments */
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "s|kksssO!",
                                     discard_const_p(char *, kwlist),
                                     &username,
                                     &uid,
                                     &gid,
                                     &gecos,
                                     &home,
                                     &shell,
                                     &PyList_Type,
                                     &py_groups)) {
        goto fail;
    }

    ops = init_ctx(self);
    if (!ops) {
        return NULL;
    }

    if (py_groups != Py_None) {
        ops->addgroups = PyList_AsStringList(self->mem_ctx, py_groups, "groups");
        if (!ops->addgroups) {
            return NULL;
        }
    }

    ops->name = username;
    ops->uid = uid;

    /* fill in defaults */
    ret = useradd_defaults(self->mem_ctx,
                           self->confdb,
                           ops, gecos,
                           home, shell);
    if (ret != EOK) {
        PyErr_SetSssError(ret);
        goto fail;
    }

    /* add the user within a sysdb transaction */
    trs = talloc_zero(self->mem_ctx, struct py_sss_transaction);
    if (!trs) {
        PyErr_NoMemory();
        return NULL;
    }
    trs->self = self;
    trs->ops = ops;

    req = sysdb_transaction_send(self->mem_ctx, self->ev, self->sysdb);
    if (!req) {
        DEBUG(1, ("Could not start transaction"));
        PyErr_NoMemory();
        goto fail;
    }
    tevent_req_set_callback(req, py_sss_useradd_transaction, trs);

    TRANSACTION_WAIT(trs, ret);

    talloc_zfree(ops);
    talloc_zfree(trs);
    Py_RETURN_NONE;

fail:
    talloc_zfree(ops);
    talloc_zfree(trs);
    return NULL;
}

static void py_sss_useradd_transaction(struct tevent_req *req)
{
    int ret;
    struct py_sss_transaction *trs = tevent_req_callback_data(req,
                                                    struct py_sss_transaction);
    struct tevent_req *subreq;

    ret = sysdb_transaction_recv(req, trs, &trs->handle);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }
    talloc_zfree(req);

    /* useradd */
    ret = useradd(trs->self->mem_ctx, trs->self->ev,
                  trs->self->sysdb, trs->handle, trs->ops);
    if (ret != EOK) {
        goto fail;
    }

    subreq = sysdb_transaction_commit_send(trs->self->mem_ctx, trs->self->ev, trs->handle);
    if (!subreq) {
        ret = ENOMEM;
        goto fail;
    }
    tevent_req_set_callback(subreq, req_done, trs);
    return;

fail:
    /* free transaction and signal error */
    talloc_zfree(trs->handle);
    trs->transaction_done = true;
    trs->error = ret;
}

/*
 * Delete a user
 */
static void py_sss_userdel_transaction(struct tevent_req *);

PyDoc_STRVAR(py_sss_userdel__doc__,
    "Remove the user named ``username``.\n\n"
    ":param username: Name of user being removed\n");

static PyObject *py_sss_userdel(PySssLocalObject *self,
                                PyObject *args,
                                PyObject *kwds)
{
    struct ops_ctx *ops = NULL;
    struct tevent_req *req;
    struct py_sss_transaction *trs = NULL;
    char *username = NULL;
    int ret;

    if(!PyArg_ParseTuple(args, "s", &username)) {
        goto fail;
    }

    ops = init_ctx(self);
    if (!ops) {
        return NULL;
    }

    ops->name = username;

    /* delete the user within a sysdb transaction */
    trs = talloc_zero(self->mem_ctx, struct py_sss_transaction);
    if (!trs) {
        PyErr_NoMemory();
        return NULL;
    }
    trs->self = self;
    trs->ops = ops;

    req = sysdb_transaction_send(self->mem_ctx, self->ev, self->sysdb);
    if (!req) {
        DEBUG(1, ("Could not start transaction"));
        PyErr_NoMemory();
        goto fail;
    }
    tevent_req_set_callback(req, py_sss_userdel_transaction, trs);

    TRANSACTION_WAIT(trs, ret);

    talloc_zfree(ops);
    talloc_zfree(trs);
    Py_RETURN_NONE;

fail:
    talloc_zfree(ops);
    talloc_zfree(trs);
    return NULL;
}

static void py_sss_userdel_transaction(struct tevent_req *req)
{
    int ret;
    struct py_sss_transaction *trs = tevent_req_callback_data(req,
                                                    struct py_sss_transaction);
    struct tevent_req *subreq;

    ret = sysdb_transaction_recv(req, trs, &trs->handle);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }
    talloc_zfree(req);

    /* userdel */
    ret = userdel(trs->self->mem_ctx, trs->self->ev,
                  trs->self->sysdb, trs->handle, trs->ops);
    if (ret != EOK) {
        goto fail;
    }

    subreq = sysdb_transaction_commit_send(trs->self->mem_ctx, trs->self->ev, trs->handle);
    if (!subreq) {
        ret = ENOMEM;
        goto fail;
    }
    tevent_req_set_callback(subreq, req_done, trs);
    return;

fail:
    /* free transaction and signal error */
    talloc_zfree(trs->handle);
    trs->transaction_done = true;
    trs->error = ret;
}

/*
 * Modify a user
 */
static void py_sss_usermod_transaction(struct tevent_req *);

PyDoc_STRVAR(py_sss_usermod__doc__,
    "Modify a user.\n\n"
    ":param username: Name of user being modified\n\n"
    ":param kwargs: Keyword arguments ro customize the operation\n\n"
    "* usermod can be customized further with keyword arguments:\n"
    "    * ``uid``: The UID of the user\n"
    "    * ``gid``: The GID of the user\n"
    "    * ``gecos``: The comment string\n"
    "    * ``homedir``: Home directory\n"
    "    * ``shell``: Login shell\n"
    "    * ``addgroups``: List of groups to add the user to\n"
    "    * ``rmgroups``: List of groups to remove the user from\n"
    "    * ``lock``: Lock or unlock the account\n");

static PyObject *py_sss_usermod(PySssLocalObject *self,
                                PyObject *args,
                                PyObject *kwds)
{
    struct ops_ctx *ops = NULL;
    struct tevent_req *req;
    struct py_sss_transaction *trs = NULL;
    int ret;
    PyObject *py_addgroups = Py_None;
    PyObject *py_rmgroups = Py_None;
    unsigned long uid = 0;
    unsigned long gid = 0;
    char *gecos = NULL;
    char *home = NULL;
    char *shell = NULL;
    char *username = NULL;
    unsigned long lock = 0;
    const char * const kwlist[] = { "username", "uid", "gid", "lock",
                                    "gecos",  "homedir", "shell",
                                    "addgroups", "rmgroups", NULL };

    /* parse arguments */
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "s|kkksssO!O!",
                                     discard_const_p(char *, kwlist),
                                     &username,
                                     &uid,
                                     &gid,
                                     &lock,
                                     &gecos,
                                     &home,
                                     &shell,
                                     &PyList_Type,
                                     &py_addgroups,
                                     &PyList_Type,
                                     &py_rmgroups)) {
        goto fail;
    }

    ops = init_ctx(self);
    if (!ops) {
        return NULL;
    }

    if (lock && lock != DO_LOCK && lock != DO_UNLOCK) {
        PyErr_SetString(PyExc_ValueError,
                        "Unkown value for lock parameter");
        goto fail;
    }

    if (py_addgroups != Py_None) {
        ops->addgroups = PyList_AsStringList(self->mem_ctx,
                                             py_addgroups,
                                             "addgroups");
        if (!ops->addgroups) {
            return NULL;
        }
    }

    if (py_rmgroups != Py_None) {
        ops->rmgroups = PyList_AsStringList(self->mem_ctx,
                                            py_rmgroups,
                                            "rmgroups");
        if (!ops->rmgroups) {
            return NULL;
        }
    }

    ops->name  = username;
    ops->uid   = uid;
    ops->gid   = gid;
    ops->gecos = gecos;
    ops->home  = home;
    ops->shell = shell;
    ops->lock  = lock;

    /* modify the user within a sysdb transaction */
    trs = talloc_zero(self->mem_ctx, struct py_sss_transaction);
    if (!trs) {
        PyErr_NoMemory();
        return NULL;
    }
    trs->self = self;
    trs->ops = ops;

    req = sysdb_transaction_send(self->mem_ctx, self->ev, self->sysdb);
    if (!req) {
        DEBUG(1, ("Could not start transaction"));
        PyErr_NoMemory();
        goto fail;
    }
    tevent_req_set_callback(req, py_sss_usermod_transaction, trs);

    TRANSACTION_WAIT(trs, ret);

    talloc_zfree(ops);
    talloc_zfree(trs);
    Py_RETURN_NONE;

fail:
    talloc_zfree(ops);
    talloc_zfree(trs);
    return NULL;
}

static void py_sss_usermod_transaction(struct tevent_req *req)
{
    int ret;
    struct py_sss_transaction *trs = tevent_req_callback_data(req,
                                                    struct py_sss_transaction);
    struct tevent_req *subreq;

    ret = sysdb_transaction_recv(req, trs, &trs->handle);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }
    talloc_zfree(req);
    /* usermod */
    ret = usermod(trs->self->mem_ctx, trs->self->ev,
                  trs->self->sysdb, trs->handle, trs->ops);
    if (ret != EOK) {
        goto fail;
    }

    subreq = sysdb_transaction_commit_send(trs->self->mem_ctx, trs->self->ev, trs->handle);
    if (!subreq) {
        ret = ENOMEM;
        goto fail;
    }
    tevent_req_set_callback(subreq, req_done, trs);
    return;

fail:
    /* free transaction and signal error */
    talloc_zfree(trs->handle);
    trs->transaction_done = true;
    trs->error = ret;
}

/*
 * Add a group
 */
static void py_sss_groupadd_transaction(struct tevent_req *);

PyDoc_STRVAR(py_sss_groupadd__doc__,
    "Add a group.\n\n"
    ":param groupname: Name of group being added\n\n"
    ":param kwargs: Keyword arguments ro customize the operation\n\n"
    "* groupmod can be customized further with keyword arguments:\n"
    "   * ``gid``: The GID of the group\n");

static PyObject *py_sss_groupadd(PySssLocalObject *self,
                                 PyObject *args,
                                 PyObject *kwds)
{
    struct ops_ctx *ops = NULL;
    struct tevent_req *req;
    struct py_sss_transaction *trs = NULL;
    char *groupname;
    unsigned long gid = 0;
    int ret;
    const char * const kwlist[] = { "groupname", "gid", NULL };

    /* parse arguments */
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "s|k",
                                     discard_const_p(char *, kwlist),
                                     &groupname,
                                     &gid)) {
        goto fail;
    }

    ops = init_ctx(self);
    if (!ops) {
        return NULL;
    }

    ops->name  = groupname;
    ops->gid = gid;

    /* add the group within a sysdb transaction */
    trs = talloc_zero(self->mem_ctx, struct py_sss_transaction);
    if (!trs) {
        PyErr_NoMemory();
        return NULL;
    }
    trs->self = self;
    trs->ops = ops;

    req = sysdb_transaction_send(self->mem_ctx, self->ev, self->sysdb);
    if (!req) {
        DEBUG(1, ("Could not start transaction"));
        PyErr_NoMemory();
        goto fail;
    }
    tevent_req_set_callback(req, py_sss_groupadd_transaction, trs);

    TRANSACTION_WAIT(trs, ret);

    talloc_zfree(ops);
    talloc_zfree(trs);
    Py_RETURN_NONE;

fail:
    talloc_zfree(ops);
    talloc_zfree(trs);
    return NULL;
}

static void py_sss_groupadd_transaction(struct tevent_req *req)
{
    int ret;
    struct py_sss_transaction *trs = tevent_req_callback_data(req,
                                                    struct py_sss_transaction);
    struct tevent_req *subreq;

    ret = sysdb_transaction_recv(req, trs, &trs->handle);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }
    talloc_zfree(req);

    /* groupadd */
    ret = groupadd(trs->self->mem_ctx, trs->self->ev,
                          trs->self->sysdb, trs->handle, trs->ops);
    if (ret != EOK) {
        goto fail;
    }

    subreq = sysdb_transaction_commit_send(trs->self->mem_ctx, trs->self->ev, trs->handle);
    if (!subreq) {
        ret = ENOMEM;
        goto fail;
    }
    tevent_req_set_callback(subreq, req_done, trs);
    return;

fail:
    /* free transaction and signal error */
    talloc_zfree(trs->handle);
    trs->transaction_done = true;
    trs->error = ret;
}

/*
 * Delete a group
 */
static void py_sss_groupdel_transaction(struct tevent_req *req);

PyDoc_STRVAR(py_sss_groupdel__doc__,
    "Remove a group.\n\n"
    ":param groupname: Name of group being removed\n");

static PyObject *py_sss_groupdel(PySssLocalObject *self,
                                PyObject *args,
                                PyObject *kwds)
{
    struct ops_ctx *ops = NULL;
    struct tevent_req *req;
    struct py_sss_transaction *trs = NULL;
    char *groupname = NULL;
    int ret;

    if(!PyArg_ParseTuple(args, "s", &groupname)) {
        goto fail;
    }

    ops = init_ctx(self);
    if (!ops) {
        return NULL;
    }

    ops->name  = groupname;

    /* delete the group within a sysdb transaction */
    trs = talloc_zero(self->mem_ctx, struct py_sss_transaction);
    if (!trs) {
        PyErr_NoMemory();
        return NULL;
    }
    trs->self = self;
    trs->ops = ops;

    req = sysdb_transaction_send(self->mem_ctx, self->ev, self->sysdb);
    if (!req) {
        DEBUG(1, ("Could not start transaction"));
        PyErr_NoMemory();
        goto fail;
    }
    tevent_req_set_callback(req, py_sss_groupdel_transaction, trs);

    TRANSACTION_WAIT(trs, ret);

    talloc_zfree(ops);
    talloc_zfree(trs);
    Py_RETURN_NONE;

fail:
    talloc_zfree(ops);
    talloc_zfree(trs);
    return NULL;
}

static void py_sss_groupdel_transaction(struct tevent_req *req)
{
    int ret;
    struct py_sss_transaction *trs = tevent_req_callback_data(req,
                                                    struct py_sss_transaction);
    struct tevent_req *subreq;

    ret = sysdb_transaction_recv(req, trs, &trs->handle);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }
    talloc_zfree(req);

    /* groupdel */
    ret = groupdel(trs->self->mem_ctx, trs->self->ev,
                          trs->self->sysdb, trs->handle, trs->ops);
    if (ret != EOK) {
        goto fail;
    }

    subreq = sysdb_transaction_commit_send(trs->self->mem_ctx, trs->self->ev, trs->handle);
    if (!subreq) {
        ret = ENOMEM;
        goto fail;
    }
    tevent_req_set_callback(subreq, req_done, trs);
    return;

fail:
    /* free transaction and signal error */
    talloc_zfree(trs->handle);
    trs->transaction_done = true;
    trs->error = ret;
}

/*
 * Modify a group
 */
static void py_sss_groupmod_transaction(struct tevent_req *);

PyDoc_STRVAR(py_sss_groupmod__doc__,
"Modify a group.\n\n"
":param groupname: Name of group being modified\n\n"
":param kwargs: Keyword arguments ro customize the operation\n\n"
"* groupmod can be customized further with keyword arguments:\n"
"   * ``gid``: The GID of the group\n\n"
"   * ``addgroups``: Groups to add the group to\n\n"
"   * ``rmgroups``: Groups to remove the group from\n\n");

static PyObject *py_sss_groupmod(PySssLocalObject *self,
                                PyObject *args,
                                PyObject *kwds)
{
    struct ops_ctx *ops = NULL;
    struct tevent_req *req;
    struct py_sss_transaction *trs = NULL;
    int ret;
    PyObject *py_addgroups = Py_None;
    PyObject *py_rmgroups = Py_None;
    unsigned long gid = 0;
    char *groupname = NULL;
    const char * const kwlist[] = { "groupname", "gid", "addgroups",
                                    "rmgroups", NULL };

    /* parse arguments */
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "s|kO!O!",
                                     discard_const_p(char *, kwlist),
                                     &groupname,
                                     &gid,
                                     &PyList_Type,
                                     &py_addgroups,
                                     &PyList_Type,
                                     &py_rmgroups)) {
        goto fail;
    }

    ops = init_ctx(self);
    if (!ops) {
        return NULL;
    }

    if (py_addgroups != Py_None) {
        ops->addgroups = PyList_AsStringList(self->mem_ctx,
                                             py_addgroups,
                                             "addgroups");
        if (!ops->addgroups) {
            return NULL;
        }
    }

    if (py_rmgroups != Py_None) {
        ops->rmgroups = PyList_AsStringList(self->mem_ctx,
                                            py_rmgroups,
                                            "rmgroups");
        if (!ops->rmgroups) {
            return NULL;
        }
    }

    ops->name  = groupname;
    ops->gid = gid;

    /* modify the group within a sysdb transaction */
    trs = talloc_zero(self->mem_ctx, struct py_sss_transaction);
    if (!trs) {
        PyErr_NoMemory();
        return NULL;
    }
    trs->self = self;
    trs->ops = ops;

    req = sysdb_transaction_send(self->mem_ctx, self->ev, self->sysdb);
    if (!req) {
        DEBUG(1, ("Could not start transaction"));
        PyErr_NoMemory();
        goto fail;
    }
    tevent_req_set_callback(req, py_sss_groupmod_transaction, trs);

    TRANSACTION_WAIT(trs, ret);


    talloc_zfree(ops);
    talloc_zfree(trs);
    Py_RETURN_NONE;

fail:
    talloc_zfree(ops);
    talloc_zfree(trs);
    return NULL;
}

static void py_sss_groupmod_transaction(struct tevent_req *req)
{
    int ret;
    struct py_sss_transaction *trs = tevent_req_callback_data(req,
                                                    struct py_sss_transaction);
    struct tevent_req *subreq;

    ret = sysdb_transaction_recv(req, trs, &trs->handle);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }
    talloc_zfree(req);

    /* groupmod */
    ret = groupmod(trs->self->mem_ctx, trs->self->ev,
                          trs->self->sysdb, trs->handle, trs->ops);
    if (ret != EOK) {
        goto fail;
    }

    subreq = sysdb_transaction_commit_send(trs->self->mem_ctx, trs->self->ev, trs->handle);
    if (!subreq) {
        ret = ENOMEM;
        goto fail;
    }
    tevent_req_set_callback(subreq, req_done, trs);
    return;

fail:
    /* free transaction and signal error */
    talloc_zfree(trs->handle);
    trs->transaction_done = true;
    trs->error = ret;
}

/*** python plumbing begins here ***/

/*
 * The sss.local destructor
 */
static void PySssLocalObject_dealloc(PySssLocalObject *self)
{
    talloc_free(self->mem_ctx);
    self->ob_type->tp_free((PyObject*) self);
}

/*
 * The sss.local constructor
 */
static PyObject *PySssLocalObject_new(PyTypeObject *type,
                                      PyObject *args,
                                      PyObject *kwds)
{
    TALLOC_CTX *mem_ctx;
    PySssLocalObject *self;
    char *confdb_path;
    int ret;

    mem_ctx = talloc_new(NULL);
    if (mem_ctx == NULL) {
        PyErr_NoMemory();
        return NULL;
    }

    self = (PySssLocalObject *) type->tp_alloc(type, 0);
    if (self == NULL) {
        talloc_free(mem_ctx);
        PyErr_NoMemory();
        return NULL;
    }
    self->mem_ctx = mem_ctx;

    self->ev = tevent_context_init(mem_ctx);
    if (self->ev == NULL) {
        talloc_free(mem_ctx);
        PyErr_SetSssErrorWithMessage(EIO, "Cannot create event context");
        return NULL;
    }

    confdb_path = talloc_asprintf(self->mem_ctx, "%s/%s", DB_PATH, CONFDB_FILE);
    if (confdb_path == NULL) {
        talloc_free(mem_ctx);
        PyErr_NoMemory();
        return NULL;
    }

    /* Connect to the conf db */
    ret = confdb_init(self->mem_ctx, &self->confdb, confdb_path);
    if (ret != EOK) {
        talloc_free(mem_ctx);
        PyErr_SetSssErrorWithMessage(ret,
                "Could not initialize connection to the confdb\n");
        return NULL;
    }

    ret = confdb_get_domain(self->confdb, "local", &self->local);
    if (ret != EOK) {
        talloc_free(mem_ctx);
        PyErr_SetSssErrorWithMessage(ret, "Cannot get local domain");
        return NULL;
    }

    /* open 'local' sysdb at default path */
    ret = sysdb_domain_init(self->mem_ctx, self->ev, self->local, DB_PATH, &self->sysdb);
    if (ret != EOK) {
        talloc_free(mem_ctx);
        PyErr_SetSssErrorWithMessage(ret,
                "Could not initialize connection to the sysdb\n");
        return NULL;
    }

    self->lock = DO_LOCK;
    self->unlock = DO_UNLOCK;

    return (PyObject *) self;
}

/*
 * sss.local object methods
 */
static PyMethodDef sss_local_methods[] = {
    { "useradd", (PyCFunction) py_sss_useradd,
      METH_KEYWORDS, py_sss_useradd__doc__
    },
    { "userdel", (PyCFunction) py_sss_userdel,
      METH_VARARGS, py_sss_userdel__doc__
    },
    { "usermod", (PyCFunction) py_sss_usermod,
      METH_KEYWORDS, py_sss_usermod__doc__
    },
    { "groupadd", (PyCFunction) py_sss_groupadd,
      METH_KEYWORDS, py_sss_groupadd__doc__
    },
    { "groupdel", (PyCFunction) py_sss_groupdel,
      METH_KEYWORDS, py_sss_groupdel__doc__
    },
    { "groupmod", (PyCFunction) py_sss_groupmod,
      METH_KEYWORDS, py_sss_groupmod__doc__
    },
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

static PyMemberDef sss_members[] = {
    { discard_const_p(char, "lock"), T_INT,
      offsetof(PySssLocalObject, lock), RO },
    { discard_const_p(char, "unlock"), T_INT,
      offsetof(PySssLocalObject, unlock), RO },
    {NULL} /* Sentinel */
};

/*
 * sss.local object properties
 */
static PyTypeObject pysss_local_type = {
    PyObject_HEAD_INIT(NULL)
    .tp_name = "sss.local",
    .tp_basicsize = sizeof(PySssLocalObject),
    .tp_new = PySssLocalObject_new,
    .tp_dealloc = (destructor) PySssLocalObject_dealloc,
    .tp_methods = sss_local_methods,
    .tp_members = sss_members,
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
    .tp_doc   = "SSS DB manipulation",
};

/*
 * Module methods
 */
static PyMethodDef module_methods[] = {
        {NULL}  /* Sentinel */
};

/*
 * Module initialization
 */
PyMODINIT_FUNC
initpysss(void)
{
    PyObject *m;

    if (PyType_Ready(&pysss_local_type) < 0)
        return;

    m = Py_InitModule("pysss", module_methods);
    if (m == NULL)
        return;

    Py_INCREF(&pysss_local_type);
    PyModule_AddObject(m, "local", (PyObject *)&pysss_local_type);
}

