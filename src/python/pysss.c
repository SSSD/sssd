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
struct tools_ctx *init_ctx(TALLOC_CTX *mem_ctx,
                           PySssLocalObject *self)
{
    struct ops_ctx *octx = NULL;
    struct tools_ctx *tctx = NULL;

    tctx = talloc_zero(self->mem_ctx, struct tools_ctx);
    if (tctx == NULL) {
        return NULL;
    }

    tctx->ev = self->ev;
    tctx->confdb = self->confdb;
    tctx->sysdb = self->sysdb;
    tctx->local = self->local;
    /* tctx->nctx is NULL here, which is OK since we don't parse domains
     * in the python bindings (yet?) */

    octx = talloc_zero(tctx, struct ops_ctx);
    if (octx == NULL) {
        PyErr_NoMemory();
        return NULL;
    }
    octx->domain = self->local;

    tctx->octx = octx;
    return tctx;
}

/*
 * Add a user
 */
PyDoc_STRVAR(py_sss_useradd__doc__,
    "Add a user named ``username``.\n\n"
    ":param username: name of the user\n\n"
    ":param kwargs: Keyword arguments that customize the operation\n\n"
    "* useradd can be customized further with keyword arguments:\n"
    "    * ``uid``: The UID of the user\n"
    "    * ``gid``: The GID of the user\n"
    "    * ``gecos``: The comment string\n"
    "    * ``homedir``: Home directory\n"
    "    * ``shell``: Login shell\n"
    "    * ``skel``: Specify an alternative skeleton directory\n"
    "    * ``create_home``: (bool) Force creation of home directory on or off\n"
    "    * ``groups``: List of groups the user is member of\n");


static PyObject *py_sss_useradd(PySssLocalObject *self,
                                PyObject *args,
                                PyObject *kwds)
{
    struct tools_ctx *tctx = NULL;
    unsigned long uid = 0;
    unsigned long gid = 0;
    const char *gecos = NULL;
    const char *home = NULL;
    const char *shell = NULL;
    const char *skel = NULL;
    char *username = NULL;
    int ret;
    const char * const kwlist[] = { "username", "uid", "gid", "gecos",
                                    "homedir", "shell", "skel",
                                    "create_home", "groups", NULL };
    PyObject *py_groups = Py_None;
    PyObject *py_create_home = Py_None;
    int create_home = 0;

    /* parse arguments */
    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                                     discard_const_p(char, "s|kkssssO!O!"),
                                     discard_const_p(char *, kwlist),
                                     &username,
                                     &uid,
                                     &gid,
                                     &gecos,
                                     &home,
                                     &shell,
                                     &skel,
                                     &PyBool_Type,
                                     &py_create_home,
                                     &PyList_Type,
                                     &py_groups)) {
        goto fail;
    }

    tctx = init_ctx(self->mem_ctx, self);
    if (!tctx) {
        PyErr_NoMemory();
        return NULL;
    }

    if (py_groups != Py_None) {
        tctx->octx->addgroups = PyList_AsStringList(tctx, py_groups, "groups");
        if (!tctx->octx->addgroups) {
            PyErr_NoMemory();
            return NULL;
        }
    }

    /* user-wise the parameter is only bool - do or don't,
     * however we must have a third state - undecided, pick default */
    if (py_create_home == Py_True) {
        create_home = DO_CREATE_HOME;
    } else if (py_create_home == Py_False) {
        create_home = DO_NOT_CREATE_HOME;
    }

    tctx->octx->name = username;
    tctx->octx->uid = uid;

    /* fill in defaults */
    ret = useradd_defaults(tctx,
                           self->confdb,
                           tctx->octx, gecos,
                           home, shell,
                           create_home,
                           skel);
    if (ret != EOK) {
        PyErr_SetSssError(ret);
        goto fail;
    }

    /* Add the user within a transaction */
    start_transaction(tctx);
    if (tctx->error != EOK) {
        PyErr_SetSssError(tctx->error);
        goto fail;
    }

    /* useradd */
    ret = useradd(tctx, self->ev,
                  self->sysdb, tctx->handle, tctx->octx);
    if (ret != EOK) {
        tctx->error = ret;

        /* cancel transaction */
        talloc_zfree(tctx->handle);
        PyErr_SetSssError(tctx->error);
        goto fail;
    }

    end_transaction(tctx);
    if (tctx->error) {
        PyErr_SetSssError(tctx->error);
        goto fail;
    }

    /* Create user's home directory and/or mail spool */
    if (tctx->octx->create_homedir) {
        /* We need to know the UID and GID of the user, if
         * sysdb did assign it automatically, do a lookup */
        if (tctx->octx->uid == 0 || tctx->octx->gid == 0) {
            ret = sysdb_getpwnam_sync(tctx,
                                      tctx->ev,
                                      tctx->sysdb,
                                      tctx->octx->name,
                                      tctx->local,
                                      &tctx->octx);
            if (ret != EOK) {
                PyErr_SetSssError(ret);
                goto fail;
            }
        }

        ret = create_homedir(tctx,
                             tctx->octx->skeldir,
                             tctx->octx->home,
                             tctx->octx->name,
                             tctx->octx->uid,
                             tctx->octx->gid,
                             tctx->octx->umask);
        if (ret != EOK) {
            PyErr_SetSssError(ret);
            goto fail;
        }

        /* failure here should not be fatal */
        create_mail_spool(tctx,
                          tctx->octx->name,
                          tctx->octx->maildir,
                          tctx->octx->uid,
                          tctx->octx->gid);
    }

    talloc_zfree(tctx);
    Py_RETURN_NONE;

fail:
    talloc_zfree(tctx);
    return NULL;
}

/*
 * Delete a user
 */
PyDoc_STRVAR(py_sss_userdel__doc__,
    "Remove the user named ``username``.\n\n"
    ":param username: Name of user being removed\n"
    ":param kwargs: Keyword arguments that customize the operation\n\n"
    "* userdel can be customized further with keyword arguments:\n"
    "    * ``force``: (bool) Force removal of files not owned by the user\n"
    "    * ``remove``: (bool) Toggle removing home directory and mail spool\n");

static PyObject *py_sss_userdel(PySssLocalObject *self,
                                PyObject *args,
                                PyObject *kwds)
{
    struct tools_ctx *tctx = NULL;
    char *username = NULL;
    int ret;
    PyObject *py_remove = Py_None;
    int remove_home = 0;
    PyObject *py_force = Py_None;
    const char * const kwlist[] = { "username", "remove", "force", NULL };

    if(!PyArg_ParseTupleAndKeywords(args, kwds,
                                    discard_const_p(char, "s|O!O!"),
                                    discard_const_p(char *, kwlist),
                                    &username,
                                    &PyBool_Type,
                                    &py_remove,
                                    &PyBool_Type,
                                    &py_force)) {
        goto fail;
    }

    tctx = init_ctx(self->mem_ctx, self);
    if (!tctx) {
        PyErr_NoMemory();
        return NULL;
    }

    tctx->octx->name = username;

    if (py_remove == Py_True) {
        remove_home = DO_REMOVE_HOME;
    } else if (py_remove == Py_False) {
        remove_home = DO_NOT_REMOVE_HOME;
    }

    /*
     * Fills in defaults for ops_ctx user did not specify.
     */
    ret = userdel_defaults(tctx,
                           tctx->confdb,
                           tctx->octx,
                           remove_home);
    if (ret != EOK) {
        PyErr_SetSssError(ret);
        goto fail;
    }

    ret = run_userdel_cmd(tctx);
    if (ret != EOK) {
        PyErr_SetSssError(ret);
        goto fail;
    }

    if (tctx->octx->remove_homedir) {
        ret = sysdb_getpwnam_sync(tctx,
                                  tctx->ev,
                                  tctx->sysdb,
                                  tctx->octx->name,
                                  tctx->local,
                                  &tctx->octx);
        if (ret != EOK) {
            PyErr_SetSssError(ret);
            goto fail;
        }
    }

    /* Delete the user within a transaction */
    start_transaction(tctx);
    if (tctx->error != EOK) {
        PyErr_SetSssError(tctx->error);
        goto fail;
    }

    ret = userdel(tctx, self->ev,
                  self->sysdb, tctx->handle, tctx->octx);
    if (ret != EOK) {
        tctx->error = ret;

        /* cancel transaction */
        talloc_zfree(tctx->handle);
        PyErr_SetSssError(tctx->error);
        goto fail;
    }

    end_transaction(tctx);
    if (tctx->error) {
        PyErr_SetSssError(tctx->error);
        goto fail;
    }

    if (tctx->octx->remove_homedir) {
        ret = remove_homedir(tctx,
                             tctx->octx->home,
                             tctx->octx->maildir,
                             tctx->octx->name,
                             tctx->octx->uid,
                             (py_force == Py_True));
        if (ret != EOK) {
            PyErr_SetSssError(ret);
            goto fail;
        }
    }

    talloc_zfree(tctx);
    Py_RETURN_NONE;

fail:
    talloc_zfree(tctx);
    return NULL;
}

/*
 * Modify a user
 */
PyDoc_STRVAR(py_sss_usermod__doc__,
    "Modify a user.\n\n"
    ":param username: Name of user being modified\n\n"
    ":param kwargs: Keyword arguments that customize the operation\n\n"
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
    struct tools_ctx *tctx = NULL;
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
    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                                     discard_const_p(char, "s|kkksssO!O!"),
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

    tctx = init_ctx(self->mem_ctx, self);
    if (!tctx) {
        PyErr_NoMemory();
        return NULL;
    }

    if (lock && lock != DO_LOCK && lock != DO_UNLOCK) {
        PyErr_SetString(PyExc_ValueError,
                        "Unkown value for lock parameter");
        goto fail;
    }

    if (py_addgroups != Py_None) {
        tctx->octx->addgroups = PyList_AsStringList(tctx,
                                                    py_addgroups,
                                                    "addgroups");
        if (!tctx->octx->addgroups) {
            return NULL;
        }
    }

    if (py_rmgroups != Py_None) {
        tctx->octx->rmgroups = PyList_AsStringList(tctx,
                                                   py_rmgroups,
                                                   "rmgroups");
        if (!tctx->octx->rmgroups) {
            return NULL;
        }
    }

    tctx->octx->name  = username;
    tctx->octx->uid   = uid;
    tctx->octx->gid   = gid;
    tctx->octx->gecos = gecos;
    tctx->octx->home  = home;
    tctx->octx->shell = shell;
    tctx->octx->lock  = lock;

    /* Modify the user within a transaction */
    start_transaction(tctx);
    if (tctx->error != EOK) {
        PyErr_SetSssError(tctx->error);
        goto fail;
    }

    /* usermod */
    ret = usermod(tctx, self->ev,
                  self->sysdb, tctx->handle, tctx->octx);
    if (ret != EOK) {
        tctx->error = ret;

        /* cancel transaction */
        talloc_zfree(tctx->handle);
        PyErr_SetSssError(tctx->error);
        goto fail;
    }

    end_transaction(tctx);
    if (tctx->error) {
        PyErr_SetSssError(tctx->error);
        goto fail;
    }

    talloc_zfree(tctx);
    Py_RETURN_NONE;

fail:
    talloc_zfree(tctx);
    return NULL;
}

/*
 * Add a group
 */
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
    struct tools_ctx *tctx = NULL;
    char *groupname;
    unsigned long gid = 0;
    int ret;
    const char * const kwlist[] = { "groupname", "gid", NULL };

    /* parse arguments */
    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                                     discard_const_p(char, "s|k"),
                                     discard_const_p(char *, kwlist),
                                     &groupname,
                                     &gid)) {
        goto fail;
    }

    tctx = init_ctx(self->mem_ctx, self);
    if (!tctx) {
        PyErr_NoMemory();
        return NULL;
    }

    tctx->octx->name = groupname;
    tctx->octx->gid = gid;

    /* Add the group within a transaction */
    start_transaction(tctx);
    if (tctx->error != EOK) {
        PyErr_SetSssError(tctx->error);
        goto fail;
    }

    /* groupadd */
    ret = groupadd(tctx, self->ev,
                   self->sysdb, tctx->handle, tctx->octx);
    if (ret != EOK) {
        tctx->error = ret;

        /* cancel transaction */
        talloc_zfree(tctx->handle);
        PyErr_SetSssError(tctx->error);
        goto fail;
    }

    end_transaction(tctx);
    if (tctx->error) {
        PyErr_SetSssError(tctx->error);
        goto fail;
    }

    talloc_zfree(tctx);
    Py_RETURN_NONE;

fail:
    talloc_zfree(tctx);
    return NULL;
}

/*
 * Delete a group
 */
PyDoc_STRVAR(py_sss_groupdel__doc__,
    "Remove a group.\n\n"
    ":param groupname: Name of group being removed\n");

static PyObject *py_sss_groupdel(PySssLocalObject *self,
                                PyObject *args,
                                PyObject *kwds)
{
    struct tools_ctx *tctx = NULL;
    char *groupname = NULL;
    int ret;

    if(!PyArg_ParseTuple(args, discard_const_p(char, "s"), &groupname)) {
        goto fail;
    }

    tctx = init_ctx(self->mem_ctx, self);
    if (!tctx) {
        PyErr_NoMemory();
        return NULL;
    }

    tctx->octx->name = groupname;

    /* Remove the group within a transaction */
    start_transaction(tctx);
    if (tctx->error != EOK) {
        PyErr_SetSssError(tctx->error);
        goto fail;
    }

    /* groupdel */
    ret = groupdel(tctx, self->ev,
                   self->sysdb, tctx->handle, tctx->octx);
    if (ret != EOK) {
        tctx->error = ret;

        /* cancel transaction */
        talloc_zfree(tctx->handle);
        PyErr_SetSssError(tctx->error);
        goto fail;
    }

    end_transaction(tctx);
    if (tctx->error) {
        PyErr_SetSssError(tctx->error);
        goto fail;
    }

    talloc_zfree(tctx);
    Py_RETURN_NONE;

fail:
    talloc_zfree(tctx);
    return NULL;
}

/*
 * Modify a group
 */
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
    struct tools_ctx *tctx = NULL;
    int ret;
    PyObject *py_addgroups = Py_None;
    PyObject *py_rmgroups = Py_None;
    unsigned long gid = 0;
    char *groupname = NULL;
    const char * const kwlist[] = { "groupname", "gid", "addgroups",
                                    "rmgroups", NULL };

    /* parse arguments */
    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                                     discard_const_p(char, "s|kO!O!"),
                                     discard_const_p(char *, kwlist),
                                     &groupname,
                                     &gid,
                                     &PyList_Type,
                                     &py_addgroups,
                                     &PyList_Type,
                                     &py_rmgroups)) {
        goto fail;
    }

    tctx = init_ctx(self->mem_ctx, self);
    if (!tctx) {
        PyErr_NoMemory();
        return NULL;
    }

    if (py_addgroups != Py_None) {
        tctx->octx->addgroups = PyList_AsStringList(tctx,
                                             py_addgroups,
                                             "addgroups");
        if (!tctx->octx->addgroups) {
            return NULL;
        }
    }

    if (py_rmgroups != Py_None) {
        tctx->octx->rmgroups = PyList_AsStringList(tctx,
                                            py_rmgroups,
                                            "rmgroups");
        if (!tctx->octx->rmgroups) {
            return NULL;
        }
    }

    tctx->octx->name = groupname;
    tctx->octx->gid = gid;

    /* Modify the group within a transaction */
    start_transaction(tctx);
    if (tctx->error != EOK) {
        PyErr_SetSssError(tctx->error);
        goto fail;
    }

    /* groupmod */
    ret = groupmod(tctx, self->ev,
                   self->sysdb, tctx->handle, tctx->octx);
    if (ret != EOK) {
        tctx->error = ret;

        /* cancel transaction */
        talloc_zfree(tctx->handle);
        PyErr_SetSssError(tctx->error);
        goto fail;
    }

    end_transaction(tctx);
    if (tctx->error) {
        PyErr_SetSssError(tctx->error);
        goto fail;
    }

    talloc_zfree(tctx);
    Py_RETURN_NONE;

fail:
    talloc_zfree(tctx);
    return NULL;
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
      METH_KEYWORDS, py_sss_userdel__doc__
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
      offsetof(PySssLocalObject, lock), RO, NULL},
    { discard_const_p(char, "unlock"), T_INT,
      offsetof(PySssLocalObject, unlock), RO, NULL},
    {NULL, 0, 0, 0, NULL} /* Sentinel */
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
        {NULL, NULL, 0, NULL}  /* Sentinel */
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

    m = Py_InitModule(discard_const_p(char, "pysss"), module_methods);
    if (m == NULL)
        return;

    Py_INCREF(&pysss_local_type);
    PyModule_AddObject(m, discard_const_p(char, "local"), (PyObject *)&pysss_local_type);
}

