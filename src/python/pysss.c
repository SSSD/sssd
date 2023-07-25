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

#include "config.h"

#include <Python.h>
#include <structmember.h>
#include <talloc.h>
#include <pwd.h>
#include <grp.h>

#include "util/util.h"
#include "util/sss_python.h"
#include "db/sysdb.h"
#include "tools/tools_util.h"
#include "tools/sss_sync_ops.h"
#include "util/crypto/sss_crypto.h"

/*
 * function taken from samba sources tree as of Aug 20 2009,
 * file source4/lib/ldb/pyldb.c
 */
static char **PyList_AsStringList(TALLOC_CTX *mem_ctx, PyObject *list,
                                  const char *paramname)
{
    char **ret;
    int i;

    ret = talloc_array(mem_ctx, char *, PyList_Size(list)+1);
    for (i = 0; i < PyList_Size(list); i++) {
        const char *itemstr;
        Py_ssize_t itemlen;
        PyObject *item = PyList_GetItem(list, i);
#ifdef IS_PY3K
        if (!PyUnicode_Check(item)) {
#else
        if (!PyString_Check(item)) {
#endif
            PyErr_Format(PyExc_TypeError, "%s should be strings", paramname);
            return NULL;
        }
#ifdef IS_PY3K
        itemstr = PyUnicode_AsUTF8AndSize(item, &itemlen);
#else
        itemstr = PyString_AsString(item);
        itemlen = strlen(itemstr);
#endif
        ret[i] = talloc_strndup(ret, itemstr, itemlen);
    }

    ret[i] = NULL;
    return ret;
}

/* ======================= sysdb python wrappers ==========================*/

/*
 * The sss.password object
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
static struct tools_ctx *init_ctx(PySssLocalObject *self)
{
    struct ops_ctx *octx = NULL;
    struct tools_ctx *tctx = NULL;

    tctx = talloc_zero(self->mem_ctx, struct tools_ctx);
    if (tctx == NULL) {
        return NULL;
    }

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
    bool in_transaction = false;

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

    tctx = init_ctx(self);
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
    tctx->error = sysdb_transaction_start(tctx->sysdb);
    if (tctx->error != EOK) {
        PyErr_SetSssError(tctx->error);
        goto fail;
    }
    in_transaction = true;

    /* useradd */
    tctx->error = useradd(tctx, tctx->octx);
    if (tctx->error) {
        PyErr_SetSssError(tctx->error);
        goto fail;
    }

    tctx->error = sysdb_transaction_commit(tctx->sysdb);
    if (tctx->error) {
        PyErr_SetSssError(tctx->error);
        goto fail;
    }
    in_transaction = false;

    /* Create user's home directory and/or mail spool */
    if (tctx->octx->create_homedir) {
        /* We need to know the UID and GID of the user, if
         * sysdb did assign it automatically, do a lookup */
        if (tctx->octx->uid == 0 || tctx->octx->gid == 0) {
            ret = sysdb_getpwnam_sync(tctx,
                                      tctx->octx->name,
                                      tctx->octx);
            if (ret != EOK) {
                PyErr_SetSssError(ret);
                goto fail;
            }
        }

        ret = create_homedir(tctx->octx->skeldir,
                             tctx->octx->home,
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
    if (in_transaction) {
        /* We do not handle return value of sysdb_transaction_cancel()
         * because we don't want to overwrite previous error code.
         */
        sysdb_transaction_cancel(tctx->sysdb);
    }
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

    tctx = init_ctx(self);
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
                                  tctx->octx->name,
                                  tctx->octx);
        if (ret != EOK) {
            PyErr_SetSssError(ret);
            goto fail;
        }
    }

    /* Delete the user */
    ret = userdel(tctx, self->sysdb, tctx->octx);
    if (ret != EOK) {
        PyErr_SetSssError(ret);
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
    bool in_transaction = false;

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

    tctx = init_ctx(self);
    if (!tctx) {
        PyErr_NoMemory();
        return NULL;
    }

    if (lock && lock != DO_LOCK && lock != DO_UNLOCK) {
        PyErr_SetString(PyExc_ValueError,
                        "Unknown value for lock parameter");
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
    tctx->error = sysdb_transaction_start(tctx->sysdb);
    if (tctx->error != EOK) {
        PyErr_SetSssError(tctx->error);
        goto fail;
    }
    in_transaction = true;

    /* usermod */
    tctx->error = usermod(tctx, tctx->octx);
    if (tctx->error) {
        PyErr_SetSssError(tctx->error);
        goto fail;
    }

    tctx->error = sysdb_transaction_commit(tctx->sysdb);
    if (tctx->error) {
        PyErr_SetSssError(tctx->error);
        goto fail;
    }
    in_transaction = false;

    talloc_zfree(tctx);
    Py_RETURN_NONE;

fail:
    if (in_transaction) {
        /* We do not handle return value of sysdb_transaction_cancel()
         * because we don't want to overwrite previous error code.
         */
        sysdb_transaction_cancel(tctx->sysdb);
    }
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
    const char * const kwlist[] = { "groupname", "gid", NULL };
    bool in_transaction = false;

    /* parse arguments */
    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                                     discard_const_p(char, "s|k"),
                                     discard_const_p(char *, kwlist),
                                     &groupname,
                                     &gid)) {
        goto fail;
    }

    tctx = init_ctx(self);
    if (!tctx) {
        PyErr_NoMemory();
        return NULL;
    }

    tctx->octx->name = groupname;
    tctx->octx->gid = gid;

    /* Add the group within a transaction */
    tctx->error = sysdb_transaction_start(tctx->sysdb);
    if (tctx->error != EOK) {
        PyErr_SetSssError(tctx->error);
        goto fail;
    }
    in_transaction = true;

    /* groupadd */
    tctx->error = groupadd(tctx->octx);
    if (tctx->error) {
        PyErr_SetSssError(tctx->error);
        goto fail;
    }

    tctx->error = sysdb_transaction_commit(tctx->sysdb);
    if (tctx->error) {
        PyErr_SetSssError(tctx->error);
        goto fail;
    }
    in_transaction = false;

    talloc_zfree(tctx);
    Py_RETURN_NONE;

fail:
    if (in_transaction) {
        /* We do not handle return value of sysdb_transaction_cancel()
         * because we don't want to overwrite previous error code.
         */
        sysdb_transaction_cancel(tctx->sysdb);
    }
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

    tctx = init_ctx(self);
    if (!tctx) {
        PyErr_NoMemory();
        return NULL;
    }

    tctx->octx->name = groupname;

    /* Remove the group */
    ret = groupdel(tctx, self->sysdb, tctx->octx);
    if (ret != EOK) {
        PyErr_SetSssError(ret);
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
    PyObject *py_addgroups = Py_None;
    PyObject *py_rmgroups = Py_None;
    unsigned long gid = 0;
    char *groupname = NULL;
    const char * const kwlist[] = { "groupname", "gid", "addgroups",
                                    "rmgroups", NULL };
    bool in_transaction = false;

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

    tctx = init_ctx(self);
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
    tctx->error = sysdb_transaction_start(tctx->sysdb);
    if (tctx->error != EOK) {
        PyErr_SetSssError(tctx->error);
        goto fail;
    }
    in_transaction = true;

    /* groupmod */
    tctx->error = groupmod(tctx, tctx->octx);
    if (tctx->error) {
        PyErr_SetSssError(tctx->error);
        goto fail;
    }

    tctx->error = sysdb_transaction_commit(tctx->sysdb);
    if (tctx->error) {
        PyErr_SetSssError(tctx->error);
        goto fail;
    }
    in_transaction = false;

    talloc_zfree(tctx);
    Py_RETURN_NONE;

fail:
    if (in_transaction) {
        /* We do not handle return value of sysdb_transaction_cancel()
         * because we don't want to overwrite previous error code.
         */
        sysdb_transaction_cancel(tctx->sysdb);
    }
    talloc_zfree(tctx);
    return NULL;
}

/*
 * Get list of groups user belongs to
 */
PyDoc_STRVAR(py_sss_getgrouplist__doc__,
    "Get list of groups user belongs to.\n\n"
    "NOTE: The interface uses the system NSS calls and is not limited to "
    "users served by the SSSD!\n"
    ":param username: name of user to get list for\n");

static PyObject *py_sss_getgrouplist(PyObject *self, PyObject *args)
{
    char *username = NULL;
    gid_t *groups = NULL;
    struct passwd *pw;
    struct group *gr;
    int ngroups;
    int ret;
    Py_ssize_t i, idx;
    PyObject *groups_tuple;

    if(!PyArg_ParseTuple(args, discard_const_p(char, "s"), &username)) {
        goto fail;
    }

    pw = getpwnam(username);
    if (pw == NULL) {
        goto fail;
    }

    ngroups = 32;
    groups = malloc(sizeof(gid_t) * ngroups);
    if (groups == NULL) {
        goto fail;
    }

    do {
        ret = getgrouplist(username, pw->pw_gid, groups, &ngroups);
        if (ret < ngroups) {
            gid_t *tmp_groups = realloc(groups, ngroups * sizeof(gid_t));
            if (tmp_groups == NULL) {
                goto fail;
            }
            groups = tmp_groups;
        }
    } while (ret != ngroups);

    groups_tuple = PyTuple_New((Py_ssize_t) ngroups);
    if (groups_tuple == NULL) {
        goto fail;
    }

    /* Populate a tuple with names of groups
     * In unlikely case of group not being able to resolve, skip it
     * We also need to resize resulting tuple to avoid empty elements there */
    idx = 0;
    for (i = 0; i < ngroups; i++) {
        gr = getgrgid(groups[i]);
        if (gr) {
            PyTuple_SetItem(groups_tuple, idx,
#ifdef IS_PY3K
                    PyUnicode_FromString(gr->gr_name)
#else
                    PyString_FromString(gr->gr_name)
#endif
                    );
            idx++;
        }
    }
    free(groups);
    groups = NULL;

    if (i != idx) {
        _PyTuple_Resize(&groups_tuple, idx);
    }

    return groups_tuple;

fail:
    free(groups);
    return NULL;
}

/*** python plumbing begins here ***/

/*
 * The sss.local destructor
 */
static void PySssLocalObject_dealloc(PySssLocalObject *self)
{
    talloc_free(self->mem_ctx);
    Py_TYPE(self)->tp_free((PyObject *)self);
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

    confdb_path = talloc_asprintf(self->mem_ctx, "%s/%s", DB_PATH, CONFDB_FILE);
    if (confdb_path == NULL) {
        PyErr_NoMemory();
        goto fail;
    }

    /* Connect to the conf db */
    ret = confdb_init(self->mem_ctx, &self->confdb, confdb_path);
    if (ret != EOK) {
        PyErr_SetSssErrorWithMessage(ret,
                "Could not initialize connection to the confdb\n");
        goto fail;
    }

    ret = sssd_domain_init(self->mem_ctx, self->confdb, "local",
                           DB_PATH, &self->local);
    if (ret != EOK) {
        PyErr_SetSssErrorWithMessage(ret,
                "Could not initialize connection to the sysdb\n");
        goto fail;
    }
    self->sysdb = self->local->sysdb;

    self->lock = DO_LOCK;
    self->unlock = DO_UNLOCK;

    return (PyObject *) self;

fail:
    Py_DECREF(self);
    return NULL;
}

/*
 * sss.local object methods
 */
static PyMethodDef sss_local_methods[] = {
    { sss_py_const_p(char, "useradd"), (PyCFunction)(void *) py_sss_useradd,
      METH_KEYWORDS, py_sss_useradd__doc__
    },
    { sss_py_const_p(char, "userdel"), (PyCFunction)(void *) py_sss_userdel,
      METH_KEYWORDS, py_sss_userdel__doc__
    },
    { sss_py_const_p(char, "usermod"), (PyCFunction)(void *) py_sss_usermod,
      METH_KEYWORDS, py_sss_usermod__doc__
    },
    { sss_py_const_p(char, "groupadd"), (PyCFunction)(void *) py_sss_groupadd,
      METH_KEYWORDS, py_sss_groupadd__doc__
    },
    { sss_py_const_p(char, "groupdel"), (PyCFunction)(void *) py_sss_groupdel,
      METH_KEYWORDS, py_sss_groupdel__doc__
    },
    { sss_py_const_p(char, "groupmod"), (PyCFunction)(void *) py_sss_groupmod,
      METH_KEYWORDS, py_sss_groupmod__doc__
    },
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

static PyMemberDef sss_local_members[] = {
    { discard_const_p(char, "lock"), T_INT,
      offsetof(PySssLocalObject, lock), READONLY, NULL},
    { discard_const_p(char, "unlock"), T_INT,
      offsetof(PySssLocalObject, unlock), READONLY, NULL},
    {NULL, 0, 0, 0, NULL} /* Sentinel */
};

/*
 * sss.local object properties
 */
static PyTypeObject pysss_local_type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = sss_py_const_p(char, "sss.local"),
    .tp_basicsize = sizeof(PySssLocalObject),
    .tp_new = PySssLocalObject_new,
    .tp_dealloc = (destructor) PySssLocalObject_dealloc,
    .tp_methods = sss_local_methods,
    .tp_members = sss_local_members,
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
    .tp_doc   = sss_py_const_p(char, "SSS DB manipulation"),
};

/* ==================== obfuscation python wrappers ========================*/

/*
 * The sss.local object
 */
typedef struct {
    PyObject_HEAD

    int aes_256;
} PySssPasswordObject;

PyDoc_STRVAR(py_sss_encrypt__doc__,
"Obfuscate a password\n\n"
":param password: The password to obfuscate\n\n"
":param method: The obfuscation method\n\n");

static PyObject *py_sss_encrypt(PySssPasswordObject *self,
                                PyObject *args)
{
    char *password = NULL;
    int plen; /* may contain NULL bytes */
    char *obfpwd = NULL;
    TALLOC_CTX *tctx = NULL;
    int ret;
    int mode;
    PyObject *retval = NULL;

    /* parse arguments */
    if (!PyArg_ParseTuple(args, discard_const_p(char, "s#i"),
                          &password, &plen, &mode)) {
        return NULL;
    }

    tctx = talloc_new(NULL);
    if (!tctx) {
        PyErr_NoMemory();
        return NULL;
    }

    ret = sss_password_encrypt(tctx, password, plen+1,
                               mode, &obfpwd);
    if (ret != EOK) {
        PyErr_SetSssError(ret);
        goto fail;
    }

    retval = Py_BuildValue(sss_py_const_p(char, "s"), obfpwd);
    if (retval == NULL) {
        goto fail;
    }

fail:
    talloc_zfree(tctx);
    return retval;
}

#if 0
PyDoc_STRVAR(py_sss_decrypt__doc__,
"Deobfuscate a password\n\n"
":param obfpwd: The password to convert back to clear text\n\n");

static PyObject *py_sss_decrypt(PySssPasswordObject *self,
                                PyObject *args,
                                PyObject *kwds)
{
    char *password = NULL;
    char *obfpwd = NULL;
    TALLOC_CTX *tctx = NULL;
    int ret;
    PyObject *retval = NULL;

    /* parse arguments */
    if (!PyArg_ParseTuple(args, discard_const_p(char, "s"),
                          &obfpwd)) {
        return NULL;
    }

    tctx = talloc_new(NULL);
    if (!tctx) {
        PyErr_NoMemory();
        return NULL;
    }

    ret = sss_password_decrypt(tctx, obfpwd, &password);
    if (ret != EOK) {
        PyErr_SetSssError(ret);
        goto fail;
    }

    retval = Py_BuildValue("s", password);
    if (retval == NULL) {
        goto fail;
    }

fail:
    talloc_zfree(tctx);
    return retval;
}
#endif

/*
 * The sss.password destructor
 */
static void PySssPasswordObject_dealloc(PySssPasswordObject *self)
{
    Py_TYPE(self)->tp_free((PyObject*) self);
}

/*
 * The sss.password constructor
 */
static PyObject *PySssPasswordObject_new(PyTypeObject *type,
                                         PyObject *args,
                                         PyObject *kwds)
{
    PySssPasswordObject *self;

    self = (PySssPasswordObject *) type->tp_alloc(type, 0);
    if (self == NULL) {
        PyErr_NoMemory();
        return NULL;
    }

    self->aes_256 = AES_256;

    return (PyObject *) self;
}

/*
 * sss.password object methods
 */
static PyMethodDef sss_password_methods[] = {
    { sss_py_const_p(char, "encrypt"), (PyCFunction) py_sss_encrypt,
      METH_VARARGS | METH_STATIC, py_sss_encrypt__doc__
    },
#if 0
    { "decrypt", (PyCFunction) py_sss_decrypt,
      METH_VARARGS | METH_STATIC, py_sss_decrypt__doc__
    },
#endif
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

/*
 * sss.password object members
 */
static PyMemberDef sss_password_members[] = {
    { discard_const_p(char, "AES_256"), T_INT,
      offsetof(PySssPasswordObject, aes_256), READONLY, NULL},
    {NULL, 0, 0, 0, NULL} /* Sentinel */
};

/*
 * sss.password object properties
 */
static PyTypeObject pysss_password_type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = sss_py_const_p(char, "sss.password"),
    .tp_basicsize = sizeof(PySssPasswordObject),
    .tp_new = PySssPasswordObject_new,
    .tp_dealloc = (destructor) PySssPasswordObject_dealloc,
    .tp_methods = sss_password_methods,
    .tp_members = sss_password_members,
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
    .tp_doc   = sss_py_const_p(char, "SSS password obfuscation"),
};

/* ==================== the sss module initialization =======================*/

/*
 * Module methods
 */
static PyMethodDef module_methods[] = {
        {"getgrouplist", py_sss_getgrouplist, METH_VARARGS, py_sss_getgrouplist__doc__},
        {NULL, NULL, 0, NULL}  /* Sentinel */
};

/*
 * Module initialization
 */
#ifdef IS_PY3K
static struct PyModuleDef pysssdef = {
    PyModuleDef_HEAD_INIT,
    "pysss",
    NULL,
    -1,
    module_methods,
    NULL,
    NULL,
    NULL,
    NULL
};

PyMODINIT_FUNC
PyInit_pysss(void)
#else
PyMODINIT_FUNC
initpysss(void)
#endif
{
    PyObject *m;

    if (PyType_Ready(&pysss_local_type) < 0)
        MODINITERROR;
    if (PyType_Ready(&pysss_password_type) < 0)
        MODINITERROR;

#ifdef IS_PY3K
    m = PyModule_Create(&pysssdef);
#else
    m = Py_InitModule(discard_const_p(char, "pysss"), module_methods);
#endif
    if (m == NULL)
        MODINITERROR;

    Py_INCREF(&pysss_local_type);
    PyModule_AddObject(m, discard_const_p(char, "local"), (PyObject *)&pysss_local_type);
    Py_INCREF(&pysss_password_type);
    PyModule_AddObject(m, discard_const_p(char, "password"), (PyObject *)&pysss_password_type);

#ifdef IS_PY3K
    return m;
#endif
}

