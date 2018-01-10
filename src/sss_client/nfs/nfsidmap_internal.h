/*
 *  nfsidmap_internal.h
 *
 *  nfs idmapping library, primarily for nfs4 client/server kernel idmapping
 *  and for userland nfs4 idmapping by acl libraries.
 *
 *  Copyright (c) 2004 The Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  Andy Adamson <andros@umich.edu>
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *  3. Neither the name of the University nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 *  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 *  DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 *  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 *  BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 *  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 *  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

char *get_default_domain(void);
struct conf_list *get_local_realms(void);

typedef struct trans_func * (*libnfsidmap_plugin_init_t)(void);

struct trans_func {
	char *name;
	int (*init)(void);
	int (*princ_to_ids)(char *secname, char *princ, uid_t *uid, gid_t *gid,
		extra_mapping_params **ex);
	int (*name_to_uid)(char *name, uid_t *uid);
	int (*name_to_gid)(char *name, gid_t *gid);
	int (*uid_to_name)(uid_t uid, char *domain, char *name, size_t len);
	int (*gid_to_name)(gid_t gid, char *domain, char *name, size_t len);
	int (*gss_princ_to_grouplist)(char *secname, char *princ, gid_t *groups,
		int *ngroups, extra_mapping_params **ex);
};

struct mapping_plugin {
	void *dl_handle;
	struct trans_func *trans;
};

typedef enum {
	IDTYPE_USER = 1,
	IDTYPE_GROUP = 2
} idtypes;

extern int idmap_verbosity;
extern nfs4_idmap_log_function_t idmap_log_func;
/* Level zero always prints, others print depending on verbosity level */
#define IDMAP_LOG(LVL, MSG) \
	do { if (LVL <= idmap_verbosity) (*idmap_log_func)MSG; } while (0)


/*
 * from libnfsidmap's cfg.h (same license as above)
 * Copyright (c) 1998, 1999, 2001 Niklas Hallqvist.  All rights reserved.
 * Copyright (c) 2000, 2003 H�kan Olsson.  All rights reserved.
 */
extern const char    *conf_get_str(const char *, const char *);
