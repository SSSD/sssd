/*
 * System Security Services Daemon. NSS Interface
 *
 * Copyright (C) Simo Sorce 2007
 *
 * You can used this header file in any way you see fit provided copyright
 * notices are preserved.
 *
 */

#if 0
/* SHADOW database NSS interface */
enum nss_status _nss_sss_getspnam_r(const char *name, struct spwd *result,
				    char *buffer, size_t buflen, int *errnop);
enum nss_status _nss_sss_setspent(void);
enum nss_status _nss_sss_getspent_r(struct spwd *result,
				    char *buffer, size_t buflen, int *errnop);
enum nss_status _nss_sss_endspent(void);


/* HOSTS database NSS interface */
enum nss_status _nss_sss_gethostbyname_r(const char *name,
					 struct hostent *result,
					 char *buffer, size_t buflen,
					 int *errnop, int *h_errnop);
enum nss_status _nss_sss_gethostbyname2_r(const char *name, int af,
					  struct hostent *result,
					  char *buffer, size_t buflen,
					  int *errnop, int *h_errnop);
enum nss_status _nss_sss_gethostbyaddr_r(const void *addr, socklen_t len,
					 int af, struct hostent *result,
					 char *buffer, size_t buflen,
					 int *errnop, int *h_errnop);
enum nss_status _nss_sss_sethostent(void);
enum nss_status _nss_sss_gethostent_r(struct hostent *result,
				      char *buffer, size_t buflen,
				      int *errnop, int *h_errnop);
enum nss_status _nss_sss_endhostent(void);

/* NETGROUP database NSS interface */
enum nss_status _nss_sss_setnetgrent(const char *netgroup,
				     struct __netgrent *result);
enum nss_status _nss_sss_getnetgrent_r(struct __netgrent *result,
				       char *buffer, size_t buflen,
				       int *errnop);
enum nss_status _nss_ldap_endnetgrent(void);
/* too bad innetgr is currently implemented as an iteration over
 * {set|get|end}netgroup ... */

/* NETWORKS database NSS interface */
enum nss_status _nss_sss_getnetbyname_r(const char *name,
					struct netent *result,
					char *buffer, size_t buflen,
					int *errnop, int *h_errnop);
enum nss_status _nss_sss_getnetbyaddr_r(uint32_t addr, int af,
					struct netent *result,
					char *buffer, size_t buflen,
					int *errnop, int *h_errnop);
enum nss_status _nss_sss_setnetent(void);
enum nss_status _nss_sss_getnetent_r(struct netent *result,
				     char *buffer, size_t buflen,
				     int *errnop, int *h_errnop);
enum nss_status _nss_sss_endnetent(void);


/* PROTOCOLS database NSS interface */
enum nss_status _nss_sss_getprotobyname_r(const char *name,
					  struct protoent *result,
					  char *buffer, size_t buflen,
					  int *errnop);
enum nss_status _nss_sss_getprotobynumber_r(int number,
					    struct protoent *result,
					    char *buffer, size_t buflen,
					    int *errnop);
enum nss_status _nss_sss_setprotoent(void);
enum nss_status _nss_sss_getprotoent_r(struct protoent *result,
				       char *buffer, size_t buflen,
				       int *errnop);
enum nss_status _nss_sss_endprotoent(void);

/* SERVICES database NSS interface */
enum nss_status _nss_sss_getservbyname_r(const char *name,
					 const char *protocol,
					 struct servent *result,
					 char *buffer, size_t buflen,
					 int *errnop);
enum nss_status _nss_sss_getservbyport_r(int port, const char *protocol,
					 struct servent *result,
					 char *buffer, size_t buflen,
					 int *errnop);
enum nss_status _nss_sss_setservent(void);
enum nss_status _nss_sss_getservent_r(struct servent *result,
				      char *buffer, size_t buflen,
				      int *errnop);
enum nss_status _nss_sss_endservent(void);

/* ALIASES database NSS interface */
enum nss_status _nss_sss_getaliasbyname_r(const char *name,
					  struct aliasent *result,
					  char *buffer, size_t buflen,
					  int *errnop);
enum nss_status _nss_sss_setaliasent(void);
enum nss_status _nss_sss_getaliasent_r(struct aliasent *result,
				       char *buffer, size_t buflen,
				       int *errnop);
enum nss_status _nss_sss_endaliasent(void);

/* ETHERS database NSS interface */
enum nss_status _nss_sss_gethostton_r(const char *name,
				      struct etherent *result,
				      char *buffer, size_t buflen,
				      int *errnop);
enum nss_status _nss_sss_getntohost_r(const struct ether_addr *addr,
				      struct etherent *result,
				      char *buffer, size_t buflen,
				      int *errnop);
enum nss_status _nss_sss_setetherent(void);
enum nss_status _nss_sss_getetherent_r(struct etherent *result,
				       char *buffer, size_t buflen,
				       int *errnop);
enum nss_status _nss_sss_endetherent(void);

/* RPC database NSS interface */
enum nss_status _nss_sss_getrpcbyname_r(const char *name,
					struct rpcent *result,
					char *buffer, size_t buflen,
					int *errnop);
enum nss_status _nss_sss_getrpcbynumber_r(int number, struct rpcent *result,
					  char *buffer, size_t buflen,
					  int *errnop);
enum nss_status _nss_sss_setrpcent(void);
enum nss_status _nss_sss_getrpcent_r(struct rpcent *result,
				     char *buffer, size_t buflen,
				     int *errnop);
enum nss_status _nss_sss_endrpcent(void);

#endif
