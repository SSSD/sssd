# SSSD Failover High-Level Documentation

This document provides high-level view on the implementation of the failover
mechanism. The code abstracts automatic server selection, connection management
a retry logic from the backend code. The backend should not touch failover
internals. The main entry port for an operation that needs to contact a remote
server is `sss_failover_transaction_send()`.

## Backend API

### Failover Context

* [sss_failover.c]()
* [sss_failover.h]()

Previously, we had one failover context per backend and the context then
contained "services" (LDAP, AD, AD_GC, ...). Now there is a single failover
context for each required service or domain. This shifts the logic a bit from
pattern "resolve_service(fctx, AD)" to "connect_to(fctx_ad)".

* `sss_failover_init()` - Initialize new failover context

### Server and Group Management

* [sss_failover_group.c]()
* [sss_failover_group.h]()

Servers are organized into prioritized groups (e.g., primary, backup). Each
group is created when the backend starts - the backend will add the hard-coded
servers and enabled DNS discovery when required.

When the failover tries to find a working server it tries to find servers
withing each group in order (group 0 has the highest priority). If no servers
are found within the group it tries the next group.

- `sss_failover_group_new()` - Create a new server group
- `sss_failover_group_add_server()` - Add static servers to group
- `sss_failover_group_setup_dns_discovery()` - Enable DNS SRV discovery for group

### Failover Transaction

* [sss_failover_transaction.c]()
* [sss_failover_transaction.h]()

The failover transaction hides the complicated logic of retrying an operation
the server fails in the middle of the operation. This replaces `sdap_id_op` code
and logic that was used previously, by hiding the logic inside a tevent request
wrapper.

#### Usage Pattern

```c
struct my_operation_state {
    struct sss_failover_ldap_connection *conn;
};

static void my_operation_done(struct tevent_req *subreq);

struct tevent_req *my_operation_send(TALLOC_CTX *mem_ctx,
                                     struct tevent_context *ev,
                                     struct sss_failover_ctx *fctx)
{
    struct my_operation_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct my_operation_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    /* ...setup state... */

    ret = sss_failover_transaction_send(state, ev, fctx, req,
                                        my_operation_done);
    if (ret != EOK) {
        goto done;
    }

    return req;

done:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);

    return req;
}

static void my_operation_done(struct tevent_req *subreq)
{
    struct my_operation_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct my_operation_state);

    state->conn = sss_failover_transaction_connected_recv(state, subreq,
                        struct sss_failover_ldap_connection);
    talloc_zfree(subreq);

    if (state->conn == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Bug: No connection?\n");
        tevent_req_error(req, EINVAL);
        return;
    }

    /* Do what needs to be done and then call tevent_req_done(req) or
     * tevent_req_error(req, ret) */

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

errno_t my_operation_recv(TALLOC_CTX *mem_ctx,
                          struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}
```

- The operation **must** return `ERR_SERVER_FAILURE` if the failure is
  server-related
- The failover code will then mark the server offline and retry with the next
  server
- Fetch all data from the server **before** writing to sysdb to ensure atomicity
  on retry

### Errors

* `ERR_SERVER_FAILURE` - Returning this error withing a failover transaction
  will retry the transaction with another server

* `ERR_NO_MORE_SERVERS` - This is returned from the transaction if there are no
  more servers to try

## Internals

### Virtual Table

* [sss_failover_vtable.c]()
* [sss_failover_vtable.h]()

Provides setters and getters of providers custom function to connect, kinit, ...

### Virtual Table Operations

* [sss_failover_vtable_op.c]()
* [sss_failover_vtable_op.h]()

This code is responsible for establishing server connection and kinit. It wraps the call to the given vtable function with server selection and resolution mechanism.

- **`sss_failover_vtable_op_kinit_send/recv()`** - Selects a KDC and obtains host credentials
- **`sss_failover_vtable_op_connect_send/recv()`** - Selects a server and establishes connection

These operations:
- Select servers from the candidate pool
- Resolve hostnames to IP addresses
- Call backend-specific vtable functions (kinit/connect)
- Mark servers as working/offline based on results
- Serialize through `vtable_op_queue` to ensure single active connection

### Server Candidates

* [sss_failover_refresh_candidates.c]()
* [sss_failover_refresh_candidates.h]()

Instead of trying to connect to a server one by one, the new failover
implementation maintains a list of "candidate servers". The list is refreshed
periodically or when needed by pining servers from a server group in parallel
batches so it can quickly find the working servers, significantly reducing
operation time.

The list of candidates is stored inside the failover context. Only one refresh
is triggered at the same time.
