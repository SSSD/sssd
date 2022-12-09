/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

    Copyright (C) 2014 Red Hat

    SSSD tests: Resolver tests using a fake resolver library

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

#include <talloc.h>
#include <tevent.h>
#include <errno.h>
#include <popt.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <stdarg.h>
#include <stdlib.h>

#include <resolv.h>

#include "resolv/async_resolv.h"
#include "tests/cmocka/common_mock.h"
#include "tests/cmocka/common_mock_resp.h"

#define TEST_BUFSIZE         1024
#define TEST_DEFAULT_TIMEOUT 5
#define TEST_SRV_QUERY "_ldap._tcp.sssd.com"

static TALLOC_CTX *global_mock_context = NULL;

struct srv_rrdata {
    uint16_t port;
    uint16_t prio;
    uint16_t weight;
    uint32_t ttl;
    const char *hostname;
};

static ssize_t dns_header(unsigned char **buf, size_t ancount)
{
    uint8_t *hb;
    HEADER h;

    hb = *buf;
    memset(hb, 0, NS_HFIXEDSZ);
    memset(&h, 0, sizeof(h));

    h.id = 0xFFFF & sss_rand();  /* random query ID */
    h.qr = 1;                    /* response flag */
    h.rd = 1;                    /* recursion desired */
    h.ra = 1;                    /* recursion available */

    h.qdcount = htons(1);          /* no. of questions */
    h.ancount = htons(ancount);    /* no. of answers */
    h.arcount = htons(0);          /* no. of add'tl records */
    memcpy(hb, &h, sizeof(h));

    hb += NS_HFIXEDSZ;              /* move past the header */
    *buf = hb;

    return NS_HFIXEDSZ;
}

static ssize_t dns_question(const char *question,
                            uint16_t type,
                            uint8_t **question_ptr,
                            size_t remaining)
{
    unsigned char *qb = *question_ptr;
    int n;

    n = ns_name_compress(question, qb, remaining, NULL, NULL);
    assert_true(n > 0);

    qb += n;
    remaining -= n;

    NS_PUT16(type, qb);
    NS_PUT16(ns_c_in, qb);

    *question_ptr = qb;
    return n + 2 * sizeof(uint16_t);
}

static ssize_t add_rr_common(uint16_t type,
                             uint32_t ttl,
                             size_t rdata_size,
                             const char *key,
                             size_t remaining,
                             uint8_t **rdata_ptr)
{
    uint8_t *rd = *rdata_ptr;
    ssize_t written = 0;

    written = ns_name_compress(key, rd, remaining, NULL, NULL);
    assert_int_not_equal(written, -1);
    rd += written;
    remaining -= written;

    assert_true(remaining > 3 * sizeof(uint16_t) + sizeof(uint32_t));
    NS_PUT16(type, rd);
    NS_PUT16(ns_c_in, rd);
    NS_PUT32(ttl, rd);
    NS_PUT16(rdata_size, rd);

    assert_true(remaining > rdata_size);
    *rdata_ptr = rd;
    return written + 3 * sizeof(uint16_t) + sizeof(uint32_t) + rdata_size;
}

static ssize_t add_srv_rr(struct srv_rrdata *rr,
                          const char *question,
                          uint8_t *answer,
                          size_t anslen)
{
    uint8_t *a = answer;
    ssize_t resp_size;
    size_t rdata_size;
    unsigned char hostname_compressed[MAXDNAME];
    ssize_t compressed_len;

    rdata_size = 3 * sizeof(uint16_t);

    /* Prepare the data to write */
    compressed_len = ns_name_compress(rr->hostname,
                                      hostname_compressed, MAXDNAME,
                                      NULL, NULL);
    assert_int_not_equal(compressed_len, -1);
    rdata_size += compressed_len;

    resp_size = add_rr_common(ns_t_srv, rr->ttl, rdata_size,
                              question, anslen, &a);

    NS_PUT16(rr->prio, a);
    NS_PUT16(rr->weight, a);
    NS_PUT16(rr->port, a);
    memcpy(a, hostname_compressed, compressed_len);

    return resp_size;
}

unsigned char *create_srv_buffer(TALLOC_CTX *mem_ctx,
                                 const char *question,
                                 struct srv_rrdata *rrs,
                                 size_t n_rrs,
                                 size_t *_buflen)
{
    unsigned char *buf;
    unsigned char *buf_head;
    ssize_t len;
    ssize_t i;
    ssize_t total = 0;

    buf = talloc_zero_array(mem_ctx, unsigned char, TEST_BUFSIZE);
    assert_non_null(buf);
    buf_head = buf;

    len = dns_header(&buf, n_rrs);
    assert_true(len > 0);
    total += len;

    len = dns_question(question, ns_t_srv, &buf, TEST_BUFSIZE - total);
    assert_true(len > 0);
    total += len;

    /* answer */
    for (i = 0; i < n_rrs; i++) {
        len = add_srv_rr(&rrs[i], question, buf, TEST_BUFSIZE - total);
        assert_true(len > 0);
        total += len;
        buf += len;
    }

    *_buflen = total;
    return buf_head;
}

struct fake_ares_query {
    int status;
    int timeouts;
    unsigned char *abuf;
    int alen;
};

void mock_ares_query(int status, int timeouts, unsigned char *abuf, int alen)
{
    will_return(__wrap_ares_query, status);
    will_return(__wrap_ares_query, timeouts);
    will_return(__wrap_ares_query, abuf);
    will_return(__wrap_ares_query, alen);
}

void __wrap_ares_query(ares_channel channel, const char *name, int dnsclass,
                       int type, ares_callback callback, void *arg)
{
    struct fake_ares_query query;

    query.status = sss_mock_type(int);
    query.timeouts = sss_mock_type(int);
    query.abuf = sss_mock_ptr_type(unsigned char *);
    query.alen = sss_mock_type(int);

    callback(arg, query.status, query.timeouts, query.abuf, query.alen);
}

/* The unit test */
struct resolv_fake_ctx {
    struct resolv_ctx *resolv;
    struct sss_test_ctx *ctx;
};

static int test_resolv_fake_setup(void **state)
{
    struct resolv_fake_ctx *test_ctx;
    int ret;

    assert_true(leak_check_setup());
    global_mock_context = talloc_new(global_talloc_context);
    assert_non_null(global_mock_context);

    test_ctx = talloc_zero(global_mock_context,
                           struct resolv_fake_ctx);
    assert_non_null(test_ctx);

    test_ctx->ctx = create_ev_test_ctx(test_ctx);
    assert_non_null(test_ctx->ctx);

    ret = resolv_init(test_ctx, test_ctx->ctx->ev,
                      TEST_DEFAULT_TIMEOUT, 2000, true, &test_ctx->resolv);
    assert_int_equal(ret, EOK);

    *state = test_ctx;
    return 0;
}

static int test_resolv_fake_teardown(void **state)
{
    struct resolv_fake_ctx *test_ctx =
        talloc_get_type(*state, struct resolv_fake_ctx);

    talloc_free(test_ctx);
    talloc_free(global_mock_context);
    assert_true(leak_check_teardown());
    return 0;
}

void test_resolv_fake_srv_done(struct tevent_req *req)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx;
    int status;
    uint32_t ttl;
    struct ares_srv_reply *srv_replies = NULL;
    struct resolv_fake_ctx *test_ctx =
        tevent_req_callback_data(req, struct resolv_fake_ctx);

    tmp_ctx = talloc_new(test_ctx);
    assert_non_null(tmp_ctx);

    ret = resolv_getsrv_recv(tmp_ctx, req, &status, NULL,
                             &srv_replies, &ttl);
    assert_int_equal(ret, EOK);

    assert_non_null(srv_replies);
    assert_int_equal(srv_replies->priority, 1);
    assert_int_equal(srv_replies->weight, 40);
    assert_int_equal(srv_replies->port, 389);
    assert_string_equal(srv_replies->host, "ldap.sssd.com");

    srv_replies = srv_replies->next;
    assert_non_null(srv_replies);
    assert_int_equal(srv_replies->priority, 1);
    assert_int_equal(srv_replies->weight, 60);
    assert_int_equal(srv_replies->port, 389);
    assert_string_equal(srv_replies->host, "ldap2.sssd.com");

    srv_replies = srv_replies->next;
    assert_null(srv_replies);

    assert_int_equal(ttl, 500);

    talloc_free(tmp_ctx);
    test_ev_done(test_ctx->ctx, EOK);
}

void test_resolv_fake_srv(void **state)
{
    int ret;
    struct tevent_req *req;
    struct resolv_fake_ctx *test_ctx =
        talloc_get_type(*state, struct resolv_fake_ctx);

    unsigned char *buf;
    size_t buflen;

    struct srv_rrdata rr[2];

    rr[0].prio = 1;
    rr[0].port = 389;
    rr[0].weight = 40;
    rr[0].ttl = 600;
    rr[0].hostname = "ldap.sssd.com";

    rr[1].prio = 1;
    rr[1].port = 389;
    rr[1].weight = 60;
    rr[1].ttl = 500;
    rr[1].hostname = "ldap2.sssd.com";

    buf = create_srv_buffer(test_ctx, TEST_SRV_QUERY, rr, 2, &buflen);
    assert_non_null(buf);
    mock_ares_query(0, 0, buf, buflen);

    req = resolv_getsrv_send(test_ctx, test_ctx->ctx->ev,
                             test_ctx->resolv, TEST_SRV_QUERY);
    assert_non_null(req);
    tevent_req_set_callback(req, test_resolv_fake_srv_done, test_ctx);

    ret = test_ev_loop(test_ctx->ctx);
    assert_int_equal(ret, ERR_OK);
}

void test_resolv_is_address(void **state)
{
    bool ret;

    ret = resolv_is_address("10.192.211.37");
    assert_true(ret);

    ret = resolv_is_address("127.0.0.1");
    assert_true(ret);

    ret = resolv_is_address("2001:0db8:85a3:0000:0000:8a2e:0370:7334");
    assert_true(ret);

    ret = resolv_is_address("sssd.ldap.com");
    assert_false(ret);

    ret = resolv_is_address("testhostname");
    assert_false(ret);

    ret = resolv_is_address("localhost");
    assert_false(ret);
}

void test_resolv_is_unix(void **state)
{
    bool ret;

    ret = resolv_is_unix("10.192.211.37");
    assert_false(ret);

    ret = resolv_is_unix("2001:0db8:85a3:0000:0000:8a2e:0370:7334");
    assert_false(ret);

    ret = resolv_is_unix("sssd.ldap.com");
    assert_false(ret);

    ret = resolv_is_unix("testhostname");
    assert_false(ret);

    ret = resolv_is_unix("/tmp/socket");
    assert_true(ret);
}

int main(int argc, const char *argv[])
{
    int rv;
    poptContext pc;
    int opt;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_DEBUG_OPTS
        POPT_TABLEEND
    };

    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_resolv_fake_srv,
                                        test_resolv_fake_setup,
                                        test_resolv_fake_teardown),
        cmocka_unit_test(test_resolv_is_address),
        cmocka_unit_test(test_resolv_is_unix),
    };

    /* Set debug level to invalid value so we can decide if -d 0 was used. */
    debug_level = SSSDBG_INVALID;

    pc = poptGetContext(argv[0], argc, argv, long_options, 0);
    while((opt = poptGetNextOpt(pc)) != -1) {
        switch(opt) {
        default:
            fprintf(stderr, "\nInvalid option %s: %s\n\n",
                    poptBadOption(pc, 0), poptStrerror(opt));
            poptPrintUsage(pc, stderr, 0);
            return 1;
        }
    }
    poptFreeContext(pc);

    DEBUG_CLI_INIT(debug_level);

    /* Even though normally the tests should clean up after themselves
     * they might not after a failed run. Remove the old DB to be sure */
    tests_set_cwd();

    rv = cmocka_run_group_tests(tests, NULL, NULL);
    return rv;
}
