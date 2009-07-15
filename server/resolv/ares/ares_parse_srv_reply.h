#ifndef __ARES_PARSE_SRV_REPLY_H__
#define __ARES_PARSE_SRV_REPLY_H__

struct srv_reply {
    u_int16_t weight;
    u_int16_t priority;
    u_int16_t port;
    char *host;
};

int _ares_parse_srv_reply (const unsigned char *abuf, int alen,
                           struct srv_reply **srv_out, int *nsrvreply);

#endif /* __ARES_PARSE_SRV_REPLY_H__ */
