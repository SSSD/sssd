#ifndef __ARES_PARSE_TXT_REPLY_H__
#define __ARES_PARSE_TXT_REPLY_H__

struct txt_reply {
    int length;         /* length of the text */
    unsigned char *txt; /* may contain nulls */
};

int _ares_parse_txt_reply(const unsigned char* abuf, int alen,
                          struct txt_reply **txt_out, int *ntxtreply);

#endif /* __ARES_PARSE_TXT_REPLY_H__ */
