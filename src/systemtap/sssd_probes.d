provider sssd {
    probe sysdb_transaction_start(int nesting);
    probe sysdb_transaction_commit_before(int nesting);
    probe sysdb_transaction_commit_after(int nesting);
    probe sysdb_transaction_cancel(int nesting);

    probe sdap_acct_req_send(int entry_type,
                             int filter_type,
                             char *filter_value,
                             char *extra_value);
    probe sdap_acct_req_recv(int entry_type,
                             int filter_type,
                             char *filter_value,
                             char *extra_value);

    probe sdap_search_user_send(const char *filter);
    probe sdap_search_user_save_begin(const char *filter);
    probe sdap_search_user_save_end(const char *filter);
    probe sdap_search_user_recv(const char *filter);

    probe sdap_get_generic_ext_send(const char *base, int scope,
                                    const char *filter, const char **attrs);
    probe sdap_get_generic_ext_recv(const char *base, int scope, const char *filter);

    probe sdap_parse_entry(const char *attrname, const char *value, int length);
    probe sdap_parse_entry_done();

    probe sdap_deref_search_send(const char *base_dn, const char *deref_attr);
    probe sdap_deref_search_recv(const char *base_dn, const char *deref_attr);

    probe sdap_nested_group_populate_pre();
    probe sdap_nested_group_populate_post();

    probe sdap_nested_group_save_pre();
    probe sdap_nested_group_save_post();

    probe sdap_nested_group_lookup_user_send();
    probe sdap_nested_group_lookup_user_recv();

    probe sdap_nested_group_lookup_group_send();
    probe sdap_nested_group_lookup_group_recv();

    probe sdap_nested_group_lookup_unknown_send();
    probe sdap_nested_group_lookup_unknown_recv();

    probe sdap_nested_group_deref_send();
    probe sdap_nested_group_deref_process_pre();
    probe sdap_nested_group_deref_process_post();
    probe sdap_nested_group_deref_recv();

    probe sdap_save_group_pre();
    probe sdap_save_group_post();

    probe sdap_save_grpmem_pre();
    probe sdap_save_grpmem_post();

    probe sdap_nested_group_send();
    probe sdap_nested_group_recv();

    probe sdap_nested_group_process_send(const char *orig_dn);
    probe sdap_nested_group_process_split_pre();
    probe sdap_nested_group_process_split_post();
    probe sdap_nested_group_process_recv(const char *orig_dn);
    probe sdap_nested_group_check_cache_pre();
    probe sdap_nested_group_check_cache_post();
    probe sdap_nested_group_sysdb_search_users_pre();
    probe sdap_nested_group_sysdb_search_users_post();
    probe sdap_nested_group_sysdb_search_groups_pre();
    probe sdap_nested_group_sysdb_search_groups_post();
    probe sdap_nested_group_populate_search_users_pre();
    probe sdap_nested_group_populate_search_users_post();

    probe dp_req_send(const char *domain, const char *dp_req_name,
                      int target, int method);
    probe dp_req_done(const char *dp_req_name, int target, int method,
                      int ret, const char *errorstr);
}
