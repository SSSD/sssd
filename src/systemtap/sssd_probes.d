provider sssd {
    probe sysdb_transaction_start(int nesting);
    probe sysdb_transaction_commit_before(int nesting);
    probe sysdb_transaction_commit_after(int nesting);
    probe sysdb_transaction_cancel(int nesting);
}
