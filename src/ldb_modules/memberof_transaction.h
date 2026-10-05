#ifndef SSSD_MEMBEROF_TRANSACTION_H_
#define SSSD_MEMBEROF_TRANSACTION_H_

#include <stdbool.h>

#include "ldb_module.h"

bool memberof_tx_enabled(struct ldb_module *module);
int memberof_tx_init(struct ldb_module *module);

int memberof_tx_add(struct ldb_module *module, struct ldb_request *req);
int memberof_tx_modify(struct ldb_module *module, struct ldb_request *req);
int memberof_tx_delete(struct ldb_module *module, struct ldb_request *req);
int memberof_tx_rename(struct ldb_module *module, struct ldb_request *req);

int memberof_tx_start(struct ldb_module *module);
int memberof_tx_prepare_commit(struct ldb_module *module);
int memberof_tx_end(struct ldb_module *module);
int memberof_tx_cancel(struct ldb_module *module);

#endif /* SSSD_MEMBEROF_TRANSACTION_H_ */
