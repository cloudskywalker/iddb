#ifndef __DB_WORKER_H__
#define __DB_WORKER_H__

#include "iddb.h"
#include "db_server.h"

/**
 * 启动工作进程
 * \param iddb 数据库句柄
 * \param child 子进程句柄
 */
void db_worker_start(iddb_t *iddb, child_t *child);

#endif
