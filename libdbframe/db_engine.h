#ifndef __IDDB_ENGINE_H__
#define __IDDB_ENGINE_H__

#include "usr/lmdb.h"
#include "usr/xmsg.h"

typedef struct db_engine_st {
	MDB_env *env;
	MDB_dbi dbi;
} db_engine_t;

db_engine_t *db_engine_open(const char *progid, const char *ns);

void db_engine_retain(db_engine_t *engine);

void db_engine_close(db_engine_t *engine);

int db_engine_get(db_engine_t *engine, const void *key, uint32_t lkey, const void **value, uint32_t *lvalue);

int db_engine_put(db_engine_t *engine, const void *key, uint32_t lkey, const void *value, uint32_t lvalue);

int db_engine_set(db_engine_t *engine, const void *key, uint32_t lkey, const void *value, uint32_t lvalue);

int db_engine_del(db_engine_t *engine, const void *key, uint32_t lkey);

int db_engine_start(db_engine_t *engine);

int db_engine_commit(db_engine_t *engine);

#endif
