#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "base/strutils.h"
#include "base/memory.h"
#include "usr/iddb_common.h"

#include "iddb.h"
#include "db_engine.h"
#include "db_logger.h"

#ifndef PATH_MAX
#define PATH_MAX			256
#endif

#define E(expr, callback)	if ((rc = (expr)) != MDB_SUCCESS) { \
	warn("%s:%d: %s: %s\n", __FILE__, __LINE__, #expr, mdb_strerror(rc));	\
	callback;	\
}

static hash_st *s_engines;
static const char *s_root_dir = DB_FILE_ROOT;
static size_t s_map_size = DB_MAP_MAX_SIZE;

/* 数据库引擎初始化 */
void db_engine_init(size_t map_size)
{
	s_engines = xhash_create(NULL, NULL);

	if (map_size > 0) { s_map_size = map_size; }
}

/* 保留一个引用计数 */
db_engine_t *db_engine_retain(db_engine_t *db_engine)
{
	db_engine->ref++;

	return db_engine;
}

/* 检查根目录是否存在 */
static void check_root_dir(const char *root_dir)
{
	if (access(root_dir, F_OK) != 0)
		mkdir(root_dir, 0777);
}

/* 打开数据库引擎 */
db_engine_t *db_engine_open(const char *root_dir, const char *ns)
{
	int rc;
	unsigned int flags = (MDB_NOSUBDIR/* | MDB_WRITEMAP*/);		/* 默认不直接map写，如有需要再放开，直接写的效率更高，不过直接写会改变文件大小 */
	MDB_dbi dbi;
	MDB_env *env = NULL;
	MDB_txn *txn = NULL;
	db_engine_t *engine = NULL;
	char file_path[PATH_MAX] = { 0 };

	if (!root_dir) { 
		root_dir = s_root_dir; 
	} else {
		s_root_dir = root_dir;
	}
	check_root_dir(root_dir);
	
	if (xhash_search(s_engines, SLEN(ns), (void **)&engine) == 0)
		return db_engine_retain(engine);
	
	str_snprintf(file_path, sizeof(file_path), "%s/%s", root_dir, ns);
	
	E(mdb_env_create(&env), { goto EXIT; })
	E(mdb_env_set_mapsize(env, s_map_size), { goto EXIT; })
	E(mdb_env_set_maxdbs(env, DB_MAXDBS_CNT), { goto EXIT; })
	/* 统一读写模式打开，防止首次以读模式open时文件不存在 */
	E(mdb_env_open(env, file_path, flags, 0664), { goto EXIT; })
	E(mdb_txn_begin(env, NULL, 0, &txn), { goto EXIT; })
	E(mdb_dbi_open(txn, ns, MDB_CREATE, &dbi), { goto EXIT; })
	mdb_txn_commit(txn);

	engine = zero_alloc(sizeof(db_engine_t));
	engine->env_ctx = zero_alloc(sizeof(db_engine_env_st));
	engine->env_ctx->env = env;
	engine->dbi = dbi;
	engine->ns = strdup_die(ns);
	xhash_insert(s_engines, SLEN(ns), (void *)engine);
	
	return db_engine_retain(engine);

EXIT:
	CLOSE_C(txn, mdb_txn_abort);
	CLOSE_C(env, mdb_env_close);
	return NULL;
}

/* 基于现有数据库引擎打开数据库表，并返回副表新引擎 */
db_engine_t *db_engine_open_dbi(db_engine_t *t_engine, const char *ns, int readonly)
{
	int rc;
	MDB_txn *txn = t_engine->env_ctx->transaction;
	MDB_dbi dbi;

	if (txn == NULL) {
		E(mdb_txn_begin(t_engine->env_ctx->env, NULL, readonly ? MDB_RDONLY : 0, &txn), { return NULL; })
	}
	E(mdb_dbi_open(txn, ns, readonly ? 0 : MDB_CREATE, &dbi), { goto EXIT; })
	if (t_engine->env_ctx->transaction == NULL) {
		if (readonly) mdb_txn_abort(txn); else mdb_txn_commit(txn);
	}

	db_engine_t *engine = zero_alloc(sizeof(db_engine_t));
	engine->env_ctx = t_engine->env_ctx;
	engine->dbi = dbi;
	engine->ns = strdup_die(ns);

	return db_engine_retain(engine);

EXIT:
	if (t_engine->env_ctx->transaction == NULL) {
		CLOSE_C(txn, mdb_txn_abort);
	}
	return NULL;
}

/* 关闭副表数据库引擎 */
void db_engine_close_dbi(db_engine_t *engine, int del)
{
	int rc;
	int i = 0;

	if (!engine) { return; }

	engine->ref--;
	
	if (engine->ref > 0) { return; }

	for (i = 0; i < DB_ENGINE_MAX_ID; i++) {
		if (engine->client_free[i]) { 
			CLOSE_C(engine->client_data[i], engine->client_free[i]); 
		}		
	}

	if (!del) {
		mdb_dbi_close(engine->env_ctx->env, engine->dbi);		
	} else {
		/* 删除并关闭数据库表 */
		MDB_txn *txn = engine->env_ctx->transaction;
		if (txn == NULL) {
			E(mdb_txn_begin(engine->env_ctx->env, NULL, 0, &txn), { goto FAILED2; })
		}
		E(mdb_drop(txn, engine->dbi, 1), { goto FAILED; })
		if (engine->env_ctx->transaction == NULL) {
			E(mdb_txn_commit(txn), { goto FAILED2; })
		}

		goto FINISH;	
	FAILED:
		if (txn && engine->env_ctx->transaction == NULL)
			mdb_txn_abort(txn);
	FAILED2:
		mdb_dbi_close(engine->env_ctx->env, engine->dbi);
	}

FINISH:
	FREE_EMPTY(engine->ns);
	FREE_EMPTY(engine);
}

/* 关闭数据库引擎 */
void db_engine_close(db_engine_t *engine)
{
	int i = 0;

	if (!engine) { return; }

	engine->ref--;
	
	if (engine->ref > 0) { return; }

	xhash_delete(s_engines, SLEN(engine->ns));

	for (i = 0; i < DB_ENGINE_MAX_ID; i++) {
		if (engine->client_free[i]) { 
			CLOSE_C(engine->client_data[i], engine->client_free[i]); 
		}
	}
	
	CLOSE_C(engine->env_ctx->transaction, mdb_txn_abort);
	mdb_dbi_close(engine->env_ctx->env, engine->dbi);
	CLOSE_C(engine->env_ctx->env, mdb_env_close);
	
	FREE_EMPTY(engine->env_ctx);
	FREE_EMPTY(engine->ns);
	FREE_EMPTY(engine);
}

/* 清空数据库表 */
void db_engine_drop(db_engine_t *engine)
{
	int rc;
	if (!engine) { return; }
	
	/* 清空数据库表 */
	MDB_txn *txn = engine->env_ctx->transaction;
	if (txn == NULL) {
		E(mdb_txn_begin(engine->env_ctx->env, NULL, 0, &txn), { return; })
	}
	E(mdb_drop(txn, engine->dbi, 0), { goto FAILED; })
	if (engine->env_ctx->transaction == NULL) {
		E(mdb_txn_commit(txn), { return; })
	}
	
	return;
FAILED:
	if (txn && engine->env_ctx->transaction == NULL)
		mdb_txn_abort(txn);
}

/* 获取名称空间 */
const char *db_engine_get_ns(db_engine_t *engine)
{
	return engine->ns;
}

/* 获取自定义数据 */
void *db_engine_get_client_data(db_engine_t *engine, int id)
{
	if (id < 0 || id >= DB_ENGINE_MAX_ID) return NULL;

	return engine->client_data[id];
}

/* 设置自定义数据及销毁函数 */
void db_engine_set_client_data(db_engine_t *engine, int id, void *client_data, client_data_free_func_t client_free)
{
	if (id < 0 || id >= DB_ENGINE_MAX_ID) return;

	engine->client_data[id] = client_data;
	engine->client_free[id] = client_free;
}

/* 返回根目录 */
const char *db_engine_get_root(db_engine_t *engine)
{
	return s_root_dir;
}

/* 读取数据 */
int db_engine_get(db_engine_t *engine, const void *key, uint32_t lkey, const void **value, uint32_t *lvalue)
{
	int rc;
	MDB_txn *txn = engine->env_ctx->transaction;
	MDB_val db_key, db_data;

	db_key.mv_data = (void *)key;
	db_key.mv_size = lkey;

	if (txn == NULL) {
		E(mdb_txn_begin(engine->env_ctx->env, NULL, MDB_RDONLY, &txn), { return DB_ESTART; })
	}
	
	rc = mdb_get(txn, engine->dbi, &db_key, &db_data);
	if (rc == MDB_SUCCESS && value && lvalue) {
		*lvalue = db_data.mv_size;
		/* 申请新内存进行保存，防止mdb_txn_abort后，其他进程的事务提交导致原内容变更 */
		*value = zero_alloc(db_data.mv_size);
		memcpy((void *)*value, db_data.mv_data, *lvalue);
	}
	
	if (engine->env_ctx->transaction == NULL) {
		mdb_txn_abort(txn);
	}
	if (rc == MDB_SUCCESS) { return DB_OK; }

	if (value && lvalue) {
		*lvalue = 0;
		*value = NULL;
	}

	if (rc == MDB_NOTFOUND) {
		debug("mdb_get %.*s not found!\n", lkey, (const char *)key);
		return DB_ENOTFOUND;
	}
	warn("mdb_get %.*s failed:%s\n", lkey, (const char *)key, mdb_strerror(rc));
	return DB_EGET;
}

/* 遍历数据 */
int db_engine_walk(db_engine_t *engine, walk_query_fn_t query, void *userdata)
{
	int rc, code = DB_OK;
	MDB_txn *txn = engine->env_ctx->transaction;
	MDB_cursor *cursor;
	MDB_val db_key, db_data;

	if (txn == NULL) {
		E(mdb_txn_begin(engine->env_ctx->env, NULL, MDB_RDONLY, &txn), { return DB_ESTART; })
	}

	E(mdb_cursor_open(txn, engine->dbi, &cursor), { code = DB_EOPENCURSOR; goto FINISH; })
	while ((rc = mdb_cursor_get(cursor, &db_key, &db_data, MDB_NEXT)) == MDB_SUCCESS) {
		if (query) {
			query(engine, db_key.mv_data, db_key.mv_size, 
						db_data.mv_data, db_data.mv_size, userdata);
		}
	}
	mdb_cursor_close(cursor);

FINISH:
	if (engine->env_ctx->transaction == NULL) {
		mdb_txn_abort(txn);
	}
	return DB_OK;
}

/* 获取个数 */
int db_engine_count(db_engine_t *engine, uint32_t *count)
{
	int rc;
	MDB_stat mst;
	MDB_txn *txn = engine->env_ctx->transaction;

	if (txn == NULL) {
		E(mdb_txn_begin(engine->env_ctx->env, NULL, MDB_RDONLY, &txn), { return DB_ESTART; })
	}
	rc = mdb_stat(txn, engine->dbi, &mst);
	if (engine->env_ctx->transaction == NULL) {
		mdb_txn_abort(txn);
	}

	if (rc == MDB_SUCCESS && count) { *count = mst.ms_entries; }
	return DB_OK;
}

/* put数据 */
static int database_put(db_engine_t *engine, int createonly, const void *key, uint32_t lkey, const void *value, uint32_t lvalue)
{
	int rc, ret = DB_OK;
	MDB_txn *txn = engine->env_ctx->transaction;
	MDB_val db_key, db_data;

	if (txn == NULL) {
		E(mdb_txn_begin(engine->env_ctx->env, NULL, 0, &txn), { return DB_ESTART; })
	}

	db_key.mv_size = lkey;
	db_key.mv_data = (void *)key;
	db_data.mv_size = lvalue;
	db_data.mv_data = (void *)value;

	E(mdb_put(txn, engine->dbi, &db_key, &db_data, createonly ? MDB_NOOVERWRITE : 0), {
		ret = rc == MDB_KEYEXIST ? DB_EEXIST : DB_EPUT;
	})
	
	if (rc == MDB_SUCCESS && engine->env_ctx->transaction == NULL) {
		E(mdb_txn_commit(txn), { ret = DB_ECOMMIT; })
	}
	if (rc != MDB_SUCCESS && engine->env_ctx->transaction == NULL) {
		mdb_txn_abort(txn);
	}

	return ret;
}

/* 添加数据 */
int db_engine_put(db_engine_t *engine, const void *key, uint32_t lkey, const void *value, uint32_t lvalue)
{
	return database_put(engine, 1, key, lkey, value, lvalue);
}

/* 修改数据 */
int db_engine_set(db_engine_t *engine, const void *key, uint32_t lkey, const void *value, uint32_t lvalue)
{
	int ret = db_engine_get(engine, key, lkey, NULL, NULL);
	if (ret != DB_OK) { return ret; }

	return database_put(engine, 0, key, lkey, value, lvalue);
}

/* 删除数据 */
int db_engine_del(db_engine_t *engine, const void *key, uint32_t lkey)
{
	int rc, ret = DB_OK;
	MDB_txn *txn = engine->env_ctx->transaction;
	MDB_val db_key;

	if (txn == NULL) {
		E(mdb_txn_begin(engine->env_ctx->env, NULL, 0, &txn), { return DB_ESTART; })
	}

	db_key.mv_size = lkey;
	db_key.mv_data = (void *)key;

	E(mdb_del(txn, engine->dbi, &db_key, NULL), {
		ret = rc == MDB_NOTFOUND ? DB_ENOTFOUND : DB_EDELETE;
	})
	
	if (rc == MDB_SUCCESS && engine->env_ctx->transaction == NULL) {
		E(mdb_txn_commit(txn), { ret = DB_ECOMMIT; })
	}
	if (rc != MDB_SUCCESS && engine->env_ctx->transaction == NULL) {
		mdb_txn_abort(txn);
	}

	return ret;
}

/* 开始事务 */
int db_engine_start(db_engine_t *engine, int readonly)
{
	int rc;
	MDB_txn *txn;

	/* 解决同一fd下，事务并发导致死锁的问题
	   注意！！目前只有批量写操作使用了事务，即便该引擎接口支持批量读事务，后续也不建议放开，
	   因为该解决方案针专门针对写操作进行了优化，若要支持批量写操作下的同一fd事务并发，改动较大
	 */
	if (engine->env_ctx->transaction) { 
		goto FINISH;
	}

	E(mdb_txn_begin(engine->env_ctx->env, NULL, readonly ? MDB_RDONLY : 0, &txn), { 
		return DB_ESTART; 
	})
	engine->env_ctx->transaction = txn;

FINISH:
	engine->env_ctx->tref++;
	return DB_OK;
}

/* 回滚事务 */
int db_engine_rollback(db_engine_t *engine)
{
	CLOSE_C(engine->env_ctx->transaction, mdb_txn_abort);
	/* 强制置0，目前只有批量写操作使用了事务，写操作下只有close时才会调用该接口 */
	engine->env_ctx->tref = 0;
	
	return DB_OK;
}

/* 提交事务 */
int db_engine_commit(db_engine_t *engine)
{
	int rc;
	
	/* 事务不存在或存在多个引用
	 * 注意！！这里存在逻辑上的不严谨，同一fd下事务并发时，其实是由最后的commit真正触发了提交
	 */
	if (!engine->env_ctx->transaction || 
			--engine->env_ctx->tref > 0) { 
		return DB_OK; 
	}
	
	E(mdb_txn_commit(engine->env_ctx->transaction), {
		return DB_ECOMMIT;
	})
	engine->env_ctx->transaction = NULL;
	
	return DB_OK;
}

