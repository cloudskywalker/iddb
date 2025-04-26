/**
 * 支持索引机制
 * \note 基于数据库表的机制实现
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "base/memory.h"
#include "base/strutils.h"
#include "usr/xmsg.h"
#include "base/error.h"
#include "base/iniparser.h"
#include "base/dirutils.h"
#include "db_interface.h"
#include "db_engine.h"

#define IDDB_TAGS_PATH		"@/../config/db_index.conf"
#define IDDB_KEY_LEN		(100)

typedef struct {
	db_engine_t *index_engine;

	/* 中间变量 */
	const void *key;
	uint32_t lkey;
	xmsg_st *old_obj;		/* 该成员可存储新申请的msg，需要手动释放，关闭时内部也会自动释放 */

	void *userdata;
} dbindex_sup_t;

#define IF_SET(a, b)		if (b) { (a) = (b); }

#define DB_INDEX_SUP_SET(a, b, c, d) do {	\
	IF_SET(sup->key, a); IF_SET(sup->lkey, b);			\
	IF_SET(sup->userdata, c); IF_SET(sup->old_obj, d);	\
} while(0)

#define DB_INDEX_SUP_RESET() do {					\
	sup->key = NULL; sup->lkey = 0;				\
	sup->userdata = NULL;						\
	FREE_EMPTY(sup->old_obj);					\
} while(0)

#define DB_OPR_EQ(key, lkey, cmd)		(lkey == strlen(cmd) && strncmp(key, cmd, lkey) == 0)
#define EXPAND_INDEX_KEY(index_key, sup)(const char *)index_key, sup->lkey, (const char *)sup->key
#define EXPAND_INDEX_OLD_VALUE()		klen, (const char *)key, lold_indexdata, (const char *)old_indexdata			


/* indexKey@indexValue作为索引键 */
static char *new_index_key(const char *key, uint32_t lkey, const char *value, uint32_t lvalue)
{
	int len = lkey + lvalue + 2;
	char *key_buf = zero_alloc(len);

	str_snprintf(key_buf, len, "%.*s@%.*s", lkey, key, lvalue, value);
	return key_buf;
}

static void free_index_key(char *index_key)
{
	FREE_EMPTY(index_key);
}

static void dbindex_sup_free(void *data)
{
	dbindex_sup_t *sup = (dbindex_sup_t *)data;
	
	db_engine_close_dbi(sup->index_engine, 0);

	FREE_EMPTY(sup->old_obj);
	free(data);
}

static int dbindex_open_posthook(db_engine_t *engine, const char *key, uint32_t lkey,	
								xmsg_st *obj, void *userdata, xmsg_st **response)
{
	if (db_engine_get_client_data(engine, DB_ENGINE_INDEX_ID)) return DB_OK;

	char index_conf[IDDB_KEY_LEN] = { 0 };
	str_snprintf(index_conf, sizeof(index_conf), "%s.index", db_engine_get_ns(engine));
	
	dbindex_sup_t *sup = zero_alloc(sizeof(dbindex_sup_t));
	sup->index_engine = db_engine_open_dbi(engine, index_conf, 0);

	/* 设置私有数据 */
	db_engine_set_client_data(engine, DB_ENGINE_INDEX_ID, (void *)sup, dbindex_sup_free);
	return DB_OK;
}

/* 在索引表里添加一个条目 */
static void dbindex_add_obj(const void *indexkey, int lindexkey, 
								const void *indexdata, int lindexdata, dbindex_sup_t *sup)
{
	char *index_key = new_index_key(indexkey, lindexkey, indexdata, lindexdata);

	debug("%s index:%s key:%.*s\n", __FUNCTION__, EXPAND_INDEX_KEY(index_key, sup));
	
	db_engine_put(sup->index_engine, SLEN(index_key), sup->key, sup->lkey);
	free_index_key(index_key);
}

/* 在索引表里删除一个条目 */
static void dbindex_del_obj(const void *indexkey, int lindexkey, 
									const void *indexdata, int lindexdata, dbindex_sup_t *sup)
{
	char *index_key = new_index_key(indexkey, lindexkey, indexdata, lindexdata);

	debug("%s index:%s key:%.*s\n", __FUNCTION__, EXPAND_INDEX_KEY(index_key, sup));
	
	int code = db_engine_del(sup->index_engine, SLEN(index_key));
	if (code != DB_OK) {
		warn("del index:%s of %.*s failed!\n", EXPAND_INDEX_KEY(index_key, sup));
	}
	
	free_index_key(index_key);
}

static int put_post_walk_index(const void *key, int klen, void *val, void *data)
{
	uint32_t lindexdata = 0;
	dbindex_sup_t *sup = (dbindex_sup_t *)data;
	xmsg_st *obj = (xmsg_st *)sup->userdata;
	const void *indexdata = xmsg_get(obj, key, klen, &lindexdata, NULL);

	if (!indexdata || lindexdata <= 0) return 0;

	dbindex_add_obj(key, klen, indexdata, lindexdata, sup);
	return 0;
}

static int dbindex_put_posthook(db_engine_t *engine, const char *key, uint32_t lkey,	
								xmsg_st *obj, void *userdata, xmsg_st **response)
{
	if (!obj) return DB_OK;

	debug("==put key: %.*s==\n", lkey, key);

	hash_st *index_hash = (hash_st *)userdata;
	dbindex_sup_t *sup = (dbindex_sup_t *)db_engine_get_client_data(engine, DB_ENGINE_INDEX_ID);

	DB_INDEX_SUP_SET(key, lkey, (void *)obj, NULL);
	xhash_walk(index_hash, (void *)sup, put_post_walk_index);
	DB_INDEX_SUP_RESET();

	return DB_OK;
}

static int dbindex_set_prehook(db_engine_t *engine, const char *key, uint32_t lkey,	
								xmsg_st *obj, void *userdata, xmsg_st **response)
{
	const void *value = NULL;
	uint32_t lvalue = 0;

	dbindex_sup_t *sup = (dbindex_sup_t *)db_engine_get_client_data(engine, DB_ENGINE_INDEX_ID);
	int code = db_engine_get(engine, key, lkey, &value, &lvalue);
	if (code != DB_OK) return code;

	xmsg_st *msg = xmsg_unpack(value, lvalue);
	FREE_EMPTY(sup->old_obj);
	sup->old_obj = msg;
	
	FREE_EMPTY(value);
	return DB_OK;
}

static int set_post_walk_index(const void *key, int klen, void *val, void *data)
{
	dbindex_sup_t *sup = (dbindex_sup_t *)data;
	uint32_t lindexdata = 0, lold_indexdata = 0;
	xmsg_st *obj = (xmsg_st *)sup->userdata;
	const void *indexdata = xmsg_get(obj, key, klen, &lindexdata, NULL);	
	xmsg_st *old_obj = (xmsg_st *)sup->old_obj;
	const void *old_indexdata = xmsg_get(old_obj, key, klen, &lold_indexdata, NULL);
	
	if (old_indexdata && lold_indexdata > 0) {
		/* 删除索引 */
		if (!indexdata || lindexdata <= 0) {
			debug("dbindex_set_posthook indexkey:%.*s indexvalue:%.*s is deleted\n", EXPAND_INDEX_OLD_VALUE());
			dbindex_del_obj(key, klen, old_indexdata, lold_indexdata, sup);
		/* 索引值改变 */
		} else if (lindexdata != lold_indexdata || 
						memcmp(indexdata, old_indexdata, lindexdata) != 0) {
			debug("dbindex_set_posthook indexkey:%.*s is changed, fro %.*s to %.*s\n", 
						EXPAND_INDEX_OLD_VALUE(), lindexdata, (const char *)indexdata);
			dbindex_del_obj(key, klen, old_indexdata, lold_indexdata, sup);
			dbindex_add_obj(key, klen, indexdata, lindexdata, sup);
		}
	} else {
		/* 新增索引 */
		if (indexdata && lindexdata > 0) {
			dbindex_add_obj(key, klen, indexdata, lindexdata, sup);
		}
	}
	return 0;
}

static int dbindex_set_posthook(db_engine_t *engine, const char *key, uint32_t lkey,	
								xmsg_st *obj, void *userdata, xmsg_st **response)
{
	if (!obj) return DB_OK;

	debug("==set key: %.*s==\n", lkey, key);

	hash_st *index_hash = (hash_st *)userdata;
	dbindex_sup_t *sup = (dbindex_sup_t *)db_engine_get_client_data(engine, DB_ENGINE_INDEX_ID);

	DB_INDEX_SUP_SET(key, lkey, obj, NULL);
	xhash_walk(index_hash, (void *)sup, set_post_walk_index);
	DB_INDEX_SUP_RESET();
	
	return DB_OK;
}

static int dbindex_del_prethook(db_engine_t *engine, const char *key, uint32_t lkey, 
							xmsg_st *obj, void *userdata, xmsg_st **response)
{
	uint32_t lvalue;
	const void *value = NULL;
	dbindex_sup_t *sup = (dbindex_sup_t *)db_engine_get_client_data(engine, DB_ENGINE_INDEX_ID);
	int code = db_engine_get(engine, key, lkey, &value, &lvalue);
	if (code != DB_OK) return code;

	xmsg_st *msg = xmsg_unpack(value, lvalue);
	FREE_EMPTY(sup->old_obj);
	sup->old_obj = msg;
	
	FREE_EMPTY(value);
	return DB_OK;
}

static int del_post_walk_index(const void *key, int klen, void *val, void *data)
{
	uint32_t lold_indexdata = 0;
	dbindex_sup_t *sup = (dbindex_sup_t *)data;
	xmsg_st *old_obj = (xmsg_st *)sup->old_obj;
	const void *old_indexdata = xmsg_get(old_obj, key, klen, &lold_indexdata, NULL);
	
	if (old_indexdata && lold_indexdata > 0) {
		debug("%s indexkey:%.*s indexvalue:%.*s is deleted\n", __FUNCTION__, EXPAND_INDEX_OLD_VALUE());
		dbindex_del_obj(key, klen, old_indexdata, lold_indexdata, sup);
	}
	
	return 0;
}

static int dbindex_del_posthook(db_engine_t *engine, const char *key, uint32_t lkey, 
								xmsg_st *obj, void *userdata, xmsg_st **response)
{
	debug("==del key: %.*s==\n", lkey, key);

	hash_st *index_hash = (hash_st *)userdata;
	dbindex_sup_t *sup = (dbindex_sup_t *)db_engine_get_client_data(engine, DB_ENGINE_INDEX_ID);
	
	DB_INDEX_SUP_SET(key, lkey, NULL, NULL);
	xhash_walk(index_hash, (void *)sup, del_post_walk_index);
	DB_INDEX_SUP_RESET();
	
	return DB_OK;
}

static int dbindex_query_attr(db_engine_t *engine, dbindex_sup_t *sup)
{
	int code = DB_OK;
	const void *value = NULL, *newvalue = NULL;
	uint32_t lvalue = 0, lnewvalue = 0;
	xmsg_st *response = (xmsg_st *)sup->userdata;

	code = db_engine_get(sup->index_engine, SLEN(sup->key), &value, &lvalue);
	if (code != DB_OK) { return code; }
	code = db_engine_get(engine, value, lvalue, &newvalue, &lnewvalue);
	FREE_EMPTY(value);
	if (code != DB_OK) { return code; }

	xmsg_add(response, SLEN("@data"), newvalue, lnewvalue);
	FREE_EMPTY(newvalue);

	return DB_OK;
}

/* 自定义命令的实现 */
static int dbindex_custom_oprhook(db_engine_t *engine, const char *key, uint32_t lkey, 
								xmsg_st *obj, void *userdata, xmsg_st **response)
{
	/* 需要排除非本插件处理的请求 */
	if (!DB_OPR_EQ(key, lkey, "query_attr")) { return DB_OK; }

	int code = DB_OK;
	uint32_t lindexkey, lindexvalue;
	xmsg_st *response_msg = xmsg_new("custom_opr");
	dbindex_sup_t *sup = (dbindex_sup_t *)db_engine_get_client_data(engine, DB_ENGINE_INDEX_ID);
	const void *indexkey = xmsg_get(obj, SLEN("key"), &lindexkey, NULL);
	const void *indexvalue = xmsg_get(obj, SLEN("value"), &lindexvalue, NULL);
	char *index_key = new_index_key(indexkey, lindexkey, indexvalue, lindexvalue);
	
	DB_INDEX_SUP_SET(index_key, 0, response_msg, NULL);
	/* 分发命令 */
	if (DB_OPR_EQ(key, lkey, "query_attr")) {
		code = dbindex_query_attr(engine, sup);
	} else {
		code = DB_EINVALIDCMD;
	}
	DB_INDEX_SUP_RESET();
	
	free_index_key(index_key);
	
	if (response) {
		*response = response_msg;
	} else {
		xmsg_release(response_msg);
	}
	return code;
}

static int dbindex_drop_prehook(db_engine_t *engine, const char *key, uint32_t lkey, 
								xmsg_st *obj, void *userdata, xmsg_st **response)
{
	debug("==drop engine:%s index==\n", db_engine_get_ns(engine));
	
	dbindex_sup_t *sup = (dbindex_sup_t *)db_engine_get_client_data(engine, DB_ENGINE_INDEX_ID);

	if (sup->index_engine) db_engine_drop(sup->index_engine);
	
	return DB_OK;
}

static void install_config_hook(const char *ns, hash_st *index_hash)
{
	db_if_install_hook(ns, DB_HOOK_POST_OPEN, dbindex_open_posthook, (void *)index_hash);
	db_if_install_hook(ns, DB_HOOK_POST_PUT, dbindex_put_posthook, (void *)index_hash);
	db_if_install_hook(ns, DB_HOOK_PRE_SET, dbindex_set_prehook, (void *)index_hash);
	db_if_install_hook(ns, DB_HOOK_POST_SET, dbindex_set_posthook, (void *)index_hash);
	db_if_install_hook(ns, DB_HOOK_PRE_DEL, dbindex_del_prethook, (void *)index_hash);
	db_if_install_hook(ns, DB_HOOK_POST_DEL, dbindex_del_posthook, (void *)index_hash);
	db_if_install_hook(ns, DB_HOOK_CUSTOM_OPR, dbindex_custom_oprhook, (void *)index_hash);
	db_if_install_hook(ns, DB_HOOK_PRE_DROP, dbindex_drop_prehook, NULL);
}

static void register_config(ini_file_st *config, const char *ns)
{
	const char *scount = NULL;
	uint32_t cnt = 0, i = 0;
	hash_st *index_hash = xhash_create(NULL, NULL);

	if ((scount = ini_file_get(config, ns, "index")))
		cnt = atoi(scount);
	
	for (i = 0; i < cnt; ++i) {
		char key[IDDB_KEY_LEN];
		const char *col;
		
		str_snprintf(key, sizeof(key), "col%u", i);
		col = ini_file_get(config, ns, key);
		xhash_insert(index_hash, SLEN(col), NULL);
	}

	install_config_hook(ns, index_hash);
	debug("install ns:%s dbindexs opr hook done\n", ns);
}

static void read_config()
{
	const char *scount = NULL;
	uint32_t cnt = 0, i = 0;
	ini_file_st *config = NULL;
	char file_path[PATH_MAX] = { 0 };

	dirutils_path_transform(IDDB_TAGS_PATH, file_path, sizeof(file_path));

	config = ini_file_load(file_path);
	if (!config) {
		warn("load config %s failed!\n", file_path);
		return;
	}

	if ((scount = ini_file_get(config, "config", "count")))
		cnt = strtol(scount, NULL, 0);
	
	for (i = 0; i < cnt; ++i) {
		char key[IDDB_KEY_LEN];
		const char *col;
		
		str_snprintf(key, sizeof(key), "config%u", i);
		col = ini_file_get(config, "config", key);
		register_config(config, col);
	}

	ini_file_free(config);
}

int dbindex_init(int argc, char **argv)
{
	read_config();
	return 0;
}
