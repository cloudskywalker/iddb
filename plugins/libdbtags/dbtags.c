/**
 * 支持标签机制
 * \note 基于数据库表的机制实现，标签信息作为表名，基于主表衍生，对象key作为标签表的成员
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

#define IDDB_TAGS_PATH		"@/../config/db_tags.conf"
#define IDDB_KEY_LEN		(100)

typedef struct {
	hash_st *engine_hash;
    db_engine_t *tag_engine;
	/* 以下为中间变量 */
	db_engine_t *engine;
	const void *key;
	uint32_t lkey;
	xmsg_st *old_obj;		/* 该成员可存储新申请的msg，需要手动释放，关闭时内部也会自动释放 */
	void *userdata;
	
	void *privatedata;		/* 自定义私有数据 */
} dbtag_sup_t;

#define IF_SET(a, b)		if (b) { (a) = (b); }

#define DB_TAG_SUP_SET(a, b, c, d, e) do {	\
	IF_SET(sup->engine, a);  									\
	IF_SET(sup->key, b); IF_SET(sup->lkey, c);				 	\
	IF_SET(sup->userdata, e); IF_SET(sup->old_obj, d);	\
} while(0)

#define DB_TAG_SUP_RESET() do {					\
	sup->key = NULL; sup->lkey = 0;				\
	sup->engine = NULL; sup->userdata = NULL;	\
	FREE_EMPTY(sup->old_obj);					\
} while(0)

#define DB_OPR_EQ(key, lkey, cmd)		(lkey == strlen(cmd) && strncmp(key, cmd, lkey) == 0)
#define EXPAND_TAG_KEY(tag_key, sup)	(const char *)tag_key, sup->lkey, (const char *)sup->key
#define EXPAND_TAG_OLD_VALUE(tagst)		tagst->klen, (const char *)tagst->key, klen, (const char *)key
#define DEBUG_NS_KEY()					debug("%s ns:%s key:%.*s\n", __FUNCTION__, db_engine_get_ns(engine), lkey, key)					

static int s_drop_dbi = 0;		/* 是否删除数据库表 */

/* tagKey@ktagValue作为标签名 */
static char *new_tag_key(const char *key, uint32_t lkey, const char *value, uint32_t lvalue)
{
	int len = lkey + lvalue + 2;
	char *key_buf = zero_alloc(len);

	str_snprintf(key_buf, len, "%.*s@%.*s", lkey, key, lvalue, value);
	return key_buf;
}

static void free_tag_key(char *tag_key)
{
	FREE_EMPTY(tag_key);
}

static void dbtag_sup_free(void *data)
{
	dbtag_sup_t *sup = (dbtag_sup_t *)data;

    if (sup->tag_engine)
        db_engine_close_dbi(sup->tag_engine, 0);
	if (sup->engine_hash)
		xhash_destroy(sup->engine_hash);
	FREE_EMPTY(sup->old_obj);
	
	free(data);
}

static void destroy_engine_hash(void *data)
{
    db_engine_t *tag_engine = (db_engine_t *)data;
	dbtag_sup_t *sup = (dbtag_sup_t *)(tag_engine->userdata);

    /* 删除tag表的同时需要删除其索引key */
	if (s_drop_dbi && sup && sup->tag_engine) {
		db_engine_del(sup->tag_engine, SLEN(db_engine_get_ns(tag_engine)));
	}
	db_engine_close_dbi((db_engine_t *)data, s_drop_dbi);
}

static int dbtags_open_posthook(db_engine_t *engine, const char *key, uint32_t lkey,	
								xmsg_st *obj, void *userdata, xmsg_st **response)
{
	if (db_engine_get_client_data(engine, DB_ENGINE_TAG_ID)) return DB_OK;

    char tag_conf[IDDB_KEY_LEN] = { 0 };
    str_snprintf(tag_conf, sizeof(tag_conf), "%s.tag", db_engine_get_ns(engine));	

	dbtag_sup_t *sup = zero_alloc(sizeof(dbtag_sup_t));
	sup->engine_hash = xhash_create(destroy_engine_hash, NULL);
    sup->tag_engine = db_engine_open_dbi(engine, tag_conf, 0);
	/* 设置私有数据 */
	db_engine_set_client_data(engine, DB_ENGINE_TAG_ID, (void *)sup, dbtag_sup_free);
	return DB_OK;
}

/* 基于现有引擎打开新表 */
static db_engine_t *open_tag_engine(dbtag_sup_t *sup, const char *tag, int readonly)
{
	uint32_t count = 0;
	int ret = 0, new = 0;
	db_engine_t *tag_engine = NULL;
	db_engine_t *engine = sup->engine;

	ret = xhash_search(sup->engine_hash, SLEN(tag), (void **)&tag_engine);
	if (ret != 0) { 
		new = 1;
		/* 不论是否只读，都必须以读写模式打开dbi，否则后续以只读模式再次访问时会出现事务错误 */
		tag_engine = db_engine_open_dbi(engine, tag, readonly);
		debug("opening tag:%s dbi in %s\n", tag, db_engine_get_ns(engine));
	}

	if (!tag_engine) return NULL;

	if (!readonly) {
		if (new) {
            tag_engine->userdata = sup;
            xhash_insert(sup->engine_hash, SLEN(tag), (void *)tag_engine);
            /* 持久化存储所有tag，以供drop调用 */
            db_engine_put(sup->tag_engine, SLEN(tag), SLEN(""));
        }
		return tag_engine;
	}

	/* 只读打开的目的是为了判断数据表是否存在，若存在则重新以读写打开 */
	if (new) {
		db_engine_close_dbi(tag_engine, 0);
		tag_engine = db_engine_open_dbi(engine, tag, 0);
		if (!tag_engine) return NULL;
	}
	ret = db_engine_count(tag_engine, &count);
	/* 表空时关闭数据表 */
	if (ret == DB_OK && count == 0) {
		debug("tag:%s database is empty, close!\n", tag);
		if (new) {
			db_engine_close_dbi(tag_engine, 0);
		} else {
			xhash_delete(sup->engine_hash, SLEN(tag));
		}
		tag_engine = NULL;
	} else if (new) {
		xhash_insert(sup->engine_hash, SLEN(tag), (void *)tag_engine);
	}

	return tag_engine;
}

/* 在标签表里添加一个条目 */
static void dbtags_add_obj(const void *tagkey, int ltagkey, 
								const void *tagdata, int ltagdata, dbtag_sup_t *sup)
{
	char *tag_key = new_tag_key(tagkey, ltagkey, tagdata, ltagdata);
	db_engine_t *engine = open_tag_engine(sup, (const char *)tag_key, 0);

	debug("%s tag:%s key:%.*s\n", __FUNCTION__, EXPAND_TAG_KEY(tag_key, sup));
	
	if (engine) db_engine_put(engine, sup->key, sup->lkey, SLEN(""));
	free_tag_key(tag_key);
}

/* 在标签表里删除一个条目 */
static void dbtags_del_obj(const void *tagkey, int ltagkey, 
									const void *tagdata, int ltagdata, dbtag_sup_t *sup)
{
	int code;
	uint32_t count = 0;
	char *tag_key = new_tag_key(tagkey, ltagkey, tagdata, ltagdata);
	db_engine_t *engine = open_tag_engine(sup, (const char *)tag_key, 0);

	if (!engine) {
		warn("del tag:%s member:%.*s, tag database not exist!\n", EXPAND_TAG_KEY(tag_key, sup));
		goto EXIT;
	}

	debug("%s tag:%s key:%.*s\n", __FUNCTION__, EXPAND_TAG_KEY(tag_key, sup));
	
	code = db_engine_del(engine, sup->key, sup->lkey);
	if (code != DB_OK) {
		warn("del tag:%s member:%.*s failed!\n", EXPAND_TAG_KEY(tag_key, sup));
	}

	/* 为空时，删除该表 */
	code = db_engine_count(engine, &count);
	if (code == DB_OK && count == 0) {
		debug("member is empty, del tag database:%s\n", tag_key);
		s_drop_dbi = 1;
		xhash_delete(sup->engine_hash, SLEN(tag_key));
		s_drop_dbi = 0;
	}

EXIT:
	free_tag_key(tag_key);
}

typedef struct {
	const void *key;
	hash_st *old_tvh;
	hash_st *new_tvh;

	int klen;
} tag_t;

/* 标签内容支持以","分割，用于多标签值场景 */
static hash_st *tags2hash(const char *data, uint32_t ldata)
{
	hash_st *tvhash = xhash_create(NULL, NULL);

	if (!data || ldata == 0) { return tvhash; }

	char *save_ptr = NULL;
	char *tagdata = strndup_die(data, ldata);
	char *value = strtok_r(tagdata, ",", &save_ptr);

	/* 分割插入 */
	while (value) {
		xhash_insert(tvhash, SLEN(value), NULL);
		value = strtok_r(NULL, ",", &save_ptr);
	}
	FREE_EMPTY(tagdata);

	return tvhash;
}

static int tag_data_add_walk(const void *key, int klen, void *val, void *data)
{
	dbtag_sup_t *sup = (dbtag_sup_t *)data;
	tag_t *tagst = (tag_t *)sup->privatedata;

	dbtags_add_obj(tagst->key, tagst->klen, key, klen, sup);
	return 0;
}

static int put_post_walk_tag(const void *key, int klen, void *val, void *data)
{
	uint32_t ltagdata = 0;
	dbtag_sup_t *sup = (dbtag_sup_t *)data;
	xmsg_st *obj = (xmsg_st *)sup->userdata;
	const void *tagdata = xmsg_get(obj, key, klen, &ltagdata, NULL);

	if (!tagdata || ltagdata <= 0) return 0;

	hash_st *tvhash = tags2hash(tagdata, ltagdata);
	tag_t tagst = { key, NULL, NULL, klen };

	/* 支持多标签值 */
	sup->privatedata = &tagst;
	xhash_walk(tvhash, data, tag_data_add_walk);
	sup->privatedata = NULL;
	
	xhash_destroy(tvhash);
	return 0;
}

static int dbtags_put_posthook(db_engine_t *engine, const char *key, uint32_t lkey,	
								xmsg_st *obj, void *userdata, xmsg_st **response)
{
	if (!obj) return DB_OK;

	debug("==put key: %.*s==\n", lkey, key);

	hash_st *tag_hash = (hash_st *)userdata;
	dbtag_sup_t *sup = (dbtag_sup_t *)db_engine_get_client_data(engine, DB_ENGINE_TAG_ID);

	DB_TAG_SUP_SET(engine, key, lkey, NULL, obj);
	xhash_walk(tag_hash, (void *)sup, put_post_walk_tag);
	DB_TAG_SUP_RESET();

	return DB_OK;
}

static int dbtags_set_prehook(db_engine_t *engine, const char *key, uint32_t lkey,	
								xmsg_st *obj, void *userdata, xmsg_st **response)
{
	const void *value = NULL;
	uint32_t lvalue = 0;

	dbtag_sup_t *sup = (dbtag_sup_t *)db_engine_get_client_data(engine, DB_ENGINE_TAG_ID);
	int code = db_engine_get(engine, key, lkey, &value, &lvalue);
	if (code != DB_OK) return code;

	xmsg_st *msg = xmsg_unpack(value, lvalue);
	FREE_EMPTY(sup->old_obj);
	sup->old_obj = msg;
	
	FREE_EMPTY(value);
	return DB_OK;
}

static int old_tag_data_walk(const void *key, int klen, void *val, void *data)
{
	dbtag_sup_t *sup = (dbtag_sup_t *)data;
	tag_t *tagst = (tag_t *)sup->privatedata;
	hash_st *new_tvh = tagst->new_tvh;
	
	if (0 != xhash_search(new_tvh, key, klen, NULL)) {
		debug("dbtags_set_posthook tagkey:%.*s tagvalue:%.*s is deleted\n", EXPAND_TAG_OLD_VALUE(tagst));
		dbtags_del_obj(tagst->key, tagst->klen, key, klen, sup);
	}
	return 0;
}

static int new_tag_data_walk(const void *key, int klen, void *val, void *data)
{
	dbtag_sup_t *sup = (dbtag_sup_t *)data;
	tag_t *tagst = (tag_t *)sup->privatedata;
	hash_st *old_tvh = tagst->old_tvh;
	
	if (0 != xhash_search(old_tvh, key, klen, NULL)) {
		debug("dbtags_set_posthook tagkey:%.*s tagvalue:%.*s is added\n", EXPAND_TAG_OLD_VALUE(tagst));
		dbtags_add_obj(tagst->key, tagst->klen, key, klen, sup);
	}
	return 0;
}

static int set_post_walk_tag(const void *key, int klen, void *val, void *data)
{
	uint32_t ltagdata = 0, lold_tagdata = 0;
	dbtag_sup_t *sup = (dbtag_sup_t *)data;
	xmsg_st *obj = (xmsg_st *)sup->userdata;	
	xmsg_st *old_obj = sup->old_obj;
	const void *tagdata = xmsg_get(obj, key, klen, &ltagdata, NULL);
	const void *old_tagdata = xmsg_get(old_obj, key, klen, &lold_tagdata, NULL);
	hash_st *old_tvh = tags2hash(old_tagdata, lold_tagdata);
	hash_st *new_tvh = tags2hash(tagdata, ltagdata);
	tag_t tagst = { key, old_tvh, new_tvh, klen };

	sup->privatedata = &tagst;
	xhash_walk(old_tvh, data, old_tag_data_walk);
	xhash_walk(new_tvh, data, new_tag_data_walk);
	sup->privatedata = NULL;

	xhash_destroy(old_tvh);
	xhash_destroy(new_tvh);
	return 0;
}

static int dbtags_set_posthook(db_engine_t *engine, const char *key, uint32_t lkey,	
								xmsg_st *obj, void *userdata, xmsg_st **response)
{
	if (!obj) return DB_OK;

	debug("==set key: %.*s==\n", lkey, key);

	hash_st *tag_hash = (hash_st *)userdata;
	dbtag_sup_t *sup = (dbtag_sup_t *)db_engine_get_client_data(engine, DB_ENGINE_TAG_ID);

	DB_TAG_SUP_SET(engine, key, lkey, NULL, obj);
	xhash_walk(tag_hash, (void *)sup, set_post_walk_tag);
	DB_TAG_SUP_RESET();
	
	return DB_OK;
}

static int dbtags_del_prethook(db_engine_t *engine, const char *key, uint32_t lkey, 
							xmsg_st *obj, void *userdata, xmsg_st **response)
{
	uint32_t lvalue;
	const void *value = NULL;
	dbtag_sup_t *sup = (dbtag_sup_t *)db_engine_get_client_data(engine, DB_ENGINE_TAG_ID);
	int code = db_engine_get(engine, key, lkey, &value, &lvalue);
	if (code != DB_OK) return code;

	xmsg_st *msg = xmsg_unpack(value, lvalue);
	FREE_EMPTY(sup->old_obj);
	sup->old_obj = msg;
	
	FREE_EMPTY(value);
	return DB_OK;
}

static int tag_data_del_walk(const void *key, int klen, void *val, void *data)
{
	dbtag_sup_t *sup = (dbtag_sup_t *)data;
	tag_t *tagst = (tag_t *)sup->privatedata;
	
	debug("dbtags_del_posthook tagkey:%.*s tagvalue:%.*s is deleted\n", EXPAND_TAG_OLD_VALUE(tagst));
	dbtags_del_obj(tagst->key, tagst->klen, key, klen, sup);
	return 0;
}

static int del_post_walk_tag(const void *key, int klen, void *val, void *data)
{
	uint32_t lold_tagdata = 0;
	dbtag_sup_t *sup = (dbtag_sup_t *)data;
	xmsg_st *old_obj = (xmsg_st *)sup->old_obj;
	const void *old_tagdata = xmsg_get(old_obj, key, klen, &lold_tagdata, NULL);
	hash_st *old_tvh = tags2hash(old_tagdata, lold_tagdata);
	tag_t tagst = { key, old_tvh, NULL, klen };

	sup->privatedata = &tagst;
	xhash_walk(old_tvh, data, tag_data_del_walk);
	sup->privatedata = NULL;

	xhash_destroy(old_tvh);
	return 0;
}

static int dbtags_del_posthook(db_engine_t *engine, const char *key, uint32_t lkey, 
								xmsg_st *obj, void *userdata, xmsg_st **response)
{
	debug("==del key: %.*s==\n", lkey, key);

	hash_st *tag_hash = (hash_st *)userdata;
	dbtag_sup_t *sup = (dbtag_sup_t *)db_engine_get_client_data(engine, DB_ENGINE_TAG_ID);
	
	DB_TAG_SUP_SET(engine, key, lkey, NULL, NULL);
	xhash_walk(tag_hash, (void *)sup, del_post_walk_tag);
	DB_TAG_SUP_RESET();
	
	return DB_OK;
}

static void walk_tag(db_engine_t *engine, const void *key, uint32_t lkey, 
										const void *value, uint32_t lvalue, void *userdata)
{
	xmsg_st *keylist = (xmsg_st *)userdata;
	xmsg_add(keylist, key, lkey, "", 0);
}

static int dbtags_select_tag(dbtag_sup_t *sup)
{
	uint32_t lnewlist;
	const char *newlist = NULL;
	xmsg_st *keylist = NULL;
	xmsg_st *response = (xmsg_st *)sup->userdata;

	keylist = xmsg_new("keylist");
	if (sup->engine) db_engine_walk(sup->engine, walk_tag, (void *)keylist);;
	newlist = xmsg_pack_aux(keylist, &lnewlist);
	xmsg_release(keylist);

	xmsg_add(response, SLEN("@data"), newlist, lnewlist);
	FREE_EMPTY(newlist);

	return DB_OK;
}

static int dbtags_tag_mcount(dbtag_sup_t *sup)
{
	uint32_t count = 0;
	xmsg_st *response = (xmsg_st *)sup->userdata;
	
	if (sup->engine) db_engine_count(sup->engine, &count);
	xmsg_add(response, SLEN("@data"), &count, sizeof(count));
	
	return DB_OK;
}

/* 自定义命令的实现 */
static int dbtags_custom_oprhook(db_engine_t *engine, const char *key, uint32_t lkey, 
								xmsg_st *obj, void *userdata, xmsg_st **response)
{
	/* 需要排除非本插件处理的请求 */
	if (!DB_OPR_EQ(key, lkey, "select_tag") && 
			!DB_OPR_EQ(key, lkey, "tag_count")) {
		return DB_OK; 
	}

	int code = DB_OK;
	uint32_t ltagkey, ltagvalue;
	char *tag_key = NULL;
	db_engine_t *tag_engine = NULL;
	xmsg_st *response_msg = xmsg_new("custom_opr");
	dbtag_sup_t *sup = (dbtag_sup_t *)db_engine_get_client_data(engine, DB_ENGINE_TAG_ID);
	const void *tagkey = xmsg_get(obj, SLEN("key"), &ltagkey, NULL);
	const void *tagvalue = xmsg_get(obj, SLEN("value"), &ltagvalue, NULL);

	sup->engine = engine;
	tag_key = new_tag_key(tagkey, ltagkey, tagvalue, ltagvalue);
	tag_engine = open_tag_engine(sup, (const char *)tag_key, 1);
	free_tag_key(tag_key);
	sup->engine = NULL;
	
	DB_TAG_SUP_SET(tag_engine, NULL, 0, NULL, response_msg);
	/* 分发命令 */
	if (DB_OPR_EQ(key, lkey, "select_tag")) {
		code = dbtags_select_tag(sup);
	} else if (DB_OPR_EQ(key, lkey, "tag_count")) {
		code = dbtags_tag_mcount(sup);
	} else {
		code = DB_EINVALIDCMD;
	}
	DB_TAG_SUP_RESET();

	if (response) {
		*response = response_msg;
	} else {
		xmsg_release(response_msg);
	}
	return code;
}

static void walk_engine_drop(db_engine_t *engine, const void *key, uint32_t lkey, 
										const void *value, uint32_t lvalue, void *userdata)
{
	char *tag_key = zero_alloc(lkey + 1);
	str_snprintf(tag_key, lkey + 1, "%.*s", lkey, (const char *)key);
	db_engine_t *master_engine = (db_engine_t *)userdata;
	db_engine_t *tag_engine = db_engine_open_dbi(master_engine, tag_key, 0);

	/* 删除tag表 */
	if (tag_engine) { db_engine_close_dbi(tag_engine, 1); }
	FREE_EMPTY(tag_key);
}

static int dbtags_drop_prehook(db_engine_t *engine, const char *key, uint32_t lkey, 
								xmsg_st *obj, void *userdata, xmsg_st **response)
{
	debug("==drop engine:%s tags==\n", db_engine_get_ns(engine));
	
	dbtag_sup_t *sup = (dbtag_sup_t *)db_engine_get_client_data(engine, DB_ENGINE_TAG_ID);

	s_drop_dbi = 1;
	if (sup->engine_hash) xhash_clear(sup->engine_hash);
	s_drop_dbi = 0;

	if (sup->tag_engine) {
		/* drop未open的tag表 */
		db_engine_walk(sup->tag_engine, walk_engine_drop, engine);
		/* 清空索引表 */
		db_engine_drop(sup->tag_engine);
	}	

	return DB_OK;
}

static void install_config_hook(const char *ns, hash_st *tag_hash)
{
	db_if_install_hook(ns, DB_HOOK_POST_OPEN, dbtags_open_posthook, (void *)tag_hash);
	db_if_install_hook(ns, DB_HOOK_POST_PUT, dbtags_put_posthook, (void *)tag_hash);
	db_if_install_hook(ns, DB_HOOK_PRE_SET, dbtags_set_prehook, (void *)tag_hash);
	db_if_install_hook(ns, DB_HOOK_POST_SET, dbtags_set_posthook, (void *)tag_hash);
	db_if_install_hook(ns, DB_HOOK_PRE_DEL, dbtags_del_prethook, (void *)tag_hash);
	db_if_install_hook(ns, DB_HOOK_POST_DEL, dbtags_del_posthook, (void *)tag_hash);
	db_if_install_hook(ns, DB_HOOK_CUSTOM_OPR, dbtags_custom_oprhook, (void *)tag_hash);
	db_if_install_hook(ns, DB_HOOK_PRE_DROP, dbtags_drop_prehook, NULL);
}

static void register_config(ini_file_st *config, const char *ns)
{
	const char *scount = NULL;
	uint32_t cnt = 0, i = 0;
	hash_st *tag_hash = xhash_create(NULL, NULL);

	if ((scount = ini_file_get(config, ns, "tags")))
		cnt = atoi(scount);
	
	for (i = 0; i < cnt; ++i) {
		char key[IDDB_KEY_LEN];
		const char *col;
		
		str_snprintf(key, sizeof(key), "col%u", i);
		col = ini_file_get(config, ns, key);
		xhash_insert(tag_hash, SLEN(col), NULL);
	}

	install_config_hook(ns, tag_hash);
	debug("install ns:%s dbtags opr hook done\n", ns);
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

int dbtags_init(int argc, char **argv)
{
	read_config();
	return 0;
}
