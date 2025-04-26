#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <assert.h>

#include "base/error.h"
#include "base/memory.h"
#include "base/plist.h"
#include "base/timer.h"

#include "iddb.h"
#include "db_logger.h"
#include "db_interface.h"
#include "db_engine.h"

#define DB_PER_SECOND		(1000)

#define DO_EXEC_HOOK(hookid, head, engine, key, lkey) 	\
							db_if_exec_hook(hookid, head, engine, key, lkey, NULL, 0, NULL, NULL, NULL)


static struct plist_head s_cfg_list;
static hash_st *s_ns_hooks;	

typedef struct db_timer_st {
	const char *ns;
	void *userdata;
	struct plist_head *plist;

	timeout_notify_fn_t time_fn;
	uint32_t seconds;
} db_timer_t;

typedef struct db_update_st {
	struct plist_head plist;

	cfg_notify_fn_t notify;
	void *userdata;
} db_update_t;

typedef struct hook_opr_st {
	struct {
		db_hook_fn_t func;
		void *userdata;
	} hooks[DB_HOOK_MAX];

	struct plist_head plist;
} hook_opr_t;


__attribute__((constructor)) static void db_interface_init(void)
{
	timer_init();
	
	plist_head_init(&s_cfg_list);

	s_ns_hooks = xhash_create(NULL, NULL);
}

static void timeout_callback(void *userdata);

static void walk_query(db_engine_t *engine, const void *key, uint32_t lkey, const void *value, uint32_t lvalue, void *userdata)
{
	int code;
	db_timer_t *timer = (db_timer_t *)userdata;
	xmsg_st *msg = NULL;

	if (value && lvalue) {
		msg = xmsg_unpack(value, lvalue);
	}
	if (timer->time_fn(key, lkey, msg, timer->userdata) == 0) {
		code = DO_EXEC_HOOK(DB_HOOK_PRE_DEL, timer->plist, engine, key, lkey);
		if (code != DB_OK) { goto EXIT; }
		
		code = db_engine_del(engine, key, lkey);
		if (code == DB_OK) { 
			DO_EXEC_HOOK(DB_HOOK_POST_DEL, timer->plist, engine, key, lkey);
		}
	}

EXIT:
	xmsg_release(msg);
}

static void timeout_callback(void *userdata)
{
	db_timer_t *timer = (db_timer_t *)userdata;
	db_engine_t *engine = db_engine_open(NULL, timer->ns);
	if (!engine) {  goto EXIT; return; }

	/* 之所以不在set_alive时准备好hook，是为了防止调用set_alive时hook还未注册，依赖于开发者的调用顺序 */
	db_if_prepare_hook(timer->ns, &timer->plist);
	
	db_engine_start(engine, 0);
	db_engine_walk(engine, walk_query, userdata);
	db_engine_commit(engine);
	db_engine_close(engine);

EXIT:
	timer_set_timeout(timer->seconds * DB_PER_SECOND, timeout_callback, userdata);
}

/**
 * 设置数据库生存时间，与实际生存可能有误差，但保证最少生存alive秒
 */
void db_if_set_alive(const char *ns, uint32_t seconds, timeout_notify_fn_t on_timeout, void *userdata)
{
	if (!ns || !on_timeout) { return; }

	db_timer_t *timer = zero_alloc(sizeof(db_timer_t));
	
	timer->ns = strdup_die(ns);
	timer->time_fn = on_timeout;
	timer->userdata = userdata;
	timer->seconds = seconds;
	
	timer_set_timeout(seconds * DB_PER_SECOND, timeout_callback, (void *)timer);
}

/**
 * 注册配置更新
 */
void db_if_reg_update(cfg_notify_fn_t cfg_update, void *userdata)
{
	if (!cfg_update) { return; }

	db_update_t *update = zero_alloc(sizeof(db_update_t));
	update->notify = cfg_update;
	update->userdata = userdata;

	plist_add(&update->plist, &s_cfg_list);
}

/**
 * 安装数据操作的hook
 */
int db_if_install_hook(const char *ns, int hookid, 
							db_hook_fn_t hook, void *userdata)
{
	struct plist_head *head = NULL;
	
	if (!ns || hookid < 0 || hookid >= DB_HOOK_MAX || !hook)
		return -1;
	
	if (xhash_search(s_ns_hooks, SLEN(ns), (void **)&head) != 0) {
		head = zero_alloc(sizeof(struct plist_head));
		xhash_insert(s_ns_hooks, SLEN(ns), head);
	}

	hook_opr_t *ht = zero_alloc(sizeof(hook_opr_t));
	ht->hooks[hookid].func = hook;
	ht->hooks[hookid].userdata = userdata;

	plist_add(&ht->plist, head);
	
	return 0;
}

/*----------------内部使用begin-------------------*/

/**
 * 辅助进程轮询
 */
int db_if_loop_once()
{
	return timer_poller();
}

/**
 * 执行配置更新
 */
void db_if_exec_update()
{
	struct plist_head *pos;
	
	for (pos = s_cfg_list.next; pos; pos = pos->next) {
		db_update_t *curr = plist_entry(pos, db_update_t, plist);

		curr->notify(curr->userdata);
	}
}

/**
 * 准备hook
 */
void db_if_prepare_hook(const char *ns, struct plist_head **head)
{
	if (!ns || !head)
		return;

	xhash_search(s_ns_hooks, SLEN(ns), (void **)head);
}

/**
 * 执行hook
 */
int db_if_exec_hook(int hookid, struct plist_head *head, db_engine_t *engine, 
								const char *key, uint32_t lkey, const char *value, 
									uint32_t lvalue, const char **new_value, uint32_t *lnew_value,
										xmsg_st **response_msg)
{
	int ret = DB_OK;
	xmsg_st *msg = NULL;
	struct plist_head *pos;
	
	if (!head || plist_empty(head) ||
			!engine || hookid < 0 || hookid >= DB_HOOK_MAX)
		return ret;
	
	for (pos = head->next; pos; pos = pos->next) {
		hook_opr_t *ht = plist_entry(pos, hook_opr_t, plist);
		if (!ht->hooks[hookid].func) 
			continue;

		/* 该hookid被注册过才初始化msg */
		if (!msg && value && lvalue)
			msg = xmsg_unpack(value, lvalue);
		
		ret = ht->hooks[hookid].func(engine, key, lkey, msg, ht->hooks[hookid].userdata, response_msg);
		/* 只处理PRE hook的返回值 */
		if (!(hookid & 0x01) && ret != DB_OK) {
			goto EXIT;
		}
	}

EXIT:
	if (msg) {
		if (ret == DB_OK && 
				new_value && lnew_value) {
			*new_value = xmsg_pack_aux(msg, lnew_value);
		}
		xmsg_release(msg);
	}
	return ret;
}


/*----------------内部使用end-------------------*/


