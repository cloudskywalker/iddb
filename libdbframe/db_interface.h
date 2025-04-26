/**
 * 为了充分发挥数据库的性能，目前只对外开放c插件，暂不放开对lua脚本的支持，不过底层已经集成了脚本机制
 */
#ifndef __DB_INTERFACE_H__
#define __DB_INTERFACE_H__

#include <stdint.h>

#include "usr/xmsg.h"
#include "usr/iddb_common.h"

#include "db_engine.h"

/* hookid，注意！！需要判断返回值是否成功的hookid一定要为偶数，一般prehook均需要判断 */
enum {
	DB_HOOK_PRE_PUT = 0,
	DB_HOOK_POST_PUT,
	DB_HOOK_PRE_SET,
	DB_HOOK_POST_SET,
	DB_HOOK_PRE_DEL,
	DB_HOOK_POST_DEL,
	DB_HOOK_CUSTOM_OPR,
	DB_HOOK_POST_OPEN,
	DB_HOOK_PRE_DROP,
	DB_HOOK_POST_DROP,
	DB_HOOK_MAX
};

/**
 * 节点超时通知函数
 * \param key key值
 * \param lkey key长度
 * \param value value值
 * \param userdata 用户数据
 * \return 0代表删除，其他代表阻止删除
 */
typedef int (*timeout_notify_fn_t)(const char *key, uint32_t lkey, xmsg_st *value, void *userdata);

/**
 * 数据操作的hook函数
 * \param engine 数据库引擎，插件里调用engine api时不需要使用事务，由客户端保证
 * \param key key值
 * \param lkey key长度
 * \param obj 属性表，当hook为PRE_DEL/POST_DEL时该值没有作用，为NULL
 * \param response [out] 回复消息，由外部释放，该消息会直接回复给客户端
 * \return 错误码，在PRE_*的hook中，返回非DB_OK值将导致客户端操作失败，并将错误信息返回给客户端，在POST_HOOK中返回值将被忽略
 */
typedef int (*db_hook_fn_t)(db_engine_t *engine, const char *key, uint32_t lkey,  
							xmsg_st *obj, void *userdata, xmsg_st **response);

/**
 * 配置更新通知函数
 * \param userdata 用户数据
 */
typedef void (*cfg_notify_fn_t)(void *userdata);

/**
 * 该功能目前只运行在辅助进程里
 * 设置数据库生存时间，与实际生存可能有误差，但保证最少生存alive秒
 * \param ns 名称空间
 * \param seconds 生存时间，单位秒
 * \param on_timeout 超时回调
 * \param userdata 用户数据
 */
void db_if_set_alive(const char *ns, uint32_t seconds, timeout_notify_fn_t on_timeout, void *userdata);

/**
 * 该功能目前只运行在写进程和辅助进程里
 * 注册配置更新，注意！！不要在插件加载时读取配置中心里的配置，因为iddb是先于ac-cfg-center启动的，在后台服务重启时会读取失败
 * \param cfg_update 配置更新回调
 * \param userdata 用户数据
 */
void db_if_reg_update(cfg_notify_fn_t cfg_update, void *userdata);

/**
 * 该功能目前只运行在写进程里
 * 注册数据操作hook，与ac-cfg-center不同的是，此处支持hook链，另外因为是多进程架构，故不能像ac-cfg-center那样可以基于现有数据进行二次扩展
 * \param ns 名称空间
 * \param hookid hook id，目前只支持PUT/SET/DEL操作，缘由同该接口注释说明，因为是多进程处理，OPEN/GET hook在此架构下的意义不大
 * \param hook hook回调
 * \param userdata 用户数据
 * \return 返回0成功安装，否则失败
 */
int db_if_install_hook(const char *ns, int hookid, 
							db_hook_fn_t hook, void *userdata);



/*----------------内部使用begin-------------------*/

/**
 * 辅助进程轮询
 */
int db_if_loop_once(void);

/**
 * 写进程和辅助进程执行配置更新
 */
void db_if_exec_update(void);

/**
 * 准备hook
 * \param ns 名称空间
 * \param head [out] hook链表头
 */
void db_if_prepare_hook(const char *ns, struct plist_head **head);

/**
 * 执行hook
 * \param hookid hook id
 * \param head hook链表头
 * \param engine 数据库引擎
 * \param key key值
 * \param lkey key长度
 * \param value value值
 * \param lvalue value长度
 * \param new_value [out] 新value值
 * \param lnew_value [out] 新value值长度
 * \param response_msg [out] 回复消息
 * \return 错误码，在PRE_*的hook中，返回非DB_OK值将导致客户端操作失败，并将错误信息返回给客户端，在POST HOOK中返回值将被忽略
 */
int db_if_exec_hook(int hookid, struct plist_head *head, db_engine_t *engine, 
								const char *key, uint32_t lkey, const char *value, 
									uint32_t lvalue, const char **new_value, uint32_t *lnew_value,
										xmsg_st **response_msg);


/*----------------内部使用end-------------------*/


#endif
