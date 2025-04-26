#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <dlfcn.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/prctl.h>
#include <sys/epoll.h>
#include <assert.h>
#include <errno.h>
#include <time.h>
#include <malloc.h>
#include <sys/un.h>

#include "base/timer.h"
#include "base/strutils.h"
#include "base/memory.h"
#include "base/hash.h"
#include "cl_ev/cl_ev.h"
#include "usr/xmsg.h"
#include "usr/iddb_common.h"

#include "db_worker.h"
#include "db_logger.h"
#include "db_command.h"
#include "db_epoll.h"
#include "db_engine.h"
#include "db_interface.h"

#define DB_EPOLL_SIZE			(10000)						/* 监听的最大客户端数 */
#define DB_EPOLL_TIMEOUT		(100)						/* epoll超时 */
#define DB_MAX_BUF				(20480)						/* 行长度 */
#define DB_DEBUG_INTV			(5)							/* 调试标记检测间隔 */
#define DB_HBEAT_INTV			(10)						/* 心跳发送间隔 */
#define DB_CHECK_GC_INTV		(60)						/* 脚本gc检查间隔 */
#define DB_BUF_LEN				(1024)
#define DB_RECV_TIMEOUT			(2)							/* recv默认超时 */

#define DB_SCRIPTS_SO 			"libdbscripts.so"
#define DB_DYM_FUNCTION			"db_scripts_check_gc"

#ifndef XMSG_MAGIC
#define	XMSG_MAGIC				0x47534d58
#endif
#ifndef SEQU
#define SEQU(s, l, t)			((l) == strlen(t) && memcmp((s), (t), (l)) == 0)
#endif
#ifndef ZSLEN
#define ZSLEN(s)				(s),strlen(s)+1
#endif

#define DB_EXPAND_ERRNO					__FUNCTION__,errno,strerror(errno)
#define DB_STRERROR_GEN(val, name, s) 	case DB_##name :  errnum = val; errstr = s; break;
#define DB_EPOLL_FD(e_event)			((client_data_t *)epoll_event_get_private(e_event))->fd

/* 定时器 */
#define SET_TIMER_INTERVAL(time_intv)	\
	static time_t check_time = 0;	\
	time_t tmp_time = check_time, now = time(NULL);		\
	if (tmp_time + (time_t)time_intv <= now) {	\
		check_time = now;	\
	} \
	if (tmp_time + (time_t)time_intv <= now)

#define CLOSE_FD(e_event)	do { 		\
	int __fd__ = DB_EPOLL_FD(e_event);	\
	debug("close fd:%d\n", __fd__);		\
	txn_ctl_close(__fd__);				\
	epoll_event_del(__fd__, e_event); 	\
} while(0)

typedef void (*db_scripts_check_func_t)(void);			/* 脚本gc函数指针 */

typedef struct client_data_st {
	struct plist_head *plist;
	db_engine_t *engine;
	xmsg_st *response;
	
	int fd;
} client_data_t;

typedef struct txn_ctl_st {
	db_engine_t *engine;

	int fd;
} txn_ctl_st;

static int s_debug;										/* 调试标记 */
static db_scripts_check_func_t s_scripts_check_fun;		/* 脚本gc函数指针全局变量 */
static txn_ctl_st s_txn_ctl;
static int s_is_running = 1;

/**
 * 创建客户端私有数据
 */
static client_data_t *client_data_new(int fd)
{
	client_data_t *client_data = zero_alloc(sizeof(client_data_t));

	client_data->fd = fd;
	return client_data;
}

/**
 * 释放客户端私有数据
 */
static void client_data_release(void *data)
{
	client_data_t *client_data = (client_data_t *)data;

	CLOSE_EMPTY(client_data->fd);
	CLOSE_C(client_data->engine, db_engine_close);
	CLOSE_C(client_data->response, xmsg_release);

	FREE_EMPTY(client_data);
}

/**
 * 开始全局事务对象
 */
static void txn_ctl_begin(int fd, db_engine_t *engine)
{
	s_txn_ctl.fd = fd;
	s_txn_ctl.engine = engine;
}

/**
 * 检查是否是所需要的事务操作
 */
static int txn_ctl_check(int fd)
{
	if (s_txn_ctl.fd <= 0) { return 0; }
	if (fd == s_txn_ctl.fd) { return 0; }

	return -1;
}

/**
 * 结束全局事务对象
 */
static void txn_ctl_end(int fd)
{
	if (s_txn_ctl.fd <= 0) { return; }
	if (fd != s_txn_ctl.fd) { return ; }
	
	s_txn_ctl.fd = -1;
	s_txn_ctl.engine = NULL;
}

/**
 * 关闭全局事务对象，防止事务执行的过程中，客户端句柄意外关闭
 */
static void txn_ctl_close(int fd)
{
	if (s_txn_ctl.fd <= 0) { return; }
	if (fd != s_txn_ctl.fd) { return ; }
	
	db_engine_rollback(s_txn_ctl.engine);
	
	s_txn_ctl.fd = -1;
	s_txn_ctl.engine = NULL;
}

/**
 * 执行配置更新
 */
static void db_worker_exec_update(iddb_t *iddb, child_t *child)
{
	/* TODO */
	debug("process:%d recv config update\n", child->pid);

	/* 当前只有写进程和辅助进程支持配置更新 */
	if (child->mode == DB_WRITE_MODE || 
			child->mode == DB_ASSIST_MODE) {
		db_if_exec_update();
	}
}

/**
 * 执行flush
 */
static void db_worker_exec_flush(iddb_t *iddb, child_t *child)
{
	/* TODO */
	debug("process:%d recv flush now\n", child->pid);
}

/**
 * 定时检查调试标记
 */
static void db_worker_check_debug(iddb_t *iddb)
{
	SET_TIMER_INTERVAL(DB_DEBUG_INTV) {
		s_debug = !!(access("/tmp/iddb.debug", F_OK) == 0);
		s_debug |= iddb->debug_mode;
	}
}

/**
 * 定时发送心跳
 */
static void db_worker_heart_beat(void)
{	
	SET_TIMER_INTERVAL(DB_HBEAT_INTV) {
		printf("%s", CMD_HEART_BEAT);
		fflush(stdout);
	}
}

/**
 * 自定义定时器
 */
static void db_worker_timer(iddb_t *iddb, child_t *child)
{
	/* TODO */
}

/**
 * 定时gc，防止内存短时间占用过高
 */
static void db_worker_check_gc()
{
	SET_TIMER_INTERVAL(DB_CHECK_GC_INTV) {
		if (s_scripts_check_fun) {
			s_scripts_check_fun();
		}
		/* 内存紧缩 */
		malloc_trim(0);
	}
}

/**
 * 接受并处理父进程发送的命令
 */
static void db_worker_command_take(iddb_t *iddb, child_t *child)
{
	int ret;
	fd_set rds;
	struct timeval tv;
	char buf[DB_MAX_BUF] = {0};
	int inno = fileno(stdin);

	bzero(&tv, sizeof(tv));

	FD_ZERO(&rds);
	FD_SET(inno, &rds);

	ret = select(inno + 1, &rds, NULL, NULL, &tv);
	if (ret <= 0)
		return;

	if (FD_ISSET(inno, &rds)) {
		if (fgets(buf, DB_MAX_BUF, stdin) == NULL) {
			/* 管道破裂，父进程遇到麻烦 */
			fprintf(stderr, "stdin unexpected closed by parent, exit\n");
			exit(1);
		}

		/* 检查输入命令，子进程会阻塞执行，所以接收缓冲区里可能有多个命令，需要使用字符匹配 */
		if (strstr(buf, CMD_UPDATE_CFG)) {
			debug("config updated event recv\n");
			db_worker_exec_update(iddb, child);
		}
		if (strstr(buf, CMD_FLUSH_NOW)) {
			debug("flush now event recv\n");
			db_worker_exec_flush(iddb, child);
		}
	}
}

/**
 * 信号处理
 */
static void db_worker_signal_handler(int sig)
{
	s_is_running = 0;
}

/**
 * 子进程信号重新初始化
 */
static void db_worker_signal_init(void)
{
	signal(SIGINT, db_worker_signal_handler);
	signal(SIGTERM, db_worker_signal_handler);
}

/**
 * 输出到标准输出，父进程可能重定向到网关日志
 */
static void log_output(ettype type, const char *msg, void *userdata)
{
	child_t *child = (child_t *)userdata;

	if (type < 0 || type >= _ET_LAST)
		return;
	
	if (s_debug == 0 && (type == ET_DEBUG || type == ET_INFO))	/* 不打印debug和info日志 */
		return;
		
	/* 错误类型 */
	static const char *error_type_strs[] = {
		"e",
		"w",
		"i",
		"d"
	};
	
	/* 需要拼接子进程前缀，注意：这里必须将错误类型放在首位按格式存放，不然记不了网关日志 */
	printf("%s:[%s process:%d]%s", error_type_strs[type], DB_EXPAND_CHILD(child), msg);
	fflush(stdout);
}

/**
 * 监控集合初始化
 */
static void db_worker_monitor_init(iddb_t *iddb, child_t *child)
{
	/* 失败退出由父进程重启 */
	if (epoll_event_create(DB_EPOLL_SIZE) < 0) {
		die("epoll_event_create failed:%s\n", strerror(errno));
	}
}

/**
 * 工作进程初始化准备
 */
static void db_worker_init(iddb_t *iddb, child_t *child)
{
	/* 子进程信号重新初始化 */
	db_worker_signal_init();

	/* 优先检测下debug标记 */
	db_worker_check_debug(iddb);

	/* 注册日志过滤接口 */
	if (error_output_register(log_output, (void *)child)) {
		warn("can not register output function\n");
	}

	/* 监控集合初始化 */
	db_worker_monitor_init(iddb, child);

	/* 数据库引擎初始化 */
	db_engine_init(iddb->db_map_size);
	
	/* 动态加载脚本gc函数，这样做的原因是libdbscripts.so会依赖本so，如果在本so里再依赖对方，会导致互相依赖，链接死循环，故采用动态加载的方式来做 */
	void *dlhandle = dlopen(DB_SCRIPTS_SO, RTLD_NOW);
	if (!dlhandle) {
		warn("%s: %d: %s\n", DB_SCRIPTS_SO, errno, dlerror());
	} else {
		s_scripts_check_fun = (db_scripts_check_func_t)dlsym(dlhandle, DB_DYM_FUNCTION);
		if (!s_scripts_check_fun)  {
			warn("dlsym %s, dynamic function not found:%s\n", DB_SCRIPTS_SO, dlerror());
			dlclose(dlhandle);
		}
	}
}

/**
 * 生成回复数据
 */
static xmsg_st *response_msg(int code, const void *key, uint32_t lkey, const void *data, uint32_t ldata)
{
	int errnum = -1;
	const char *errstr = "Unknown system error";
	xmsg_st *res = xmsg_new("iddb");

	switch (code) {
		IDDB_ERRNO_MAP(DB_STRERROR_GEN);
		default:
			break;
	}
	
	xmsg_add(res, SLEN("@error"), ZSLEN(errstr));
	xmsg_add(res, SLEN("@errno"), &errnum, sizeof(int));

	if (key && lkey) {
		xmsg_add(res, SLEN("@key"), key, lkey);
	}
	if (data && ldata) {
		xmsg_add(res, SLEN("@data"), data, ldata);
	}
	
	return res;
}

#define	RESPONSE_SMSG(code)				response_msg(code, NULL, 0, NULL, 0)
#define	RESPONSE_KMSG(code, key, lkey)	response_msg(code, key, lkey, NULL, 0)
#define DO_EXEC_HOOK(hookid, head, engine, key, lkey, value, lvalue) 						\
										db_if_exec_hook(hookid, head, engine, key, lkey, value, lvalue, NULL, NULL, NULL)
#define RETURN_CHECK(engine)			if (!engine) return RESPONSE_SMSG(DB_EINTERNAL)

/**
 * 打开数据库
 */
static xmsg_st *do_open(xmsg_st *msg, struct epoll_event *e_event, const char *root_dir)
{
	int code = DB_EOPEN;
	uint32_t lns;
		
	const char *progid = xmsg_get_creator(msg);
	const char *ns = xmsg_get(msg, SLEN("ns"), &lns, NULL);

	if (!ns)
		return RESPONSE_SMSG(DB_EINVALIDNS);

	debug("opening: %s, from %s\n", ns, progid);
	
	db_engine_t *engine = db_engine_open(root_dir, ns);
	if (engine) {
		code = DB_OK;
		client_data_t *data = epoll_event_get_private(e_event);
		data->engine = engine;
		
		db_if_prepare_hook(ns, &data->plist);
		DO_EXEC_HOOK(DB_HOOK_POST_OPEN, data->plist, engine, NULL, 0, NULL, 0);
	}
	
	return RESPONSE_SMSG(code);
}

/**
 * 查询数据
 */
static xmsg_st *do_get(xmsg_st *msg, db_engine_t *engine)
{
	RETURN_CHECK(engine);

	int code;
	uint32_t lkey, lvalue;
	const void *key = xmsg_get(msg, SLEN("key"), &lkey, NULL);
	const void *value;
	xmsg_st *response;

	if (!key)
		return RESPONSE_SMSG(DB_EINVALIDKEY);

	code = db_engine_get(engine, key, lkey, &value, &lvalue);
	if (code != DB_OK) {
		return RESPONSE_SMSG(code);
	}

	response = response_msg(code, NULL, 0, value, lvalue);
	FREE_EMPTY(value);
	return response;
}

/**
 * 查询根目录
 */
static xmsg_st *do_get_root(xmsg_st *msg, db_engine_t *engine)
{
	RETURN_CHECK(engine);

	const char *root = db_engine_get_root(engine);
	if (!root) {
		return RESPONSE_SMSG(DB_EINTERNAL);
	}

	xmsg_st *response = response_msg(DB_OK, NULL, 0, SLEN(root));
	return response;
}

/**
 * 查询条目个数
 */
static xmsg_st *do_count(xmsg_st *msg, db_engine_t *engine)
{
	RETURN_CHECK(engine);

	int code;
	uint32_t count;
	xmsg_st *response;

	code = db_engine_count(engine, &count);
	if (code != DB_OK) {
		return RESPONSE_SMSG(code);
	}

	response = response_msg(code, NULL, 0, &count, sizeof(uint32_t));
	return response;
}

/**
 * 添加数据
 */
static xmsg_st *do_add(xmsg_st *msg, db_engine_t *engine, struct plist_head *head)
{
	RETURN_CHECK(engine);

	int code;
	uint32_t lkey, lvalue, lnew_value = 0;
	const char *new_value = NULL;

	const void *key = xmsg_get(msg, SLEN("key"), &lkey, NULL);
	const void *value = xmsg_get(msg, SLEN("value"), &lvalue, NULL);

	if (!key)
		return RESPONSE_SMSG(DB_EINVALIDKEY);
	if (!value)
		return RESPONSE_SMSG(DB_EINVALIDVALUE);

	code = db_if_exec_hook(DB_HOOK_PRE_PUT, head, engine, key, lkey,
							value, lvalue, &new_value, &lnew_value, NULL);
	if (code != DB_OK) { goto EXIT; }

	if (new_value && lnew_value) {
		value = new_value;
		lvalue = lnew_value;
	}
	
	code = db_engine_put(engine, key, lkey, value, lvalue);
	if (code == DB_OK) { 
		DO_EXEC_HOOK(DB_HOOK_POST_PUT, head, engine, key, lkey, value, lvalue); 
	}
	FREE_EMPTY(new_value);
	
EXIT:
	return RESPONSE_KMSG(code, key, lkey);
}

/**
 * 修改数据
 */
static xmsg_st *do_mod(xmsg_st *msg, db_engine_t *engine, struct plist_head *head)
{
	RETURN_CHECK(engine);

	int code;
	uint32_t lkey, lvalue, lnew_value = 0;
	const char *new_value = NULL;

	const void *key = xmsg_get(msg, SLEN("key"), &lkey, NULL);
	const void *value = xmsg_get(msg, SLEN("value"), &lvalue, NULL);

	if (!key)
		return RESPONSE_SMSG(DB_EINVALIDKEY);
	if (!value)
		return RESPONSE_SMSG(DB_EINVALIDVALUE);

	code = db_if_exec_hook(DB_HOOK_PRE_SET, head, engine, key, lkey, 
							value, lvalue, &new_value, &lnew_value, NULL);
	if (code != DB_OK) { goto EXIT; }

	if (new_value && lnew_value) {
		value = new_value;
		lvalue = lnew_value;
	}
	
	code = db_engine_set(engine, key, lkey, value, lvalue);
	if (code == DB_OK) { 
		DO_EXEC_HOOK(DB_HOOK_POST_SET, head, engine, key, lkey, value, lvalue); 
	}
	FREE_EMPTY(new_value);

EXIT:
	return RESPONSE_KMSG(code, key, lkey);
}

/**
 * 删除数据
 */
static xmsg_st *do_del(xmsg_st *msg, db_engine_t *engine, struct plist_head *head)
{
	RETURN_CHECK(engine);

	int code;
	uint32_t lkey;
	const void *key = xmsg_get(msg, SLEN("key"), &lkey, NULL);

	if (!key)
		return RESPONSE_SMSG(DB_EINVALIDKEY);

	code = DO_EXEC_HOOK(DB_HOOK_PRE_DEL, head, engine, key, lkey, NULL, 0);
	if (code != DB_OK) { goto EXIT; }
	
	code = db_engine_del(engine, key, lkey);
	if (code == DB_OK) {
		DO_EXEC_HOOK(DB_HOOK_POST_DEL, head, engine, key, lkey, NULL, 0);
	}

EXIT:	
	return RESPONSE_KMSG(code, key, lkey);
}

/**
 * 开始事务
 */
static xmsg_st *do_start(xmsg_st *msg, db_engine_t *engine, int fd)
{
	RETURN_CHECK(engine);

	uint32_t lkey;
	const void *key = xmsg_get(msg, SLEN("readonly"), &lkey, NULL);
	int code = db_engine_start(engine, key ? *(int *)key : 0);

	if (code == DB_OK) { txn_ctl_begin(fd, engine); }
	return RESPONSE_SMSG(code);
}

/**
 * 回滚事务
 */
static xmsg_st *do_rollback(xmsg_st *msg, db_engine_t *engine, int fd)
{
	RETURN_CHECK(engine);

	int code = db_engine_rollback(engine);
	
	if (code == DB_OK) { txn_ctl_end(fd); }
	return RESPONSE_SMSG(code);
}

/**
 * 提交事务
 */
static xmsg_st *do_commit(xmsg_st *msg, db_engine_t *engine, int fd)
{
	RETURN_CHECK(engine);

	int code = db_engine_commit(engine);
	
	if (code == DB_OK) { txn_ctl_end(fd); }
	return RESPONSE_SMSG(code);
}

/**
 * 生成自定义回复数据
 */
static xmsg_st *custom_msg(xmsg_st *response, int code)
{
	int errnum = -1;
	const char *errstr = "Unknown system error";

	switch (code) {
		IDDB_ERRNO_MAP(DB_STRERROR_GEN);
		default:
			break;
	}
	
	xmsg_add(response, SLEN("@error"), ZSLEN(errstr));
	xmsg_add(response, SLEN("@errno"), &errnum, sizeof(int));
	
	return response;
}

/**
 * 清空数据库表
 */
static xmsg_st *do_drop(xmsg_st *msg, db_engine_t *engine, struct plist_head *head)
{
	int code = DO_EXEC_HOOK(DB_HOOK_PRE_DROP, head, engine, NULL, 0, NULL, 0);
	if (code != DB_OK) { goto EXIT; }
	
	db_engine_drop(engine);
	DO_EXEC_HOOK(DB_HOOK_POST_DROP, head, engine, NULL, 0, NULL, 0);

EXIT:
	return RESPONSE_SMSG(code);
}

/**
 * 自定义操作
 */
static xmsg_st *do_custom_opr(xmsg_st *msg, db_engine_t *engine, struct plist_head *head)
{
	int code;
	uint32_t lkey, lvalue = 0;
	xmsg_st *response = NULL;

	const void *key = xmsg_get(msg, SLEN("opr"), &lkey, NULL);
	const void *value = xmsg_get(msg, SLEN("data"), &lvalue, NULL);

	if (!key)
		return RESPONSE_SMSG(DB_EINVALIDKEY);

	code = db_if_exec_hook(DB_HOOK_CUSTOM_OPR, head, engine, key, lkey, 
									value, lvalue, NULL, NULL, &response);
	if (!response) {
		response = RESPONSE_SMSG(code);
	} else {
		response = custom_msg(response, code);
	}
	return response;
}

/**
 * 命令分发
 */
static xmsg_st *db_worker_dispatch(struct epoll_event *e_event, xmsg_st *request, iddb_t *iddb, child_t *child)
{
	uint32_t lcmd;
	xmsg_st *res;
	const char *cmd = xmsg_get(request, SLEN("cmd"), &lcmd, NULL);
	client_data_t *data = epoll_event_get_private(e_event);
	int fd = data->fd;
	db_engine_t *engine = data->engine;
	struct plist_head *head = data->plist;
	
	if (!cmd) {
		return RESPONSE_SMSG(DB_EINVALIDCMD);
	}
	if (!engine && strcmp(cmd, "open") != 0) {
		return RESPONSE_SMSG(DB_ENOTOPEN);
	}

	switch(*cmd) {
		case 'o':
			res = do_open(request, e_event, iddb->db_dir);
			break;
		case 'g':
			res = do_get(request, engine);
			break;
		case 'p':
			res = do_get_root(request, engine);
			break;
		case 'n':
			res = do_count(request, engine);
			break;
		case 'a':
			res = do_add(request, engine, head);
			break;
		case 'm':
			res = do_mod(request, engine, head);
			break;
		case 'd':
			res = do_del(request, engine, head);
			break;
		case 's':
			res = do_start(request, engine, fd);
			break;
		case 'r':
			res = do_rollback(request, engine, fd);
			break;
		case 'c':
			res = do_commit(request, engine, fd);
			break;
		case 'u':
			res = do_custom_opr(request, engine, head);
			break;
		case 'e':
			res = do_drop(request, engine, head);
			break;
		default:
			res = RESPONSE_SMSG(DB_EINVALIDCMD);
	}

	return res;
}

/**
 * 回复请求
 */
static void db_worker_send_response(struct epoll_event *e_event, iddb_t *iddb, child_t *child)
{
	uint32_t size_out;
	client_data_t *data = epoll_event_get_private(e_event);
	int client_fd = data->fd;
	assert(data && data->response);
	char *buf = xmsg_pack_aux(data->response, &size_out);

	/* 发送len */
	if (send(client_fd, &size_out, sizeof(uint32_t), 0) != sizeof(uint32_t)) {
		warn("%s send data len failed, errno:%d, errstr:%s\n", DB_EXPAND_ERRNO);
		CLOSE_FD(e_event); 	/* 关闭触发重连 */
		goto EXIT;
	}

	/* 发送data */
	if (send(client_fd, buf, size_out, 0) != size_out) {
		warn("%s send data failed, errno:%d, errstr:%s\n", DB_EXPAND_ERRNO);
		CLOSE_FD(e_event); 	/* 关闭触发重连 */
	}
	
	/* 重设epoll事件 */
	epoll_event_set(client_fd, e_event, EPOLLIN);

EXIT:
	FREE_EMPTY(buf);
}

/**
 * 请求接收
 */
static void db_worker_recv_request(struct epoll_event *e_event, iddb_t *iddb, child_t *child)
{
	int len, cur = 0;
	uint32_t data_len = 0;
	char *buf = NULL;
	xmsg_st *request, *res;
	client_data_t *data = epoll_event_get_private(e_event);
	int client_fd = data->fd;

	/* 接收len */
	len = recv(client_fd, &data_len, sizeof(uint32_t), 0);
	if (len < sizeof(uint32_t) || data_len < sizeof(uint32_t)) {
		warn("%s recv failed, errno:%d, errstr:%s, request_len:%d data_len:%d is invalid, close!\n", DB_EXPAND_ERRNO, len, data_len);
		CLOSE_FD(e_event);	/* 关闭触发重连 */
		return;
	}

	/* 接收data */
	buf = zero_alloc(data_len); 
	while (cur < data_len) {
		len = recv(client_fd, buf, data_len, 0);
		if (len <= 0) {
			debug("%s recv failed, maybe close by peer, errno:%d, errstr:%s\n", DB_EXPAND_ERRNO);
			CLOSE_FD(e_event);	/* 关闭触发重连 */
			FREE_EMPTY(buf);
			return;
		} else {
			cur += len;
		}
	}

	/* 判断魔数是否合法，本来xmsg_unpack里应该会做校验的，但是并没有做，
	 * 这里保险起见，双层校验
	 */
	if (*(uint32_t *)buf != XMSG_MAGIC || 
		!(request = xmsg_unpack(buf, data_len))) {
		warn("%s recv request data is invalid, magic:%x!\n", __FUNCTION__, *(uint32_t *)buf);
		CLOSE_FD(e_event);	/* 关闭触发重连 */
		FREE_EMPTY(buf);
		return;
	}
	FREE_EMPTY(buf);
	
	/* 命令分发 */
	res = db_worker_dispatch(e_event, request, iddb, child);

	/* 重设epoll事件 */
	if (data->response) { xmsg_release(data->response); }
	data->response = res;
	epoll_event_set(client_fd, e_event, EPOLLOUT);

	xmsg_release(request);
}

/**
 * 接收连接
 */
static void db_worker_accept(iddb_t *iddb, child_t *child, int sock_fd)
{
	int client_fd, flags;
	struct timeval tv;
	struct sockaddr_in addr;
	unsigned int addr_size = sizeof(addr);

	/* 2.6内核后就不再有惊群现象了 */
	client_fd = accept(sock_fd, (struct sockaddr*)&addr, &addr_size);
	if (client_fd < 0)	{ return; }
	
	/* 关闭非阻塞IO，防止一次调用db_worker_recv_request时数据接收不完整 */
	flags = fcntl(client_fd, F_GETFL, 0);
    fcntl(client_fd, F_SETFL, flags & ~O_NONBLOCK);
	
	tv.tv_sec = DB_RECV_TIMEOUT;
	tv.tv_usec = 0;

	/* 设置recv超时，防止db_worker_recv_request阻塞 */
	if (0 != setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, (void*)&tv, sizeof(tv)))
		warn("unable to set RCVTIMEO on socket!\n");

	/* 设置缓冲区大小 */
	if (0 != dbcm_set_socketbuf_size(client_fd))
		warn("set socket bufsize error:%s\n", strerror(errno));
	
	client_data_t *client_data = client_data_new(client_fd);
	epoll_event_put(client_fd, EPOLLIN, (void *)client_data, client_data_release);
}

/**
 * 请求轮询
 */
static void db_worker_polling(iddb_t *iddb, child_t *child)
{
	int i, count = 0;
	struct epoll_event e_events[DB_EPOLL_SIZE];
	
	count = epoll_event_wait(e_events, DB_EPOLL_SIZE, DB_EPOLL_TIMEOUT);
	if (count < 0) {
		if (errno == EINTR) { return; }
		/* 其他失败需要退出 */
		die("epoll_wait failed:%d %s\n", errno, strerror(errno));
	}
	
	for (i = 0; i < count; i++) {
		/* 关闭套接字 */
		if (e_events[i].events & (EPOLLERR | EPOLLRDHUP | EPOLLHUP)) {
			CLOSE_FD(&e_events[i]);
			continue;
		}

		/* 同一时间段内只允许执行一个事务，防止客户端并发执行事务时可能引发的事务错乱问题 */
		if ((e_events[i].events & EPOLLIN) &&
				txn_ctl_check(DB_EPOLL_FD(&e_events[i])) == 0) {
			db_worker_recv_request(&e_events[i], iddb, child);
		} else if (e_events[i].events & EPOLLOUT) {
			db_worker_send_response(&e_events[i], iddb, child);
		}
	}
}

/**
 * 读写进程轮询
 */
static void db_worker_loop_once(iddb_t *iddb, child_t *child)
{
	int sock = child->mode == DB_READ_MODE ? iddb->sread_sock : iddb->swrite_sock;

	db_worker_accept(iddb, child, sock);

	db_worker_polling(iddb, child);
}

/**
 * 工作进程轮询
 */
static void db_worker_poller(iddb_t *iddb, child_t *child)
{
	if (child->mode == DB_ASSIST_MODE) {
		if (db_if_loop_once() == 0)
			usleep(10000);
	} else {
		db_worker_loop_once(iddb, child);
	}
}

/**
 * ev轮询
 */
static void db_worker_ev_poller(void)
{
	cl_ev_loop_nowait(1);
	cl_event_loop_once();
}

/**
 * 启动工作进程
 */
void db_worker_start(iddb_t *iddb, child_t *child)
{
	/* 进程初始化准备 */
	db_worker_init(iddb, child);

	/* 子进程已设置为伴随父进程退出 */
	while (s_is_running) {
		db_worker_check_debug(iddb);
		db_worker_command_take(iddb, child);
		db_worker_heart_beat();
		db_worker_poller(iddb, child);
		db_worker_ev_poller();
		db_worker_timer(iddb, child);
		db_worker_check_gc();
	}
}

