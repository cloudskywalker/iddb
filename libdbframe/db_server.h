#ifndef __DB_SERVER_H__
#define __DB_SERVER_H__

#include "iddb.h"

/* 工作模式 */
enum {
	DB_READ_MODE = 0,
	DB_WRITE_MODE,
	DB_ASSIST_MODE,
	DB_MAX_MODE,
};

static inline const char *db_mode_name(int mode)
{
	switch(mode) {
		case DB_READ_MODE:
			return "read";
		case DB_WRITE_MODE:
			return "write";
		case DB_ASSIST_MODE:
			return "assist";
		default:
			return "unkown";
	}
}

#define DB_EXPAND_CHILD(child)	(db_mode_name(child->mode)),(child->pid)

/* 子进程句柄 */
typedef struct child_st {
	const char *name;			/* 子进程名 */

	time_t uptime;				/* 保活时间戳 */
	pid_t pid;					/* pid */
	int in, out;				/* 读写管道 */

	uint8_t mode;				/* 读写模式 */
	uint8_t command;			/* 命令字 */
} child_t;

/**
 * 服务系统初始化
 * \param argv 命令行参数
 * \param environ 进程环境变量
 * \param iddb 数据库句柄
 */
void db_server_init(char **argv, char **environ, iddb_t *iddb);

/**
 * 一次服务处理循环
 */
void db_server_loop_once(iddb_t *iddb);

/**
 * 服务退出
 * \param iddb 数据库句柄
 */
void db_server_deinit(iddb_t *iddb);

/**
 * 命令通知
 * \param iddb 数据库句柄
 * \param command 命令字
 */
void db_server_exec_command(iddb_t *iddb, uint8_t command);

#endif
