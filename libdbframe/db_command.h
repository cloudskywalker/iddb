#ifndef __IDDB_COMMAND_H__
#define __IDDB_COMMAND_H__

#include "iddb.h"

/* 命令字 */
enum {
	DB_CMD_UPDATE	= 0x1,
	DB_CMD_FLUSH	= 0x2,
};

#define CMD_UPDATE_CFG		"config update\n"	/* 日志更新命令 */
#define CMD_FLUSH_NOW		"flush now\n"		/* 立即flush命令 */
#define CMD_HEART_BEAT		"heart beat\n"		/* 心跳命令 */

/**
 * 命令处理系统初始化
 */
void db_command_init(void);

/**
 * 一次命令处理循环
 * \param iddb 数据库句柄
 */
void db_command_loop_once(iddb_t *iddb);

/**
 * 命令处理系统反初始化
 */
void db_command_deinit(void);

#endif
