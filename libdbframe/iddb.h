#ifndef __IDDB_H__
#define __IDDB_H__

#include <stdint.h>

#include "base/hash.h"
#include "pathdef/pathdef.h"
#include "usr/iddb_common.h"

#define DB_FILE_ROOT		DIR_LINK_DATA "iddb"
#define DB_MAP_MAX_SIZE		(31457280000)		/* 29G, default size * 3 * 1000 */

/* 数据库句柄 */
typedef struct iddb_st {
	hash_st *child_process;		/* 子进程列表 */
	const char *db_dir;			/* 数据库根目录 */
	size_t db_map_size;			/* 数据库文件最大大小，单位byte */
	
	int sread_sock, swrite_sock;/* 数据库读写句柄 */
	uint16_t nprocess;			/* 子进程个数，不包括辅助进程 */
	uint8_t debug_mode;			/* 调试模式 */
} iddb_t;

/**
 * 数据库初始化.
 * \param argc 命令行参数个数
 * \param argv 命令行参数数组
 * \param environ 进程环境变量
 */
void iddb_init(int argc, char **argv, char **environ);

/**
 * 开始运行数据库
 */
void iddb_start(void);

/**
 * 停止数据库运行
 */
void iddb_stop(void);

/**
 * 数据库退出处理
 */
void iddb_deinit(void);

#endif
