#ifndef __IDDB_LOGGER_H__
#define __IDDB_LOGGER_H__

#include <stdio.h>
#include "base/error.h"
#include "iddb.h"

/* 全局日志文件描述符 */
FILE *g_private_log_fd;

const char *privatelog_get_stamp();						/* 获取时间戳 */
int privatelog_check_log_limit();						/* 检查是否超出上限，返回0未超出，等于1为超出上限 */
unsigned int privatelog_get_log_len();					/* 获取日志文件大小 */
void privatelog_set_log_len(unsigned int len);			/* 设置日志文件大小 */

#define plog(format, args...) 												\
	do {																	\
		FILE *fp = g_private_log_fd ? g_private_log_fd : stderr;	\
		if (privatelog_check_log_limit() == 1) {							\
			rewind(fp);														\
			privatelog_set_log_len(0);										\
		}																	\
		int len = fprintf(fp, "%s==>%s:%d: "format, privatelog_get_stamp(), \
				__FILE__, __LINE__, ##args);								\
		privatelog_set_log_len(privatelog_get_log_len() + len);				\
		fflush(fp);															\
	} while(0)

/**
 * 记录日志
 * param msg	日志信息
 */
void do_log(char *msg);

/**
 * 日志系统初始化
 */
void db_logger_init(iddb_t *iddb);

/**
 * 一次日志处理循环
 */
void db_logger_loop_once(void);

/**
 * 日志系统反初始化
 */
void db_logger_deinit(iddb_t *iddb);

#endif
