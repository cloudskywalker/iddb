#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>

#include "sys/DefaultPort.h"
#include "sys/CommonCmd.h"
#include "sys/LogCInterface.h"
#include "sys/logstruct.h"
#include "base/strutils.h"
#include "base/error.h"
#include "base/memory.h"

#include "db_logger.h"

#define DB_LOOP_ACTIVE_INTV			(15)
#define MAX_FILE_NAME				(64)
#define LOGGER_MIN(a, b)			((a)<(b)?(a):(b))
#define TIME_STR_SIZE 				(128)					/* 时间串长度 */
#define DB_LOG_PATH					DIR_VAR_LOG "iddb"
#define DB_DIR_MODE					(0755)					/* 目录权限 */
#define MAX_LOG_COUNT				(7)						/* 仅保存最近一周的日志 */
#define MAX_FILE_LENGTH				(20971520)				/* (20 * 1024 * 1024) 日志文件最大为20M */
#define LOG_FILE_INCR				(30)					/* 目录名称增量 */


static unsigned int s_file_length = 0;
static int s_logger_init_ok;
static int s_is_debug = 0;


/**
 * 网关日志初始化
 */
static int logger_init(void)
{
	int id = IDDB_PID;

	if (!INITLOG(id)) {
		fprintf(stderr, "init logclient interface failed, maybe there's another proccess running at the same time\n");
		return -1;
	}
	
	return 0;
}

/**
 * 根据内容提取出日志类型，文件名，行号等信息，并调用库进行日志记录
 */
static void logger_log(const char *oldcontent)
{
	int type = DebugLog;
	char file[MAX_FILE_NAME] = "no_source";
	int lineno = 0;
	char *content_dup = strdup(oldcontent);
	char *content;
	int i;
	
	if (!content_dup)
		return;
		
	if (strlen(content_dup) < 5)	/* d:[] 最少要5个字符，日志才合法 */
		goto failret;
	
	if (*content_dup != 'e' && *content_dup != 'w' && *content_dup != 'i' && *content_dup != 'd') 
		goto failret;
	
	/* 转义 */
	for (i = 0; content_dup[i]; ++i) {
		if (content_dup[i] >= 0x7f || content_dup[i] < ' ')
			content_dup[i] = ' ';
	}
	
	content = content_dup + 2;		/* 跳过首两个字符 */
	if (*content == '[') {
		char *p;
		
		content++;
		p = strchr(content, ':');
		if (p) {
			unsigned int tocpy = LOGGER_MIN(MAX_FILE_NAME - 1, p - content);
			
			memcpy(file, content, tocpy);
			file[tocpy] = 0;
			
			lineno = atoi(p + 1);
			
			p = strchr(p, ']');
			if (p) {
				content = p + 1;
			}
		}
	}
	
	/* printf("type: %d, file: %s, lineno: %d, content: %s\n", type, file, lineno, content); */
	ac_logit(type, 0, file, lineno, "%s", content);
	
failret:
	free(content_dup);
}

/**
 * 取得当前时间戳
 */
static void time_stamp(char *buf, size_t buflen, char *hms, size_t hmslen)
{
	time_t timep;
	struct tm *p;
	
	time(&timep);
	p = localtime(&timep);
	if (!p) {									/* 失败时返回19700101 */
		const char fallback[] = "19700101";
		const char fallbackhms[] = "000000";
		memcpy(buf, fallback, sizeof(fallback) < buflen ? sizeof(fallback) : buflen);
		memcpy(hms, fallbackhms, sizeof(fallbackhms) < hmslen ? sizeof(fallbackhms) : hmslen);
		return;
	}
	
	str_snprintf(buf, buflen, "%d%02d%02d",
		(1900 + p->tm_year), (1 + p->tm_mon), p->tm_mday);
	str_snprintf(hms, hmslen, "%02d%02d%02d", p->tm_hour, p->tm_min, p->tm_sec);
}

/**
 * 目录排序比较函数
 */
static int dirnamecmp(const void *a, const void *b)
{
	char *s1 = *(char **)a;
	char *s2 = *(char **)b;
	
	return strcmp(s1, s2);
}

/**
 * 删除日志路径中超出的文件
 */
static int check_log_dir(void)
{
	DIR *dip;
	struct dirent *dit;
	
	/* 尝试打开目录，如果没有目录则创建之 */
	if ((dip = opendir(DB_LOG_PATH)) == NULL) {
		if (mkdir(DB_LOG_PATH, DB_DIR_MODE) < 0) {
			warn("mkdir %s failed.", DB_LOG_PATH);
			return -1;
		}
		if ((dip = opendir(DB_LOG_PATH)) == NULL) {
			warn( "opendir %s failed.", DB_LOG_PATH);
			return -1;
		}
	}
	
	/* 读取目录，如果目录个数超过规定数目，则删除之 */
	{
		char **dirname = (char **)zero_alloc(LOG_FILE_INCR * sizeof(char *));
		int size = LOG_FILE_INCR;
		int cnt = 0;
		char path[PATH_MAX];
		int i;

		while ((dit = readdir(dip)) != NULL) {
			if (strcmp(dit->d_name, ".") == 0 || strcmp(dit->d_name, "..") == 0) {
				continue;
			}
			if (cnt >= size) {
				size += LOG_FILE_INCR;
				dirname = (char **) realloc_die(dirname, size * sizeof(char *));
			}
			
			dirname[cnt] = strdup_die(dit->d_name);
			cnt++;
		}
		
		/* log文件数目大于指定数目 */
		if (cnt >= MAX_LOG_COUNT) {
			qsort(dirname, cnt, sizeof(char *), dirnamecmp);
			
			/* 只保留后MAX_LOG_CNT - 1个 */
			for (i = 0; i <= cnt - MAX_LOG_COUNT; ++i) {
				str_snprintf(path, PATH_MAX, "%s/%s", DB_LOG_PATH, dirname[i]);
				unlink(path);		/* 忽略返回值 */
			}
		}
		
		for (i = 0; i < cnt; ++i) 
			free(dirname[i]);
	
		free(dirname);
	}
	
    closedir(dip);
	return 0;
}

/**
 * 获取时间戳
 */
const char *privatelog_get_stamp(void)
{
	static char log_timestamp[TIME_STR_SIZE];
	time_t timep;
	struct tm *p;
	
	time(&timep);
	if ((p = localtime(&timep))) {
		str_snprintf(log_timestamp, TIME_STR_SIZE, "[%02d:%02d:%02d] ", p->tm_hour, p->tm_min, p->tm_sec);	
	} else {
		memcpy(log_timestamp, "[00:00:00] ", strlen("[00:00:00] ") + 1);
	}
	
	return log_timestamp;
}

/**
 * 检查是否超出上限，返回0未超出，等于1为超出
 */
int privatelog_check_log_limit(void)
{
	return s_file_length > MAX_FILE_LENGTH ? 1 : 0;
}

/**
 * 获取日志文件大小
 */
unsigned int privatelog_get_log_len(void)
{
	return s_file_length;
}

/**
 * 设置日志文件大小
 */
void privatelog_set_log_len(unsigned int len)
{
	s_file_length = len;
}

/**
 * 定时调用该函数切换日志文件
 */
static void privatelog_active(void)
{
	static char last_timestmp[TIME_STR_SIZE];
	char timestmp[TIME_STR_SIZE];
	char hmsstmp[TIME_STR_SIZE];
	char path[PATH_MAX];
	
	time_stamp(timestmp, sizeof(timestmp), hmsstmp, sizeof(hmsstmp));
	if (strcmp(last_timestmp, timestmp) != 0) {
		check_log_dir();
		str_snprintf(path, PATH_MAX, "%s/%s-%s.log", DB_LOG_PATH, timestmp, hmsstmp);
	
		if (g_private_log_fd)
			fclose(g_private_log_fd);
			
		g_private_log_fd = fopen(path, "w");
		memcpy(last_timestmp, timestmp, TIME_STR_SIZE);
		s_file_length = 0;
	}
}

/**
 * 将msg写入日志文件中
 */
static void plog_raw(const char *msg)
{
	ssize_t size;
	if (msg == NULL)
		return;
	
	FILE *fp = g_private_log_fd ? g_private_log_fd : stderr;	
	
	// 当单个日志文件超过了20M，则从头开始写，只记录最新的(这里会丢日志)
	if (fp != stderr && s_file_length > MAX_FILE_LENGTH) {
		rewind(fp);
		s_file_length = 0;
	}
	
	const char *stamp = privatelog_get_stamp();							
	size = fwrite(stamp, 1, strlen(stamp), fp);							
	size = fwrite((msg), 1, strlen(msg), fp);
	size = fwrite("\n", 1, 1, fp);
	(void)size;
	s_file_length += strlen(stamp) + strlen(msg) + 1;
	fflush(fp);
}

/**
 * 日志系统初始化
 */
void db_logger_init(iddb_t *iddb)
{
	if (iddb->debug_mode) {
		s_is_debug = 1;
		return;
	}

	privatelog_active();
	
	/* 连接日志 */
	if (logger_init()) {
		plog("application run, no logs connected, log will not send to logs\n");
		s_logger_init_ok = 0;
	} else {
		s_logger_init_ok = 1;
	}
}

static void log_one(const char *msg)
{
	if (strncmp(msg, "heart beat", strlen("heart beat")) == 0) {
		/* 排除心跳 */
	} else if (s_is_debug) {
		fprintf(stderr, "%s\n", msg);
	} else if (s_logger_init_ok) {
		logger_log(msg);
		plog_raw(msg);
	} else {
		fprintf(stderr, "%s\n", msg);
		plog_raw(msg);
	}
}

/**
 * 记录日志
 */
void do_log(char *msg)
{
	char *start = msg;
	char *p;
	
	while (*start && (p = strchr(start, '\n'))) {
		*p = 0;
		log_one(start);
		start = p + 1;
	}
	
	if (*start) {
		log_one(start);
	}
}

/**
 * 激活日志
 */
static void loop_active(void)
{
	static time_t last_time;
	time_t this_time = time(NULL);
	
	if (this_time != last_time) {
		/* 可能的切换日志 */
		privatelog_active();
		last_time = this_time;
	}
}

/**
 * 一次日志处理循环
 */
void db_logger_loop_once(void)
{
	static unsigned int loop_cnt = 0;

	if (s_is_debug)
		return;
	
	if ((loop_cnt % DB_LOOP_ACTIVE_INTV) == 0) {
		loop_active();
	}
	
	loop_cnt++;
}

/**
 * 日志系统反初始化
 */
void db_logger_deinit(iddb_t *iddb)
{
	/* 反初始化 */
	return;
}

