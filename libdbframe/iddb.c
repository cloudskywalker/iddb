#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <assert.h>

#include "base/error.h"
#include "base/memory.h"

#include "iddb.h"
#include "db_logger.h"
#include "db_command.h"
#include "db_server.h"

#define CPU_LITTLE_NAP		(3000)
#define GB					(1024 * 1024 * 1024)
#define MAX_PROCESS			(256)

static int s_keep_running = 1;
static iddb_t *s_iddb;

/**
 * usage
 */
static void usage() {
	printf("Usage: iddb [-c number] [-s number] [-f path] [-h] [-d]\n"
	       "\t-c number    Set the number of child processes. Not include assist process.\n"
	       "\t-s number    Set the database map size (maximum size on disk).\n"
		   "\t-f path      Path to the database directory.\n"
	       "\t-h           Shows this help and exits.\n"
	       "\t-d           Debug mode. Error messages are more verbose.\n"
	       "\n");
}

/** 
 * 命令行参数解析
 */
static void db_args_init(int argc, char **argv, iddb_t *iddb)
{
	assert(iddb);
	
	char *optstr = "dhc:s:f:";
	int flag;
	
	while ((flag = getopt(argc, argv, optstr)) != -1) {
		switch (flag) {
		case 'c':
			iddb->nprocess = (uint16_t)strtol(optarg, NULL, 0);
			break;
		case 's':
			iddb->db_map_size = strtoul(optarg, NULL, 0);
			break;
		case 'f':
			iddb->db_dir = strdup_die(optarg);
			break;
		case 'd':
			iddb->debug_mode = 1;
			break;
		case 'h':
			usage();
			exit(0);
		}
	}
}

/**
 * 获取KEY:VALUE结构里面的VALUE键的数值
 */
static uint64_t get_proc_value(const char *file, const char *key)
{
	FILE *fp = fopen(file, "r");
	char buf[BUFSIZ];
	if (!fp)
		return 0;

	while (fgets(buf, sizeof(buf), fp)) {
		if (memcmp(buf, SLEN(key)) == 0) {
			fclose(fp);
			return atoll(buf + strlen(key)) * 1024;
		}
	}

	fclose(fp);
	return 0;
}

/** 
 * 根据内存大小计算启动进程个数，1G对应一个进程
 */
static uint64_t get_cpu_count_by_memory()
{
	uint64_t memory_size = get_proc_value("/proc/meminfo", "MemTotal:");
	uint64_t num = memory_size / GB;
	return num ? (num + 1) : 1;
}

/** 
 * 获取工作进程数
 */
static int iddb_get_process_count()
{
	/* 取得cpu个数 */
	int ncpu = sysconf(_SC_NPROCESSORS_ONLN);
	int mcpu = get_cpu_count_by_memory();
	
	if (mcpu < ncpu)
		ncpu = mcpu;
	
	/* 全局变量 */
	if (getenv("NPROCESS")) {
		ncpu = strtol(getenv("NPROCESS"), NULL, 0);
	}

	if (ncpu < 2 || ncpu > MAX_PROCESS) {
		die("worker process count:at least 2 and less than %d\n", MAX_PROCESS);
	}
	
	return ncpu;
}

/** 
 * 获取数据库文件map最大值
 */
static size_t iddb_get_map_size()
{
	size_t map_size = DB_MAP_MAX_SIZE;
	
	/* 全局变量 */
	if (getenv("DB_MAP_MAX_SIZE")) {
		map_size = strtoul(getenv("DB_MAP_MAX_SIZE"), NULL, 0);;
	}
	
	return map_size;
}

/** 
 * 获取数据库根目录
 */
static const char *iddb_get_root_dir()
{
	const char *db_dir = DB_FILE_ROOT;
	
	/* 全局变量 */
	if (getenv("DB_FILE_ROOT")) {
		db_dir = getenv("DB_FILE_ROOT");
	}
	return db_dir;
}

/** 
 * 创建数据库结构体
 */
static iddb_t *iddb_new(int argc, char **argv)
{
	iddb_t *iddb = zero_alloc(sizeof(iddb_t));
	
	iddb->nprocess = iddb_get_process_count();
	iddb->db_dir = strdup_die(iddb_get_root_dir());
	iddb->db_map_size = iddb_get_map_size();
	
	db_args_init(argc, argv, iddb);
	
	return iddb;
}

/** 
 * 销毁数据库结构体
 */
static void iddb_release(iddb_t *iddb)
{
	if (!iddb) return;
	 
	FREE_EMPTY(iddb->db_dir);
	FREE_EMPTY(iddb);
}

/**
 * 数据库初始化
 */
void iddb_init(int argc, char **argv, char **environ)
{
	s_iddb = iddb_new(argc, argv);
	
	db_logger_init(s_iddb);
	db_command_init();
	db_server_init(argv, environ, s_iddb);
}

/**
 * 开始运行数据库
 */
void iddb_start(void)
{
	/* 先触发一次全部配置更新 */
	db_server_exec_command(s_iddb, DB_CMD_UPDATE);
	
	while (s_keep_running) {
		db_command_loop_once(s_iddb);
		usleep(CPU_LITTLE_NAP);	
		db_server_loop_once(s_iddb);
		db_logger_loop_once();
	}
}

/**
 * 停止数据库运行
 */
void iddb_stop(void)
{
	s_keep_running = 0;
}

/**
 * 数据库退出处理
 */
void iddb_deinit(void)
{
	db_logger_deinit(s_iddb);
	db_command_deinit();
	db_server_deinit(s_iddb);

	iddb_release(s_iddb);
}
