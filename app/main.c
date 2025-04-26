/**
 * iddb数据库
 * \author qinzhen
 * \note iddb基于LMDB引擎开发，采用多进程、epoll、读写分离模式，支持插件扩展；
 *		 iddb为类MMAPv1引擎的mongoDB，基于文件映射的文件型数据库。
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/file.h>

#include "sys/resource.h"
#include "usr/module.h"
#include "base/error.h"
#include "i18n/i18n.h"

#include "iddb.h"
#include "db_command.h"
#include "db_server.h"
#include "db_logger.h"
#include "db_scripts.h"

#define MAX_FILE_FD_NUM			(100000)
#define IDDB_ROOT				"@/.."
#define IDDB_CONFIG_ROOT		IDDB_ROOT "/config"
#define IDDB_CONFIG_PATH		IDDB_CONFIG_ROOT "/iddbmod.ini"

extern char **environ;

/**
 * 进程单例
 */
static void keep_singleton(void)
{
	int pid_file = open("/var/lock/iddb.pid", O_CREAT | O_RDWR | O_CLOEXEC, 0666);
	if (pid_file < 0) {
		warn("can not open lock file\n");
		sleep(3);
		exit(1);
	}
	
	int rc = flock(pid_file, LOCK_EX | LOCK_NB);
	if (rc) {
		warn("Another instance is running\n");
		sleep(3);
		exit(1);
	}
	/* 单实例保证，句柄不能关闭 */
}

/**
 * 信号处理
 */
static void db_signal_handler(int signal)
{
	iddb_stop();
}

/**
 * 信号初始化
 */
static void db_signal_init(void)
{
	signal(SIGINT, db_signal_handler);
	signal(SIGTERM, db_signal_handler);
	signal(SIGABRT, db_signal_handler);
}

/**
 * 初始化运行环境
 */
static void db_env_init(void)
{
	db_signal_init();
	
	module_set_config_root(IDDB_CONFIG_ROOT);
	module_set_lang_id(i18n_get_cur_lang());

	/* 设置句柄上限 */
	struct rlimit limit;
	limit.rlim_max = MAX_FILE_FD_NUM;
	limit.rlim_cur = MAX_FILE_FD_NUM;
	
	if (setrlimit(RLIMIT_NOFILE, &limit) != 0) {
		warn("setrlimit error, setmax=%d\n", MAX_FILE_FD_NUM);
	}
}

/**
 * 加载插件
 */
static int db_plugins_load(const char *cfg_path)
{
	return module_load_all(cfg_path, 0);
}

int main(int argc, char **argv)
{
	keep_singleton();
	db_env_init();
	
	/* 加载插件 */
	if (db_plugins_load(IDDB_CONFIG_PATH)) {
		die("Can not load module\n");
	}
	/* 加载脚本 */
	if (db_scripts_load(IDDB_ROOT)) {
		die("Can not load scripts\n");
	}
	
	iddb_init(argc, argv, environ);
	iddb_start();
	iddb_deinit();
	return 0;
}
