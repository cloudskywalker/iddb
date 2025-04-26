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
#include <dirent.h>
#include <sys/un.h>

#include "sys/file_path.h"
#include "base/timer.h"
#include "base/strutils.h"
#include "base/memory.h"
#include "base/hash.h"

#include "db_server.h"
#include "db_worker.h"
#include "db_logger.h"
#include "db_command.h"

#define DB_LOOP_CHECK_INTV		(100)						/* 心跳检测间隔 */
#define DB_CHILD_STUCKED_INTV	(30)						/* 读写进程假死超时，秒(n秒未有心跳则认为假死) */
#define DB_CHILD_A_STUCKED_INTV	(15 * 60)					/* 辅助进程假死超时，秒(n秒未有心跳则认为假死) */
#define DB_EPOLL_SIZE			(10000)						/* 监听的最大客户端数 */
#define DB_EPOLL_TIMEOUT		(100)						/* epoll超时 */
#define DB_MAX_BUF				(20480)						/* 行长度 */
#define DB_FULL_DB_INTV			(10 * 60)					/* 默认全量同步最短间隔时长 */
#define DB_BUF_LEN				(1024)
#define UNPATH_OFFSET			(1)

#define DB_DOMAIN_RSOCK			"/var/iddbr.sock"
#define DB_DOMAIN_WSOCK			"/var/iddbw.sock"
#define DB_RCHILD_NAME			"iddb: read worker process"
#define DB_WCHILD_NAME			"iddb: write worker process"
#define DB_ACHILD_NAME			"iddb: assist worker process"

#define DUP_STDFD(dst, src) do {	\
	close(fd##dst[~src]);			\
	if (fd##dst[src] != src) {		\
		dup2(fd##dst[src], src);	\
		close(fd##dst[src]);		\
	}	\
} while(0)

#define CLOSE_FD(IN, OUT) do {		\
		close(fd##IN[0]);			\
		close(fd##IN[1]);			\
		close(fd##OUT[0]);			\
		close(fd##OUT[1]);			\
} while(0)

static char **s_pr_argv;		/* 进程命令行参数 */
static char **s_pr_environ;		/* 进程环境变量 */
static int s_epollfd;			/* epoll句柄 */

/** 
 * 将所要监听的套接字进行处理
 */
static int epoll_ctl_all(int epoll_fd, int events, int ctl, int fd, void *userdata)
{
	int err;
	struct epoll_event e_event;
	
	bzero(&e_event, sizeof(e_event));
	e_event.events = events;
	e_event.data.ptr = userdata;
	
	err = epoll_ctl(epoll_fd, ctl, fd, &e_event);
	if (err < 0) {
		plog("epoll_ctl failed, opr:%d\n", ctl);
		return -1;
	}
	
	return 0;
}

/** 
 * 将服务节点添加到监听集合里
 */
static int epoll_set_add(child_t *child)
{
	if (epoll_ctl_all(s_epollfd, EPOLLIN, EPOLL_CTL_ADD, child->in, (void *)child))
		return -1;
	
	if (epoll_ctl_all(s_epollfd, EPOLLOUT, EPOLL_CTL_ADD, child->out, (void *)child)) {
		epoll_ctl_all(s_epollfd, 0, EPOLL_CTL_DEL, child->in, NULL);
		return -1;
	}
	
	return 0;
}

/** 
 * 将服务节点从监听集合删除
 */
static int epoll_set_del(child_t *child)
{
	if (epoll_ctl_all(s_epollfd, 0, EPOLL_CTL_DEL, child->in, (void *)child)
			|| epoll_ctl_all(s_epollfd, 0, EPOLL_CTL_DEL, child->out, (void *)child)) {
		return -1;
	}
	
	return 0;
}

/**
 * 启动服务监听
 */
static int db_server_listen(const char *sock_path)
{
#define EXPAND_SOCK_ERR	__FUNCTION__,sock_path,strerror(errno)

	int sock_fd, flags;
	socklen_t socklen;
	struct sockaddr_un sa;
	
	bzero(&sa, sizeof(sa));
	sa.sun_family = AF_UNIX;
	/* 使用虚拟文件路径，保持和proto_server的行为一致，否则proto_client连接不上 */
	str_strlcpy(sa.sun_path + UNPATH_OFFSET, sock_path, sizeof(sa.sun_path));
	socklen = sizeof(sa);
	
	sock_fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sock_fd < 0) {
		die("%s socket %s failed, err:%s\n", EXPAND_SOCK_ERR);
	}

	/* 设置非阻塞 */
	flags = fcntl(sock_fd, F_GETFL, 0);
    fcntl(sock_fd, F_SETFL, flags | O_NONBLOCK);
	
	if (bind(sock_fd, (struct sockaddr*)&sa, socklen) != 0) {
		close(sock_fd);
		die("%s bind %s failed, err:%s\n", EXPAND_SOCK_ERR);
	}

	if(listen(sock_fd, 10) < 0) {
		close(sock_fd);
		die("%s listen %s failed, err:%s\n", EXPAND_SOCK_ERR);
    }

	return sock_fd;
}

/**
 * 创建子进程句柄
 */
static child_t *child_new(int mode, int in, int out)
{
	child_t *child = zero_alloc(sizeof(child_t));

	child->mode = mode;
	child->in = dup(in);
	child->out = dup(out);
	child->uptime = time(NULL);

	if (mode == DB_ASSIST_MODE) {
		child->name = DB_ACHILD_NAME;
	} else {
		child->name = mode == DB_READ_MODE ? DB_RCHILD_NAME : DB_WCHILD_NAME;
	}

	return child;
}

/**
 * 释放子进程句柄
 */
static void child_release(child_t *child)
{
	if (!child) return;

	CLOSE_EMPTY(child->in);
	CLOSE_EMPTY(child->out);
	
	FREE_EMPTY(child);
}

/**
 * 初始化子进程句柄
 */
static child_t *child_init(int mode, int in, int out)
{
	child_t *child = child_new(mode, in, out);

	/* 将服务节点加入监听集合 */
	if (epoll_set_add(child) != 0) {
		plog("epoll_set_add error:%s\n", strerror(errno));
		child_release(child);
		return NULL;
	}

	return child;
}

/**
 * 反初始化子进程句柄
 */
static void child_deinit(child_t *child)
{
	/* 将服务节点从监听集合删除 */
	epoll_set_del(child);

	child_release(child);
}

/**
 * 重新分配环境变量指向的内存地址
 * \param [out] plast_env 返回原始环境变量内存的结尾地址，为NULL时代表环境变量为空
 * \return 0-代表成功，-1-代表失败
 */
static int realloc_pr_env(char **plast_env)
{	
	int i, env_size = 0;
	char *pnew_env = NULL;
	int env_name_len = strlen(s_pr_argv[0]) + strlen("_=") + 1;
	char *new_name = zero_alloc(env_name_len);

	str_snprintf(new_name, env_name_len, "_=%s", s_pr_argv[0]);

	for (i = 0; s_pr_environ[i]; i++) {
		env_size = env_size + strlen(s_pr_environ[i]) + 1;
		/* env的连续空间不包括用户setenv设置的环境变量，这里以指定格式行为结尾标识系统环境变量结束，格式为_:argv[0] */
		if (strcasecmp(s_pr_environ[i], new_name) == 0) {
			*plast_env = s_pr_environ[i] + strlen(s_pr_environ[i]) + 1;
			printf("last env value:%s, end address:%p, argv[0] address:%p\n", s_pr_environ[i], *plast_env, s_pr_argv[0]);
		}
	}
	
	FREE_EMPTY(new_name);

	--i;
	if (i < 0 || !(*plast_env)) {
		*plast_env = NULL;
		return -1;
	}
	
	pnew_env = (char *)zero_alloc(env_size);
	
	for (i = 0; s_pr_environ[i]; i++) {
		memcpy(pnew_env, s_pr_environ[i], strlen(s_pr_environ[i]) + 1);
		pnew_env = pnew_env + strlen(s_pr_environ[i]) + 1;
		s_pr_environ[i] = pnew_env;
	}
	
	return 0;
}

/**
 * 子进程重命名
 */
static void db_child_rename(const char *process_name)
{
	int name_len = 0;
	char *child_name = NULL;
	char *plast_env = NULL;
	
	/* 
	 * 修改argv[0]，使ps和top命令都能查询到修改后的名称，且放开名称长度限制
	 * 原理如下：linux环境下argv和环境变量environ在内存空间上是相邻的，
	 * 将environ和argv[1]以及其后的参数保存到其他空间，腾出这一整块的内存空间给argv[0]使用。
	 */
	if (realloc_pr_env(&plast_env) != 0)
		return;
	
	name_len = plast_env - s_pr_argv[0];
	printf("new argv[0] len:%d\n", name_len);
	child_name = (char *)zero_alloc(name_len);
	str_snprintf(child_name, name_len, "%s", process_name);
	s_pr_argv[1] = NULL;
	str_strlcpy(s_pr_argv[0], child_name, name_len);
	
	/* 
	 * 使用prctl修改，该种方式只能修改/prco/$(PID)/stat和/prco/$(PID)/status的值，使用ps -L -p pid能看到，
	 * 且名称长度有限制最多16个字节（包括'\0'）
	 */
	prctl(PR_SET_NAME, child_name);
	FREE_EMPTY(child_name);
	
	/* 结合以上两种方法，该子进程就会被彻底改名，不论用任何方法查看都是修改后的名称 */
}

/**
 * 启动工作进程
 */
static int start_worker_process(iddb_t *iddb, int mode)
{
	int fdin[2] = { 0 };
	int fdout[2] = { 0 };
	pid_t pid;
	child_t *child = NULL;
	
	/* 创建用于连接的管道 */
	if (pipe(fdin) < 0) {
		plog("pipe fdin error:%s\n", strerror(errno));
		return -1;
	}
	if (pipe(fdout) < 0) {
		plog("pipe fdout error:%s\n", strerror(errno));
		CLOSE_FD(in, in);
		return -1;
	}
	
	child = child_init(mode, fdin[0], fdout[1]);
	if (!child) {
		plog("child_init failed!\n");
		CLOSE_FD(in, out);
		return -1;
	}

	/* 运行进程，并定向子进程stdin和stdout用于与当前进程通讯 */
	if ((pid = fork()) < 0) {
		plog("can not create process, err:%s\n", strerror(errno));
		CLOSE_FD(in, out);
		child_deinit(child);

		return -1;
	}
	
	if (pid > 0) {
		/* 父进程 */
		CLOSE_FD(in, out);
		/* 更新pid */
		child->pid = pid;
		/* 加入进程列表 */
		xhash_insert(iddb->child_process, (const void *)&pid, sizeof(pid), (void *)child);

		plog("DB server create worker process mode:%s pid:%d, done\n", DB_EXPAND_CHILD(child));
		return 0;
	}

	child->pid = getpid();
	/* 父进程退出时自动发送信号给子进程 */
	prctl(PR_SET_PDEATHSIG, SIGKILL);
	/* 子进程重命名 */
	db_child_rename(child->name);
	
	DUP_STDFD(in, STDOUT_FILENO);
	DUP_STDFD(out, STDIN_FILENO);
	
	/* 服务循环 */
	db_worker_start(iddb, child);
	exit(0);
}

/**
 * 停止工作进程
 */
static int stop_worker_process(iddb_t *iddb, child_t *child, int need_kill)
{
	pid_t pid = child->pid;

	/* 杀死子进程 */
	if (need_kill) {
		kill(pid, SIGKILL);
	}

	/* 清理相关资源 */
	child_deinit(child);
	xhash_delete(iddb->child_process, (const void *)&pid, sizeof(pid));

	return 0;
}

/**
 * 重启工作进程
 */
static int restart_worker_process(iddb_t *iddb, child_t *child, int need_kill)
{
	int mode = child->mode;

	stop_worker_process(iddb, child, need_kill);
	return start_worker_process(iddb, mode);
}

/**
 * 进程遍历统计
 */
int child_count_walk(const void *key, int klen, void *val, void *data)
{
	child_t *child = (child_t *)val;
	uint32_t count = *((uint32_t *)data);

	/* high 2 byte is readcount，low 2 byte is writecount, highest bit is assistcount */
	if (child->mode == DB_READ_MODE) {
		count = count + (1 << 16);
	} else if (child->mode == DB_WRITE_MODE) {
		count = count + 1;
	} else {
		count |= 1 << 31;
	}

	*((uint32_t *)data) = count;

	return 0;
}

/**
 * 创建工作进程
 * @note：采用读写分离模型，LMDB引擎是读优化而非写优化的，根据过往经验来看，读操作是远大于写操作的
 *		  这里读写进程数各占一半的决策，即基于上述理论，可以理解为读写操作的性能提升源于多核优化，读操作的性能提升源于LMDB引擎
 */
static void db_server_create_worker(iddb_t *iddb)
{
	int i = 0;
	uint32_t count = 0;
	/* 读写进程数各占一半 */
	uint16_t wcnt = iddb->nprocess / 2;
	uint16_t rcnt = iddb->nprocess - wcnt;
	/* 保留一个辅助进程 */
	uint16_t acnt = 1;
	
	/* 统计当前正在工作的进程 */
	xhash_walk(iddb->child_process, &count, child_count_walk);
	
	/* 统计当前缺失的进程 */
	acnt = acnt - (count >> 31);
	count &= ~(1 << 31);
	rcnt = rcnt - (count >> 16);
	wcnt = wcnt - (count & 0xffff);
	count = rcnt + wcnt;

	if (count) {
		plog("DB server number of missing process, read:%d, write:%d, assist:%d!\n", rcnt, wcnt, acnt);
	}

	/* 恢复读写缺失进程 */
	for (i = 0; i < count; i++) {
		if (start_worker_process(iddb, 
				i < wcnt ? DB_WRITE_MODE : DB_READ_MODE) != 0) {
			plog("start_worker_process failed!\n");
		}
	}
	/* 恢复辅助缺失进程 */
	if (acnt) {
		if (start_worker_process(iddb, DB_ASSIST_MODE) != 0) {
			plog("start assist process failed!\n");
		}
	}
}

/**
 * 服务系统初始化
 */
void db_server_init(char **argv, char **environ, iddb_t *iddb)
{
	s_pr_argv = argv;
	s_pr_environ = environ;
	
	s_epollfd = epoll_create(DB_EPOLL_SIZE);
	if (s_epollfd < 0) {
		die("epoll_create failed:%s\n", strerror(errno));
	}

	iddb->sread_sock = db_server_listen(DB_DOMAIN_RSOCK);
	iddb->swrite_sock = db_server_listen(DB_DOMAIN_WSOCK);
	iddb->child_process = xhash_create(NULL, NULL);

	/* 启动工作进程 */
	db_server_create_worker(iddb);
}

/**
 * 父子进程任务交接，读取子进程日志，下发父进程命令
 */
static void db_server_handover()
{
	int i, rcnt, wcnt, count = 0;
	char readbuffer[DB_MAX_BUF] = {0};
	struct epoll_event e_events[DB_EPOLL_SIZE];
	child_t *child = NULL;
	
	count = epoll_wait(s_epollfd, e_events, DB_EPOLL_SIZE, DB_EPOLL_TIMEOUT);
	if (count < 0) {
		plog("epoll_wait failed:%s\n", strerror(errno));
		return;
	}
	
	for (i = 0; i < count; i++) {
		child = (child_t *)e_events[i].data.ptr;
		
		if (e_events[i].events & (EPOLLERR | EPOLLRDHUP)) {
			continue;
		}
		
		if (e_events[i].events & EPOLLIN) {
			/* 将子进程输出作为日志发送 */
			rcnt = read(child->in, readbuffer, sizeof(readbuffer) - 1);
			if (rcnt > 0) {
				readbuffer[rcnt] = 0;
				do_log(readbuffer);
				/* 更新保活时间 */
				child->uptime = time(NULL);
			}
		} else if (e_events[i].events & EPOLLOUT) {
			/* 命令下发 */
			if (child->command & DB_CMD_UPDATE) {
				plog("send config update to worker process, mode:%s, pid:%d\n", DB_EXPAND_CHILD(child));
				
				wcnt = write(child->out, CMD_UPDATE_CFG, strlen(CMD_UPDATE_CFG));
				if (wcnt > 0) {
					child->command &= ~DB_CMD_UPDATE;
				}
			}
			if (child->command & DB_CMD_FLUSH) {
				plog("send flush now to worker process, mode:%s, pid:%d\n", DB_EXPAND_CHILD(child));
				
				wcnt = write(child->out, CMD_FLUSH_NOW, strlen(CMD_FLUSH_NOW));
				if (wcnt > 0) {
					child->command &= ~DB_CMD_FLUSH;
				}
			}
		}
	}
}

/**
 * 判断进程是否在调试
 */
static int is_debugging(pid_t pid)
{
	char buf[PATH_MAX];
	FILE *fp;
	
	str_snprintf(buf, sizeof(buf), "/proc/%d/status", (int)pid);
	fp = fopen(buf, "rb");
	if (!fp)
		return 0;
	
	while (fgets(buf, sizeof(buf), fp)) {
		if (memcmp(buf, "TracerPid:\t", 11) == 0) {
			fclose(fp);
			return atoi(buf + 11);
		}
	}
	
	fclose(fp);
	return 0;
}

/**
 * 子进程过期遍历检查
 */
static int child_expire_walk(const void *key, int klen, void *val, void *data)
{
	time_t now = time(NULL);
	int dbgpid;
	child_t *child = (child_t *)val;
	int stucked_intv = child->mode == DB_ASSIST_MODE ? DB_CHILD_A_STUCKED_INTV : DB_CHILD_STUCKED_INTV;
	
	if (!child->pid)
		return 0;
	
	if (child->uptime + stucked_intv < now) {
		if ((dbgpid = is_debugging(child->pid))) {
			plog("the worker process mode:%s pid:%d is not responsing, but it is being debug(by %d), ignored\n", 
				DB_EXPAND_CHILD(child), dbgpid);
			
			/* 更新时间到下一次 */
			child->uptime = now;
		} else {
			plog("the worker process mode:%s pid:%d is not responsing, killed(last response: %lu, now: %lu)\n", 
				 DB_EXPAND_CHILD(child), child->uptime, now);
			
			/* 杀死子进程 */
			kill(child->pid, SIGKILL);
		}
	}
	
	return 0;
}

/**
 * 检查并杀掉过期子进程
 */
static void db_server_expire_check(iddb_t *iddb)
{	
	xhash_walk(iddb->child_process, NULL, child_expire_walk);
}

/**
 * 子进程心跳检测
 */
static void db_server_hbeat_check(iddb_t *iddb)
{
	static unsigned int loop_cnt = 0;
	
	if ((loop_cnt % DB_LOOP_CHECK_INTV) == 0) {
		/* 心跳检查 */
		db_server_expire_check(iddb);
		/* 守护工作进程 */
		db_server_create_worker(iddb);
	}
	
	loop_cnt++;
}

/**
 * 回收子进程
 */
static void db_server_wait(iddb_t *iddb)
{
	int status;
	child_t *child = NULL;
	pid_t exited_pid = waitpid(-1, &status, WNOHANG);
	
	if (exited_pid == 0)
		return;
	
	if (exited_pid < 0) {
		if (errno != ECHILD) {
			plog("wait worker process errno:%d, error:%s\n", errno, strerror(errno));
		}
		sleep(1);
		return;
	}
	
	if (xhash_search(iddb->child_process, &exited_pid, sizeof(pid_t), (void **)&child)) {
		plog("no find worker process, pid:%d\n", exited_pid);
		return;
	}
	
	plog("the worker process mode:%s pid:%d exit, status info is as follows:\n", DB_EXPAND_CHILD(child));
	
	/* 子进程异常退出则重启该服务，正常退出则删除该服务节点 */
	if (WIFSIGNALED(status)) {
		plog("terminated unormally by signal:%d, restart now\n", WTERMSIG(status));
	} else if (WIFEXITED(status)) {
		if (WEXITSTATUS(status) != 0) {
			plog("exit unormally, exit code:%d, restart now\n", WEXITSTATUS(status));
		} else {
			plog("exit normally maybe because of business bugs in the worker process, restart now\n");
		}
	}

	/* 重启工作进程 */
	restart_worker_process(iddb, child, 0);
}


/**
 * 一次服务处理循环
 */
void db_server_loop_once(iddb_t *iddb)
{
	db_server_handover();
	db_server_hbeat_check(iddb);
	db_server_wait(iddb);
}

/**
 * 命令字更新
 */
int child_command_walk(const void *key, int klen, void *val, void *data)
{
	child_t *child = (child_t *)val;
	uint8_t command = *(uint8_t *)data;

	/* 读进程不需要执行flush */
	if (command == DB_CMD_FLUSH && 
			child->mode == DB_READ_MODE) {
		return 0;
	}
	
	child->command |= command;
	return 0;
}

/**
 * 执行命令
 */
void db_server_exec_command(iddb_t *iddb, uint8_t command)
{
	xhash_walk(iddb->child_process, (void *)&command, child_command_walk);
}

/**
 * 给子进程发送终结信号
 */
static int child_term_walk(const void *key, int klen, void *val, void *data)
{
	child_t *child = (child_t *)val;
	
	if (!child->pid)
		return 0;
	
	/* 终结子进程 */
	kill(child->pid, SIGTERM);
	
	return 0;
}

/**
 * 终结子进程
 */
static void db_term_child(iddb_t *iddb)
{
	xhash_walk(iddb->child_process, NULL, child_term_walk);

	/* 睡眠5s，等待子进程退出*/
	sleep(5);

	/* 随后父进程退出，若此时子进程还存在则伴随强制退出（子进程初始化时已通过prctl设置了伴随退出信号） */
}

/**
 * 服务系统反初始化
 */
void db_server_deinit(iddb_t *iddb)
{
	CLOSE_EMPTY(iddb->sread_sock);
	CLOSE_EMPTY(iddb->swrite_sock);
	CLOSE_EMPTY(s_epollfd);

	db_term_child(iddb);
	CLOSE_C(iddb->child_process, xhash_destroy);
}

