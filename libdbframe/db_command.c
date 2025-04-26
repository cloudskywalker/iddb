#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <assert.h>

#include "base/memory.h"
#include "sys/CommonCmd.h"

#include "db_command.h"
#include "db_logger.h"
#include "db_server.h"


#define DB_COMMAND_LEN		(100)

static int s_sockfd = -1;


/**
 * 命令处理初始化
 */
void db_command_init(void)
{
	struct sockaddr_un sa;
	int flag;
	
	memset(&sa, 0, sizeof(sa));
	sa.sun_family = AF_UNIX;
	strncpy(sa.sun_path, UNIXSOCK_NOTIFY_IDDB, sizeof(sa.sun_path) - 1);
	unlink(UNIXSOCK_NOTIFY_IDDB);
	
	s_sockfd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (s_sockfd < 0) {
		die("sync_commoand_init failed, socket err:%s\n", strerror(errno));
	}
	
	/* 
	 * 设置close_on_exec标记, 防止子进程继承了该socket, 父进程重启后起不来
	 * 设置失败仍然继续, 仅打印告警日志
	 */
	if ((flag = fcntl(s_sockfd, F_GETFD, 0)) >= 0) {
		if (fcntl(s_sockfd, F_SETFD, flag | FD_CLOEXEC) < 0) {
			plog("sync_commoand_init, set socket flag failed!\n");
		}
	}
	
	if (bind(s_sockfd, (struct sockaddr*)&sa, sizeof(struct sockaddr_un)) != 0) {
		close(s_sockfd);
		die("sync_commoand_init failed, bind err:%s\n", strerror(errno));
	}
}

/**
 * 分发命令
 */
static void db_command_dispatch(stCmdFrame *pcmdfrm, iddb_t *iddb)
{
	assert(pcmdfrm);
	assert(pcmdfrm->flag == CMD_FLAG);

	//const char *cmd_data = pcmdfrm->size == sizeof(stCmdFrame) ? NULL : (const char *)pcmdfrm->data;
	
	switch (pcmdfrm->cid) {
		case CMDIDDB_CFG_UPDATE:
			db_server_exec_command(iddb, DB_CMD_UPDATE);
			break;
		case CMDIDDB_FLUSH_NOW:
			db_server_exec_command(iddb, DB_CMD_FLUSH);
			break;
		default:
			plog("no support cmd:%d\n", pcmdfrm->cid);
			break;
	}
}

/**
 * 收到命令
 */
static int command_has_recived(stCmdFrame **ppcmd, int frmlen)
{
	fd_set rds;
	struct timeval tv = { 0 };
	int ret;
	stCmdFrame *pcmdfrm = *ppcmd;
	
	FD_ZERO(&rds);
	FD_SET(s_sockfd, &rds);
	
	if (select(s_sockfd + 1, &rds, NULL, NULL, &tv) <= 0)
		return 0;
	
	if (!FD_ISSET(s_sockfd, &rds))
		return 0;
	
	ret = read(s_sockfd, pcmdfrm, frmlen - 1);
	if (ret <= 0) {
		plog("command read error:%s\n", strerror(errno));
		return 0;
	}
	
	//非命令帧标识
	if (pcmdfrm->flag != CMD_FLAG) {
		plog("command recv bad cmd flag or size: flag=0x%08x, size=%d", pcmdfrm->flag, pcmdfrm->size);
		return 0;
	}
	
	return 1;
}

/**
 * 一次命令处理循环
 */
void db_command_loop_once(iddb_t *iddb)
{
	int frmlen = sizeof(stCmdFrame) + DB_COMMAND_LEN;
	stCmdFrame *pcmdfrm = (stCmdFrame *)zero_alloc(frmlen);;
	
	if (command_has_recived(&pcmdfrm, frmlen)) {
		db_command_dispatch(pcmdfrm, iddb);
	}
	
	free(pcmdfrm);
}

/**
 * 命令系统反初始化
 */
void db_command_deinit(void)
{
	close(s_sockfd);
}