#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

#include "base/memory.h"

#include "iddb.h"
#include "db_epoll.h"
#include "db_logger.h"

static int s_epollfd;			/* epoll句柄 */

typedef struct epoll_private_st {
	void *pdata;
	epoll_private_free_func_t pfree;
} epoll_private_t;

/** 
 * 将所要监听的套接字进行处理
 */
static int epoll_ctl_all(int events, int ctl, int fd, void *userdata)
{
	int err;
	struct epoll_event e_event;
	
	bzero(&e_event, sizeof(e_event));
	e_event.events = events;
	e_event.data.fd = fd;
	e_event.data.ptr = userdata;
	
	err = epoll_ctl(s_epollfd, ctl, fd, &e_event);
	if (err < 0) {
		warn("epoll_ctl failed, opr:%d, err:%s\n", ctl, strerror(errno));
		return -1;
	}
	
	return 0;
}

/** 
 * 创建监听事件
 */
int epoll_event_create(int size)
{
	s_epollfd = epoll_create(size);
	
	return s_epollfd;
}

/** 
 * 轮询监听事件
 */
int epoll_event_wait(struct epoll_event *events, int maxevents, int timeout)
{
	return epoll_wait(s_epollfd, events, maxevents, timeout);
}

/** 
 * 将服务节点添加到监听事件
 */
int epoll_event_put(int fd, int events, void *pdata, epoll_private_free_func_t pfree)
{
	epoll_private_t *private = zero_alloc(sizeof(epoll_private_t));

	private->pdata = pdata;
	private->pfree = pfree;
	
	if (epoll_ctl_all(events, EPOLL_CTL_ADD, fd, (void *)private))
		return -1;
	
	return 0;
}

/** 
 * 修改服务节点的监听事件
 */
int epoll_event_set(int fd, struct epoll_event *e_event, int events)
{
	if (epoll_ctl_all(events, EPOLL_CTL_MOD, fd, (void *)e_event->data.ptr))
		return -1;
	
	return 0;
}

/** 
 * 将服务节点从监听事件里删除
 */
int epoll_event_del(int fd, struct epoll_event *e_event)
{
	epoll_private_t *private = (epoll_private_t *)e_event->data.ptr;
	
	if (epoll_ctl_all(0, EPOLL_CTL_DEL, fd, NULL)) {
		return -1;
	}

	if (private->pdata && private->pfree) {
		CLOSE_C(private->pdata, private->pfree);
	}

	FREE_EMPTY(private);
	
	return 0;
}

/** 
 * 获取私有数据
 */
void *epoll_event_get_private(struct epoll_event *e_event)
{
	epoll_private_t *private = (epoll_private_t *)e_event->data.ptr;

	return private->pdata;
}
