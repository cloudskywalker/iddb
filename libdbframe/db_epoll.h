#ifndef __IDDB_EPOLL_H__
#define __IDDB_EPOLL_H__

#include <sys/epoll.h>

typedef void (*epoll_private_free_func_t)(void *data);

/** 
 * 创建监听事件
 * \param size 监听fd数
 * \return epoll句柄
 */
int epoll_event_create(int size);

/** 
 * 轮询监听事件
 * \param events 事件集合
 * \param maxevents 事件集合最大个数
 * \param timeout 超时
 * \return 发生事件数
 */
int epoll_event_wait(struct epoll_event *events, int maxevents, int timeout);

/** 
 * 将句柄添加到监听事件
 * \param fd 句柄
 * \param events epoll事件
 * \param pdata 私有数据
 * \param pfree 私有数据的释放函数
 * \return 0-代表成功，其他-代表失败
 */
int epoll_event_put(int fd, int events, void *pdata, epoll_private_free_func_t pfree);

/** 
 * 修改服务节点的监听事件
 * \param fd 句柄
 * \param e_event 事件对象
 * \param events 事件动作
 * \return 0-代表成功，其他-代表失败
 */
int epoll_event_set(int fd, struct epoll_event *e_event, int events);

/** 
 * 将服务节点从监听事件里删除
 * \param fd 句柄
 * \param e_event 事件对象
 * \return 0-代表成功，其他-代表失败
 */
int epoll_event_del(int fd, struct epoll_event *e_event);

/** 
 * 获取私有数据
 * \param e_event 事件对象
 * \return 私有数据
 */
void *epoll_event_get_private(struct epoll_event *e_event);

#endif
