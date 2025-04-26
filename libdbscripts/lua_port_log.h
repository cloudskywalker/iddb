#ifndef __PORT_LOG_H__
#define __PORT_LOG_H__

void port_log_init(lua_State *L);

/* 从luaState中取得行号及文件名 */
const char *get_lua_file_line(lua_State *L, int *lineno);


#endif
