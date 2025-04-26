#ifndef __DB_LUA_H__
#define __DB_LUA_H__


/**
 * 加载lua脚本
 * \param lua_dir lua脚本目录
 */
int db_lua_load(const char *lua_dir);

/**
 * 进行垃圾回收检查
 */
void db_lua_check_gc();

#endif
