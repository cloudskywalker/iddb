#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <limits.h>

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include "base/error.h"
#include "base/memory.h"
#include "base/dirutils.h"
#include "base/strutils.h"
#include "usr/luautils.h"

#include "db_lua.h"

#define LUA_DIR		"luascripts"


/**
 * 获取对应脚本语言绝对目录
 * \param scripts_root_dir 脚本根目录
 * \param script 脚本目录
 * \return 脚本语言绝对目录
 */
static char *get_script_dir(const char *scripts_root_dir, const char *script)
{
	static char script_dir[PATH_MAX] = { 0 };
	
	str_snprintf(script_dir, sizeof(script_dir), "%s/%s", scripts_root_dir, script);
	return script_dir;
}

/**
 * 加载脚本
 * \param scripts_root_dir 脚本根目录
 * \return 0-代表成功，其他代表失败
 */
int db_scripts_load(const char *scripts_root_dir)
{
	char newpath[PATH_MAX] = { 0 };

	if (!scripts_root_dir) {
		warn("no scripts root dir\n");
		return -1;
	}

	/* 路径转换 */
	dirutils_path_transform(scripts_root_dir, newpath, sizeof(newpath));

	/* 加载lua脚本 */
	if (db_lua_load(get_script_dir(newpath, LUA_DIR))) {
		warn("lua scripts loaded with error\n");
		return -1;
	}
	
	return 0;
}

/**
 * 进行垃圾回收检查
 */
void db_scripts_check_gc()
{
	db_lua_check_gc();
}
