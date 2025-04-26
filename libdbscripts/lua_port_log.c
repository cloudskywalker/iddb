#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include <lua.h>
#include <lauxlib.h>

#include "base/error.h"
#include "base/strutils.h"

/* 从luaState中取得行号及文件名 */
const char *get_lua_file_line(lua_State *L, int *lineno)
{
	static char name[LUA_IDSIZE];
	lua_Debug ar = { 0 };
	char *slash;
	
	lua_getstack(L, 1, &ar);			/* 获得调用者的栈信息 */
	lua_getinfo(L, "Sl", &ar);			/* 获得行号信息 */
	
	*lineno = ar.currentline;
	slash = strrchr(ar.short_src, '/');
	if (slash)
		slash++;
	else
		slash = ar.short_src;
	
	strncpy(name, slash, LUA_IDSIZE);

	return name;
}

/* 输出函数 */
static int do_output(ettype et, lua_State *L)
{
	int lineno;
	const char *fname = get_lua_file_line(L, &lineno);
	char outbuf[1024];
	int outcur = 0;

	int n = lua_gettop(L);
	int i;
	for (i = 1; i <= n; ++i) {
		switch (lua_type(L, i)) {
		case LUA_TNUMBER:
		case LUA_TSTRING:
			outcur += str_snprintf(outbuf + outcur, sizeof(outbuf) - outcur, "%s", lua_tostring(L, i));
			break;
		case LUA_TBOOLEAN:
			outcur += str_snprintf(outbuf + outcur, sizeof(outbuf) - outcur, "%s", lua_toboolean(L, i) ? "true" : "false");
			break;
		case LUA_TNIL:
			outcur += str_snprintf(outbuf + outcur, sizeof(outbuf) - outcur, "nil");
			break;
		default:
			outcur += str_snprintf(outbuf + outcur, sizeof(outbuf) - outcur, "%s: %p", luaL_typename(L, i), lua_topointer(L, i));
			break;
		}

		if (i >= 1)
			outcur += str_snprintf(outbuf + outcur, sizeof(outbuf) - outcur, "\t");
	}

	error_output(et, fname, lineno, "%s\n", outbuf);
	return 0;
}

static int error_func(lua_State *L)
{
	return do_output(ET_DIE, L);
}

static int warn_func(lua_State *L)
{
	return do_output(ET_WARN, L);
}

static int debug_func(lua_State *L)
{
	return do_output(ET_DEBUG, L);
}

static int info_func(lua_State *L)
{
	return do_output(ET_INFO, L);
}

/**
 * \defgroup log 日志输出
 * 调用这些函数以使用认证内部的日志输出
 * \namespace global 全局函数
 */
void port_log_init(lua_State *L)
{
/**
 * \static function error
 * 输出一条错误日志
 * \param msg string 日志（必要时自行使用string.format进行格式化）
 */
	lua_pushcfunction(L, error_func);
	lua_setglobal(L, "error");

/**
 * \static function warn
 * 输出一条警告日志
 * \param msg string 日志（必要时自行使用string.format进行格式化）
 */
	lua_pushcfunction(L, warn_func);
	lua_setglobal(L, "warn");

/**
 * \static function debug
 * 输出一条调试日志（此信息将不送往网关日志）
 * \param msg string 日志（必要时自行使用string.format进行格式化）
 */
	lua_pushcfunction(L, debug_func);
	lua_setglobal(L, "debug");

/**
 * \static function info
 * 输出一条信息日志
 * \param msg string 日志（必要时自行使用string.format进行格式化）
 */
	lua_pushcfunction(L, info_func);
	lua_setglobal(L, "info");

	lua_pushcfunction(L, info_func);
	lua_setglobal(L, "print");
}
