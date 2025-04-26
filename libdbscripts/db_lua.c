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
#include "usr/luautils.h"

#include "usr/lport/port_msg.h"
#include "usr/lport/port_xconfig.h"
#include "usr/lport/port_mfind.h"
#include "usr/lport/port_regex.h"
#include "lua_port_module.h"
#include "lua_port_log.h"


static void mem_one(const char *name, lua_State *Lstate, void *userdata)
{
	lua_State *L = (lua_State *)userdata;
	
	int count = lua_gc(Lstate, LUA_GCCOUNT, 0);
	
	lua_pushinteger(L, count);
	lua_setfield(L, -2, name);
}

static int mem_usage(lua_State *L)
{
	lua_newtable(L);
	lport_foreach_module(mem_one, L);
	return 1;
}

/**
 * \defgroup syncLua lua插件调试
 * 提供调试api
 * \namespace syncLua lua插件调试
 */
static lport_reg_st s_synclua_reg[] = {
/**
 * \static function memUsage
 * 返回lua插件的内存占用
 * \return table 返回一个表，key为lua脚本名称，value为内存用量（KB）
 */
	{ "memUsage",		{ 0, NULL, mem_usage } },

	{ NULL }
};

static void setup_cpath(lua_State *L)
{
	char path[512];
#ifdef _MSC_VER
	dirutils_path_transform("@/../lualibs/?.dll", path, sizeof(path));
#else
	dirutils_path_transform("@/../../../common/lualibs/?.so", path, sizeof(path));
#endif

	lua_getglobal(L, "package");
	lua_pushliteral(L, "cpath");
	lua_pushstring(L, path);
	lua_rawset(L, -3);
	lua_pop(L, 1);
}

static void setup_path(lua_State *L)
{
	char path[512];
	dirutils_path_transform("@/../../../common/lualibs/?.lua", path, sizeof(path));
	
	lua_getglobal(L, "package");
	lua_pushliteral(L, "path");
	lua_pushstring(L, path);
	lua_rawset(L, -3);
	lua_pop(L, 1);
}

static void dblua_context_setup(lua_State *L)
{
	luaL_openlibs(L);		/* LUA内部库初始化 */
	setup_cpath(L);
	setup_path(L);

	port_msg_init(L);
	port_log_init(L);
	port_mfind_init(L);
	port_regex_init(L);
	
	lport_register(L, "syncLua", s_synclua_reg);
}

static int load_one_script(const char *filename)
{
	lua_State *L = lua_open();
	int err;

	if (!L)
		die("lua_open failed?\n");

	dblua_context_setup(L);

	info("loading %s\n", filename);
	err = luaL_loadfile(L, filename) || lua_pcall(L, 0, 0, 0);

	if (err) {
		warn("lua script %s load error: %s\n", filename, lua_tostring(L, -1));
		lua_pop(L, 1);
	}
	
	lport_set_module(filename, L);

	return 0;
}

static int is_lua_script(const char *filename)
{
	//内部接口 不再判断输入合法性 调用者保证
	static char lua_suffix[] = ".lua";
	int filename_len = strlen(filename);
	int suffix_len = sizeof(lua_suffix) - 1;

	if (filename_len <= suffix_len) {
		return 0;
	}

	return !(strncmp(lua_suffix, filename + filename_len - suffix_len, suffix_len));
}

static int dir_callback(int isdir, const char *entry, void *userdata)
{
	if (isdir) {
		return dirutils_listdir(entry, NULL, dir_callback);
	}

	//仅加载.lua后缀的lua脚本
	if(entry && is_lua_script(entry)) {
		return load_one_script(entry);
	}

	return 0;
}

struct mem_stat_st {
	int after_gc_mem;
};

static void check_gc_one(const char *name, lua_State *L, void *userdata)
{
	struct mem_stat_st *mem_stat = lport_get_private_date(L);
	int before, after;
	
	if (!mem_stat) {			/* init */
		mem_stat = zero_alloc(sizeof(struct mem_stat_st));
		lport_set_private_data(L, mem_stat);
		
		lua_gc(L, LUA_GCCOLLECT, 0);
		mem_stat->after_gc_mem = lua_gc(L, LUA_GCCOUNT, 0);
		
		info("%s after load, memory: %d KB\n", name, mem_stat->after_gc_mem);
		return;
	}
	
	before = lua_gc(L, LUA_GCCOUNT, 0);
	if (before > mem_stat->after_gc_mem * 2) {	/* 两倍时进行回收 */
		lua_gc(L, LUA_GCCOLLECT, 0);
		after = lua_gc(L, LUA_GCCOUNT, 0);
		
		info("%s: %d KB collected(%d-%d KB)\n", name, before - after, before, after);
		mem_stat->after_gc_mem = after;
	}
}

/**
 * 加载lua脚本
 * \param lua_dir lua脚本目录
 */
int db_lua_load(const char *lua_dir)
{
	if (!lua_dir) {
		warn("lua plugins init without param(which should be a path that contains lua scripts)\n");
		return 0;
	}

	if (dirutils_listdir(lua_dir, NULL, dir_callback)) {
		//warn("no lua scripts loaded\n");
	}
	
	return 0;
}

/**
 * 进行垃圾回收检查
 */
void db_lua_check_gc()
{
	lport_foreach_module(check_gc_one, NULL);
}
