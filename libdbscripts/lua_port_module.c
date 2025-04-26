#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "base/memory.h"
#include "base/hash.h"

#include "lua_port_module.h"

static hash_st *s_modules;		/* name -> L */
static hash_st *s_privatedata;	/* L -> void * */

void lport_set_module(const char *file, lua_State *L)
{
	if (!s_modules)
		s_modules = xhash_create(NULL, NULL);
		
	xhash_insert(s_modules, file, strlen(file) + 1, L);
}

struct walk_tmp_st {
	lport_mod_walk_fn_t callback;
	void *userdata;
};

static int each_module(const void *key, int klen, void *val, void *data)
{
	struct walk_tmp_st *tmp = (struct walk_tmp_st *)data;
	
	tmp->callback(key, (lua_State *)val, tmp->userdata);
	return 0;
}

void lport_foreach_module(lport_mod_walk_fn_t callback, void *userdata)
{
	struct walk_tmp_st tmp = {
		callback,
		userdata
	};
	
	if (!s_modules)
		return;
	
	xhash_walk(s_modules, &tmp, each_module);
}

void *lport_get_private_date(lua_State *L)
{
	void *ret;
	
	if (!s_privatedata)
		s_privatedata = xhash_create(NULL, NULL);
	
	if (xhash_search(s_privatedata, &L, sizeof(L), &ret) != 0)
		return NULL;
	
	return ret;
}

void lport_set_private_data(lua_State *L, void *data)
{
	if (!s_privatedata)
		s_privatedata = xhash_create(NULL, NULL);
	
	xhash_insert(s_privatedata, &L, sizeof(L), data);
}

char *lport_load_to_memory(const char *file, size_t *size)
{
	struct stat st_buf;
	FILE *fp;
	char *ret;
	
	if (stat(file, &st_buf) != 0)
		return NULL;
	
	fp = fopen(file, "rb");
	if (!fp)
		return NULL;
	
	ret = zero_alloc(st_buf.st_size + 1);
	if (fread(ret, 1, st_buf.st_size, fp) != st_buf.st_size) {
		free(ret);
		fclose(fp);
		return NULL;
	}
	
	fclose(fp);
	if (size)
		*size = st_buf.st_size;
	
	return ret;
}
