#ifndef __LPORT_MODULE_H__
#define __LPORT_MODULE_H__

#include <stdio.h>
#include <lua.h>

void lport_set_module(const char *file, lua_State *L);

typedef void (*lport_mod_walk_fn_t)(const char *name, lua_State *L, void *userdata);

void lport_foreach_module(lport_mod_walk_fn_t callback, void *userdata);
char *lport_load_to_memory(const char *file, size_t *size);

void *lport_get_private_date(lua_State *L);
void lport_set_private_data(lua_State *L, void *data);

#endif
