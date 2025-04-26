#ifndef __DB_SCRIPTS_H__
#define __DB_SCRIPTS_H__

/**
 * 加载脚本
 * \param scripts_root_dir 脚本根目录
 * \return 0-代表成功，其他代表失败
 */
int db_scripts_load(const char *scripts_root_dir);

/**
 * 进行垃圾回收检查
 */
void db_scripts_check_gc();

#endif
