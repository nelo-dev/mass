#ifndef DATABASE_H
#define DATABASE_H

#include <sqlite3.h>
#include "lib/filelib.h"

sqlite3* create_and_open_db(const char *db_name, int cache_size_mb);
void close_db(sqlite3 *db);

char* register_user(sqlite3 *db, const char *input_json);
char* login_user(sqlite3 *db, const char *input_json, const char *jwt_secret, char **jwt_token);
char* get_user_json(sqlite3 *db, const char *username);
int update_profile_picture(sqlite3 *db, const char *username, const unsigned char *image_buffer, size_t buffer_size, const char *profile_pic_path, const char *file_ending, int max_kb);

#endif