#ifndef DATABASE_H
#define DATABASE_H

#include <sqlite3.h>
#include "lib/filelib.h"
#include "lib/downloader.h"

typedef enum {
    ACCESS_UNAPPROVED = 0,  // Unapproved user
    ACCESS_VISITOR = 1,     // Approved visitor
    ACCESS_MODERATOR = 2,   // Approved moderator
    ACCESS_ADMIN = 3        // Approved admin
} AccessLevel;

sqlite3* create_and_open_db(const char *db_name, int cache_size_mb);
void close_db(sqlite3 *db);

char* register_user(sqlite3 *db, const char *input_json);
char* login_user(sqlite3 *db, const char *input_json, const char *jwt_secret, char **jwt_token, int login_timeout);
char* get_user_json(sqlite3 *db, const char *username);
int update_profile_picture(sqlite3 *db, const char *username, const unsigned char *image_buffer, size_t buffer_size, const char *profile_pic_path, const char *file_ending, int max_kb);
int get_user_access_level(sqlite3 *db, const char *username, int approval_enabled);
char* search_users(sqlite3* db, const char* search_json);
char *toggle_user_approval_by_requester(sqlite3 *db, const char *json_input, const char *requester_username);
char *toggle_user_role_by_requester(sqlite3 *db, const char *json_input, const char *requester_username);
char* create_api_key(sqlite3 *db, const char *request_username, const char *json_input);
char* destroy_api_key(sqlite3 *db, const char *json_input);
char* get_all_api_keys(sqlite3 *db);
char* insert_media(sqlite3* db, Downloader* dl, const char* input_json, const char* media_dir, const char* preview_dir, const char* description_dir);
char* search_media(sqlite3 *db, const char *input_json);
char* autocomplete_tags(sqlite3 *db, const char *json_input);
char* get_media_info(sqlite3 *db, const char *json_input);
int get_total_media_count(sqlite3 *db);

#endif