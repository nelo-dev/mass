#include "database.h"
#include "lib/jwt.h"
#include <stdio.h>
#include <jansson.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <time.h>
#include <regex.h>

#define SALT_SIZE 16
#define HASH_SIZE 64

sqlite3* create_and_open_db(const char *db_name, int cache_size_mb) {
    sqlite3 *db;
    int rc = sqlite3_open(db_name, &db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        return NULL;
    }

    // Configure PRAGMA settings
    sqlite3_exec(db, "PRAGMA journal_mode=WAL;", NULL, NULL, NULL);
    sqlite3_exec(db, "PRAGMA synchronous=NORMAL;", NULL, NULL, NULL);
    sqlite3_exec(db, "PRAGMA mmap_size=268435456;", NULL, NULL, NULL);
    int cache_size_pages = (cache_size_mb * 1024 * 1024) / 4096;
    char sql_cache[64];
    snprintf(sql_cache, sizeof(sql_cache), "PRAGMA cache_size=%d;", -cache_size_pages);
    sqlite3_exec(db, sql_cache, NULL, NULL, NULL);
    sqlite3_exec(db, "PRAGMA temp_store=MEMORY;", NULL, NULL, NULL);
    sqlite3_exec(db, "PRAGMA auto_vacuum=FULL;", NULL, NULL, NULL);
    sqlite3_exec(db, "PRAGMA page_size=4096;", NULL, NULL, NULL);
    sqlite3_exec(db, "PRAGMA optimize;", NULL, NULL, NULL);

    char *err_msg = NULL;

    // Create the users table with an additional profile_pic_id column.
    // The profile_pic_id column is a foreign key referencing the profile_pics table.
    const char *sql_create_users_table =
        "CREATE TABLE IF NOT EXISTS users ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "name TEXT UNIQUE NOT NULL, "
        "password TEXT NOT NULL "
        ");";

    rc = sqlite3_exec(db, sql_create_users_table, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to create users table: %s\n", err_msg);
        sqlite3_free(err_msg);
    }

    return db;
}

void close_db(sqlite3 *db) {
    if (db) {
        sqlite3_close(db);
    }
}

void generate_salt(unsigned char *salt) {
    RAND_bytes(salt, SALT_SIZE);
}

void hash_password(const char *password, const unsigned char *salt, unsigned char *hash) {
    PKCS5_PBKDF2_HMAC(password, strlen(password), salt, SALT_SIZE, 100000, EVP_sha256(), HASH_SIZE, hash);
}

void bin_to_hex(const unsigned char *bin, size_t len, char *hex) {
    for (size_t i = 0; i < len; i++) {
        sprintf(hex + (i * 2), "%02x", bin[i]);
    }
    hex[len * 2] = '\0';
}

void hex_to_bin(const char *hex, unsigned char *bin, size_t len) {
    for (size_t i = 0; i < len; i++) {
        sscanf(hex + (i * 2), "%2hhx", &bin[i]);
    }
}

int is_valid_username(const char *username) {
    regex_t regex;
    if (regcomp(&regex, "^[a-zA-Z0-9_-]+$", REG_EXTENDED))
        return 0;
    int ret = regexec(&regex, username, 0, NULL, 0);
    regfree(&regex);
    return (ret == 0);
}

char* register_user(sqlite3 *db, const char *input_json) {
    json_error_t error;
    json_t *root = json_loads(input_json, 0, &error);
    if (!root)
        return strdup("{\"status\":\"error\", \"message\":\"Invalid JSON format\"}");

    const char *name = json_string_value(json_object_get(root, "name"));
    const char *password = json_string_value(json_object_get(root, "password"));

    if (!name || !password) {
        json_decref(root);
        return strdup("{\"status\":\"error\", \"message\":\"Missing name or password\"}");
    }
    if (!is_valid_username(name)) {
        json_decref(root);
        return strdup("{\"status\":\"error\", \"message\":\"Invalid username format. Only letters, numbers, _ and - are allowed.\"}");
    }

    unsigned char salt[SALT_SIZE], hash[HASH_SIZE];
    generate_salt(salt);
    hash_password(password, salt, hash);

    char salt_hex[SALT_SIZE * 2 + 1], hash_hex[HASH_SIZE * 2 + 1];
    bin_to_hex(salt, SALT_SIZE, salt_hex);
    bin_to_hex(hash, HASH_SIZE, hash_hex);

    char sql[512];
    snprintf(sql, sizeof(sql), "INSERT INTO users (name, password) VALUES ('%s', '%s:%s');", name, salt_hex, hash_hex);

    char *err_msg = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &err_msg) != SQLITE_OK) {
        sqlite3_free(err_msg);
        json_decref(root);
        return strdup("{\"status\":\"error\", \"message\":\"Username already exists\"}");
    }
    json_decref(root);
    return strdup("{\"status\":\"success\", \"message\":\"User registered successfully\"}");
}

char* login_user(sqlite3 *db, const char *input_json, const char *jwt_secret, char **jwt_token) {
    json_error_t error;
    json_t *root = json_loads(input_json, 0, &error);
    if (!root)
        return strdup("{\"status\":\"error\", \"message\":\"Invalid JSON format\"}");

    const char *name = json_string_value(json_object_get(root, "name"));
    const char *password = json_string_value(json_object_get(root, "password"));

    if (!name || !password) {
        json_decref(root);
        return strdup("{\"status\":\"error\", \"message\":\"Missing name or password\"}");
    }

    char sql[256];
    snprintf(sql, sizeof(sql), "SELECT password FROM users WHERE name='%s';", name);
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, 0) != SQLITE_OK) {
        json_decref(root);
        return strdup("{\"status\":\"error\", \"message\":\"Database error\"}");
    }

    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        json_decref(root);
        return strdup("{\"status\":\"error\", \"message\":\"Invalid username or password\"}");
    }

    const char *stored_password = (const char *)sqlite3_column_text(stmt, 0);
    char salt_hex[SALT_SIZE * 2 + 1], hash_hex[HASH_SIZE * 2 + 1];
    sscanf(stored_password, "%32s:%128s", salt_hex, hash_hex);

    unsigned char salt[SALT_SIZE], stored_hash[HASH_SIZE], computed_hash[HASH_SIZE];
    hex_to_bin(salt_hex, salt, SALT_SIZE);
    hex_to_bin(hash_hex, stored_hash, HASH_SIZE);
    hash_password(password, salt, computed_hash);
    sqlite3_finalize(stmt);

    char *name_copy = strdup(name);
    json_decref(root);

    if (memcmp(stored_hash, computed_hash, HASH_SIZE) != 0) {
        free(name_copy);
        return strdup("{\"status\":\"error\", \"message\":\"Invalid username or password\"}");
    }

    jwt_header_t header = { "HS256", "JWT" };
    jwt_payload_t payload = { name_copy, "SubRoutine", time(NULL) + 3600 };

    if (jwt_encode(jwt_secret, &header, &payload, jwt_token) != 0) {
        free(payload.sub);
        return strdup("{\"status\":\"error\", \"message\":\"Failed to generate JWT\"}");
    }
    free(payload.sub);
    return strdup("{\"status\":\"success\", \"message\":\"Login successful\"}");
}

char* get_user_json(sqlite3 *db, const char *username) {
    sqlite3_stmt *stmt;
    const char *sql = "SELECT id, name FROM users WHERE name = ?;";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return strdup("{\"error\": \"Failed to prepare query\"}");

    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    char *json_str = NULL;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        int id = sqlite3_column_int(stmt, 0);
        const char *name = (const char*)sqlite3_column_text(stmt, 1);
        json_t *json_obj = json_object();
        json_object_set_new(json_obj, "id", json_integer(id));
        json_object_set_new(json_obj, "name", json_string(name));
        json_str = json_dumps(json_obj, JSON_COMPACT);
        json_decref(json_obj);
    } else {
        json_str = strdup("{\"error\": \"User not found\"}");
    }
    sqlite3_finalize(stmt);
    return json_str;
}
