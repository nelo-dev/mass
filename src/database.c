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

    const char *pragmas[] = {
        "PRAGMA journal_mode=WAL;",
        "PRAGMA synchronous=NORMAL;",
        "PRAGMA mmap_size=268435456;",
        "PRAGMA temp_store=MEMORY;",
        "PRAGMA auto_vacuum=FULL;",
        "PRAGMA page_size=4096;",
        "PRAGMA optimize;"
    };

    for (size_t i = 0; i < sizeof(pragmas) / sizeof(pragmas[0]); i++) {
        sqlite3_exec(db, pragmas[i], NULL, NULL, NULL);
    }

    char sql_cache[64];
    snprintf(sql_cache, sizeof(sql_cache), "PRAGMA cache_size=%d;", -(cache_size_mb * 1024 * 1024) / 4096);
    sqlite3_exec(db, sql_cache, NULL, NULL, NULL);

    const char *tables[] = {
        "CREATE TABLE IF NOT EXISTS profile_pics ("
        "profile_id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "profile_img_path TEXT NOT NULL);",

        "CREATE TABLE IF NOT EXISTS roles ("
        "role_id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "role_name TEXT UNIQUE NOT NULL);",

        "CREATE TABLE IF NOT EXISTS user ("
        "user_id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "user_name TEXT UNIQUE NOT NULL, "
        "user_password TEXT NOT NULL, "
        "profile_id INTEGER, "
        "role_id INTEGER, "
        "approved INTEGER DEFAULT 0, "
        "FOREIGN KEY(profile_id) REFERENCES profile_pics(profile_id) ON DELETE SET NULL, "
        "FOREIGN KEY(role_id) REFERENCES roles(role_id) ON DELETE SET NULL);",

        "CREATE TABLE IF NOT EXISTS media ("
        "media_id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "url TEXT UNIQUE NOT NULL, "
        "preview_url TEXT UNIQUE NOT NULL, "
        "path TEXT UNIQUE NOT NULL, "
        "preview_path TEXT UNIQUE NOT NULL, "
        "title TEXT, "
        "creator TEXT, "
        "score INTEGER, "
        "web_id INTEGER);",

        "CREATE TABLE IF NOT EXISTS tags ("
        "tag_id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "tag_name TEXT NOT NULL UNIQUE);",

        "CREATE TABLE IF NOT EXISTS media_tags ("
        "media_id INTEGER, "
        "tag_id INTEGER, "
        "PRIMARY KEY (media_id, tag_id), "
        "FOREIGN KEY(media_id) REFERENCES media(media_id) ON DELETE CASCADE, "
        "FOREIGN KEY(tag_id) REFERENCES tags(tag_id) ON DELETE CASCADE);",

        "CREATE TABLE IF NOT EXISTS api_keys ("
        "api_id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "user_id INTEGER NOT NULL, "
        "api_key TEXT UNIQUE NOT NULL, "
        "created_at DATETIME DEFAULT CURRENT_TIMESTAMP, "
        "is_active INTEGER DEFAULT 1, "
        "FOREIGN KEY(user_id) REFERENCES user(user_id) ON DELETE CASCADE);"
    };

    // Index creation queries
    const char *indexes[] = {
        "CREATE INDEX IF NOT EXISTS idx_media_score ON media(score);",
        "CREATE INDEX IF NOT EXISTS idx_media_web_id ON media(web_id);",
        "CREATE INDEX IF NOT EXISTS idx_tag_name ON tags(tag_name);",
        "CREATE INDEX IF NOT EXISTS idx_mediatags_media_id ON media_tags(media_id);",
        "CREATE INDEX IF NOT EXISTS idx_mediatags_tag_id ON media_tags(tag_id);",
        "CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id);",
        "CREATE INDEX IF NOT EXISTS idx_api_keys_is_active ON api_keys(is_active);",
        "CREATE INDEX IF NOT EXISTS idx_user_role_id ON user(role_id);",
        "CREATE INDEX IF NOT EXISTS idx_user_approved ON user(approved);"
    };

    // Default role insertion queries
    const char *default_roles[] = {
        "INSERT INTO roles (role_name) VALUES ('admin') ON CONFLICT(role_name) DO NOTHING;",
        "INSERT INTO roles (role_name) VALUES ('moderator') ON CONFLICT(role_name) DO NOTHING;",
        "INSERT INTO roles (role_name) VALUES ('visitor') ON CONFLICT(role_name) DO NOTHING;"
    };

    for (size_t i = 0; i < sizeof(tables) / sizeof(tables[0]); i++) {
        char *err_msg = NULL;
        rc = sqlite3_exec(db, tables[i], NULL, NULL, &err_msg);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "SQL error: %s\n", err_msg);
            sqlite3_free(err_msg);
            sqlite3_close(db);
            return NULL;
        }
    }

    for (size_t i = 0; i < sizeof(indexes) / sizeof(indexes[0]); i++) {
        sqlite3_exec(db, indexes[i], NULL, NULL, NULL);
    }

    for (size_t i = 0; i < sizeof(default_roles) / sizeof(default_roles[0]); i++) {
        sqlite3_exec(db, default_roles[i], NULL, NULL, NULL);
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

    // Begin transaction
    sqlite3_exec(db, "BEGIN TRANSACTION;", NULL, NULL, NULL);

    // Insert default profile picture
    const char *default_pic = "resources/default_user.png";
    char profile_sql[256];
    snprintf(profile_sql, sizeof(profile_sql), 
             "INSERT INTO profile_pics (profile_img_path) VALUES ('%s');", 
             default_pic);
    
    if (sqlite3_exec(db, profile_sql, NULL, NULL, NULL) != SQLITE_OK) {
        sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
        json_decref(root);
        return strdup("{\"status\":\"error\", \"message\":\"Failed to set profile picture\"}");
    }

    // Get the last inserted profile_id
    sqlite3_int64 profile_id = sqlite3_last_insert_rowid(db);

    // Check if this is the first user
    int is_first_user = 0;
    sqlite3_stmt *stmt;
    const char *count_sql = "SELECT COUNT(*) FROM user;";
    if (sqlite3_prepare_v2(db, count_sql, -1, &stmt, NULL) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            is_first_user = (sqlite3_column_int(stmt, 0) == 0);
        }
        sqlite3_finalize(stmt);
    }

    // Get role_id for either 'admin' or 'visitor'
    const char *role_name = is_first_user ? "admin" : "visitor";
    sqlite3_int64 role_id = 0;
    char role_sql[128];
    snprintf(role_sql, sizeof(role_sql), 
             "SELECT role_id FROM roles WHERE role_name = '%s';", 
             role_name);
    
    if (sqlite3_prepare_v2(db, role_sql, -1, &stmt, NULL) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            role_id = sqlite3_column_int64(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }

    // Generate salt and hash for password
    unsigned char salt[SALT_SIZE], hash[HASH_SIZE];
    generate_salt(salt);
    hash_password(password, salt, hash);

    char salt_hex[SALT_SIZE * 2 + 1], hash_hex[HASH_SIZE * 2 + 1];
    bin_to_hex(salt, SALT_SIZE, salt_hex);
    bin_to_hex(hash, HASH_SIZE, hash_hex);

    // Insert user with profile_id, role_id, and approved (1 for first user, 0 for others)
    char sql[512];
    snprintf(sql, sizeof(sql), 
             "INSERT INTO user (user_name, user_password, profile_id, role_id, approved) "
             "VALUES ('%s', '%s:%s', %lld, %lld, %d);", 
             name, salt_hex, hash_hex, profile_id, role_id, is_first_user ? 1 : 0);

    char *err_msg = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &err_msg) != SQLITE_OK) {
        sqlite3_free(err_msg);
        sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
        json_decref(root);
        return strdup("{\"status\":\"error\", \"message\":\"Username already exists\"}");
    }

    // Commit transaction
    sqlite3_exec(db, "COMMIT;", NULL, NULL, NULL);
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
    snprintf(sql, sizeof(sql), "SELECT user_password FROM user WHERE user_name='%s';", name);
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
    const char *sql = "SELECT u.user_id, u.user_name, p.profile_img_path, r.role_name "
                     "FROM user u "
                     "LEFT JOIN profile_pics p ON u.profile_id = p.profile_id "
                     "LEFT JOIN roles r ON u.role_id = r.role_id "
                     "WHERE u.user_name = ?;";
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return strdup("{\"error\": \"Failed to prepare query\"}");

    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    char *json_str = NULL;
    
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        int id = sqlite3_column_int(stmt, 0);
        const char *name = (const char*)sqlite3_column_text(stmt, 1);
        const char *profile_path = sqlite3_column_text(stmt, 2) 
            ? (const char*)sqlite3_column_text(stmt, 2) 
            : "resources/default_user.png";
        const char *role = sqlite3_column_text(stmt, 3) 
            ? (const char*)sqlite3_column_text(stmt, 3) 
            : "visitor";  // Fallback if role is NULL
        
        json_t *json_obj = json_object();
        json_object_set_new(json_obj, "id", json_integer(id));
        json_object_set_new(json_obj, "name", json_string(name));
        json_object_set_new(json_obj, "profile_picture", json_string(profile_path));
        json_object_set_new(json_obj, "role", json_string(role));
        
        json_str = json_dumps(json_obj, JSON_COMPACT);
        json_decref(json_obj);
    } else {
        json_str = strdup("{\"error\": \"User not found\"}");
    }
    
    sqlite3_finalize(stmt);
    return json_str;
}

int get_user_access_level(sqlite3 *db, const char *username, int approval_enabled) {
    sqlite3_stmt *stmt;
    const char *sql = "SELECT r.role_name, u.approved FROM user u LEFT JOIN roles r ON u.role_id = r.role_id WHERE u.user_name = ?;";
    
    // Prepare the SQL statement and bind the username
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK || 
        sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        return -1;  // Error case
    }

    int level = -1;  // Default to error/invalid
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *role_name = (const char *)sqlite3_column_text(stmt, 0);
        int is_approved = sqlite3_column_int(stmt, 1);
        
        if (approval_enabled && !is_approved) {
            level = 0;  // Unapproved user when approval is enforced
        } else {
            // Approval is either disabled or user is approved; base level on role
            if (role_name) {
                if (strcmp(role_name, "admin") == 0) level = 3;
                else if (strcmp(role_name, "moderator") == 0) level = 2;
                else if (strcmp(role_name, "visitor") == 0) level = 1;
                else level = 1;  // Default to visitor if role is unrecognized
            } else {
                level = 1;  // No role specified, treat as visitor
            }
        }
    }
    
    sqlite3_finalize(stmt);
    return level;
}

int update_profile_picture(sqlite3 *db, const char *username, const unsigned char *image_buffer, size_t buffer_size, const char *profile_pic_path, const char *file_ending, int max_kb) {
    if (buffer_size > max_kb * 1024) return -1;

    // Allowed file endings
    const char *allowed_endings[] = {"jpg", "jpeg", "png", "gif"};
    int valid_ending = 0;
    for (int i = 0; i < 4; i++) {
        if (strcasecmp(file_ending, allowed_endings[i]) == 0) {
            valid_ending = 1;
            break;
        }
    }
    if (!valid_ending) return -1;

    sqlite3_stmt *stmt;
    const char *check_sql = "SELECT user_id FROM user WHERE user_name = ?;";
    if (sqlite3_prepare_v2(db, check_sql, -1, &stmt, NULL) != SQLITE_OK) return -1;
    
    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    sqlite3_int64 user_id = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        user_id = sqlite3_column_int64(stmt, 0);
    } else {
        sqlite3_finalize(stmt);
        return -1;
    }
    sqlite3_finalize(stmt);

    // Get the count of existing profile pictures for this user
    int pic_number = 0;
    const char *count_sql = "SELECT COUNT(*) FROM profile_pics WHERE profile_img_path LIKE ?;";
    if (sqlite3_prepare_v2(db, count_sql, -1, &stmt, NULL) == SQLITE_OK) {
        char pattern[256];
        snprintf(pattern, sizeof(pattern), "profile/%s_%%", username);
        sqlite3_bind_text(stmt, 1, pattern, -1, SQLITE_STATIC);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            pic_number = sqlite3_column_int(stmt, 0);
        }
    }
    sqlite3_finalize(stmt);

    sqlite3_exec(db, "BEGIN TRANSACTION;", NULL, NULL, NULL);
    
    struct stat st = {0};
    if (folder_create(profile_pic_path) != 0) {
        sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
        return -1;
    }

    char new_path[256];
    snprintf(new_path, sizeof(new_path), "%s/%s_%d.%s", 
             profile_pic_path, username, pic_number, file_ending);

    FILE *fp = fopen(new_path, "wb");
    if (!fp || fwrite(image_buffer, 1, buffer_size, fp) != buffer_size) {
        if (fp) fclose(fp);
        sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
        return -1;
    }
    fclose(fp);

    char file_name[256];
    snprintf(file_name, sizeof(file_name), "profile/%s_%d.%s", username, pic_number, file_ending);

    // Insert new profile picture record
    const char *insert_sql = "INSERT INTO profile_pics (profile_img_path) VALUES (?);";
    if (sqlite3_prepare_v2(db, insert_sql, -1, &stmt, NULL) != SQLITE_OK ||
        sqlite3_bind_text(stmt, 1, file_name, -1, SQLITE_STATIC) != SQLITE_OK ||
        sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
        return -1;
    }
    
    sqlite3_int64 new_profile_id = sqlite3_last_insert_rowid(db);
    sqlite3_finalize(stmt);

    // Update user's current profile picture reference
    const char *update_sql = "UPDATE user SET profile_id = ? WHERE user_id = ?;";
    if (sqlite3_prepare_v2(db, update_sql, -1, &stmt, NULL) != SQLITE_OK ||
        sqlite3_bind_int64(stmt, 1, new_profile_id) != SQLITE_OK ||
        sqlite3_bind_int64(stmt, 2, user_id) != SQLITE_OK ||
        sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
        return -1;
    }

    sqlite3_finalize(stmt);
    return sqlite3_exec(db, "COMMIT;", NULL, NULL, NULL) == SQLITE_OK ? 0 : -1;
}