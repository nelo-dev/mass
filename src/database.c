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
        "PRAGMA synchronous=OFF;",
        "PRAGMA mmap_size=268435456;",
        "PRAGMA temp_store=MEMORY;",
        "PRAGMA page_size=4096;",
        "PRAGMA optimize;"
        "PRAGMA foreign_keys = OFF;"
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
        "description_path TEXT UNIQUE NOT NULL, "
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

        // Updated api_keys table with an active column
        "CREATE TABLE IF NOT EXISTS api_keys ("
        "api_id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "user_id INTEGER NOT NULL, "
        "api_key TEXT UNIQUE NOT NULL, "
        "active INTEGER DEFAULT 1, "
        "created_at DATETIME DEFAULT CURRENT_TIMESTAMP, "
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
        "CREATE INDEX IF NOT EXISTS idx_user_role_id ON user(role_id);",
        "CREATE INDEX IF NOT EXISTS idx_user_approved ON user(approved);"
        "CREATE INDEX IF NOT EXISTS idx_media_title ON media(title);"
        "CREATE INDEX idx_tag_trgm ON tags USING GIN (tag_name gin_trgm_ops);"
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

char* search_users(sqlite3* db, const char* search_json) {
    json_t* result;

    // Validate database pointer
    if (!db) {
        result = json_object();
        json_object_set_new(result, "error", json_string("Database connection is null"));
        return json_dumps(result, JSON_COMPACT);
    }

    // Validate search_json and parse it
    if (!search_json) {
        result = json_object();
        json_object_set_new(result, "error", json_string("No search JSON provided"));
        return json_dumps(result, JSON_COMPACT);
    }

    json_t* root;
    json_error_t error;
    root = json_loads(search_json, 0, &error);
    if (!root) {
        result = json_object();
        json_object_set_new(result, "error", json_string("Invalid JSON format"));
        return json_dumps(result, JSON_COMPACT);
    }

    // Extract the "username" field from the JSON
    json_t* username_json = json_object_get(root, "username");
    if (!username_json || !json_is_string(username_json)) {
        result = json_object();
        json_object_set_new(result, "error", json_string("Missing or invalid 'username' in JSON"));
        json_decref(root);
        return json_dumps(result, JSON_COMPACT);
    }
    const char* username = json_string_value(username_json);

    // Create the LIKE pattern for partial matching (e.g., "%jo%")
    char* like_pattern = sqlite3_mprintf("%%%s%%", username);
    if (!like_pattern) {
        result = json_object();
        json_object_set_new(result, "error", json_string("Failed to allocate LIKE pattern"));
        json_decref(root);
        return json_dumps(result, JSON_COMPACT);
    }

    // Define the SQL query with LEFT JOINs
    const char* sql = "SELECT u.user_name, p.profile_img_path, r.role_name, u.approved "
                      "FROM user u "
                      "LEFT JOIN profile_pics p ON u.profile_id = p.profile_id "
                      "LEFT JOIN roles r ON u.role_id = r.role_id "
                      "WHERE u.user_name LIKE ?"
                      "LIMIT 16";

    // Prepare the SQL statement
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        result = json_object();
        json_object_set_new(result, "error", json_string("Failed to prepare SQL statement"));
        sqlite3_free(like_pattern);
        json_decref(root);
        return json_dumps(result, JSON_COMPACT);
    }

    // Bind the LIKE pattern to the query
    rc = sqlite3_bind_text(stmt, 1, like_pattern, -1, SQLITE_TRANSIENT);
    if (rc != SQLITE_OK) {
        result = json_object();
        json_object_set_new(result, "error", json_string("Failed to bind SQL parameters"));
        sqlite3_finalize(stmt);
        sqlite3_free(like_pattern);
        json_decref(root);
        return json_dumps(result, JSON_COMPACT);
    }

    // Create a JSON array for successful results
    result = json_array();

    // Execute the query and process each row
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        const char* user_name = (const char*)sqlite3_column_text(stmt, 0);
        const char* profile_path = (const char*)sqlite3_column_text(stmt, 1);
        const char* role_name = (const char*)sqlite3_column_text(stmt, 2);
        int approved = sqlite3_column_int(stmt, 3);

        json_t* user_obj = json_object();
        json_object_set_new(user_obj, "name", json_string(user_name));
        json_object_set_new(user_obj, "profile_path", 
                            profile_path ? json_string(profile_path) : json_null());
        json_object_set_new(user_obj, "role", 
                            role_name ? json_string(role_name) : json_null());
        json_object_set_new(user_obj, "approved", json_integer(approved));

        json_array_append_new(result, user_obj);
    }

    // Check if query execution completed successfully
    if (rc != SQLITE_DONE) {
        json_decref(result);
        result = json_object();
        json_object_set_new(result, "error", json_string("Failed to execute SQL query"));
    }

    // Clean up SQLite resources
    sqlite3_finalize(stmt);
    sqlite3_free(like_pattern);
    json_decref(root);

    // Convert the result (array or error object) to a string
    char* result_json = json_dumps(result, JSON_COMPACT);
    json_decref(result);

    // Return the JSON string (caller must free this memory)
    return result_json;
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

char *toggle_user_approval_by_requester(sqlite3 *db, const char *json_input, const char *requester_username) {
    json_t *root = json_loads(json_input, 0, NULL);
    if (!root) return strdup("{\"success\":false,\"error\":\"Invalid JSON\"}");

    const char *target_username = json_string_value(json_object_get(root, "username"));
    if (!target_username) {
        json_decref(root);
        return strdup("{\"success\":false,\"error\":\"Missing username\"}");
    }

    // Check if requester is trying to modify their own status
    if (strcmp(requester_username, target_username) == 0) {
        json_decref(root);
        return strdup("{\"success\":false,\"error\":\"Cannot modify own approval status\"}");
    }

    // Get requester's role and approval status
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, 
        "SELECT r.role_name FROM user u JOIN roles r ON u.role_id = r.role_id WHERE u.user_name = ?", 
        -1, &stmt, NULL) != SQLITE_OK) {
        json_decref(root);
        return strdup("{\"success\":false,\"error\":\"DB prep error for requester\"}");
    }

    sqlite3_bind_text(stmt, 1, requester_username, -1, SQLITE_STATIC);
    int requester_rank = -1;  // -1: not found, 0: visitor, 1: moderator, 2: admin
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *requester_role = (const char*)sqlite3_column_text(stmt, 0);
        if (strcmp(requester_role, "admin") == 0) requester_rank = 2;
        else if (strcmp(requester_role, "moderator") == 0) requester_rank = 1;
        else if (strcmp(requester_role, "visitor") == 0) requester_rank = 0;
    }
    sqlite3_finalize(stmt);

    if (requester_rank == -1) {
        json_decref(root);
        return strdup("{\"success\":false,\"error\":\"Requester not found\"}");
    }

    // Get target user's role and approval status
    if (sqlite3_prepare_v2(db, 
        "SELECT u.approved, r.role_name FROM user u JOIN roles r ON u.role_id = r.role_id WHERE u.user_name = ?", 
        -1, &stmt, NULL) != SQLITE_OK) {
        json_decref(root);
        return strdup("{\"success\":false,\"error\":\"DB prep error for target\"}");
    }

    sqlite3_bind_text(stmt, 1, target_username, -1, SQLITE_STATIC);
    int step_result = sqlite3_step(stmt);
    int new_approval = -1;
    int target_rank = -1;  // -1: not found, 0: visitor, 1: moderator, 2: admin
    if (step_result == SQLITE_ROW) {
        new_approval = !sqlite3_column_int(stmt, 0);
        const char *target_role = (const char*)sqlite3_column_text(stmt, 1);
        if (strcmp(target_role, "admin") == 0) target_rank = 2;
        else if (strcmp(target_role, "moderator") == 0) target_rank = 1;
        else if (strcmp(target_role, "visitor") == 0) target_rank = 0;
    }
    sqlite3_finalize(stmt);

    if (new_approval == -1) {
        json_decref(root);
        return strdup("{\"success\":false,\"error\":\"Target user not found\"}");
    }

    // Check permission hierarchy
    if (requester_rank <= target_rank) {
        json_decref(root);
        return strdup("{\"success\":false,\"error\":\"Insufficient permissions to modify this user\"}");
    }

    // Perform the update
    if (sqlite3_prepare_v2(db, 
        "UPDATE user SET approved = ? WHERE user_name = ?", 
        -1, &stmt, NULL) != SQLITE_OK ||
        sqlite3_bind_int(stmt, 1, new_approval) != SQLITE_OK ||
        sqlite3_bind_text(stmt, 2, target_username, -1, SQLITE_STATIC) != SQLITE_OK ||
        sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        json_decref(root);
        return strdup("{\"success\":false,\"error\":\"Update failed\"}");
    }

    sqlite3_finalize(stmt);
    json_decref(root);

    json_t *response = json_pack("{sbsisi}", 
        "success", 1, 
        "username", target_username, 
        "approved", new_approval);
    char *result = json_dumps(response, JSON_COMPACT);
    json_decref(response);
    return result;
}

char *toggle_user_role_by_requester(sqlite3 *db, const char *json_input, const char *requester_username) {
    json_t *root = json_loads(json_input, 0, NULL);
    if (!root) return strdup("{\"success\":false,\"error\":\"Invalid JSON\"}");

    const char *target_username = json_string_value(json_object_get(root, "username"));
    if (!target_username) {
        json_decref(root);
        return strdup("{\"success\":false,\"error\":\"Missing username\"}");
    }

    if (strcmp(requester_username, target_username) == 0) {
        json_decref(root);
        return strdup("{\"success\":false,\"error\":\"Cannot modify own role\"}");
    }

    // Check if requester is admin
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db,
        "SELECT r.role_name FROM user u JOIN roles r ON u.role_id = r.role_id WHERE u.user_name = ?",
        -1, &stmt, NULL) != SQLITE_OK) {
        json_decref(root);
        return strdup("{\"success\":false,\"error\":\"DB prep error for requester\"}");
    }

    sqlite3_bind_text(stmt, 1, requester_username, -1, SQLITE_STATIC);
    int is_requester_admin = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *role = (const char*)sqlite3_column_text(stmt, 0);
        if (role && strcmp(role, "admin") == 0) {
            is_requester_admin = 1;
        }
    }
    sqlite3_finalize(stmt);

    if (!is_requester_admin) {
        json_decref(root);
        return strdup("{\"success\":false,\"error\":\"Only admins can modify roles\"}");
    }

    // Get current role with safer handling
    if (sqlite3_prepare_v2(db,
        "SELECT r.role_name FROM user u JOIN roles r ON u.role_id = r.role_id WHERE u.user_name = ?",
        -1, &stmt, NULL) != SQLITE_OK) {
        json_decref(root);
        return strdup("{\"success\":false,\"error\":\"DB prep error for target\"}");
    }

    sqlite3_bind_text(stmt, 1, target_username, -1, SQLITE_STATIC);
    char current_role[16] = {0};  // Buffer for role name (visitor/moderator/admin)
    int has_result = 0;
    
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *role_temp = (const char*)sqlite3_column_text(stmt, 0);
        if (role_temp) {
            strncpy(current_role, role_temp, sizeof(current_role) - 1);
            has_result = 1;
        }
    }
    sqlite3_finalize(stmt);

    if (!has_result) {
        json_decref(root);
        return strdup("{\"success\":false,\"error\":\"Target user not found\"}");
    }

    // Determine next role
    const char *next_role;
    if (strcmp(current_role, "visitor") == 0) {
        next_role = "moderator";
    } else {
        next_role = "visitor";
    }

    // Update the role
    if (sqlite3_prepare_v2(db,
        "UPDATE user SET role_id = (SELECT role_id FROM roles WHERE role_name = ?) WHERE user_name = ?",
        -1, &stmt, NULL) != SQLITE_OK ||
        sqlite3_bind_text(stmt, 1, next_role, -1, SQLITE_STATIC) != SQLITE_OK ||
        sqlite3_bind_text(stmt, 2, target_username, -1, SQLITE_STATIC) != SQLITE_OK ||
        sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        json_decref(root);
        return strdup("{\"success\":false,\"error\":\"Role update failed\"}");
    }

    sqlite3_finalize(stmt);
    json_decref(root);

    json_t *response = json_pack("{sbsiss}", 
        "success", 1,
        "username", target_username,
        "new_role", next_role);
    char *result = json_dumps(response, JSON_COMPACT);
    json_decref(response);
    return result;
}

char *generate_random_key(size_t length) {
    const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    char *random_string = malloc(length + 1);
    if (!random_string) return NULL;

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    unsigned int seed = (unsigned int)(ts.tv_nsec ^ ts.tv_sec);
    srand(seed);

    for (size_t i = 0; i < length; i++) {
        random_string[i] = charset[rand() % (sizeof(charset) - 1)];
    }
    random_string[length] = '\0';

    return random_string;
}

char* create_api_key(sqlite3 *db, const char *request_username, const char *json_input) {
    (void)json_input;  /* currently not used */
    sqlite3_stmt *stmt = NULL;
    const char *sql = "SELECT user_id FROM user WHERE user_name = ?;";
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Prepare failed: %s\n", sqlite3_errmsg(db));
        goto error;
    }
    sqlite3_bind_text(stmt, 1, request_username, -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        fprintf(stderr, "User '%s' not found.\n", request_username);
        sqlite3_finalize(stmt);
        goto error;
    }
    int user_id = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);

    /* Generate a random API key */
    char *api_key = generate_random_key(32);
    if (!api_key) {
        fprintf(stderr, "Failed to generate API key.\n");
        goto error;
    }

    /* Insert the new API key record (active by default) */
    sql = "INSERT INTO api_keys (user_id, api_key) VALUES (?, ?);";
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Prepare insert failed: %s\n", sqlite3_errmsg(db));
        free(api_key);
        goto error;
    }
    sqlite3_bind_int(stmt, 1, user_id);
    sqlite3_bind_text(stmt, 2, api_key, -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "Insert failed: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        free(api_key);
        goto error;
    }
    sqlite3_finalize(stmt);

    /* Build success JSON response */
    json_t *root = json_object();
    json_object_set_new(root, "status", json_string("success"));
    json_object_set_new(root, "api_key", json_string(api_key));
    char *output = json_dumps(root, 0);
    json_decref(root);
    free(api_key);
    return output;

error:
    {
        json_t *err = json_object();
        json_object_set_new(err, "status", json_string("error"));
        char *err_output = json_dumps(err, 0);
        json_decref(err);
        return err_output;
    }
}

char* destroy_api_key(sqlite3 *db, const char *json_input) {
    json_error_t error;
    json_t *root = json_loads(json_input, 0, &error);
    if (!root) {
        fprintf(stderr, "JSON parse error: %s\n", error.text);
        goto json_error;
    }

    json_t *j_api_key = json_object_get(root, "api_key");
    if (!json_is_string(j_api_key)) {
        fprintf(stderr, "Invalid JSON input. 'api_key' must be a string.\n");
        json_decref(root);
        goto json_error;
    }

    const char *api_key = json_string_value(j_api_key);

    sqlite3_stmt *stmt = NULL;
    // Update the API key record to set active to 0 (deactivation)
    const char *sql = "UPDATE api_keys SET active = 0 WHERE api_key = ?;";
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Prepare update failed: %s\n", sqlite3_errmsg(db));
        json_decref(root);
        goto json_error;
    }
    sqlite3_bind_text(stmt, 1, api_key, -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "Update failed: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        json_decref(root);
        goto json_error;
    }
    sqlite3_finalize(stmt);
    json_decref(root);

    json_t *response = json_object();
    json_object_set_new(response, "status", json_string("success"));
    char *output = json_dumps(response, 0);
    json_decref(response);
    return output;

json_error:
    {
        json_t *err = json_object();
        json_object_set_new(err, "status", json_string("error"));
        char *err_output = json_dumps(err, 0);
        json_decref(err);
        return err_output;
    }
}

char* get_all_api_keys(sqlite3 *db) {
    // Only retrieve active API keys
    const char *sql = "SELECT api_keys.api_id, user.user_name, api_keys.api_key, api_keys.created_at "
                      "FROM api_keys "
                      "JOIN user ON api_keys.user_id = user.user_id "
                      "WHERE api_keys.active = 1;";
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Prepare failed: %s\n", sqlite3_errmsg(db));
        goto error;
    }

    json_t *result_array = json_array();
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        json_t *row_obj = json_object();

        int api_id = sqlite3_column_int(stmt, 0);
        const unsigned char *username = sqlite3_column_text(stmt, 1);
        const unsigned char *api_key = sqlite3_column_text(stmt, 2);
        const unsigned char *created_at = sqlite3_column_text(stmt, 3);

        json_object_set_new(row_obj, "api_id", json_integer(api_id));
        json_object_set_new(row_obj, "username", json_string(username ? (const char*)username : ""));
        json_object_set_new(row_obj, "api_key", json_string(api_key ? (const char*)api_key : ""));
        json_object_set_new(row_obj, "created_at", json_string(created_at ? (const char*)created_at : ""));

        json_array_append_new(result_array, row_obj);
    }
    sqlite3_finalize(stmt);

    char *output = json_dumps(result_array, 0);
    json_decref(result_array);
    return output;

error:
    {
        json_t *err = json_object();
        json_object_set_new(err, "status", json_string("error"));
        char *err_output = json_dumps(err, 0);
        json_decref(err);
        return err_output;
    }
}

// Helper function to convert an integer to a 6-character base32 string
char* int_to_base32(int64_t num, int length) {
    const char* alphabet = "0123456789abcdefghijklmnopqrstuv";
    char* result = malloc(length + 1);
    if (!result) return NULL;
    result[length] = '\0';
    for (int i = length - 1; i >= 0; i--) {
        int remainder = num % 32;
        result[i] = alphabet[remainder];
        num /= 32;
    }
    return result;
}

// Helper function to extract file extension from a URL
const char* get_extension(const char* url) {
    const char* dot = strrchr(url, '.');
    if (!dot || dot == url) return "bin"; // Default extension if none found
    return dot + 1;
}

// Helper function to create error JSON
char* error_json(const char* message) {
    json_t* root = json_object();
    json_object_set_new(root, "status", json_string("error"));
    json_object_set_new(root, "message", json_string(message));
    char* result = json_dumps(root, JSON_COMPACT);
    json_decref(root);
    return result;
}

// Helper function to create success JSON
char* success_json() {
    json_t* root = json_object();
    json_object_set_new(root, "status", json_string("success"));
    char* result = json_dumps(root, JSON_COMPACT);
    json_decref(root);
    return result;
}

char* insert_media(sqlite3* db, Downloader* dl, const char* input_json, 
                  const char* media_dir, const char* preview_dir, const char* description_dir) {
    // Parse the input JSON
    json_t* root = json_loads(input_json, 0, NULL);
    if (!root) {
        return error_json("Invalid JSON");
    }

    // Extract required fields
    const char* api_key = json_string_value(json_object_get(root, "api_key"));
    const char* dl_url = json_string_value(json_object_get(root, "dl_url"));
    const char* preview_url = json_string_value(json_object_get(root, "preview_url"));
    const char* description = json_string_value(json_object_get(root, "description"));
    json_t* web_id_json = json_object_get(root, "web_id");
    const char* title = json_string_value(json_object_get(root, "title"));
    const char* creator = json_string_value(json_object_get(root, "creator"));
    json_t* score_json = json_object_get(root, "score");
    json_t* tags_json = json_object_get(root, "tags");

    // Validate required fields
    if (!api_key || !dl_url || !preview_url || !description || !json_is_integer(web_id_json) || 
        !title || !creator || !json_is_integer(score_json) || !json_is_array(tags_json)) {
        json_decref(root);
        return error_json("Missing or invalid required fields");
    }

    int web_id = json_integer_value(web_id_json);
    int score = json_integer_value(score_json);

    // Validate API key
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, "SELECT active FROM api_keys WHERE api_key = ?", -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        json_decref(root);
        return error_json("Database error during API key validation");
    }
    sqlite3_bind_text(stmt, 1, api_key, -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW || sqlite3_column_int(stmt, 0) != 1) {
        sqlite3_finalize(stmt);
        json_decref(root);
        return error_json("Invalid or inactive API key");
    }
    sqlite3_finalize(stmt);

    // Start transaction
    rc = sqlite3_exec(db, "BEGIN TRANSACTION", NULL, NULL, NULL);
    if (rc != SQLITE_OK) {
        json_decref(root);
        return error_json("Failed to start transaction");
    }

    // Insert media with temporary paths
    char* temp_desc_path = malloc(strlen(dl_url) + 6); // "_desc\0"
    if (!temp_desc_path) {
        json_decref(root);
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        return error_json("Memory allocation failed");
    }
    sprintf(temp_desc_path, "%s_desc", dl_url);

    const char* insert_sql = "INSERT INTO media (url, preview_url, path, preview_path, "
                             "description_path, title, creator, score, web_id) "
                             "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
    rc = sqlite3_prepare_v2(db, insert_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        free(temp_desc_path);
        json_decref(root);
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        return error_json("Database error during media insertion");
    }

    sqlite3_bind_text(stmt, 1, dl_url, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, preview_url, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, dl_url, -1, SQLITE_STATIC); // Temporary path
    sqlite3_bind_text(stmt, 4, preview_url, -1, SQLITE_STATIC); // Temporary preview_path
    sqlite3_bind_text(stmt, 5, temp_desc_path, -1, SQLITE_STATIC); // Temporary description_path
    sqlite3_bind_text(stmt, 6, title, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 7, creator, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 8, score);
    sqlite3_bind_int(stmt, 9, web_id);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        free(temp_desc_path);
        json_decref(root);
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        return error_json("Failed to insert media");
    }
    sqlite3_finalize(stmt);
    int64_t media_id = sqlite3_last_insert_rowid(db);

    // Generate base32 string from media_id
    char* base32_str = int_to_base32(media_id, 6);
    if (!base32_str) {
        free(temp_desc_path);
        json_decref(root);
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        return error_json("Failed to generate base32 string");
    }

    // Extract file extensions
    const char* media_ext = get_extension(dl_url);
    const char* preview_ext = get_extension(preview_url);

    // Construct subdir
    char subdir[6]; // "/ab/cd"
    sprintf(subdir, "/%c%c/%c%c", base32_str[0], base32_str[1], base32_str[2], base32_str[3]);

    // Construct full paths for downloading
    char* media_dir_path = malloc(strlen(media_dir) + 6 + 1);
    char* media_path = malloc(strlen(media_dir) + 6 + 1 + 6 + 1 + strlen(media_ext) + 1);
    if (!media_dir_path || !media_path) {
        free(base32_str); free(temp_desc_path); free(media_dir_path); free(media_path);
        json_decref(root);
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        return error_json("Memory allocation failed");
    }
    sprintf(media_dir_path, "%s%s", media_dir, subdir);
    sprintf(media_path, "%s/%s.%s", media_dir_path, base32_str, media_ext);
    folder_create(media_dir_path);

    char* preview_dir_path = malloc(strlen(preview_dir) + 6 + 1);
    char* preview_path = malloc(strlen(preview_dir) + 6 + 1 + 6 + 1 + strlen(preview_ext) + 1);
    if (!preview_dir_path || !preview_path) {
        free(base32_str); free(temp_desc_path); free(media_dir_path); free(media_path);
        free(preview_dir_path); free(preview_path);
        json_decref(root);
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        return error_json("Memory allocation failed");
    }
    sprintf(preview_dir_path, "%s%s", preview_dir, subdir);
    sprintf(preview_path, "%s/%s.%s", preview_dir_path, base32_str, preview_ext);
    folder_create(preview_dir_path);

    char* desc_dir_path = malloc(strlen(description_dir) + 6 + 1);
    char* desc_path = malloc(strlen(description_dir) + 6 + 1 + 6 + 5); // ".html"
    if (!desc_dir_path || !desc_path) {
        free(base32_str); free(temp_desc_path); free(media_dir_path); free(media_path);
        free(preview_dir_path); free(preview_path); free(desc_dir_path); free(desc_path);
        json_decref(root);
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        return error_json("Memory allocation failed");
    }
    sprintf(desc_dir_path, "%s%s", description_dir, subdir);
    sprintf(desc_path, "%s/%s.html", desc_dir_path, base32_str);
    folder_create(desc_dir_path);

    // Construct relative paths for database storage
    char* relative_media_path = malloc(6 + strlen(subdir) + 1 + strlen(base32_str) + 1 + strlen(media_ext) + 1);
    char* relative_preview_path = malloc(8 + strlen(subdir) + 1 + strlen(base32_str) + 1 + strlen(preview_ext) + 1);
    char* relative_desc_path = malloc(12 + strlen(subdir) + 1 + strlen(base32_str) + 5); // "description" + subdir + "/" + base32_str + ".html"
    if (!relative_media_path || !relative_preview_path || !relative_desc_path) {
        free(base32_str); free(temp_desc_path); free(media_dir_path); free(media_path);
        free(preview_dir_path); free(preview_path); free(desc_dir_path); free(desc_path);
        free(relative_media_path); free(relative_preview_path); free(relative_desc_path);
        json_decref(root);
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        return error_json("Memory allocation failed");
    }
    sprintf(relative_media_path, "media%s/%s.%s", subdir, base32_str, media_ext);
    sprintf(relative_preview_path, "preview%s/%s.%s", subdir, base32_str, preview_ext);
    sprintf(relative_desc_path, "description%s/%s.html", subdir, base32_str);

    // Download media and preview, save description using full paths
    downloader_add(dl, dl_url, media_path);
    downloader_add(dl, preview_url, preview_path);
    if (file_write(desc_path, description, strlen(description)) != 0) {
        free(base32_str); free(temp_desc_path); free(media_dir_path); free(media_path);
        free(preview_dir_path); free(preview_path); free(desc_dir_path); free(desc_path);
        free(relative_media_path); free(relative_preview_path); free(relative_desc_path);
        json_decref(root);
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        return error_json("Failed to write description file");
    }

    // Update media with relative paths in the database
    const char* update_sql = "UPDATE media SET path=?, preview_path=?, description_path=? WHERE media_id=?";
    rc = sqlite3_prepare_v2(db, update_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        free(base32_str); free(temp_desc_path); free(media_dir_path); free(media_path);
        free(preview_dir_path); free(preview_path); free(desc_dir_path); free(desc_path);
        free(relative_media_path); free(relative_preview_path); free(relative_desc_path);
        json_decref(root);
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        return error_json("Database error during path update");
    }
    sqlite3_bind_text(stmt, 1, relative_media_path, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, relative_preview_path, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, relative_desc_path, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 4, media_id);
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        free(base32_str); free(temp_desc_path); free(media_dir_path); free(media_path);
        free(preview_dir_path); free(preview_path); free(desc_dir_path); free(desc_path);
        free(relative_media_path); free(relative_preview_path); free(relative_desc_path);
        json_decref(root);
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        return error_json("Failed to update media paths");
    }
    sqlite3_finalize(stmt);

    // Insert tags
    size_t index;
    json_t* tag_json;
    json_array_foreach(tags_json, index, tag_json) {
        const char* tag = json_string_value(tag_json);
        if (!tag) continue;

        // Insert into tags if not exists
        rc = sqlite3_prepare_v2(db, "INSERT OR IGNORE INTO tags (tag_name) VALUES (?)", -1, &stmt, NULL);
        sqlite3_bind_text(stmt, 1, tag, -1, SQLITE_STATIC);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);

        // Get tag_id
        rc = sqlite3_prepare_v2(db, "SELECT tag_id FROM tags WHERE tag_name=?", -1, &stmt, NULL);
        sqlite3_bind_text(stmt, 1, tag, -1, SQLITE_STATIC);
        rc = sqlite3_step(stmt);
        if (rc == SQLITE_ROW) {
            int tag_id = sqlite3_column_int(stmt, 0);
            sqlite3_finalize(stmt);

            // Insert into media_tags
            rc = sqlite3_prepare_v2(db, "INSERT INTO media_tags (media_id, tag_id) VALUES (?, ?)", -1, &stmt, NULL);
            sqlite3_bind_int64(stmt, 1, media_id);
            sqlite3_bind_int(stmt, 2, tag_id);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        } else {
            sqlite3_finalize(stmt);
        }
    }

    // Commit transaction
    rc = sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);
    if (rc != SQLITE_OK) {
        free(base32_str); free(temp_desc_path); free(media_dir_path); free(media_path);
        free(preview_dir_path); free(preview_path); free(desc_dir_path); free(desc_path);
        free(relative_media_path); free(relative_preview_path); free(relative_desc_path);
        json_decref(root);
        return error_json("Failed to commit transaction");
    }

    // Cleanup
    free(base32_str);
    free(temp_desc_path);
    free(media_dir_path);
    free(media_path);
    free(preview_dir_path);
    free(preview_path);
    free(desc_dir_path);
    free(desc_path);
    free(relative_media_path);
    free(relative_preview_path);
    free(relative_desc_path);
    json_decref(root);

    return success_json();
}

// Helper function to create error JSON
static char* create_error_json(const char* message) {
    json_t* error_obj = json_object();
    json_object_set_new(error_obj, "error", json_string(message));
    char* error_str = json_dumps(error_obj, JSON_COMPACT);
    json_decref(error_obj);
    return error_str;
}

char* search_media(sqlite3* db, const char* json_input) {
    // Parse JSON input
    json_t *root;
    json_error_t error;
    root = json_loads(json_input, 0, &error);
    if (!root) {
        return create_error_json("JSON parse error");
    }
    if (!json_is_object(root)) {
        json_decref(root);
        return create_error_json("Input must be a JSON object");
    }

    // Extract JSON fields
    json_t *tags = json_object_get(root, "tags");
    json_t *title = json_object_get(root, "title");
    json_t *search_type = json_object_get(root, "search_type");
    json_t *sort = json_object_get(root, "sort");
    json_t *order = json_object_get(root, "order");
    json_t *limit_json = json_object_get(root, "limit");
    json_t *offset_json = json_object_get(root, "offset");

    // Validate required fields
    if (!json_is_array(tags) || !json_is_string(title) || !json_is_string(search_type) ||
        !json_is_string(sort) || !json_is_string(order) || !json_is_integer(limit_json)) {
        json_decref(root);
        return create_error_json("Missing or invalid required fields");
    }

    // Extract and validate limit
    int limit_val = json_integer_value(limit_json);
    if (limit_val < 1 || limit_val > 128) {
        json_decref(root);
        return create_error_json("Limit must be between 1 and 128");
    }

    // Extract and validate offset
    int offset_val = 0;
    if (offset_json != NULL) {
        if (!json_is_integer(offset_json)) {
            json_decref(root);
            return create_error_json("Offset must be an integer");
        }
        offset_val = json_integer_value(offset_json);
        if (offset_val < 0) {
            json_decref(root);
            return create_error_json("Offset must be non-negative");
        }
    }

    // Extract other fields
    const char *search_type_str = json_string_value(search_type);
    const char *sort_str = json_string_value(sort);
    const char *order_str = json_string_value(order);
    const char *order_by = (strcmp(sort_str, "media_id") == 0) ? "m.media_id" :
                           (strcmp(sort_str, "score") == 0) ? "m.score" : "m.web_id";
    const char *order_dir = (strcmp(order_str, "asc") == 0) ? "ASC" : "DESC";

    // Prepare SQL query
    char *sql = NULL;
    sqlite3_stmt *stmt = NULL;

    if (strcmp(search_type_str, "tags") == 0) {
        size_t num_tags = json_array_size(tags);
        if (num_tags > 0) {
            // Validate tags are strings
            for (size_t i = 0; i < num_tags; i++) {
                if (!json_is_string(json_array_get(tags, i))) {
                    json_decref(root);
                    return create_error_json("Tags must be strings");
                }
            }
            // Build IN clause for tags
            char in_clause[2 * num_tags + 1];
            strcpy(in_clause, "?");
            for (size_t i = 1; i < num_tags; i++) {
                strcat(in_clause, ",?");
            }
            sql = sqlite3_mprintf(
                "SELECT m.media_id, m.title, m.score, m.web_id, m.preview_path, m.path, m.creator "
                "FROM media m "
                "JOIN media_tags mt ON m.media_id = mt.media_id "
                "JOIN tags t ON mt.tag_id = t.tag_id "
                "WHERE t.tag_name IN (%s) "
                "GROUP BY m.media_id, m.title, m.score, m.web_id, m.preview_path, m.path, m.creator "
                "HAVING COUNT(DISTINCT t.tag_id) = %d "
                "ORDER BY %s %s LIMIT %d OFFSET %d",
                in_clause, num_tags, order_by, order_dir, limit_val, offset_val
            );
        } else {
            // No tags: return all media
            sql = sqlite3_mprintf(
                "SELECT m.media_id, m.title, m.score, m.web_id, m.preview_path, m.path, m.creator "
                "FROM media m "
                "ORDER BY %s %s LIMIT %d OFFSET %d",
                order_by, order_dir, limit_val, offset_val
            );
        }
    } else if (strcmp(search_type_str, "title") == 0) {
        const char *title_str = json_string_value(title);
        if (strlen(title_str) > 0) {
            sql = sqlite3_mprintf(
                "SELECT m.media_id, m.title, m.score, m.web_id, m.preview_path, m.path, m.creator "
                "FROM media m "
                "WHERE m.title LIKE ? "
                "ORDER BY %s %s LIMIT %d OFFSET %d",
                order_by, order_dir, limit_val, offset_val
            );
        } else {
            // No title: return all media
            sql = sqlite3_mprintf(
                "SELECT m.media_id, m.title, m.score, m.web_id, m.preview_path, m.path, m.creator "
                "FROM media m "
                "ORDER BY %s %s LIMIT %d OFFSET %d",
                order_by, order_dir, limit_val, offset_val
            );
        }
    } else {
        json_decref(root);
        return create_error_json("Invalid search_type");
    }

    if (!sql) {
        json_decref(root);
        return create_error_json("SQL query construction failed");
    }

    // Prepare and bind SQL statement
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        sqlite3_free(sql);
        json_decref(root);
        return create_error_json("SQL preparation failed");
    }
    sqlite3_free(sql);

    if (strcmp(search_type_str, "tags") == 0 && json_array_size(tags) > 0) {
        for (size_t i = 0; i < json_array_size(tags); i++) {
            const char *tag = json_string_value(json_array_get(tags, i));
            sqlite3_bind_text(stmt, i + 1, tag, -1, SQLITE_STATIC);
        }
    } else if (strcmp(search_type_str, "title") == 0 && strlen(json_string_value(title)) > 0) {
        char *like_str = sqlite3_mprintf("%%%s%%", json_string_value(title));
        sqlite3_bind_text(stmt, 1, like_str, -1, SQLITE_TRANSIENT);
        sqlite3_free(like_str);
    }

    // Execute query and build JSON result
    json_t *results = json_array();
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        json_t *media = json_object();
        json_object_set_new(media, "media_id", json_integer(sqlite3_column_int(stmt, 0)));
        json_object_set_new(media, "title", json_string((const char*)sqlite3_column_text(stmt, 1)));
        json_object_set_new(media, "score", json_integer(sqlite3_column_int(stmt, 2)));
        json_object_set_new(media, "web_id", json_integer(sqlite3_column_int(stmt, 3)));
        json_object_set_new(media, "preview_path", json_string((const char*)sqlite3_column_text(stmt, 4)));
        json_object_set_new(media, "path", json_string((const char*)sqlite3_column_text(stmt, 5)));
        json_object_set_new(media, "creator", json_string((const char*)sqlite3_column_text(stmt, 6)));
        json_array_append_new(results, media);
    }

    sqlite3_finalize(stmt);

    char *result_str = json_dumps(results, JSON_COMPACT);
    json_decref(results);
    json_decref(root);

    if (!result_str) {
        return create_error_json("JSON serialization failed");
    }

    return result_str;
}

char* autocomplete_tags(sqlite3 *db, const char *json_input) {
    json_t *root = NULL;
    json_error_t error;
    char *result_json = NULL;
    sqlite3_stmt *stmt = NULL;
    
    // Parse input JSON
    root = json_loads(json_input, 0, &error);
    if (!root) {
        return json_dumps(json_pack("{s:s}", "error", "Invalid JSON input"), JSON_COMPACT);
    }

    const char *tag_partial = json_string_value(json_object_get(root, "tag"));
    if (!tag_partial) {
        json_decref(root);
        return json_dumps(json_pack("{s:s}", "error", "Missing 'tag' field"), JSON_COMPACT);
    }

    // Prepare SQL query with LIKE and count optimization
    const char *sql = 
        "SELECT t.tag_name, COUNT(mt.media_id) as occurrence "
        "FROM tags t "
        "LEFT JOIN media_tags mt ON t.tag_id = mt.tag_id "
        "WHERE t.tag_name LIKE ?1 "
        "GROUP BY t.tag_name, t.tag_id "
        "ORDER BY occurrence DESC "
        "LIMIT 10";

    // Use prepared statement for better performance
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        json_decref(root);
        return json_dumps(json_pack("{s:s}", "error", sqlite3_errmsg(db)), JSON_COMPACT);
    }

    // Create search pattern (e.g., "tag%" for prefix matching)
    char *pattern = sqlite3_mprintf("%s%%", tag_partial);
    sqlite3_bind_text(stmt, 1, pattern, -1, SQLITE_STATIC);

    // Create JSON array for results
    json_t *results = json_array();

    // Fetch results
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *tag_name = (const char *)sqlite3_column_text(stmt, 0);
        int occurrence = sqlite3_column_int(stmt, 1);

        json_t *tag_obj = json_pack("{s:s, s:i}", 
            "tag", tag_name,
            "count", occurrence
        );
        json_array_append_new(results, tag_obj);
    }

    // Clean up SQLite resources
    sqlite3_free(pattern);
    sqlite3_finalize(stmt);

    // Create final JSON object
    json_t *output = json_pack("{s:o}", "tags", results);
    result_json = json_dumps(output, JSON_COMPACT);

    // Clean up JSON resources
    json_decref(root);
    json_decref(output);

    return result_json ? result_json : json_dumps(json_pack("{s:s}", "error", "Failed to generate response"), JSON_COMPACT);
}

char* get_media_info(sqlite3 *db, const char *json_input) {
    json_t *root;
    json_error_t error;
    root = json_loads(json_input, 0, &error);
    if (!root) {
        json_t *error_json = json_object();
        json_object_set_new(error_json, "error", json_string("Invalid JSON input"));
        char *error_response = json_dumps(error_json, JSON_COMPACT);
        json_decref(error_json);
        return error_response;
    }

    json_t *media_id_json = json_object_get(root, "media_id");
    if (!json_is_integer(media_id_json)) {
        json_decref(root);
        json_t *error_json = json_object();
        json_object_set_new(error_json, "error", json_string("Missing or invalid media_id"));
        char *error_response = json_dumps(error_json, JSON_COMPACT);
        json_decref(error_json);
        return error_response;
    }
    int media_id = json_integer_value(media_id_json);
    json_decref(root);

    const char *query = 
        "SELECT media_id, url, preview_url, path, preview_path, description_path, title, creator, score, web_id "
        "FROM media WHERE media_id = ?;";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, query, -1, &stmt, NULL) != SQLITE_OK) {
        json_t *error_json = json_object();
        json_object_set_new(error_json, "error", json_string("Database query failed"));
        char *error_response = json_dumps(error_json, JSON_COMPACT);
        json_decref(error_json);
        return error_response;
    }
    sqlite3_bind_int(stmt, 1, media_id);

    json_t *media_json = json_object();
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        json_object_set_new(media_json, "media_id", json_integer(sqlite3_column_int(stmt, 0)));
        json_object_set_new(media_json, "url", json_string((const char*)sqlite3_column_text(stmt, 1)));
        json_object_set_new(media_json, "preview_url", json_string((const char*)sqlite3_column_text(stmt, 2)));
        json_object_set_new(media_json, "path", json_string((const char*)sqlite3_column_text(stmt, 3)));
        json_object_set_new(media_json, "preview_path", json_string((const char*)sqlite3_column_text(stmt, 4)));
        json_object_set_new(media_json, "description_path", json_string((const char*)sqlite3_column_text(stmt, 5)));
        json_object_set_new(media_json, "title", json_string((const char*)sqlite3_column_text(stmt, 6)));
        json_object_set_new(media_json, "creator", json_string((const char*)sqlite3_column_text(stmt, 7)));
        json_object_set_new(media_json, "score", json_integer(sqlite3_column_int(stmt, 8)));
        json_object_set_new(media_json, "web_id", json_integer(sqlite3_column_int(stmt, 9)));
    } else {
        json_decref(media_json);
        sqlite3_finalize(stmt);
        json_t *error_json = json_object();
        json_object_set_new(error_json, "error", json_string("Media entry not found"));
        char *error_response = json_dumps(error_json, JSON_COMPACT);
        json_decref(error_json);
        return error_response;
    }
    sqlite3_finalize(stmt);

    const char *tags_query = 
        "SELECT t.tag_name FROM tags t "
        "JOIN media_tags mt ON t.tag_id = mt.tag_id "
        "WHERE mt.media_id = ?;";

    if (sqlite3_prepare_v2(db, tags_query, -1, &stmt, NULL) != SQLITE_OK) {
        json_decref(media_json);
        json_t *error_json = json_object();
        json_object_set_new(error_json, "error", json_string("Failed to retrieve tags"));
        char *error_response = json_dumps(error_json, JSON_COMPACT);
        json_decref(error_json);
        return error_response;
    }
    sqlite3_bind_int(stmt, 1, media_id);

    json_t *tags_array = json_array();
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        json_array_append_new(tags_array, json_string((const char*)sqlite3_column_text(stmt, 0)));
    }
    sqlite3_finalize(stmt);
    json_object_set_new(media_json, "tags", tags_array);

    char *result = json_dumps(media_json, JSON_COMPACT);
    json_decref(media_json);
    return result;
}