#include "app.h"
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <stdbool.h>
#include <unistd.h>

void generate_random_string(char *str, size_t length) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    size_t charset_size = sizeof(charset) - 1;

    for (size_t i = 0; i < length; i++) {
        str[i] = charset[rand() % charset_size];
    }
    str[length] = '\0';
}

void init_config()
{
    create_config(CFG_PATH);
    add_comment(CFG_PATH, "Managed Archival Storage Server (M.A.S.S) configuration file. Changes require restart!");
    add_comment(CFG_PATH, "Server port:");
    add_param(CFG_PATH, "port", "8080");
    add_comment(CFG_PATH, "SSL key path (optional)");
    add_param(CFG_PATH, "ssl_key", "");
    add_comment(CFG_PATH, "SSL certificate path (optional)");
    add_param(CFG_PATH, "ssl_crt", "");
    add_comment(CFG_PATH, "Database file-path:");
    add_param(CFG_PATH, "db_path", "data/db/mass.db");
    add_comment(CFG_PATH, "Size of database cache in MegaByte (greatly improves speed on large archives):");
    add_param(CFG_PATH, "db_cache", "512");
    add_comment(CFG_PATH, "Server Name");
    add_param(CFG_PATH, "server_name", "mass");
    add_comment(CFG_PATH, "Server Icon (must be placed in folder public/resources)");
    add_param(CFG_PATH, "server_icon", "resources/placeholder_icon.png");
    add_comment(CFG_PATH, "Download Threads (concurrent media download count)");
    add_param(CFG_PATH, "dl_thread_cnt", "8");
    add_comment(CFG_PATH, "Max Download Queue Count (max elements pending in download queue)");
    add_param(CFG_PATH, "dl_queue_size", "64");
    add_comment(CFG_PATH, "Profile picture path:");
    add_param(CFG_PATH, "profile_path", "data/profiles/");
    add_comment(CFG_PATH, "Max Profile Image Size (in kB):");
    add_param(CFG_PATH, "max_profile_size", "128");
    add_comment(CFG_PATH, "New users require approval:");
    add_param(CFG_PATH, "approval", "1");
    add_comment(CFG_PATH, "Media Folder");
    add_param(CFG_PATH, "media_path", "data/media");
    add_comment(CFG_PATH, "Preview Folder");
    add_param(CFG_PATH, "preview_path", "data/preview");
    add_comment(CFG_PATH, "Description Folder");
    add_param(CFG_PATH, "description_path", "data/description");
    add_comment(CFG_PATH, "Login Timeout (in seconds)");
    add_param(CFG_PATH, "login_timeout", "3600");
}

App create_app()
{
    srand(time(NULL));

    App app = calloc(1, sizeof(App_t));
    init_config();

    if (get_param_string(CFG_PATH, "media_path", app->media_path, 256) == -1) {
        fprintf(stderr, "Error: Invalid or missing media_path. Using default path data/media/.\n");
        strcpy(app->media_path, "data/media");
    }

    if (get_param_string(CFG_PATH, "preview_path", app->preview_path, 256) == -1) {
        fprintf(stderr, "Error: Invalid or missing preview_path. Using default path data/preview/.\n");
        strcpy(app->preview_path, "data/preview");
    }

    if (get_param_string(CFG_PATH, "description_path", app->description_path, 256) == -1) {
        fprintf(stderr, "Error: Invalid or missing description_path. Using default path data/description/.\n");
        strcpy(app->description_path, "data/description");
    }

    char db_path[MAX_PATH_LEN];
    if (get_param_string(CFG_PATH, "db_path", db_path, MAX_PATH_LEN) == -1) {
        printf("Could not find database path (db_path) in config! Defaulting to db/mass.db");
        strcpy(db_path, "data/db/mass.db");
    }

    int db_cache = 0;
    if (get_param_int(CFG_PATH, "db_cache", &db_cache) == -1 || db_cache < 0) {
        fprintf(stderr, "Error: Invalid or missing db_cache configuration. Using default value of 512 MB.\n");
        db_cache = 512;
    }

    folder_create(db_path);
    app->db = create_and_open_db(db_path, db_cache);

    int dl_thread_cnt = 0;
    if (get_param_int(CFG_PATH, "dl_thread_cnt", &dl_thread_cnt) == -1 || dl_thread_cnt < 0) {
        fprintf(stderr, "Error: Invalid or missing dl_threaf_cnt configuration. Using default value of 8.\n");
        dl_thread_cnt = 8;
    }

    int dl_queue_size = 0;
    if (get_param_int(CFG_PATH, "dl_queue_size", &dl_queue_size) == -1 || dl_queue_size < 0) {
        fprintf(stderr, "Error: Invalid or missing dl_queue_size configuration. Using default value of 64.\n");
        dl_queue_size = 64;
    }

    app->login_timeout = 0;
    if (get_param_int(CFG_PATH, "login_timeout", &app->login_timeout) == -1 || app->login_timeout <= 0) {
        fprintf(stderr, "Error: Invalid or missing login_timeout configuration. Using default value of 3600 seconds.\n");
        app->login_timeout = 3600;
    }

    app->dl = downloader_create(dl_thread_cnt, dl_queue_size);

    generate_random_string(app->jwt_secret, 31);

    if (get_param_string(CFG_PATH, "server_name", app->server_name, 128) == -1) {
        fprintf(stderr, "Error: Invalid or missing server_name. Using default name.\n");
        strcpy(app->server_name, "mass");
    }

    if (get_param_string(CFG_PATH, "server_icon", app->icon_path, 256) == -1) {
        fprintf(stderr, "Error: Invalid or missing server_icon path. Using default placeholder icon.\n");
        strcpy(app->icon_path, "resources/placeholder_icon.png");
    }

    if (get_param_string(CFG_PATH, "profile_path", app->profile_path, 256) == -1) {
        fprintf(stderr, "Error: Invalid or missing profile_path path. Using default path data/profiles/.\n");
        strcpy(app->icon_path, "data/profiles/");
    }

    if (get_param_int(CFG_PATH, "max_profile_size", &app->max_profile_size) == -1 || dl_queue_size < 0) {
        fprintf(stderr, "Error: Invalid or missing max_profile_size configuration. Using default value of 128 kB.\n");
        app->max_profile_size = 128;
    }

    if (get_param_int(CFG_PATH, "approval", &app->approval) == -1 || dl_queue_size < 0) {
        fprintf(stderr, "Error: Approval (approval) is not configured. Request require approval on default.\n");
        app->approval = 1;
    }

    int port = 0;
    char ssl_key_path[MAX_PATH_LEN] = {0};
    char ssl_crt_path[MAX_PATH_LEN] = {0};
    bool ssl_key_found = false, ssl_crt_found = false;

    if (get_param_int(CFG_PATH, "port", &port) == -1 || port <= 0 || port > 65535) {
        fprintf(stderr, "Error: Invalid or missing port configuration. Using default port 8080.\n");
        port = 8080;
    }

    if (get_param_string(CFG_PATH, "ssl_key", ssl_key_path, MAX_PATH_LEN) == 0) {
        ssl_key_found = true;
    }

    if (get_param_string(CFG_PATH, "ssl_crt", ssl_crt_path, MAX_PATH_LEN) == 0) {
        ssl_crt_found = true;
    }

    if (ssl_key_found && ssl_crt_found) {
        app->daemon = start_webserver(port, ssl_key_path, ssl_crt_path, app);
    } else {
        app->daemon = start_webserver(port, NULL, NULL, app);
    }

    return app;
}

volatile sig_atomic_t keep_running = 1;

void handle_signal(int signal) {
    keep_running = 0;
}

void run_app(App app)
{
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    while (keep_running) {
        usleep(50000);
    }
}

void destroy_app(App app)
{
    stop_webserver(app->daemon);
    downloader_stop(app->dl);
    downloader_destroy(app->dl);
    close_db(app->db);
    free(app);
}