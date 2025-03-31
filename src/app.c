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
    add_comment(CFG_PATH, "Database file-path:");
    add_param(CFG_PATH, "db_path", "db/mass.db");
    add_comment(CFG_PATH, "Size of database cache in MegaByte (greatly improves speed on large archives):");
    add_param(CFG_PATH, "db_cache", "512");
    add_comment(CFG_PATH, "SSL key path (optional)");
    add_param(CFG_PATH, "ssl_key", "");
    add_comment(CFG_PATH, "SSL certificate path (optional)");
    add_param(CFG_PATH, "ssl_crt", "");
    add_comment(CFG_PATH, "Server Name");
    add_param(CFG_PATH, "server_name", "mass");
    add_comment(CFG_PATH, "Server Icon (must be placed in folder public/resources)");
    add_param(CFG_PATH, "server_icon", "public/resources/placeholder_icon.png");
}

App create_app()
{
    srand(time(NULL));

    App app = calloc(1, sizeof(App_t));
    init_config();

    char db_path[MAX_PATH_LEN];
    if (get_param_string(CFG_PATH, "db_path", db_path, MAX_PATH_LEN) == -1) {
        printf("Could not find database path (db_path) in config! Defaulting to db/mass.db");
        strcpy(db_path, "db/mass.db");
    }

    int db_cache = 0;
    if (get_param_int(CFG_PATH, "db_cache", &db_cache) == -1 || db_cache < 0) {
        fprintf(stderr, "Error: Invalid or missing db_cache configuration. Using default value of 512 MB.\n");
        db_cache = 512;
    }

    folder_create(db_path);
    app->db = create_and_open_db(db_path, db_cache);

    generate_random_string(app->jwt_secret, 31);

    if (get_param_string(CFG_PATH, "server_name", app->server_name, 128) == -1) {
        fprintf(stderr, "Error: Invalid or missing server_name. Using default name.\n");
        strcpy(app->server_name, "mass");
    }

    if (get_param_string(CFG_PATH, "server_icon", app->icon_path, 256) == -1) {
        fprintf(stderr, "Error: Invalid or missing server_icon path. Using default placeholder icon.\n");
        strcpy(app->icon_path, "public/resources/placeholder_icon.png");
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
    close_db(app->db);
    free(app);
}