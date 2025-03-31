#ifndef APP_H
#define APP_H

#include "lib/config.h"
#include "lib/filelib.h"
#include "microhttpd.h"
#include "sqlite3.h"

#define CFG_PATH        "mass.cfg"
#define MAX_PATH_LEN    4096

typedef struct App_t {
    struct MHD_Daemon *daemon;
    sqlite3 * db;
    char jwt_secret[32];
    char server_name[128];
    char icon_path[256];
} App_t;

typedef App_t * App;

#include "webserver.h"
#include "database.h"

App create_app();
void run_app(App app);
void destroy_app(App app);

#endif