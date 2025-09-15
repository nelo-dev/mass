#ifndef WEBSERVER_H
#define WEBSERVER_H

#include <microhttpd.h>
#include "app.h"

struct MHD_Daemon *start_webserver(int port, char *key_path, char *crt_path, int thread_cnt, App app);
void stop_webserver(struct MHD_Daemon *daemon);

#endif