#include "webserver.h"
#include "lib/filelib.h"
#include "lib/jwt.h"
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <microhttpd.h>
#include <jansson.h>

/* ------------------------------------------------------------------
   REQUEST DATA STRUCTURE (DYNAMIC BUFFER)
   ------------------------------------------------------------------ */
typedef struct {
    char *buffer;       // Dynamically allocated buffer
    size_t length;      // Current used length of the buffer
    size_t allocated;   // Current allocated size of the buffer
    jwt_payload_t *jwt_payload; // JWT payload if authenticated
} RequestData;

/* ------------------------------------------------------------------
   CONTENT TYPE DETECTION
   ------------------------------------------------------------------ */
static const char *get_content_type(const char *filename) {
    const char *dot = strrchr(filename, '.');
    if (!dot || dot == filename) return "application/octet-stream";
    if (strcmp(dot, ".html") == 0 || strcmp(dot, ".htm") == 0) return "text/html";
    if (strcmp(dot, ".css") == 0) return "text/css";
    if (strcmp(dot, ".js") == 0) return "application/javascript";
    if (strcmp(dot, ".json") == 0) return "application/json";
    if (strcmp(dot, ".xml") == 0) return "application/xml";
    if (strcmp(dot, ".png") == 0) return "image/png";
    if ((strcmp(dot, ".jpg") == 0) || (strcmp(dot, ".jpeg") == 0)) return "image/jpeg";
    if (strcmp(dot, ".gif") == 0) return "image/gif";
    if (strcmp(dot, ".svg") == 0) return "image/svg+xml";
    if (strcmp(dot, ".ico") == 0) return "image/x-icon";
    if (strcmp(dot, ".pdf") == 0) return "application/pdf";
    if (strcmp(dot, ".zip") == 0) return "application/zip";
    if (strcmp(dot, ".tar") == 0) return "application/x-tar";
    if (strcmp(dot, ".mp3") == 0) return "audio/mpeg";
    if (strcmp(dot, ".mp4") == 0) return "video/mp4";
    if (strcmp(dot, ".webm") == 0) return "video/webm";
    if (strcmp(dot, ".ogg") == 0) return "audio/ogg";
    if (strcmp(dot, ".wav") == 0) return "audio/wav";
    if (strcmp(dot, ".txt") == 0) return "text/plain";
    return "application/octet-stream";
}

/* ------------------------------------------------------------------
   COOKIE PARSING
   ------------------------------------------------------------------ */
char *get_cookie_value(const char *cookie_header, const char *cookie_name) {
    if (!cookie_header || !cookie_name) return NULL;

    size_t name_len = strlen(cookie_name);
    const char *p = cookie_header;

    while (*p) {
        while (*p && (isspace((unsigned char)*p) || *p == ';')) p++;
        if (!strncmp(p, cookie_name, name_len) && p[name_len] == '=') {
            p += name_len + 1;
            while (*p && isspace((unsigned char)*p)) p++;
            const char *value_start = p;
            while (*p && *p != ';') p++;
            const char *value_end = p;
            while (value_end > value_start && isspace((unsigned char)*(value_end - 1))) value_end--;
            size_t value_len = value_end - value_start;
            char *value = malloc(value_len + 1);
            if (value) {
                memcpy(value, value_start, value_len);
                value[value_len] = '\0';
            }
            return value;
        }
        while (*p && *p != ';') p++;
    }
    return NULL;
}

/* ------------------------------------------------------------------
   RESPONSE HELPERS
   ------------------------------------------------------------------ */
static int send_json_response(struct MHD_Connection *connection, unsigned int status_code, const char *json_str, const char *set_cookie) {
    struct MHD_Response *response = MHD_create_response_from_buffer(strlen(json_str), (void *)json_str, MHD_RESPMEM_MUST_COPY);
    if (!response) return MHD_NO;
    MHD_add_response_header(response, "Content-Type", "application/json");
    if (set_cookie) MHD_add_response_header(response, "Set-Cookie", set_cookie);
    int ret = MHD_queue_response(connection, status_code, response);
    MHD_destroy_response(response);
    return ret;
}

static int send_redirect(struct MHD_Connection *connection, const char *location) {
    struct MHD_Response *response = MHD_create_response_from_buffer(0, "", MHD_RESPMEM_PERSISTENT);
    if (!response) return MHD_NO;
    MHD_add_response_header(response, "Location", location);
    int ret = MHD_queue_response(connection, MHD_HTTP_FOUND, response);
    MHD_destroy_response(response);
    return ret;
}

/* ------------------------------------------------------------------
   FILE SERVING
   ------------------------------------------------------------------ */
static int serve_file(struct MHD_Connection *connection, const char *filepath) {
    FILE *fp = fopen(filepath, "rb");
    if (!fp) 
        return send_json_response(connection, MHD_HTTP_NOT_FOUND, "{\"error\":\"File not found\"}", NULL);

    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char *buffer = malloc(size);
    if (!buffer) {
        fclose(fp);
        return send_json_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, "{\"error\":\"Error reading file\"}", NULL);
    }

    fread(buffer, 1, size, fp);
    fclose(fp);

    struct MHD_Response *response = MHD_create_response_from_buffer(size, buffer, MHD_RESPMEM_MUST_FREE);
    if (!response) {
        free(buffer);
        return send_json_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, "{\"error\":\"Error creating response\"}", NULL);
    }

    MHD_add_response_header(response, "Content-Type", get_content_type(filepath));
    int ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
    MHD_destroy_response(response);
    return ret;
}

/* ------------------------------------------------------------------
   JWT HANDLING
   ------------------------------------------------------------------ */
static int validate_jwt_cookie(struct MHD_Connection *connection, const char *jwt_secret, jwt_header_t **out_header, jwt_payload_t **out_payload) {
    const char *cookie_hdr = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "Cookie");
    if (!cookie_hdr) return -1;
    char *jwt_cookie = get_cookie_value(cookie_hdr, "jwt");
    if (!jwt_cookie) return -1;
    if (jwt_decode(jwt_secret, jwt_cookie, out_header, out_payload) != 0) {
        free(jwt_cookie);
        return -1;
    }
    free(jwt_cookie);
    return 0; /* success */
}

/* ------------------------------------------------------------------
   HANDLERS FOR SPECIFIC ENDPOINTS
   Note: All handlers now receive the full URL as the last parameter.
   ------------------------------------------------------------------ */
static int handle_register(struct MHD_Connection *connection, RequestData *req_data, App app, const char *url) {
    (void)url;
    char *response_json = register_user(app->db, req_data->buffer);
    int ret = send_json_response(connection, MHD_HTTP_OK, response_json, NULL);
    free(response_json);
    return ret;
}

static int handle_login(struct MHD_Connection *connection, RequestData *req_data, App app, const char *url) {
    (void)url;
    char *jwt_token = NULL;
    char cookie_hdr[4096] = {0};
    char *response_json = login_user(app->db, req_data->buffer, app->jwt_secret, &jwt_token);
    if (jwt_token) {
        snprintf(cookie_hdr, sizeof(cookie_hdr), "jwt=%s; HttpOnly; Secure; Path=/;", jwt_token);
        free(jwt_token);
    }
    int ret = send_json_response(connection, MHD_HTTP_OK, response_json, jwt_token ? cookie_hdr : NULL);
    free(response_json);
    return ret;
}

static int handle_get_user(struct MHD_Connection *connection, RequestData *req_data, App app, const char *url) {
    (void)url;
    if (!req_data->jwt_payload) {
        return send_json_response(connection, MHD_HTTP_UNAUTHORIZED, "{\"error\":\"Unauthorized\"}", NULL);
    }
    char *user_json = get_user_json(app->db, req_data->jwt_payload->sub);
    int ret = send_json_response(connection, MHD_HTTP_OK, user_json, NULL);
    free(user_json);
    return ret;
}

static int handle_logout(struct MHD_Connection *connection, RequestData *req_data, App app, const char *url) {
    (void)req_data; (void)app; (void)url;
    const char *msg = "{\"success\":\"Logged out!\"}";
    return send_json_response(connection, MHD_HTTP_OK, msg, "jwt=; HttpOnly; Secure; Path=/;");
}

static int handle_info(struct MHD_Connection *connection, RequestData *req_data, App_t *app, const char *url) {
    (void)req_data; (void)url;
    if (!app) return MHD_NO;
    
    json_t *json_response = json_pack("{s:s, s:s, s:i}", "server_name", app->server_name, "icon_path", app->icon_path, "max_profile_size", app->max_profile_size);
    if (!json_response) return MHD_NO;
    
    char *json_str = json_dumps(json_response, JSON_COMPACT);
    json_decref(json_response);
    if (!json_str) return MHD_NO;
    
    int ret = send_json_response(connection, MHD_HTTP_OK, json_str, NULL);
    free(json_str);
    return ret;
}

static int handle_profile(struct MHD_Connection *connection, RequestData *req_data, App app, const char *url) {
    (void)url;
    if (!req_data->jwt_payload || !req_data->jwt_payload->sub)
        return send_json_response(connection, MHD_HTTP_UNAUTHORIZED, "{\"error\":\"Unauthorized\"}", NULL);

    const char *filename = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "filename");
    if (!filename)
        return send_json_response(connection, MHD_HTTP_BAD_REQUEST, "{\"error\":\"Missing filename\"}", NULL);

    char prefix[256], suffix[32];
    if (sscanf(filename, "%255[^.].%31s", prefix, suffix) != 2)
        return send_json_response(connection, MHD_HTTP_BAD_REQUEST, "{\"error\":\"Invalid filename\"}", NULL);

    char response[512];
    if (update_profile_picture(app->db, req_data->jwt_payload->sub, (const unsigned char *)req_data->buffer, req_data->length,  app->profile_path, suffix, app->max_profile_size) != 0) {
        snprintf(response, sizeof(response), "{\"error\":\"Image bigger than %d kB or invalid format.\"}",  app->max_profile_size);
        return send_json_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, response, NULL);
    } 

    snprintf(response, sizeof(response), "{\"status\":\"success\",\"message\":\"Profile picture updated for %s\"}",  req_data->jwt_payload->sub);
    return send_json_response(connection, MHD_HTTP_OK, response, NULL);
}

static int handle_users(struct MHD_Connection *connection, RequestData *req_data, App app, const char *url) {
    (void)url;
    char *response_json = search_users(app->db, req_data->buffer);
    int ret = send_json_response(connection, MHD_HTTP_OK, response_json, NULL);
    free(response_json);
    return ret;
}

static int handle_toggle_approval(struct MHD_Connection *connection, RequestData *req_data, App app, const char *url) {
    (void)url;

    if (!req_data->jwt_payload) {
        return send_json_response(connection, MHD_HTTP_UNAUTHORIZED, "{\"error\":\"Unauthorized\"}", NULL);
    }

    char *response_json = toggle_user_approval_by_requester(app->db, req_data->buffer, req_data->jwt_payload->sub);
    int ret = send_json_response(connection, MHD_HTTP_OK, response_json, NULL);
    free(response_json);
    return ret;
}

static int handle_toggle_role(struct MHD_Connection *connection, RequestData *req_data, App app, const char *url) {
    (void)url;
    if (!req_data->jwt_payload) {
        return send_json_response(connection, MHD_HTTP_UNAUTHORIZED, "{\"error\":\"Unauthorized\"}", NULL);
    }
    char *user_json = toggle_user_role_by_requester(app->db, req_data->buffer, req_data->jwt_payload->sub);
    int ret = send_json_response(connection, MHD_HTTP_OK, user_json, NULL);
    free(user_json);
    return ret;
}

static int handle_create_api_key(struct MHD_Connection *connection, RequestData *req_data, App app, const char *url) {
    (void)url;
    if (!req_data->jwt_payload) {
        return send_json_response(connection, MHD_HTTP_UNAUTHORIZED, "{\"error\":\"Unauthorized\"}", NULL);
    }
    char *user_json = create_api_key(app->db, req_data->jwt_payload->sub, req_data->buffer);
    int ret = send_json_response(connection, MHD_HTTP_OK, user_json, NULL);
    free(user_json);
    return ret;
}

static int handle_delete_api_key(struct MHD_Connection *connection, RequestData *req_data, App app, const char *url) {
    (void)url;
    char *response_json = destroy_api_key(app->db, req_data->buffer);
    int ret = send_json_response(connection, MHD_HTTP_OK, response_json, NULL);
    free(response_json);
    return ret;
}

static int handle_get_api_keys(struct MHD_Connection *connection, RequestData *req_data, App app, const char *url) {
    (void)url;
    char *response_json = get_all_api_keys(app->db);
    int ret = send_json_response(connection, MHD_HTTP_OK, response_json, NULL);
    free(response_json);
    return ret;
}

static int handle_upload(struct MHD_Connection *connection, RequestData *req_data, App app, const char *url) {
    (void)url;
    char *response_json = insert_media(app->db, app->dl, req_data->buffer, app->media_path, app->preview_path, app->description_path);
    int ret = send_json_response(connection, MHD_HTTP_OK, response_json, NULL);
    free(response_json);
    return ret;
}

static int handle_get_register(struct MHD_Connection *connection, RequestData *req_data, App app, const char *url) {
    (void)req_data; (void)url;
    return serve_file(connection, "public/register.html");
}

static int handle_get_login(struct MHD_Connection *connection, RequestData *req_data, App app, const char *url) {
    (void)req_data; (void)url;
    return serve_file(connection, "public/login.html");
}

static int handle_get_home(struct MHD_Connection *connection, RequestData *req_data, App app, const char *url) {
    (void)req_data; (void)url;
    return serve_file(connection, "public/home.html");
}

static int handle_get_profile(struct MHD_Connection *connection, RequestData *req_data, App app, const char *url) {
    (void)req_data; (void)url;
    return serve_file(connection, "public/profile.html");
}

static int handle_get_unapproved(struct MHD_Connection *connection, RequestData *req_data, App app, const char *url) {
    (void)req_data; (void)url;
    return serve_file(connection, "public/unapproved.html");
}

static int handle_get_management(struct MHD_Connection *connection, RequestData *req_data, App app, const char *url) {
    (void)req_data; (void)url;
    return serve_file(connection, "public/management.html");
}

static int handle_get_api(struct MHD_Connection *connection, RequestData *req_data, App app, const char *url) {
    (void)req_data; (void)url;
    return serve_file(connection, "public/api.html");
}

/* ------------------------------------------------------------------
   NEW STATIC HANDLER: Serve all files under public/res/
   ------------------------------------------------------------------ */
static int handle_static_res(struct MHD_Connection *connection, RequestData *req_data, App app, const char *full_url) {
    (void)req_data; (void)app;
    const char *prefix = "/resources/";
    const char *relative_path = full_url + strlen(prefix);
    char filepath[512];
    // If no specific file is requested, serve an index file
    if (strlen(relative_path) == 0) {
        snprintf(filepath, sizeof(filepath), "public/404.html");
    } else {
        snprintf(filepath, sizeof(filepath), "public/resources/%s", relative_path);
    }
    return serve_file(connection, filepath);
}

static int handle_static_profile(struct MHD_Connection *connection, RequestData *req_data, App app, const char *full_url) {
    (void)req_data; (void)app;
    const char *prefix = "/profile/";
    const char *relative_path = full_url + strlen(prefix);
    char filepath[512];
    // If no specific file is requested, serve an index file
    if (strlen(relative_path) == 0) {
        snprintf(filepath, sizeof(filepath), "public/404.html");
    } else {
        snprintf(filepath, sizeof(filepath), "%s/%s", app->profile_path, relative_path);
    }
    return serve_file(connection, filepath);
}

/* ------------------------------------------------------------------
   ADVANCED ROUTE DISPATCH
   ------------------------------------------------------------------ */
typedef int (*RouteHandler)(struct MHD_Connection*, RequestData*, App, const char*);

typedef struct {
    const char *method;
    const char *path;         // Base path for the route
    RouteHandler handler;
    bool requires_auth;       // Indicates if JWT auth is required
    int min_access_level;     // Minimum access level required (only if requires_auth is true)
    bool prefix_match;        // If true, perform prefix matching on the URL
} Route;

static const Route route_table[] = {
    /* POST routes */
    {"POST", "/register", handle_register, false, -1, false},
    {"POST", "/login", handle_login, false, -1, false},
    {"POST", "/user", handle_get_user, true, 0, false},
    {"POST", "/logout", handle_logout, true, 0, false},
    {"POST", "/info", handle_info, false, -1, false},
    {"POST", "/profile", handle_profile, true, 0, false},
    {"POST", "/users", handle_users, true, 2, false},
    {"POST", "/toggleapproval", handle_toggle_approval, true, 2, false},
    {"POST", "/togglerole", handle_toggle_role, true, 2, false},
    {"POST", "/createkey", handle_create_api_key, true, 3, false},
    {"POST", "/deletekey", handle_delete_api_key, true, 3, false},
    {"POST", "/keys", handle_get_api_keys, true, 3, false},
    {"POST", "/upload", handle_upload, false, -1, false},

    /* GET routes */
    {"GET", "/register", handle_get_register, false, -1, false},
    {"GET", "/login", handle_get_login, false, -1, false},
    {"GET", "/", handle_get_home, true, 1, false},
    {"GET", "/profile", handle_get_profile, true, 0, false},
    {"GET", "/unapproved", handle_get_unapproved, true, 0, false},
    {"GET", "/management", handle_get_management, true, 2, false},
    {"GET", "/api", handle_get_api, true, 3, false},

    /* Static file routes */
    {"GET", "/resources/", handle_static_res, false, -1, true},
    {"GET", "/profile/", handle_static_profile, false, -1, true}};

static const Route *find_route(const char *method, const char *url) {
    for (size_t i = 0; i < sizeof(route_table)/sizeof(route_table[0]); i++) {
        if (strcmp(method, route_table[i].method) == 0) {
            if (route_table[i].prefix_match) {
                size_t len = strlen(route_table[i].path);
                if (strncmp(url, route_table[i].path, len) == 0) {
                    return &route_table[i];
                }
            } else {
                if (strcmp(url, route_table[i].path) == 0) {
                    return &route_table[i];
                }
            }
        }
    }
    return NULL;
}

/* ------------------------------------------------------------------
   REQUEST HANDLER
   ------------------------------------------------------------------ */
   static enum MHD_Result request_handler(void *cls, struct MHD_Connection *connection, const char *url, const char *method, const char *version, const char *upload_data, size_t *upload_data_size, void **con_cls) {
    (void)version;
    App app = (App)cls;

    if (*con_cls == NULL) {
        RequestData *req_data = calloc(1, sizeof(RequestData));
        if (!req_data) return MHD_NO;
        req_data->allocated = 4096;
        req_data->buffer = malloc(req_data->allocated);
        if (!req_data->buffer) {
            free(req_data);
            return MHD_NO;
        }
        req_data->length = 0;
        req_data->buffer[0] = '\0';
        req_data->jwt_payload = NULL;
        *con_cls = req_data;
        return MHD_YES;
    }

    RequestData *req_data = (RequestData *)(*con_cls);

    if (strcmp(method, "POST") == 0 && *upload_data_size > 0) {
        if (req_data->length + *upload_data_size >= req_data->allocated) {
            size_t new_allocated = req_data->allocated;
            while (req_data->length + *upload_data_size >= new_allocated) {
                new_allocated *= 2;
            }
            char *new_buffer = realloc(req_data->buffer, new_allocated);
            if (!new_buffer) {
                return MHD_NO;
            }
            req_data->buffer = new_buffer;
            req_data->allocated = new_allocated;
        }
        memcpy(req_data->buffer + req_data->length, upload_data, *upload_data_size);
        req_data->length += *upload_data_size;
        req_data->buffer[req_data->length] = '\0';
        *upload_data_size = 0;
        return MHD_YES;
    }

    const Route *route = find_route(method, url);
    if (!route) {
        int ret;
        if (strcmp(method, "GET") == 0) {
            ret = serve_file(connection, "public/404.html");
        } else {
            ret = send_json_response(connection, MHD_HTTP_METHOD_NOT_ALLOWED, "{\"error\":\"Method Not Allowed\"}", NULL);
        }
        free(req_data->buffer);
        free(req_data);
        *con_cls = NULL;
        return ret;
    }

    /* Centralized authentication and access level check */
    if (route->requires_auth) {
        jwt_header_t *jwt_header = NULL;
        jwt_payload_t *jwt_payload = NULL;
        if (validate_jwt_cookie(connection, app->jwt_secret, &jwt_header, &jwt_payload) != 0) {
            free(req_data->buffer);
            free(req_data);
            *con_cls = NULL;
            if (strcmp(method, "GET") == 0) {
                return send_redirect(connection, "/login");
            } else {
                return send_json_response(connection, MHD_HTTP_UNAUTHORIZED, "{\"error\":\"Unauthorized\"}", NULL);
            }
        }
        req_data->jwt_payload = jwt_payload;
        jwt_free_header(jwt_header);

        /* Check user's access level */
        int user_access_level = get_user_access_level(app->db, req_data->jwt_payload->sub, app->approval);
        if (user_access_level == -1) {
            /* Error retrieving access level, treat as unauthorized */
            free(req_data->buffer);
            free(req_data);
            *con_cls = NULL;
            if (strcmp(method, "GET") == 0) {
                return send_redirect(connection, "/login");
            } else {
                return send_json_response(connection, MHD_HTTP_UNAUTHORIZED, "{\"error\":\"Unauthorized\"}", NULL);
            }
        }

        if (user_access_level < route->min_access_level) {
            /* Insufficient access level */
            free(req_data->buffer);
            free(req_data);
            *con_cls = NULL;
            if (strcmp(method, "GET") == 0) {
                return send_redirect(connection, "/unapproved");
            } else {
                return send_json_response(connection, MHD_HTTP_FORBIDDEN, "{\"error\":\"Insufficient permissions\"}", NULL);
            }
        }
    }

    int ret = route->handler(connection, req_data, app, url);
    if (req_data->jwt_payload) {
        jwt_free_payload(req_data->jwt_payload);
    }
    free(req_data->buffer);
    free(req_data);
    *con_cls = NULL;
    return ret;
}

/* ------------------------------------------------------------------
   WEB SERVER START/STOP
   ------------------------------------------------------------------ */
struct MHD_Daemon *start_webserver(int port, char *key_path, char *crt_path, App app) {
    struct MHD_Daemon *daemon = NULL;
    char *key = NULL, *crt = NULL;
    ssize_t key_size = 0, crt_size = 0;

    if (key_path && crt_path) {
        key_size = file_read(key_path, &key);
        crt_size = file_read(crt_path, &crt);
        if (key_size == -1 || crt_size == -1) {
            free(key);
            free(crt);
            key = crt = NULL;
        }
    }

    if (key && crt) {
        printf("Starting server with SSL on \033[0;32mhttps://localhost:%d\033[0m\n", port);
        daemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY | MHD_USE_TLS, port, NULL, NULL, &request_handler, app,
                                  MHD_OPTION_HTTPS_MEM_KEY, key,
                                  MHD_OPTION_HTTPS_MEM_CERT, crt,
                                  MHD_OPTION_END);
    } else {
        printf("Starting server without SSL on http://localhost:%d\n", port);
        daemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY, port, NULL, NULL, &request_handler, app, MHD_OPTION_END);
    }

    if (!daemon) fprintf(stderr, "Failed to start server\n");

    free(key);
    free(crt);
    return daemon;
}

void stop_webserver(struct MHD_Daemon *daemon) {
    if (daemon) {
        MHD_stop_daemon(daemon);
        printf("Server stopped successfully.\n");
    }
}
