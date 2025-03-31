#include "filelib.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
    #include <direct.h>
    #include <windows.h>
    #define PATH_SEPARATOR '\\'
#else
    #include <sys/stat.h>
    #include <unistd.h>
    #define PATH_SEPARATOR '/'
#endif

// Utility: Extract the parent directory from a given path.
// Returns a newly allocated string (caller must free) or NULL if no directory exists.
static char *get_parent_directory(const char *path) {
    if (!path) return NULL;
    const char *last_sep = NULL;
    for (const char *p = path; *p; p++) {
        if (*p == '/' || *p == '\\') {
            last_sep = p;
        }
    }
    if (!last_sep) {
        // No directory separator found.
        return NULL;
    }
    size_t len = last_sep - path;
    if (len == 0) {
        // Path is something like "/file.txt" – return root.
        len = 1;
    }
    char *dir = (char *)malloc(len + 1);
    if (!dir) return NULL;
    strncpy(dir, path, len);
    dir[len] = '\0';
    return dir;
}

// Utility: Recursively create directories (similar to "mkdir -p").
static int mkdir_p(const char *path) {
    char *tmp = strdup(path);
    if (!tmp) return -1;
    size_t len = strlen(tmp);
    if (len == 0) {
        free(tmp);
        return -1;
    }
    // Remove trailing separator if any.
    if (tmp[len - 1] == '/' || tmp[len - 1] == '\\') {
        tmp[len - 1] = '\0';
    }
    // Create each directory in the path.
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/' || *p == '\\') {
            *p = '\0';
#ifdef _WIN32
            if (_mkdir(tmp) != 0) {
                DWORD attr = GetFileAttributes(tmp);
                if (attr == INVALID_FILE_ATTRIBUTES || !(attr & FILE_ATTRIBUTE_DIRECTORY)) {
                    free(tmp);
                    return -1;
                }
            }
#else
            if (mkdir(tmp, 0755) != 0) {
                // Ignore error if directory already exists.
            }
#endif
            *p = PATH_SEPARATOR;
        }
    }
    // Create the final directory.
#ifdef _WIN32
    if (_mkdir(tmp) != 0) {
        DWORD attr = GetFileAttributes(tmp);
        if (attr == INVALID_FILE_ATTRIBUTES || !(attr & FILE_ATTRIBUTE_DIRECTORY)) {
            free(tmp);
            return -1;
        }
    }
#else
    if (mkdir(tmp, 0755) != 0) {
        // Ignore error if directory already exists.
    }
#endif
    free(tmp);
    return 0;
}

int file_create(const char *path) {
    FILE *fp = fopen(path, "wb");
    if (!fp) return -1;
    fclose(fp);
    return 0;
}

int file_destroy(const char *path) {
    return remove(path);
}

size_t file_read(const char *path, char **buffer) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;

    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return -1;
    }
    long size = ftell(fp);
    if (size < 0) {
        fclose(fp);
        return -1;
    }
    rewind(fp);

    char *buf = (char *)malloc(size + 1);
    if (!buf) {
        fclose(fp);
        return -1;
    }
    size_t read_bytes = fread(buf, 1, size, fp);
    if (read_bytes != (size_t)size) {
        free(buf);
        fclose(fp);
        return -1;
    }
    buf[size] = '\0';  // Null-terminate
    fclose(fp);
    *buffer = buf;
    return size;
}

int file_write(const char *path, const char *data, size_t size) {
    FILE *fp = fopen(path, "wb");
    if (!fp) return -1;
    size_t written = fwrite(data, 1, size, fp);
    fclose(fp);
    return (written == size) ? 0 : -1;
}

int folder_create(const char *path) {
    if (!path) return -1;
    char *dir_path = NULL;
    size_t len = strlen(path);

    // If the path ends with a separator, treat it as a directory.
    if (len > 0 && (path[len - 1] == '/' || path[len - 1] == '\\')) {
        dir_path = strdup(path);
    } else {
        // If the path appears to be a file path (naively checking for a dot after the last separator),
        // extract the parent directory.
        const char *dot = strrchr(path, '.');
        const char *sep = strrchr(path, '/');
#ifdef _WIN32
        const char *bsep = strrchr(path, '\\');
        if (bsep && (!sep || bsep > sep))
            sep = bsep;
#endif
        if (dot && (!sep || dot > sep)) {
            // Looks like a file name is present.
            dir_path = get_parent_directory(path);
            if (!dir_path) {
                // No directory part to create.
                return 0;
            }
        } else {
            // Otherwise, treat the entire path as a directory.
            dir_path = strdup(path);
        }
    }
    if (!dir_path) return -1;
    int ret = mkdir_p(dir_path);
    free(dir_path);
    return ret;
}

int folder_destroy(const char *path) {
#ifdef _WIN32
    return _rmdir(path);
#else
    return rmdir(path);
#endif
}