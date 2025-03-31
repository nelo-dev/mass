#ifndef FILELIB_H
#define FILELIB_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

// Create an empty file at the given path.
// Returns 0 on success, -1 on error.
int file_create(const char *path);

// Delete the file at the given path.
// Returns 0 on success, -1 on error.
int file_destroy(const char *path);

// Read the entire content of the file.
// On success, *buffer is allocated (caller must free) and the number of bytes is returned.
// Returns -1 on error.
size_t file_read(const char *path, char **buffer);

// Write data to the file.
// Returns 0 on success, -1 on error.
int file_write(const char *path, const char *data, size_t size);

// Create a folder (or its parent if a file path is provided).
// If intermediate directories do not exist, they are created.
// Returns 0 on success, -1 on error.
int folder_create(const char *path);

// Remove an empty folder.
// Returns 0 on success, -1 on error.
int folder_destroy(const char *path);

#ifdef __cplusplus
}
#endif

#endif // FILELIB_H
