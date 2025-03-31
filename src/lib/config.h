#ifndef CONFIG_H
#define CONFIG_H

#include <stddef.h>  // for size_t

#ifdef __cplusplus
extern "C" {
#endif

// Create a config file at the given path if it doesn't exist.
// Returns 0 on success, -1 on error.
int create_config(const char *filepath);

// Add a parameter (key-value pair) to the config file.
// If the parameter is already present, the file is not altered.
// Returns 0 on success, -1 on error.
int add_param(const char *filepath, const char *key, const char *value);

// Retrieve the parameter value by key as an int.
// Returns 0 on success, -1 if the key is not found.
int get_param_int(const char *filepath, const char *key, int *value);

// Retrieve the parameter value by key as a float.
// Returns 0 on success, -1 if the key is not found.
int get_param_float(const char *filepath, const char *key, float *value);

// Retrieve the parameter value by key as a string.
// The retrieved value is copied into buffer (of size bufsize).
// Returns 0 on success, -1 if the key is not found.
int get_param_string(const char *filepath, const char *key, char *buffer, size_t bufsize);

// Add a comment line to the config file.
// The comment is prefixed with "# " and will not be added if it already exists.
// Returns 0 on success, -1 on error.
int add_comment(const char *filepath, const char *comment);

#ifdef __cplusplus
}
#endif

#endif // CONFIG_H
