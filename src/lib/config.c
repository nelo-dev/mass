#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAX_LINE_LENGTH 256

// Helper: Remove leading and trailing whitespace from a string.
static void trim(char *str) {
    char *start = str;
    while (isspace((unsigned char)*start))
        start++;
    if (start != str)
        memmove(str, start, strlen(start) + 1);
    char *end = str + strlen(str) - 1;
    while (end >= str && isspace((unsigned char)*end)) {
        *end = '\0';
        end--;
    }
}

// Create a config file at the given path if it doesn't exist.
int create_config(const char *filepath) {
    FILE *fp = fopen(filepath, "r");
    if (fp) {  // File exists
        fclose(fp);
        return 0;
    }
    fp = fopen(filepath, "w");
    if (!fp)
        return -1;
    fclose(fp);
    return 0;
}

// Helper: Check if a line is a comment or empty.
static int is_comment_or_empty(const char *line) {
    while (*line && isspace((unsigned char)*line))
        line++;
    return (*line == '#' || *line == ';' || *line == '\0');
}

// Add a parameter (key-value pair) to the config file.
// If the parameter is already present, do nothing.
int add_param(const char *filepath, const char *key, const char *value) {
    char line[MAX_LINE_LENGTH];
    FILE *fp = fopen(filepath, "r");
    if (fp) {
        while (fgets(line, sizeof(line), fp)) {
            if (is_comment_or_empty(line))
                continue;
            char *eq = strchr(line, '=');
            if (!eq)
                continue;
            *eq = '\0';
            char temp_key[MAX_LINE_LENGTH];
            strncpy(temp_key, line, sizeof(temp_key));
            temp_key[sizeof(temp_key) - 1] = '\0';
            trim(temp_key);
            if (strcmp(temp_key, key) == 0) {
                // Parameter already exists; do not modify.
                fclose(fp);
                return 0;
            }
        }
        fclose(fp);
    }
    // Append the new parameter.
    fp = fopen(filepath, "a");
    if (!fp)
        return -1;
    fprintf(fp, "%s = %s\n", key, value);
    fclose(fp);
    return 0;
}

// Helper: Retrieve the raw value string for a given key.
// Copies the value (if found) into value_str (up to bufsize).
// Returns 0 if found, -1 otherwise.
static int get_param_value(const char *filepath, const char *key, char *value_str, size_t bufsize) {
    char line[MAX_LINE_LENGTH];
    FILE *fp = fopen(filepath, "r");
    if (!fp)
        return -1;
    int found = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (is_comment_or_empty(line))
            continue;
        char *eq = strchr(line, '=');
        if (!eq)
            continue;
        *eq = '\0';
        char temp_key[MAX_LINE_LENGTH];
        strncpy(temp_key, line, sizeof(temp_key));
        temp_key[sizeof(temp_key) - 1] = '\0';
        trim(temp_key);
        if (strcmp(temp_key, key) == 0) {
            // Key found; now process the value.
            char *temp_val = eq + 1;
            char *newline = strchr(temp_val, '\n');
            if (newline)
                *newline = '\0';
            trim(temp_val);
            if (value_str) {
                strncpy(value_str, temp_val, bufsize);
                value_str[bufsize - 1] = '\0';
            }
            found = 1;
            break;
        }
    }
    fclose(fp);
    return found ? 0 : -1;
}

// Retrieve parameter value by key as an int.
int get_param_int(const char *filepath, const char *key, int *value) {
    char value_str[MAX_LINE_LENGTH];
    if (get_param_value(filepath, key, value_str, sizeof(value_str)) != 0)
        return -1;
    if (value)
        *value = atoi(value_str);
    return 0;
}

// Retrieve parameter value by key as a float.
int get_param_float(const char *filepath, const char *key, float *value) {
    char value_str[MAX_LINE_LENGTH];
    if (get_param_value(filepath, key, value_str, sizeof(value_str)) != 0)
        return -1;
    if (value)
        *value = (float)atof(value_str);
    return 0;
}

// Retrieve parameter value by key as a string.
int get_param_string(const char *filepath, const char *key, char *buffer, size_t bufsize) {
    if (get_param_value(filepath, key, buffer, bufsize) != 0)
        return -1;
    return 0;
}

// Add a comment line to the config file.
// If the same comment (prefixed with "# ") already exists, it will not be added again.
int add_comment(const char *filepath, const char *comment) {
    char line[MAX_LINE_LENGTH];
    char target_comment[MAX_LINE_LENGTH];
    snprintf(target_comment, sizeof(target_comment), "# %s", comment);

    // Check if the comment already exists in the file.
    FILE *fp = fopen(filepath, "r");
    if (fp) {
        while (fgets(line, sizeof(line), fp)) {
            char temp_line[MAX_LINE_LENGTH];
            strncpy(temp_line, line, sizeof(temp_line));
            temp_line[sizeof(temp_line) - 1] = '\0';
            trim(temp_line);
            if (strcmp(temp_line, target_comment) == 0) {
                fclose(fp);
                return 0;  // Comment already exists, do not add again.
            }
        }
        fclose(fp);
    }
    // Append the comment if it was not found.
    fp = fopen(filepath, "a");
    if (!fp)
        return -1;
    fprintf(fp, "%s\n", target_comment);
    fclose(fp);
    return 0;
}