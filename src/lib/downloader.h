#ifndef DOWNLOADER_H
#define DOWNLOADER_H

#include <stdbool.h>
#include <pthread.h>

typedef struct Downloader Downloader;

Downloader* downloader_create(int max_threads, int max_queue_size);
void downloader_add(Downloader* dl, const char* url, const char* dl_path);
void downloader_stop(Downloader* dl);
void downloader_destroy(Downloader* dl);

#endif