#ifndef DOWNLOADER_H
#define DOWNLOADER_H

#include <pthread.h>
#include <curl/curl.h>
#include <stdbool.h>

/* Opaque pointer to the Downloader struct, hiding implementation details */
typedef struct Downloader Downloader;

/**
 * Creates a new downloader instance.
 * @param max_threads Maximum number of worker threads to start.
 * @param max_queue_size Maximum number of tasks the queue can hold.
 * @return Pointer to the new Downloader instance, or NULL on failure.
 */
Downloader* downloader_create(int max_threads, int max_queue_size);

/**
 * Adds a download task to the queue.
 * @param dl Downloader instance.
 * @param url URL of the file to download.
 * @param dl_path Local path where the file will be saved.
 */
void downloader_add(Downloader* dl, const char* url, const char* dl_path);

/**
 * Stops the downloader, waiting for all pending downloads to finish.
 * @param dl Downloader instance.
 */
void downloader_stop(Downloader* dl);

/**
 * Destroys the downloader instance and frees resources.
 * @param dl Downloader instance to destroy.
 */
void downloader_destroy(Downloader* dl);

#endif /* DOWNLOADER_H */