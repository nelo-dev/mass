#include "downloader.h"
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

/* Structure for a download task */
typedef struct {
    char* url;       /* URL to download from */
    char* dl_path;   /* Local path to save the file */
} Task;

/* Downloader structure */
struct Downloader {
    pthread_mutex_t mutex;         /* Protects the queue and shared variables */
    pthread_cond_t cond_not_full;  /* Signals when queue has space */
    pthread_cond_t cond_all_done;  /* Signals when all threads are done */
    Task* queue;                   /* Circular buffer for tasks */
    int front;                     /* Index of the front of the queue */
    int rear;                      /* Index of the rear of the queue */
    int count;                     /* Current number of tasks in queue */
    int max_queue_size;            /* Maximum queue capacity */
    bool stopped;                  /* Flag to indicate downloader should stop */
    int active_threads;            /* Number of currently active threads */
    int max_threads;               /* Maximum number of threads allowed */
};

/**
 * Downloads a file using libcurl.
 * @param url URL of the file to download.
 * @param dl_path Local path to save the file.
 */
static void download(const char* url, const char* dl_path) {
    CURL* curl = curl_easy_init();
    if (curl) {
        FILE* fp = fopen(dl_path, "wb");
        if (fp) {
            curl_easy_setopt(curl, CURLOPT_URL, url);
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, NULL);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
            CURLcode res = curl_easy_perform(curl);
            if (res != CURLE_OK) {
                /* Basic error handling: could log or report error */
            }
            fclose(fp);
        }
        curl_easy_cleanup(curl);
    }
}

/**
 * Worker thread function to process download tasks.
 * @param arg Pointer to the Downloader instance.
 * @return NULL
 */
static void* thread_func(void* arg) {
    Downloader* dl = (Downloader*)arg;

    /* Detach the thread so it cleans up automatically when it terminates */
    pthread_detach(pthread_self());

    /* Increment active_threads safely */
    pthread_mutex_lock(&dl->mutex);
    dl->active_threads++;
    pthread_mutex_unlock(&dl->mutex);

    /* Process tasks until the queue is empty */
    while (true) {
        pthread_mutex_lock(&dl->mutex);
        if (dl->count == 0) {
            pthread_mutex_unlock(&dl->mutex);
            break; /* Exit the loop and terminate if queue is empty */
        }
        /* Dequeue a task */
        Task task = dl->queue[dl->front];
        dl->front = (dl->front + 1) % dl->max_queue_size;
        dl->count--;
        pthread_mutex_unlock(&dl->mutex);

        /* Signal that the queue has space for new tasks */
        pthread_cond_signal(&dl->cond_not_full);

        /* Process the task */
        download(task.url, task.dl_path);
        free(task.url);
        free(task.dl_path);
    }

    /* Thread is terminating, decrement active_threads */
    pthread_mutex_lock(&dl->mutex);
    dl->active_threads--;
    if (dl->active_threads == 0) {
        /* Signal that all threads are done, if this is the last one */
        pthread_cond_signal(&dl->cond_all_done);
    }
    pthread_mutex_unlock(&dl->mutex);

    return NULL;
}

/**
 * Creates a new Downloader instance.
 * @param max_threads Maximum number of concurrent download threads.
 * @param max_queue_size Maximum number of tasks in the queue.
 * @return Pointer to the new Downloader, or NULL on failure.
 */
Downloader* downloader_create(int max_threads, int max_queue_size) {
    Downloader* dl = malloc(sizeof(Downloader));
    if (!dl) return NULL;

    dl->queue = malloc(sizeof(Task) * max_queue_size);
    if (!dl->queue) {
        free(dl);
        return NULL;
    }

    /* Initialize downloader state */
    dl->max_queue_size = max_queue_size;
    dl->front = 0;
    dl->rear = 0;
    dl->count = 0;
    dl->stopped = false;
    dl->active_threads = 0;
    dl->max_threads = max_threads;

    /* Initialize synchronization primitives */
    pthread_mutex_init(&dl->mutex, NULL);
    pthread_cond_init(&dl->cond_not_full, NULL);
    pthread_cond_init(&dl->cond_all_done, NULL);

    /* No threads are started here; they start when tasks are added */
    return dl;
}

/**
 * Adds a download task to the queue and starts a thread if needed.
 * @param dl Downloader instance.
 * @param url URL to download from.
 * @param dl_path Local path to save the file.
 */
void downloader_add(Downloader* dl, const char* url, const char* dl_path) {
    if (!dl) return;

    /* Create a new task */
    Task task;
    task.url = strdup(url);
    task.dl_path = strdup(dl_path);
    if (!task.url || !task.dl_path) {
        free(task.url);
        free(task.dl_path);
        return;
    }

    pthread_mutex_lock(&dl->mutex);

    /* Wait if the queue is full and not stopped */
    while (dl->count >= dl->max_queue_size && !dl->stopped) {
        pthread_cond_wait(&dl->cond_not_full, &dl->mutex);
    }

    /* If stopped, discard the task and return */
    if (dl->stopped) {
        pthread_mutex_unlock(&dl->mutex);
        free(task.url);
        free(task.dl_path);
        return;
    }

    /* Enqueue the task */
    dl->queue[dl->rear] = task;
    dl->rear = (dl->rear + 1) % dl->max_queue_size;
    dl->count++;

    /* Start a new thread if fewer than max_threads are active */
    if (dl->active_threads < dl->max_threads) {
        pthread_t thread;
        if (pthread_create(&thread, NULL, thread_func, dl) == 0) {
            /* Thread will detach itself and increment active_threads */
        } else {
            /* Failed to create thread; task is still in queue, will be picked up later */
        }
    }

    pthread_mutex_unlock(&dl->mutex);
}

/**
 * Stops the downloader, waiting for all active threads to complete.
 * @param dl Downloader instance.
 */
void downloader_stop(Downloader* dl) {
    if (!dl) return;

    pthread_mutex_lock(&dl->mutex);
    dl->stopped = true;

    /* Wake up any threads waiting in downloader_add */
    pthread_cond_broadcast(&dl->cond_not_full);

    /* Wait until all active threads have terminated */
    while (dl->active_threads > 0) {
        pthread_cond_wait(&dl->cond_all_done, &dl->mutex);
    }

    pthread_mutex_unlock(&dl->mutex);
}

/**
 * Destroys the Downloader instance and frees its resources.
 * @param dl Downloader instance.
 */
void downloader_destroy(Downloader* dl) {
    if (!dl) return;

    /* Assume downloader_stop has been called, so no active threads remain */
    free(dl->queue);
    pthread_mutex_destroy(&dl->mutex);
    pthread_cond_destroy(&dl->cond_not_full);
    pthread_cond_destroy(&dl->cond_all_done);
    free(dl);
}