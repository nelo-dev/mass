#include "downloader.h"
#include <stdlib.h>
#include <string.h>

/* Structure for a download task */
typedef struct {
    char* url;       /* URL to download from */
    char* dl_path;   /* Local path to save the file */
} Task;

/* Downloader structure */
struct Downloader {
    pthread_mutex_t mutex;         /* Protects the queue */
    pthread_cond_t cond_not_empty; /* Signals when queue has tasks */
    pthread_cond_t cond_not_full;  /* Signals when queue has space */
    Task* queue;                   /* Circular buffer for tasks */
    int front;                     /* Index of the front of the queue */
    int rear;                      /* Index of the rear of the queue */
    int count;                     /* Current number of tasks in queue */
    int max_queue_size;            /* Maximum queue capacity */
    bool stopped;                  /* Flag to indicate downloader should stop */
    pthread_t* threads;            /* Array of worker thread IDs */
    int max_threads;               /* Maximum number of threads */
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
    while (true) {
        Task task;
        pthread_mutex_lock(&dl->mutex);
        /* Wait if queue is empty and not stopped */
        while (dl->count == 0 && !dl->stopped) {
            pthread_cond_wait(&dl->cond_not_empty, &dl->mutex);
        }
        /* Exit if queue is empty and stopped */
        if (dl->count == 0 && dl->stopped) {
            pthread_mutex_unlock(&dl->mutex);
            break;
        }
        /* Dequeue a task */
        task = dl->queue[dl->front];
        dl->front = (dl->front + 1) % dl->max_queue_size;
        dl->count--;
        pthread_mutex_unlock(&dl->mutex);
        /* Signal that the queue has space */
        pthread_cond_signal(&dl->cond_not_full);
        /* Process the download */
        download(task.url, task.dl_path);
        /* Free allocated strings */
        free(task.url);
        free(task.dl_path);
    }
    return NULL;
}

Downloader* downloader_create(int max_threads, int max_queue_size) {
    Downloader* dl = malloc(sizeof(Downloader));
    if (!dl) return NULL;

    dl->queue = malloc(sizeof(Task) * max_queue_size);
    if (!dl->queue) {
        free(dl);
        return NULL;
    }

    dl->threads = malloc(sizeof(pthread_t) * max_threads);
    if (!dl->threads) {
        free(dl->queue);
        free(dl);
        return NULL;
    }

    /* Initialize downloader state */
    dl->max_queue_size = max_queue_size;
    dl->front = 0;
    dl->rear = 0;
    dl->count = 0;
    dl->stopped = false;
    dl->max_threads = max_threads;

    /* Initialize synchronization primitives */
    pthread_mutex_init(&dl->mutex, NULL);
    pthread_cond_init(&dl->cond_not_empty, NULL);
    pthread_cond_init(&dl->cond_not_full, NULL);

    /* Start worker threads */
    for (int i = 0; i < max_threads; i++) {
        if (pthread_create(&dl->threads[i], NULL, thread_func, dl) != 0) {
            /* Basic error handling: could clean up partially created threads */
            dl->max_threads = i; /* Adjust for cleanup in destroy */
            downloader_destroy(dl);
            return NULL;
        }
    }

    return dl;
}

void downloader_add(Downloader* dl, const char* url, const char* dl_path) {
    Task task;
    /* Duplicate strings to manage memory */
    task.url = strdup(url);
    task.dl_path = strdup(dl_path);

    pthread_mutex_lock(&dl->mutex);
    /* Wait until there is space in the queue */
    while (dl->count >= dl->max_queue_size && !dl->stopped) {
        pthread_cond_wait(&dl->cond_not_full, &dl->mutex);
    }
    /* If stopped while waiting, free resources and return */
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
    pthread_mutex_unlock(&dl->mutex);
    /* Signal that the queue has a task */
    pthread_cond_signal(&dl->cond_not_empty);
}

void downloader_stop(Downloader* dl) {
    if (!dl) return;
    pthread_mutex_lock(&dl->mutex);
    dl->stopped = true;
    /* Wake up all threads to check stop condition */
    pthread_cond_broadcast(&dl->cond_not_empty);
    pthread_mutex_unlock(&dl->mutex);
    /* Wait for all threads to finish */
    for (int i = 0; i < dl->max_threads; i++) {
        pthread_join(dl->threads[i], NULL);
    }
}

void downloader_destroy(Downloader* dl) {
    if (!dl) return;
    free(dl->queue);
    free(dl->threads);
    pthread_mutex_destroy(&dl->mutex);
    pthread_cond_destroy(&dl->cond_not_empty);
    pthread_cond_destroy(&dl->cond_not_full);
    free(dl);
}