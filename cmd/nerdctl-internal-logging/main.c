#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <errno.h>

#define _NERDCTL_INTERNAL_LOGGING "_NERDCTL_INTERNAL_LOGGING"
#define MAX_LOG_LINE_SIZE (16 * 1024)
#define MAX_FILE_SIZE (50 * 1024 * 1024)
#define SELECT_TIMEOUT_SECS 60

long long write_json_line(FILE *log_file, const char *name, int fd, char *buffer);

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s %s <path>\n", argv[0], _NERDCTL_INTERNAL_LOGGING);
        return -1;
    }
    if (strcmp(argv[1], _NERDCTL_INTERNAL_LOGGING) != 0) {
        fprintf(stderr, "Usage: %s %s <path>\n", argv[0], _NERDCTL_INTERNAL_LOGGING);
        return -1;
    }
    const char *path = argv[2];

    const char *ns = getenv("CONTAINER_NAMESPACE");
    if (!ns) {
        fputs("Error: CONTAINER_NAMESPACE environment variable not set\n", stderr);
        return -1;
    }

    const char *cid = getenv("CONTAINER_ID");
    if (!cid) {
        fputs("Error: CONTAINER_ID environment variable not set\n", stderr);
        return -1;
    }

    char filename[1024];
    snprintf(filename, sizeof(filename), "%s/containers/%s/%s/%s-json.log", path, ns, cid, cid);

    FILE *log_file = fopen(filename, "a");
    if (!log_file) {
        perror("Failed to open log file");
        return -1;
    }

    if (setvbuf(log_file, NULL, _IOFBF, MAX_LOG_LINE_SIZE) != 0) {
        perror("Failed to setvbuf log file");
        return -1;
    }

    long long filesize = ftell(log_file);
    if (filesize < 0) {
        perror("Failed to get log filesize");
        return -1;
    }

    if (fcntl(3, F_SETFL, fcntl(3, F_GETFL) | O_NONBLOCK) == -1) {
        perror("fcntl 3 failed");
        return -1;
    }
    if (fcntl(4, F_SETFL, fcntl(4, F_GETFL) | O_NONBLOCK) == -1) {
        perror("fcntl 4 failed");
        return -1;
    }

    // Singal started.
    close(5);

    fd_set read_fds;
    struct timeval timeout;
    char buffer[MAX_LOG_LINE_SIZE];

    while (1) {
        if (filesize >= MAX_FILE_SIZE) {
            fclose(log_file);
            char new_filename[1050];
            snprintf(new_filename, sizeof(new_filename), "%s.1", filename);
            if (rename(filename, new_filename) != 0) {
                perror("Failed to rotate log file");
                // Continue logging to the old file as a fallback
                log_file = fopen(filename, "a");
            } else {
                log_file = fopen(filename, "w"); // New empty file
            }

            if (!log_file) {
                perror("Failed to reopen log file after rotation");
                return -1;
            }
            filesize = 0;
        }

        FD_ZERO(&read_fds);
        FD_SET(3, &read_fds);
        FD_SET(4, &read_fds);

        timeout.tv_sec = SELECT_TIMEOUT_SECS;
        timeout.tv_usec = 0;

        int ret = select(5, &read_fds, NULL, NULL, &timeout);
        if (ret == -1) {
            perror("select failed");
            break; // Exit loop on select error
        }

        if (ret > 0) {
            long long n = 0;
            if (FD_ISSET(3, &read_fds)) {
                n = write_json_line(log_file, "stdout", 3, buffer);
                if (n > 0)
                    filesize = n;
                if (n == -1)
                    break;
            }
            if (FD_ISSET(4, &read_fds)) {
                n = write_json_line(log_file, "stderr", 4, buffer);
                if (n > 0)
                    filesize = n;
                if (n == -1)
                    break;
            }
        }
        // If ret is 0, it's a timeout, and the loop continues.
    }

    fclose(log_file);
    return 0;
}

long long write_json_line(FILE *log_file, const char *name, int fd, char *buffer) {
    ssize_t n = read(fd, buffer, MAX_LOG_LINE_SIZE - 1);
    if (n <= 0) {
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            // This is expected in non-blocking mode, not an error.
            return 0;
        }
        // EOF or real error, we might want to exit the program.
        // For now, we just stop processing this line.
        // In a real-world scenario, EOF on fd 3/4 means the container process exited.
        // The main loop will eventually timeout or exit.
        return -1;
    }
    buffer[n] = '\0';

    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        perror("clock_gettime failed");
        return -1;
    }

    struct tm tm_s;
    if (gmtime_r(&ts.tv_sec, &tm_s) == NULL) {
        perror("gmtime_r failed");
        return -1;
    }

    fprintf(log_file,
            "{\"time\":\"%04d-%02d-%02dT%02d:%02d:%02d.%09ldZ\",\"stream\":\"%s\",\"log\":\"",
            tm_s.tm_year + 1900,
            tm_s.tm_mon + 1,
            tm_s.tm_mday,
            tm_s.tm_hour,
            tm_s.tm_min,
            tm_s.tm_sec,
            ts.tv_nsec,
            name);

    for (ssize_t i = 0; i < n; ++i) {
        unsigned char c = buffer[i];
        switch (c) {
            case '"' : fputs("\\\"", log_file); break;
            case '<' : fputs("\\u003c", log_file); break;
            case '\'' : fputs("\\u0027", log_file); break;
            case '\\' : fputs("\\\\", log_file); break;
            case '\r' : fputs("\\r", log_file); break;
            case '\n' : fputs("\\n", log_file); break;
            case '\t' : fputs("\\t", log_file); break;
            case '\f' : fputs("\\u000c", log_file); break;
            case '\b' : fputs("\\u0008", log_file); break;
            case '\x1b' : fputs("\\u001b", log_file); break;
            default:
                if (c < 32) {
                    fprintf(log_file, "\\u%04x", c);
                } else {
                    fputc(c, log_file);
                }
                break;
        }
    }

    fputs("\"}\n", log_file);
    fflush(log_file);

    // Update filesize
    return ftell(log_file);
}
