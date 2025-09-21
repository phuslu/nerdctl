#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <errno.h>
#include <signal.h>

#define _NERDCTL_INTERNAL_LOGGING "_NERDCTL_INTERNAL_LOGGING"
#define MAX_LOG_LINE_SIZE (16 * 1024)
#define MAX_FILE_SIZE (50 * 1024 * 1024)
#define SELECT_TIMEOUT_SECS 60

long long write_json_line(FILE *log_file, const char *name, int fd, char *buffer);

static volatile sig_atomic_t shutdown_requested = 0;

static void handle_signal(int signo) {
    (void)signo;
    shutdown_requested = 1;
}

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

    if (signal(SIGTERM, handle_signal) == SIG_ERR) {
        perror("signal SIGTERM failed");
        fclose(log_file);
        return -1;
    }
    if (signal(SIGINT, handle_signal) == SIG_ERR) {
        perror("signal SIGINT failed");
        fclose(log_file);
        return -1;
    }

    if (setvbuf(log_file, NULL, _IOFBF, MAX_LOG_LINE_SIZE) != 0) {
        perror("Failed to setvbuf log file");
        fclose(log_file);
        return -1;
    }

    long long filesize = ftell(log_file);
    if (filesize < 0) {
        perror("Failed to get log filesize");
        fclose(log_file);
        return -1;
    }

    if (fcntl(3, F_SETFL, fcntl(3, F_GETFL) | O_NONBLOCK) == -1) {
        perror("fcntl 3 failed");
        fclose(log_file);
        return -1;
    }
    if (fcntl(4, F_SETFL, fcntl(4, F_GETFL) | O_NONBLOCK) == -1) {
        perror("fcntl 4 failed");
        fclose(log_file);
        return -1;
    }

    // Singal started.
    close(5);

    fd_set read_fds;
    struct timeval timeout;
    char buffer[MAX_LOG_LINE_SIZE];

    while (!shutdown_requested) {
        if (filesize >= MAX_FILE_SIZE) {
            fclose(log_file);
            char new_filename[1050];
            snprintf(new_filename, sizeof(new_filename), "%s.1", filename);
            if (rename(filename, new_filename) != 0) {
                perror("Failed to rotate log file");
                log_file = fopen(filename, "a");
            } else {
                log_file = fopen(filename, "w");
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

        int ret = select(4 + 1, &read_fds, NULL, NULL, &timeout);

        if (ret == -1) {
            if (errno == EINTR) {
                if (shutdown_requested) {
                    break;
                }
                continue;
            }
            perror("select failed");
            break;
        }

        if (ret > 0) {
            if (shutdown_requested) {
                continue;
            }

            long long bytes_written = 0;
            if (FD_ISSET(3, &read_fds)) {
                bytes_written = write_json_line(log_file, "stdout", 3, buffer);
                if (bytes_written > 0)
                    filesize += bytes_written;
                if (bytes_written == -1)
                    break;
            }
            if (FD_ISSET(4, &read_fds)) {
                bytes_written = write_json_line(log_file, "stderr", 4, buffer);
                if (bytes_written > 0)
                    filesize += bytes_written;
                if (bytes_written == -1)
                    break;
            }
        }
    }

    fclose(log_file);
    return 0;
}

long long write_json_line(FILE *log_file, const char *name, int fd, char *buffer) {
    ssize_t n = read(fd, buffer, MAX_LOG_LINE_SIZE - 1);
    if (n <= 0) {
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return 0;
        }
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

    long long bytes_written = 0;
    int rc;

    rc = fprintf(log_file,
            "{\"time\":\"%04d-%02d-%02dT%02d:%02d:%02d.%09ldZ\",\"stream\":\"%s\",\"log\":\"",
            tm_s.tm_year + 1900,
            tm_s.tm_mon + 1,
            tm_s.tm_mday,
            tm_s.tm_hour,
            tm_s.tm_min,
            tm_s.tm_sec,
            ts.tv_nsec,
            name);
    if (rc < 0) return -1;
    bytes_written += rc;

    for (ssize_t i = 0; i < n; ++i) {
        unsigned char c = buffer[i];
        switch (c) {
            case '"' : if (fputs("\\\"", log_file) == EOF) return -1; bytes_written += 2; break;
            case '<' : if (fputs("\\u003c", log_file) == EOF) return -1; bytes_written += 6; break;
            case '\'' : if (fputs("\\u0027", log_file) == EOF) return -1; bytes_written += 6; break;
            case '\\' : if (fputs("\\\\", log_file) == EOF) return -1; bytes_written += 2; break;
            case '\r' : if (fputs("\\r", log_file) == EOF) return -1; bytes_written += 2; break;
            case '\n' : if (fputs("\\n", log_file) == EOF) return -1; bytes_written += 2; break;
            case '\t' : if (fputs("\\t", log_file) == EOF) return -1; bytes_written += 2; break;
            case '\f' : if (fputs("\\u000c", log_file) == EOF) return -1; bytes_written += 6; break;
            case '\b' : if (fputs("\\u0008", log_file) == EOF) return -1; bytes_written += 6; break;
            case '\x1b' : if (fputs("\\u001b", log_file) == EOF) return -1; bytes_written += 6; break;
            default:
                if (c < 32) {
                    rc = fprintf(log_file, "\\u%04x", c);
                    if (rc < 0) return -1;
                    bytes_written += rc;
                } else {
                    if (fputc(c, log_file) == EOF) return -1;
                    bytes_written += 1;
                }
                break;
        }
    }

    if (fputs("\"}\n", log_file) == EOF) return -1;
    bytes_written += 3;

    fflush(log_file);

    return bytes_written;
}
