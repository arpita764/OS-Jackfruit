/*
 * engine.c - Supervised Multi-Container Runtime (User Space)
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "monitor_ioctl.h"

#define STACK_SIZE (1024 * 1024)
#define CONTAINER_ID_LEN 32
#define CONTROL_PATH "/tmp/mini_runtime.sock"
#define LOG_DIR "logs"
#define CONTROL_MESSAGE_LEN 256
#define CHILD_COMMAND_LEN 256
#define LOG_CHUNK_SIZE 4096
#define LOG_BUFFER_CAPACITY 16
#define DEFAULT_SOFT_LIMIT (40UL << 20)
#define DEFAULT_HARD_LIMIT (64UL << 20)

typedef enum {
    CMD_SUPERVISOR = 0,
    CMD_START,
    CMD_RUN,
    CMD_PS,
    CMD_LOGS,
    CMD_STOP
} command_kind_t;

typedef enum {
    CONTAINER_STARTING = 0,
    CONTAINER_RUNNING,
    CONTAINER_STOPPED,
    CONTAINER_KILLED,
    CONTAINER_EXITED
} container_state_t;

typedef struct container_record {
    char id[CONTAINER_ID_LEN];
    pid_t host_pid;
    time_t started_at;
    container_state_t state;
    unsigned long soft_limit_bytes;
    unsigned long hard_limit_bytes;
    int exit_code;
    int exit_signal;
    int stop_requested;
    char log_path[PATH_MAX];
    struct container_record *next;
} container_record_t;

typedef struct {
    char container_id[CONTAINER_ID_LEN];
    size_t length;
    char data[LOG_CHUNK_SIZE];
} log_item_t;

typedef struct {
    log_item_t items[LOG_BUFFER_CAPACITY];
    size_t head;
    size_t tail;
    size_t count;
    int shutting_down;
    pthread_mutex_t mutex;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;
} bounded_buffer_t;

typedef struct {
    command_kind_t kind;
    char container_id[CONTAINER_ID_LEN];
    char rootfs[PATH_MAX];
    char command[CHILD_COMMAND_LEN];
    unsigned long soft_limit_bytes;
    unsigned long hard_limit_bytes;
    int nice_value;
} control_request_t;

typedef struct {
    int status;
    char message[CONTROL_MESSAGE_LEN];
} control_response_t;

typedef struct {
    char id[CONTAINER_ID_LEN];
    char rootfs[PATH_MAX];
    char command[CHILD_COMMAND_LEN];
    int nice_value;
    int log_write_fd;
} child_config_t;

typedef struct {
    int server_fd;
    int monitor_fd;
    int should_stop;
    pthread_t logger_thread;
    bounded_buffer_t log_buffer;
    pthread_mutex_t metadata_lock;
    container_record_t *containers;
} supervisor_ctx_t;

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage:\n"
            "  %s supervisor <base-rootfs>\n"
            "  %s start <id> <container-rootfs> <command> [--soft-mib N] [--hard-mib N] [--nice N]\n"
            "  %s run <id> <container-rootfs> <command> [--soft-mib N] [--hard-mib N] [--nice N]\n"
            "  %s ps\n"
            "  %s logs <id>\n"
            "  %s stop <id>\n",
            prog, prog, prog, prog, prog, prog);
}

static int parse_mib_flag(const char *flag,
                          const char *value,
                          unsigned long *target_bytes)
{
    char *end = NULL;
    unsigned long mib;

    errno = 0;
    mib = strtoul(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0') {
        fprintf(stderr, "Invalid value for %s: %s\n", flag, value);
        return -1;
    }

    if (mib > ULONG_MAX / (1UL << 20)) {
        fprintf(stderr, "Value for %s is too large: %s\n", flag, value);
        return -1;
    }

    *target_bytes = mib * (1UL << 20);
    return 0;
}

static int parse_optional_flags(control_request_t *req,
                                int argc,
                                char *argv[],
                                int start_index)
{
    int i;

    for (i = start_index; i < argc; i += 2) {
        char *end = NULL;
        long nice_value;

        if (i + 1 >= argc) {
            fprintf(stderr, "Missing value for option: %s\n", argv[i]);
            return -1;
        }

        if (strcmp(argv[i], "--soft-mib") == 0) {
            if (parse_mib_flag("--soft-mib", argv[i + 1], &req->soft_limit_bytes) != 0)
                return -1;
            continue;
        }

        if (strcmp(argv[i], "--hard-mib") == 0) {
            if (parse_mib_flag("--hard-mib", argv[i + 1], &req->hard_limit_bytes) != 0)
                return -1;
            continue;
        }

        if (strcmp(argv[i], "--nice") == 0) {
            errno = 0;
            nice_value = strtol(argv[i + 1], &end, 10);
            if (errno != 0 || end == argv[i + 1] || *end != '\0' ||
                nice_value < -20 || nice_value > 19) {
                fprintf(stderr,
                        "Invalid value for --nice (expected -20..19): %s\n",
                        argv[i + 1]);
                return -1;
            }
            req->nice_value = (int)nice_value;
            continue;
        }

        fprintf(stderr, "Unknown option: %s\n", argv[i]);
        return -1;
    }

    if (req->soft_limit_bytes > req->hard_limit_bytes) {
        fprintf(stderr, "Invalid limits: soft limit cannot exceed hard limit\n");
        return -1;
    }

    return 0;
}

static const char *state_to_string(container_state_t state)
{
    switch (state) {
    case CONTAINER_STARTING:
        return "starting";
    case CONTAINER_RUNNING:
        return "running";
    case CONTAINER_STOPPED:
        return "stopped";
    case CONTAINER_KILLED:
        return "killed (hard-limit)";
    case CONTAINER_EXITED:
        return "exited";
    default:
        return "unknown";
    }
}

static int bounded_buffer_init(bounded_buffer_t *buffer)
{
    int rc;

    memset(buffer, 0, sizeof(*buffer));

    rc = pthread_mutex_init(&buffer->mutex, NULL);
    if (rc != 0)
        return rc;

    rc = pthread_cond_init(&buffer->not_empty, NULL);
    if (rc != 0) {
        pthread_mutex_destroy(&buffer->mutex);
        return rc;
    }

    rc = pthread_cond_init(&buffer->not_full, NULL);
    if (rc != 0) {
        pthread_cond_destroy(&buffer->not_empty);
        pthread_mutex_destroy(&buffer->mutex);
        return rc;
    }

    return 0;
}

static void bounded_buffer_destroy(bounded_buffer_t *buffer)
{
    pthread_cond_destroy(&buffer->not_full);
    pthread_cond_destroy(&buffer->not_empty);
    pthread_mutex_destroy(&buffer->mutex);
}

static void bounded_buffer_begin_shutdown(bounded_buffer_t *buffer)
{
    pthread_mutex_lock(&buffer->mutex);
    buffer->shutting_down = 1;
    pthread_cond_broadcast(&buffer->not_empty);
    pthread_cond_broadcast(&buffer->not_full);
    pthread_mutex_unlock(&buffer->mutex);
}

/*
 * TODO:
 * Implement producer-side insertion into the bounded buffer.
 *
 * Requirements:
 *   - block or fail according to your chosen policy when the buffer is full
 *   - wake consumers correctly
 *   - stop cleanly if shutdown begins
 */
int bounded_buffer_push(bounded_buffer_t *buffer, const log_item_t *item)
{
    pthread_mutex_lock(&buffer->mutex);
 
    while (buffer->count == LOG_BUFFER_CAPACITY && !buffer->shutting_down)
        pthread_cond_wait(&buffer->not_full, &buffer->mutex);
 
    if (buffer->shutting_down) {
        pthread_mutex_unlock(&buffer->mutex);
        return -1;
    }
 
    buffer->items[buffer->tail] = *item;
    buffer->tail = (buffer->tail + 1) % LOG_BUFFER_CAPACITY;
    buffer->count++;
 
    pthread_cond_signal(&buffer->not_empty);
    pthread_mutex_unlock(&buffer->mutex);
    return 0;
}

/*
 * TODO:
 * Implement consumer-side removal from the bounded buffer.
 *
 * Requirements:
 *   - wait correctly while the buffer is empty
 *   - return a useful status when shutdown is in progress
 *   - avoid races with producers and shutdown
 */
int bounded_buffer_pop(bounded_buffer_t *buffer, log_item_t *item)
{
    pthread_mutex_lock(&buffer->mutex);
 
    while (buffer->count == 0 && !buffer->shutting_down)
        pthread_cond_wait(&buffer->not_empty, &buffer->mutex);
 
    if (buffer->count == 0) {
        /* Shutdown and buffer empty — consumer should exit. */
        pthread_mutex_unlock(&buffer->mutex);
        return -1;
    }
 
    *item = buffer->items[buffer->head];
    buffer->head = (buffer->head + 1) % LOG_BUFFER_CAPACITY;
    buffer->count--;
 
    pthread_cond_signal(&buffer->not_full);
    pthread_mutex_unlock(&buffer->mutex);
    return 0;
}

/*
 * TODO:
 * Implement the logging consumer thread.
 *
 * Suggested responsibilities:
 *   - remove log chunks from the bounded buffer
 *   - route each chunk to the correct per-container log file
 *   - exit cleanly when shutdown begins and pending work is drained
 */
void *logging_thread(void *arg)
{
    supervisor_ctx_t *ctx = (supervisor_ctx_t *)arg;
    log_item_t item;
 
    /* Ensure log directory exists. */
    mkdir(LOG_DIR, 0755);
 
    while (bounded_buffer_pop(&ctx->log_buffer, &item) == 0) {
        char path[PATH_MAX];
        int fd;
 
        snprintf(path, sizeof(path), "%s/%s.log", LOG_DIR, item.container_id);
        fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (fd < 0) {
            perror("logging_thread: open log file");
            continue;
        }
        /* Write exactly item.length bytes (may be less than LOG_CHUNK_SIZE). */
        if (write(fd, item.data, item.length) < 0)
            perror("logging_thread: write");
        close(fd);
    }
 
    fprintf(stderr, "[supervisor] Logging thread exiting.\n");
    return NULL;
}

/*
 * TODO:
 * Implement the clone child entrypoint.
 *
 * Required outcomes:
 *   - isolated PID / UTS / mount context
 *   - chroot or pivot_root into rootfs
 *   - working /proc inside container
 *   - stdout / stderr redirected to the supervisor logging path
 *   - configured command executed inside the container
 */
int child_fn(void *arg)
{
    child_config_t *cfg = (child_config_t *)arg;
    char *argv_exec[] = { "/bin/sh", "-c", cfg->command, NULL };

    /* 1. Set hostname */
    if (sethostname(cfg->id, strlen(cfg->id)) < 0)
        perror("child: sethostname");

    /* 2. Mount /proc inside the new mount namespace */
    if (mount("proc", "/proc", "proc",
              MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) < 0) {
        perror("child: mount /proc (pre-chroot)");
    } else {
        fprintf(stderr, "[child] Mounted /proc (pre-chroot)\n");
    }

    /* 3. chroot into container rootfs */
    if (chroot(cfg->rootfs) < 0) {
        perror("child: chroot");
        return 1;
    }
    if (chdir("/") < 0) {
        perror("child: chdir /");
        return 1;
    }

    /* Re-mount /proc inside the chroot */
    if (mount("proc", "/proc", "proc",
              MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) < 0) {
        perror("child: mount /proc (post-chroot)");
    } else {
        fprintf(stderr, "[child] Mounted /proc (post-chroot) - ps should work now\n");
    }

    /* 4. Redirect stdout and stderr to the logging pipe */
    if (cfg->log_write_fd >= 0) {
        dup2(cfg->log_write_fd, STDOUT_FILENO);
        dup2(cfg->log_write_fd, STDERR_FILENO);
        close(cfg->log_write_fd);
    }

    /* 5. Apply nice value */
    if (cfg->nice_value != 0) {
        if (nice(cfg->nice_value) < 0)
            perror("child: nice");
    }

    /* 6. exec */
    execv("/bin/sh", argv_exec);
    perror("child: execv");
    return 1;
}

int register_with_monitor(int monitor_fd,
                          const char *container_id,
                          pid_t host_pid,
                          unsigned long soft_limit_bytes,
                          unsigned long hard_limit_bytes)
{
    struct monitor_request req;

    memset(&req, 0, sizeof(req));
    req.pid = host_pid;
    req.soft_limit_bytes = soft_limit_bytes;
    req.hard_limit_bytes = hard_limit_bytes;
    strncpy(req.container_id, container_id, sizeof(req.container_id) - 1);

    if (ioctl(monitor_fd, MONITOR_REGISTER, &req) < 0)
        return -1;

    return 0;
}

int unregister_from_monitor(int monitor_fd, const char *container_id, pid_t host_pid)
{
    struct monitor_request req;

    memset(&req, 0, sizeof(req));
    req.pid = host_pid;
    strncpy(req.container_id, container_id, sizeof(req.container_id) - 1);

    if (ioctl(monitor_fd, MONITOR_UNREGISTER, &req) < 0)
        return -1;

    return 0;
}

/* Global pointer used by signal handlers to reach supervisor context. */
static supervisor_ctx_t *g_ctx = NULL;

/* ---------------------------------------------------------------
 * Container metadata helpers (always call with metadata_lock held)
 * --------------------------------------------------------------- */
static container_record_t *find_container(supervisor_ctx_t *ctx, const char *id)
{
    container_record_t *r = ctx->containers;
    while (r) {
        if (strncmp(r->id, id, CONTAINER_ID_LEN) == 0)
            return r;
        r = r->next;
    }
    return NULL;
}

static void add_container(supervisor_ctx_t *ctx, container_record_t *rec)
{
    if (ctx->containers == NULL) {
        ctx->containers = rec;
    } else {
        container_record_t *temp = ctx->containers;
        while (temp->next != NULL) {
            temp = temp->next;
        }
        temp->next = rec;
    }
}

/* ---------------------------------------------------------------
 * Log reader thread — spawned to read from a pipe and push into buffer
 * --------------------------------------------------------------- */
typedef struct {
    supervisor_ctx_t *ctx;
    int               read_fd;
    char              container_id[CONTAINER_ID_LEN];
} log_reader_arg_t;

static void *log_reader_thread(void *arg)
{
    log_reader_arg_t *lra = (log_reader_arg_t *)arg;
    log_item_t item;
    ssize_t n;

    memset(&item, 0, sizeof(item));
    strncpy(item.container_id, lra->container_id, CONTAINER_ID_LEN - 1);

    while ((n = read(lra->read_fd, item.data, sizeof(item.data))) > 0) {
        item.length = (size_t)n;
        bounded_buffer_push(&lra->ctx->log_buffer, &item);
    }

    close(lra->read_fd);
    free(lra);
    return NULL;
}

static void spawn_log_reader(supervisor_ctx_t *ctx,
                              int read_fd,
                              const char *container_id)
{
    log_reader_arg_t *lra = malloc(sizeof(*lra));
    pthread_t tid;
    pthread_attr_t attr;

    if (!lra) { close(read_fd); return; }

    lra->ctx = ctx;
    lra->read_fd = read_fd;
    strncpy(lra->container_id, container_id, CONTAINER_ID_LEN - 1);
    lra->container_id[CONTAINER_ID_LEN - 1] = '\0';

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&tid, &attr, log_reader_thread, lra);
    pthread_attr_destroy(&attr);
}

/* ---------------------------------------------------------------
 * launch_container — create namespaces, clone, register with monitor.
 * --------------------------------------------------------------- */
static pid_t launch_container(supervisor_ctx_t *ctx,
                               const char *id,
                               const char *rootfs,
                               const char *command,
                               int nice_value,
                               unsigned long soft_limit_bytes,
                               unsigned long hard_limit_bytes,
                               int *out_log_read_fd)
{
    char *stack, *stack_top;
    int pipefd[2];
    pid_t pid;
    int clone_flags;

    if (pipe(pipefd) < 0) {
        perror("launch_container: pipe");
        return -1;
    }

    stack = malloc(STACK_SIZE);
    if (!stack) {
        perror("launch_container: malloc stack");
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }
    stack_top = stack + STACK_SIZE;

    child_config_t *cfg = malloc(sizeof(*cfg));
    if (!cfg) {
        free(stack);
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }
    strncpy(cfg->id, id, CONTAINER_ID_LEN - 1);
    cfg->id[CONTAINER_ID_LEN - 1] = '\0';
    strncpy(cfg->rootfs, rootfs, PATH_MAX - 1);
    cfg->rootfs[PATH_MAX - 1] = '\0';
    strncpy(cfg->command, command, CHILD_COMMAND_LEN - 1);
    cfg->command[CHILD_COMMAND_LEN - 1] = '\0';
    cfg->nice_value  = nice_value;
    cfg->log_write_fd = pipefd[1];

    clone_flags = CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWNS | SIGCHLD;

    pid = clone(child_fn, stack_top, clone_flags, cfg);
    free(stack);

    if (pid < 0) {
        perror("launch_container: clone");
        free(cfg);
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    close(pipefd[1]);

    if (register_with_monitor(ctx->monitor_fd, id, pid,
                               soft_limit_bytes, hard_limit_bytes) < 0)
        perror("launch_container: register_with_monitor");

    *out_log_read_fd = pipefd[0];
    return pid;
}

/* ---------------------------------------------------------------
 * Signal handlers
 * --------------------------------------------------------------- */
static void sigchld_handler(int sig)
{
    (void)sig;
    int status;
    pid_t pid;
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        if (!g_ctx) continue;

        pthread_mutex_lock(&g_ctx->metadata_lock);
        container_record_t *r = g_ctx->containers;
        while (r) {
            if (r->host_pid == pid) {
                if (WIFSIGNALED(status)) {
                    int term_sig = WTERMSIG(status);
                    r->exit_signal = term_sig;
                    
                    /* Attribution logic: distinguish manual stop from kernel kill */
                    if (term_sig == SIGKILL) {
                        if (r->stop_requested) {
                            r->state = CONTAINER_STOPPED;
                            fprintf(stderr, "[SIGCHLD] Reaped container '%s' (PID %d) with SIGKILL [state: STOPPED (manual stop)]\n",
                                    r->id, pid);
                        } else {
                            r->state = CONTAINER_KILLED;
                            fprintf(stderr, "[SIGCHLD] Reaped container '%s' (PID %d) with SIGKILL [state: KILLED (HARD LIMIT)]\n",
                                    r->id, pid);
                        }
                    } else {
                        r->state = CONTAINER_STOPPED;
                        fprintf(stderr, "[SIGCHLD] Reaped container '%s' (PID %d) with signal %d [state: STOPPED]\n",
                                r->id, pid, term_sig);
                    }
                } else {
                    r->state     = CONTAINER_EXITED;
                    r->exit_code = WEXITSTATUS(status);
                    fprintf(stderr, "[SIGCHLD] Reaped container '%s' (PID %d) with exit code %d [state: EXITED]\n",
                            r->id, pid, WEXITSTATUS(status));
                }
                unregister_from_monitor(g_ctx->monitor_fd, r->id, pid);
                break;
            }
            r = r->next;
        }
        pthread_mutex_unlock(&g_ctx->metadata_lock);
    }
}

static void sigterm_handler(int sig)
{
    (void)sig;
    if (g_ctx)
        g_ctx->should_stop = 1;
}

/* ---------------------------------------------------------------
 * Control socket helpers
 * --------------------------------------------------------------- */
static int create_control_socket(void)
{
    int fd;
    struct sockaddr_un addr;

    unlink(CONTROL_PATH);

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return -1; }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CONTROL_PATH, sizeof(addr.sun_path) - 1);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(fd);
        return -1;
    }
    if (listen(fd, 8) < 0) {
        perror("listen");
        close(fd);
        return -1;
    }
    return fd;
}

static void send_response(int client_fd, int status, const char *message)
{
    control_response_t resp;
    memset(&resp, 0, sizeof(resp));
    resp.status = status;
    strncpy(resp.message, message, CONTROL_MESSAGE_LEN - 1);
    write(client_fd, &resp, sizeof(resp));
}

/* ---------------------------------------------------------------
 * Handle a single control request
 * --------------------------------------------------------------- */
static void handle_control_request(supervisor_ctx_t *ctx,
                                    int client_fd,
                                    const control_request_t *req)
{
    char msg[CONTROL_MESSAGE_LEN];
    const char *cmd_name = "";

    switch (req->kind) {

    case CMD_START:
        cmd_name = "CMD_START";
        fprintf(stderr, "[IPC] Received %s from client for container '%s'\n", cmd_name, req->container_id);
        break;
    case CMD_RUN:
        cmd_name = "CMD_RUN";
        fprintf(stderr, "[IPC] Received %s from client for container '%s'\n", cmd_name, req->container_id);
        break;
    case CMD_PS:
        cmd_name = "CMD_PS";
        fprintf(stderr, "[IPC] Received %s from client\n", cmd_name);
        break;
    case CMD_LOGS:
        cmd_name = "CMD_LOGS";
        fprintf(stderr, "[IPC] Received %s from client for container '%s'\n", cmd_name, req->container_id);
        break;
    case CMD_STOP:
        cmd_name = "CMD_STOP";
        fprintf(stderr, "[IPC] Received %s from client for container '%s'\n", cmd_name, req->container_id);
        break;
    }

    switch (req->kind) {

    case CMD_START:
    case CMD_RUN: {
        int log_read_fd = -1;
        pid_t pid;
        container_record_t *rec;

        pthread_mutex_lock(&ctx->metadata_lock);
        if (find_container(ctx, req->container_id)) {
            pthread_mutex_unlock(&ctx->metadata_lock);
            send_response(client_fd, -1, "Container ID already exists.");
            return;
        }
        pthread_mutex_unlock(&ctx->metadata_lock);

        pid = launch_container(ctx,
                               req->container_id,
                               req->rootfs,
                               req->command,
                               req->nice_value,
                               req->soft_limit_bytes,
                               req->hard_limit_bytes,
                               &log_read_fd);
        if (pid < 0) {
            send_response(client_fd, -1, "Failed to launch container.");
            return;
        }

        rec = calloc(1, sizeof(*rec));
        if (!rec) {
            send_response(client_fd, -1, "Out of memory.");
            return;
        }
        strncpy(rec->id, req->container_id, CONTAINER_ID_LEN - 1);
        rec->host_pid         = pid;
        rec->started_at       = time(NULL);
        rec->state            = CONTAINER_RUNNING;
        rec->soft_limit_bytes = req->soft_limit_bytes;
        rec->hard_limit_bytes = req->hard_limit_bytes;
        rec->stop_requested   = 0;  /* Initialize stop_requested flag */
        snprintf(rec->log_path, PATH_MAX, "%s/%s.log", LOG_DIR, req->container_id);

        pthread_mutex_lock(&ctx->metadata_lock);
        add_container(ctx, rec);
        pthread_mutex_unlock(&ctx->metadata_lock);

        spawn_log_reader(ctx, log_read_fd, req->container_id);

        fprintf(stderr, "[LIFECYCLE] Container '%s' started: PID=%d, state=RUNNING, log_path=%s\n",
                req->container_id, (int)pid, rec->log_path);
        fflush(stderr);
        printf("New container started: %s (PID: %d)\n", req->container_id, (int)pid);
        fflush(stdout);

        snprintf(msg, sizeof(msg), "Started container %s (pid=%d).",
                 req->container_id, (int)pid);
        send_response(client_fd, 0, msg);

        if (req->kind == CMD_RUN) {
            int status;
            waitpid(pid, &status, 0);
            pthread_mutex_lock(&ctx->metadata_lock);
            container_record_t *r = find_container(ctx, req->container_id);
            if (r && r->state == CONTAINER_RUNNING)
                r->state = CONTAINER_EXITED;
            pthread_mutex_unlock(&ctx->metadata_lock);
        }
        break;
    }

    case CMD_PS: {
        char buf[8192] = "";
        int off = 0;

        off += snprintf(buf + off, sizeof(buf) - off,
                        "%-9s %-6s %-8s %-20s %-18s %s\n",
                        "ID", "PID", "STATE", "START_TIME", "LOG_PATH", "SOFT(Mib)/HARD(Mib)");

        pthread_mutex_lock(&ctx->metadata_lock);
        container_record_t *r = ctx->containers;
        while (r && off < (int)sizeof(buf) - 1) {
            char tbuf[32];
            char mem_info[32];
            struct tm *tm_info = localtime(&r->started_at);
            strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", tm_info);
            snprintf(mem_info, sizeof(mem_info), "%lu/%lu MiB",
                     r->soft_limit_bytes >> 20,
                     r->hard_limit_bytes >> 20);

            off += snprintf(buf + off, sizeof(buf) - off,
                            "%-9s %-6d %-8s %-20s %-18s %s\n",
                            r->id, (int)r->host_pid,
                            state_to_string(r->state), tbuf,
                            r->log_path, mem_info);
            r = r->next;
        }
        pthread_mutex_unlock(&ctx->metadata_lock);

        send_response(client_fd, 0, buf);
        break;
    }

    case CMD_LOGS: {
        char path[PATH_MAX];
        char buf[LOG_CHUNK_SIZE];
        int fd;
        ssize_t n;

        pthread_mutex_lock(&ctx->metadata_lock);
        container_record_t *r = find_container(ctx, req->container_id);
        if (r)
            strncpy(path, r->log_path, PATH_MAX - 1);
        pthread_mutex_unlock(&ctx->metadata_lock);

        if (!r) {
            send_response(client_fd, -1, "Container not found.");
            return;
        }

        fd = open(path, O_RDONLY);
        if (fd < 0) {
            send_response(client_fd, -1, "Log file not found.");
            return;
        }

        send_response(client_fd, 0, "Log follows:");

        while ((n = read(fd, buf, sizeof(buf))) > 0)
            write(client_fd, buf, n);

        close(fd);
        break;
    }

    case CMD_STOP: {
        pid_t pid = -1;

        pthread_mutex_lock(&ctx->metadata_lock);
        container_record_t *r = find_container(ctx, req->container_id);
        if (r && r->state == CONTAINER_RUNNING) {
            pid = r->host_pid;
            r->stop_requested = 1;  /* Mark that stop was requested by user */
            fprintf(stderr, "[LIFECYCLE] Stopping container '%s' (PID %d) - sending SIGTERM\n",
                    req->container_id, (int)pid);
            r->state = CONTAINER_STOPPED;
        }
        pthread_mutex_unlock(&ctx->metadata_lock);

        if (pid < 0) {
            send_response(client_fd, -1, "Container not found or not running.");
            return;
        }

        if (kill(pid, SIGTERM) < 0 && errno != ESRCH) {
            snprintf(msg, sizeof(msg), "kill(SIGTERM) failed: %s", strerror(errno));
            send_response(client_fd, -1, msg);
            return;
        }

        snprintf(msg, sizeof(msg), "Sent SIGTERM to container %s (pid=%d).",
                 req->container_id, (int)pid);
        send_response(client_fd, 0, msg);
        break;
    }

    default:
        send_response(client_fd, -1, "Unknown command.");
        break;
    }
}

/*
 * TODO:
 * Implement the long-running supervisor process.
 *
 * Suggested responsibilities:
 *   - create and bind the control-plane IPC endpoint
 *   - initialize shared metadata and the bounded buffer
 *   - start the logging thread
 *   - accept control requests and update container state
 *   - reap children and respond to signals
 */
static int run_supervisor(const char *rootfs)
{
    supervisor_ctx_t ctx;
    struct sigaction sa;
    int rc;

    (void)rootfs; /* Not currently used in this implementation */

    memset(&ctx, 0, sizeof(ctx));
    ctx.server_fd  = -1;
    ctx.monitor_fd = -1;
    g_ctx = &ctx;

    rc = pthread_mutex_init(&ctx.metadata_lock, NULL);
    if (rc != 0) { errno = rc; perror("pthread_mutex_init"); return 1; }

    rc = bounded_buffer_init(&ctx.log_buffer);
    if (rc != 0) {
        errno = rc;
        perror("bounded_buffer_init");
        pthread_mutex_destroy(&ctx.metadata_lock);
        return 1;
    }

    mkdir(LOG_DIR, 0755);

    ctx.monitor_fd = open("/dev/container_monitor", O_RDWR);
    if (ctx.monitor_fd < 0)
        fprintf(stderr, "[supervisor] Warning: could not open /dev/container_monitor (%s). "
                "Memory monitoring disabled.\n", strerror(errno));

    ctx.server_fd = create_control_socket();
    if (ctx.server_fd < 0) {
        fprintf(stderr, "[supervisor] Failed to create control socket.\n");
        bounded_buffer_begin_shutdown(&ctx.log_buffer);
        bounded_buffer_destroy(&ctx.log_buffer);
        pthread_mutex_destroy(&ctx.metadata_lock);
        if (ctx.monitor_fd >= 0) close(ctx.monitor_fd);
        return 1;
    }

    memset(&sa, 0, sizeof(sa));
    sigemptyset(&sa.sa_mask);

    sa.sa_handler = sigchld_handler;
    sa.sa_flags   = SA_RESTART | SA_NOCLDSTOP;
    sigaction(SIGCHLD, &sa, NULL);

    sa.sa_handler = sigterm_handler;
    sa.sa_flags   = SA_RESTART;
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    rc = pthread_create(&ctx.logger_thread, NULL, logging_thread, &ctx);
    if (rc != 0) {
        errno = rc;
        perror("pthread_create logger");
        close(ctx.server_fd);
        unlink(CONTROL_PATH);
        bounded_buffer_begin_shutdown(&ctx.log_buffer);
        bounded_buffer_destroy(&ctx.log_buffer);
        pthread_mutex_destroy(&ctx.metadata_lock);
        if (ctx.monitor_fd >= 0) close(ctx.monitor_fd);
        return 1;
    }

    fprintf(stderr, "[supervisor] Ready. Control socket: %s  base-rootfs: %s\n",
            CONTROL_PATH, rootfs);

    while (!ctx.should_stop) {
        int client_fd;
        control_request_t req;
        fd_set rfds;
        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };

        FD_ZERO(&rfds);
        FD_SET(ctx.server_fd, &rfds);

        int sel = select(ctx.server_fd + 1, &rfds, NULL, NULL, &tv);
        if (sel < 0) {
            if (errno == EINTR) continue;
            perror("select");
            break;
        }
        if (sel == 0) continue;

        client_fd = accept(ctx.server_fd, NULL, NULL);
        if (client_fd < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            continue;
        }

        ssize_t n = read(client_fd, &req, sizeof(req));
        if (n == (ssize_t)sizeof(req)) {
            handle_control_request(&ctx, client_fd, &req);
        }
        close(client_fd);
    }

    fprintf(stderr, "[supervisor] Shutting down.\n");

    pthread_mutex_lock(&ctx.metadata_lock);
    {
        container_record_t *r = ctx.containers;
        while (r) {
            if (r->state == CONTAINER_RUNNING) {
                kill(r->host_pid, SIGTERM);
                r->state = CONTAINER_STOPPED;
            }
            r = r->next;
        }
    }
    pthread_mutex_unlock(&ctx.metadata_lock);

    {
        int status;
        while (waitpid(-1, &status, WNOHANG) > 0)
            ;
    }

    bounded_buffer_begin_shutdown(&ctx.log_buffer);
    pthread_join(ctx.logger_thread, NULL);
    bounded_buffer_destroy(&ctx.log_buffer);

    pthread_mutex_lock(&ctx.metadata_lock);
    {
        container_record_t *r = ctx.containers;
        while (r) {
            container_record_t *next = r->next;
            free(r);
            r = next;
        }
        ctx.containers = NULL;
    }
    pthread_mutex_unlock(&ctx.metadata_lock);
    pthread_mutex_destroy(&ctx.metadata_lock);

    close(ctx.server_fd);
    unlink(CONTROL_PATH);
    if (ctx.monitor_fd >= 0) close(ctx.monitor_fd);

    fprintf(stderr, "[supervisor] Exited cleanly.\n");
    return 0;
}

/*
 * TODO:
 * Implement the client-side control request path.
 *
 * The CLI commands should use a second IPC mechanism distinct from the
 * logging pipe. A UNIX domain socket is the most direct option, but a
 * FIFO or shared memory design is also acceptable if justified.
 */
static int send_control_request(const control_request_t *req)
{
    int fd;
    struct sockaddr_un addr;
    control_response_t resp;
    ssize_t n;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return 1; }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CONTROL_PATH, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect (is the supervisor running?)");
        close(fd);
        return 1;
    }

    if (write(fd, req, sizeof(*req)) < 0) {
        perror("write");
        close(fd);
        return 1;
    }

    n = read(fd, &resp, sizeof(resp));
    if (n != (ssize_t)sizeof(resp)) {
        fprintf(stderr, "Incomplete response from supervisor.\n");
        close(fd);
        return 1;
    }

    if (resp.status != 0) {
        fprintf(stderr, "Error: %s\n", resp.message);
        close(fd);
        return 1;
    }

    printf("%s\n", resp.message);

    if (req->kind == CMD_LOGS) {
        char buf[4096];
        while ((n = read(fd, buf, sizeof(buf))) > 0)
            fwrite(buf, 1, n, stdout);
    }

    close(fd);
    return 0;
}

static int cmd_start(int argc, char *argv[])
{
    control_request_t req;

    if (argc < 5) {
        fprintf(stderr,
                "Usage: %s start <id> <container-rootfs> <command> [--soft-mib N] [--hard-mib N] [--nice N]\n",
                argv[0]);
        return 1;
    }

    memset(&req, 0, sizeof(req));
    req.kind = CMD_START;
    strncpy(req.container_id, argv[2], sizeof(req.container_id) - 1);
    strncpy(req.rootfs, argv[3], sizeof(req.rootfs) - 1);
    strncpy(req.command, argv[4], sizeof(req.command) - 1);
    req.soft_limit_bytes = DEFAULT_SOFT_LIMIT;
    req.hard_limit_bytes = DEFAULT_HARD_LIMIT;

    if (parse_optional_flags(&req, argc, argv, 5) != 0)
        return 1;

    return send_control_request(&req);
}

static int cmd_run(int argc, char *argv[])
{
    control_request_t req;

    if (argc < 5) {
        fprintf(stderr,
                "Usage: %s run <id> <container-rootfs> <command> [--soft-mib N] [--hard-mib N] [--nice N]\n",
                argv[0]);
        return 1;
    }

    memset(&req, 0, sizeof(req));
    req.kind = CMD_RUN;
    strncpy(req.container_id, argv[2], sizeof(req.container_id) - 1);
    strncpy(req.rootfs, argv[3], sizeof(req.rootfs) - 1);
    strncpy(req.command, argv[4], sizeof(req.command) - 1);
    req.soft_limit_bytes = DEFAULT_SOFT_LIMIT;
    req.hard_limit_bytes = DEFAULT_HARD_LIMIT;

    if (parse_optional_flags(&req, argc, argv, 5) != 0)
        return 1;

    return send_control_request(&req);
}

static int cmd_ps(void)
{
    control_request_t req;

    memset(&req, 0, sizeof(req));
    req.kind = CMD_PS;

    return send_control_request(&req);
}

static int cmd_logs(int argc, char *argv[])
{
    control_request_t req;

    if (argc < 3) {
        fprintf(stderr, "Usage: %s logs <id>\n", argv[0]);
        return 1;
    }

    memset(&req, 0, sizeof(req));
    req.kind = CMD_LOGS;
    strncpy(req.container_id, argv[2], sizeof(req.container_id) - 1);

    return send_control_request(&req);
}

static int cmd_stop(int argc, char *argv[])
{
    control_request_t req;

    if (argc < 3) {
        fprintf(stderr, "Usage: %s stop <id>\n", argv[0]);
        return 1;
    }

    memset(&req, 0, sizeof(req));
    req.kind = CMD_STOP;
    strncpy(req.container_id, argv[2], sizeof(req.container_id) - 1);

    return send_control_request(&req);
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "supervisor") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s supervisor <base-rootfs>\n", argv[0]);
            return 1;
        }
        return run_supervisor(argv[2]);
    }

    if (strcmp(argv[1], "start") == 0)
        return cmd_start(argc, argv);

    if (strcmp(argv[1], "run") == 0)
        return cmd_run(argc, argv);

    if (strcmp(argv[1], "ps") == 0)
        return cmd_ps();

    if (strcmp(argv[1], "logs") == 0)
        return cmd_logs(argc, argv);

    if (strcmp(argv[1], "stop") == 0)
        return cmd_stop(argc, argv);

    usage(argv[0]);
    return 1;
}
