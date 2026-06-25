/*
 * IE2102 - Network Programming Assignment
 * Student: IT24100368
 * Server ID (SID): 1003
 * Port: 50368
 * File: server_0368.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>


/*____configuration__________________*/
#define PORT           50368
#define SID            "1003"
#define REGNO          "IT24100368"
#define MAX_PAYLOAD    4096
#define MAX_BUF        8192
#define TOKEN_EXPIRE   300          /* 5 minutes in seconds   */
#define MAX_FAIL       5            /* lockout after 5 fails  */
#define LOCKOUT_TIME   300          /* 5-minute lockout       */
#define RATE_LIMIT     20           /* max requests per minute*/
#define USER_DB        "/srv/ie2102/IT24100368/users.db"
#define LOG_FILE       "server_IT24100368.log"
#define DATA_DIR       "/srv/ie2102/IT24100368"


/*___per-child session state____________*/
typedef struct {
    char   username[64];
    char   token[65];
    time_t token_issued;
    int    logged_in;
} Session;


/*_____rate-limit tracker (per child)___________*/

static int    req_count    = 0;
static time_t rate_window  = 0;

/*____forward declarations____________*/
static void  sigchld_handler(int s);
static void  log_event(const char *client_ip, int client_port,
                        pid_t pid, const char *username,
                        const char *cmd, const char *result);
static int   recv_all(int fd, char *buf, int len);
static int   send_msg(int fd, const char *msg);
static void  handle_client(int cfd, struct sockaddr_in *cli);

/* password hashing (SHA-256 via /usr/bin/sha256sum) */
static void  hash_password(const char *pass, const char *salt, char *out, size_t outsz);
static void  gen_token(char *out, size_t sz);
static int   validate_username(const char *u);

/* user DB helpers */
static int   user_exists(const char *username);
static int   register_user(const char *username, const char *password);
static int   check_password(const char *username, const char *password);

/* command handlers */
static void  cmd_register(int cfd, Session *sess, char *args,
                           const char *ip, int port);
static void  cmd_login(int cfd, Session *sess, char *args,
                        const char *ip, int port);
static void  cmd_logout(int cfd, Session *sess,
                         const char *ip, int port);


/*______MAIN_____________*/
int main(void)
{
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t cli_len = sizeof(client_addr);
    int opt = 1;

    /*______create data directory_____*/

    mkdir("/srv",              0755);
    mkdir("/srv/ie2102",       0755);
    mkdir(DATA_DIR,            0755);

    /*___SIGCHLD — reap zombie children______*/
    struct sigaction sa;
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGCHLD, &sa, NULL);

    /*____create TCP socket_____*/

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) { perror("socket"); exit(1); }

    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family      = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port        = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&server_addr,
             sizeof(server_addr)) < 0) {
        perror("bind"); exit(1);
    }

    if (listen(server_fd, 20) < 0) { perror("listen"); exit(1); }

    printf("[SID:%s] Server IT24100368 listening on port %d\n", SID, PORT);
    fflush(stdout);


    /* ── accept loop ──────────────────────────────────────── */
    while (1) {
        client_fd = accept(server_fd,
                           (struct sockaddr *)&client_addr, &cli_len);
        if (client_fd < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            continue;
        }

        pid_t pid = fork();
        if (pid < 0) {
            perror("fork");
            close(client_fd);
            continue;
        }
        if (pid == 0) {
            /* child */
            close(server_fd);
            handle_client(client_fd, &client_addr);
            close(client_fd);
            exit(0);
        }
        /* parent */
        close(client_fd);
    }

    close(server_fd);
    return 0;
}


/*____SIGCHLD — avoid zombie processes______*/

static void sigchld_handler(int s)
{
    (void)s;
    int saved_errno = errno;
    while (waitpid(-1, NULL, WNOHANG) > 0);
    errno = saved_errno;
}

/*________LOGGING_________________*/
static void log_event(const char *client_ip, int client_port,
                       pid_t pid, const char *username,
                       const char *cmd, const char *result)
{
    FILE *f = fopen(LOG_FILE, "a");
    if (!f) return;

    time_t now = time(NULL);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&now));

    fprintf(f, "[%s] CLIENT=%s:%d PID=%d USER=%s CMD=%s RESULT=%s\n",
            ts,
            client_ip, client_port,
            (int)pid,
            username[0] ? username : "-",
            cmd, result);
    fclose(f);
}


/*_______network helpers____________*/

/* reliable recv exactly `len` bytes */
static int recv_all(int fd, char *buf, int len)
{
    int total = 0;
    while (total < len) {
        int n = recv(fd, buf + total, len - total, 0);
        if (n <= 0) return n;
        total += n;
    }
    return total;
}

/* send a null-terminated string */
static int send_msg(int fd, const char *msg)
{
    int len = strlen(msg);
    int sent = 0;
    while (sent < len) {
        int n = send(fd, msg + sent, len - sent, 0);
        if (n < 0) return -1;
        sent += n;
    }
    return 0;
}


/*_____TOKEN + USERNAME UTILITIES_____________*/

static void gen_token(char *out, size_t sz)
{
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) { snprintf(out, sz, "STATIC_TOKEN_%ld", time(NULL)); return; }
    unsigned char raw[32];
    fread(raw, 1, sizeof(raw), f);
    fclose(f);
    for (int i = 0; i < 32 && (size_t)(i*2+2) < sz; i++)
        sprintf(out + i*2, "%02x", raw[i]);
    out[64] = '\0';
}

static int validate_username(const char *u)
{
    if (!u || strlen(u) < 3 || strlen(u) > 32) return 0;
    for (const char *p = u; *p; p++)
        if (!isalnum(*p) && *p != '_') return 0;
    return 1;
}



/*_____PASSWORD HASHING  (salt:sha256hex stored in DB________*/
static void hash_password(const char *pass, const char *salt,
                           char *out, size_t outsz)
{
    /* combine salt+password, pipe through sha256sum */
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "printf '%%s%%s' '%s' '%s' | sha256sum | awk '{print $1}'",
             salt, pass);
    FILE *p = popen(cmd, "r");
    if (!p) { snprintf(out, outsz, "ERROR"); return; }
    fgets(out, outsz, p);
    pclose(p);
    /* strip trailing newline */
    out[strcspn(out, "\n")] = '\0';
}


/*______user database (falt file: username:salt:hash_________*/
static int user_exists(const char *username)
{
    FILE *f = fopen(USER_DB, "r");
    if (!f) return 0;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        char *tok = strtok(line, ":");
        if (tok && strcmp(tok, username) == 0) { fclose(f); return 1; }
    }
    fclose(f);
    return 0;
}

static int register_user(const char *username, const char *password)
{
    if (user_exists(username)) return -1;   /* already exists */

    /* generate a random 8-char salt */
    char salt[9];
    FILE *r = fopen("/dev/urandom", "rb");
    if (!r) return -2;
    unsigned char raw[4];
    fread(raw, 1, sizeof(raw), r);
    fclose(r);
    snprintf(salt, sizeof(salt), "%02x%02x%02x%02x",
             raw[0], raw[1], raw[2], raw[3]);

    char hash[128];
    hash_password(password, salt, hash, sizeof(hash));

    /* create per-user data directory */
    char udir[256];
    snprintf(udir, sizeof(udir), "%s/%s", DATA_DIR, username);
    mkdir(udir, 0700);

    FILE *f = fopen(USER_DB, "a");
    if (!f) return -2;
    fprintf(f, "%s:%s:%s\n", username, salt, hash);
    fclose(f);
    return 0;
}

static int check_password(const char *username, const char *password)
{
    FILE *f = fopen(USER_DB, "r");
    if (!f) return 0;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        char tmp[256];
        strncpy(tmp, line, sizeof(tmp));
        tmp[sizeof(tmp)-1] = '\0';

        char *uname = strtok(tmp, ":");
        char *salt  = strtok(NULL, ":");
        char *stored= strtok(NULL, ":\n");

        if (uname && salt && stored &&
            strcmp(uname, username) == 0) {
            fclose(f);
            char computed[128];
            hash_password(password, salt, computed, sizeof(computed));
            return (strcmp(computed, stored) == 0) ? 1 : 0;
        }
    }
    fclose(f);
    return 0;
}

/*_____client handler (run in child process)_________*/


static void handle_client(int cfd, struct sockaddr_in *cli)
{
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &cli->sin_addr, client_ip, sizeof(client_ip));
    int client_port = ntohs(cli->sin_port);
    pid_t mypid = getpid();

    Session sess;
    memset(&sess, 0, sizeof(sess));

    /* brute-force / rate-limit state */
    int   fail_count    = 0;
    time_t locked_until = 0;
    rate_window = time(NULL);

    log_event(client_ip, client_port, mypid, "", "CONNECT", "OK");

    /* ── message receive loop ─────────────────────────────── */
    while (1) {
        /* ── rate limiting ── */
        time_t now = time(NULL);
        if (now - rate_window > 60) {
            rate_window = now;
            req_count   = 0;
        }
        if (req_count >= RATE_LIMIT) {
            char resp[256];
            snprintf(resp, sizeof(resp),
                     "ERR 429 SID:%s Rate limit exceeded\n", SID);
            send_msg(cfd, resp);
            log_event(client_ip, client_port, mypid,
                      sess.username, "RATE_LIMIT", "BLOCKED");
            break;
        }
        req_count++;

        /* ── read LEN:<n>\n header ── */
        char header[64];
        memset(header, 0, sizeof(header));
        int hi = 0;
        char c;
        while (hi < (int)sizeof(header) - 1) {
            int n = recv(cfd, &c, 1, 0);
            if (n <= 0) goto disconnect;
            if (c == '\n') break;
            header[hi++] = c;
        }
        header[hi] = '\0';

        if (strncmp(header, "LEN:", 4) != 0) {
            char resp[128];
            snprintf(resp, sizeof(resp),
                     "ERR 400 SID:%s Invalid framing\n", SID);
            send_msg(cfd, resp);
            log_event(client_ip, client_port, mypid,
                      sess.username, "FRAMING", "INVALID");
            continue;
        }

        int payload_len = atoi(header + 4);

        /* ── reject oversized payload ── */
        if (payload_len <= 0 || payload_len > MAX_PAYLOAD) {
            char resp[128];
            snprintf(resp, sizeof(resp),
                     "ERR 413 SID:%s Payload too large or invalid\n", SID);
            send_msg(cfd, resp);
            log_event(client_ip, client_port, mypid,
                      sess.username, "PAYLOAD_SIZE", "REJECTED");
            /* drain if possible */
            if (payload_len > 0 && payload_len <= 65536) {
                char *drain = malloc(payload_len);
                if (drain) { recv_all(cfd, drain, payload_len); free(drain); }
            }
            continue;
        }

        /* ── recv payload bytes ── */
        char payload[MAX_PAYLOAD + 1];
        memset(payload, 0, sizeof(payload));
        int got = recv_all(cfd, payload, payload_len);
        if (got <= 0) goto disconnect;
        payload[payload_len] = '\0';

        /* ── check token expiry ── */
        if (sess.logged_in) {
            if (time(NULL) - sess.token_issued > TOKEN_EXPIRE) {
                sess.logged_in = 0;
                memset(sess.token, 0, sizeof(sess.token));
                char resp[128];
                snprintf(resp, sizeof(resp),
                         "ERR 401 SID:%s Session expired, please login again\n",
                         SID);
                send_msg(cfd, resp);
                log_event(client_ip, client_port, mypid,
                          sess.username, "TOKEN_EXPIRE", "SESSION_CLEARED");
                continue;
            }
            /* refresh token timer on activity */
            sess.token_issued = time(NULL);
        }

        /* ── parse command ── */
        char cmd[32];
        char args[MAX_PAYLOAD];
        memset(cmd,  0, sizeof(cmd));
        memset(args, 0, sizeof(args));

        char *sp = strchr(payload, ' ');
        if (sp) {
            int clen = sp - payload;
            if (clen >= (int)sizeof(cmd)) clen = sizeof(cmd)-1;
            strncpy(cmd, payload, clen);
            strncpy(args, sp + 1, sizeof(args) - 1);
        } else {
            strncpy(cmd, payload, sizeof(cmd) - 1);
        }

        /* strip trailing newline from args */
        args[strcspn(args, "\n")] = '\0';

        /* ── dispatch ── */
        if (strcmp(cmd, "REGISTER") == 0) {
            cmd_register(cfd, &sess, args, client_ip, client_port);

        } else if (strcmp(cmd, "LOGIN") == 0) {
            /* brute-force lockout */
            if (time(NULL) < locked_until) {
                char resp[128];
                snprintf(resp, sizeof(resp),
                         "ERR 423 SID:%s Account locked due to failed attempts\n",
                         SID);
                send_msg(cfd, resp);
                log_event(client_ip, client_port, mypid,
                          sess.username, "LOGIN", "LOCKED");
                continue;
            }
            /* parse user/pass from args for fail tracking */
            char uarg[64], parg[64];
            memset(uarg, 0, sizeof(uarg));
            memset(parg, 0, sizeof(parg));
            sscanf(args, "%63s %63s", uarg, parg);

            int ok = check_password(uarg, parg);
            if (!ok) {
                fail_count++;
                if (fail_count >= MAX_FAIL) {
                    locked_until = time(NULL) + LOCKOUT_TIME;
                    char resp[128];
                    snprintf(resp, sizeof(resp),
                             "ERR 423 SID:%s Too many failed attempts. Locked for 5 min\n",
                             SID);
                    send_msg(cfd, resp);
                    log_event(client_ip, client_port, mypid,
                              uarg, "LOGIN", "LOCKOUT");
                } else {
                    char resp[128];
                    snprintf(resp, sizeof(resp),
                             "ERR 401 SID:%s Invalid username or password\n", SID);
                    send_msg(cfd, resp);
                    log_event(client_ip, client_port, mypid,
                              uarg, "LOGIN", "FAILED");
                }
            } else {
                fail_count = 0;
                cmd_login(cfd, &sess, args, client_ip, client_port);
            }

        } else if (strcmp(cmd, "LOGOUT") == 0) {
            cmd_logout(cfd, &sess, client_ip, client_port);

        } else if (strcmp(cmd, "QUIT") == 0 ||
                   strcmp(cmd, "EXIT") == 0) {
            char resp[128];
            snprintf(resp, sizeof(resp),
                     "OK 200 SID:%s Goodbye\n", SID);
            send_msg(cfd, resp);
            log_event(client_ip, client_port, mypid,
                      sess.username, cmd, "DISCONNECTED");
            break;

        } else {
            /* unknown command or protected command without token */
            if (!sess.logged_in) {
                char resp[128];
                snprintf(resp, sizeof(resp),
                         "ERR 403 SID:%s Authentication required\n", SID);
                send_msg(cfd, resp);
                log_event(client_ip, client_port, mypid,
                          sess.username, cmd, "AUTH_REQUIRED");
            } else {
                char resp[128];
                snprintf(resp, sizeof(resp),
                         "ERR 400 SID:%s Unknown command\n", SID);
                send_msg(cfd, resp);
                log_event(client_ip, client_port, mypid,
                          sess.username, cmd, "UNKNOWN_CMD");
            }
        }
    }

disconnect:
    log_event(client_ip, client_port, mypid,
              sess.username, "DISCONNECT", "OK");
}


/*_____command implementation______________*/

static void cmd_register(int cfd, Session *sess, char *args,
                          const char *ip, int port)
{
    (void)sess;
    char user[64], pass[128];
    memset(user, 0, sizeof(user));
    memset(pass, 0, sizeof(pass));

    if (sscanf(args, "%63s %127s", user, pass) != 2) {
        char resp[128];
        snprintf(resp, sizeof(resp),
                 "ERR 400 SID:%s Usage: REGISTER <user> <pass>\n", SID);
        send_msg(cfd, resp);
        log_event(ip, port, getpid(), "", "REGISTER", "BAD_ARGS");
        return;
    }

    if (!validate_username(user)) {
        char resp[128];
        snprintf(resp, sizeof(resp),
                 "ERR 400 SID:%s Invalid username (3-32 alphanumeric/_)\n", SID);
        send_msg(cfd, resp);
        log_event(ip, port, getpid(), user, "REGISTER", "INVALID_USER");
        return;
    }

    int result = register_user(user, pass);
    char resp[256];
    if (result == 0) {
        snprintf(resp, sizeof(resp),
                 "OK 201 SID:%s User %s registered successfully\n", SID, user);
        log_event(ip, port, getpid(), user, "REGISTER", "OK");
    } else if (result == -1) {
        snprintf(resp, sizeof(resp),
                 "ERR 409 SID:%s Username already exists\n", SID);
        log_event(ip, port, getpid(), user, "REGISTER", "DUPLICATE");
    } else {
        snprintf(resp, sizeof(resp),
                 "ERR 500 SID:%s Server error during registration\n", SID);
        log_event(ip, port, getpid(), user, "REGISTER", "SERVER_ERROR");
    }
    send_msg(cfd, resp);
}

static void cmd_login(int cfd, Session *sess, char *args,
                       const char *ip, int port)
{
    char user[64], pass[128];
    memset(user, 0, sizeof(user));
    memset(pass, 0, sizeof(pass));

    if (sscanf(args, "%63s %127s", user, pass) != 2) {
        char resp[128];
        snprintf(resp, sizeof(resp),
                 "ERR 400 SID:%s Usage: LOGIN <user> <pass>\n", SID);
        send_msg(cfd, resp);
        log_event(ip, port, getpid(), "", "LOGIN", "BAD_ARGS");
        return;
    }

    /* password already verified by caller */
    strncpy(sess->username, user, sizeof(sess->username) - 1);
    gen_token(sess->token, sizeof(sess->token));
    sess->token_issued = time(NULL);
    sess->logged_in    = 1;

    char resp[256];
    snprintf(resp, sizeof(resp),
             "OK 200 SID:%s Login successful. TOKEN:%s\n",
             SID, sess->token);
    send_msg(cfd, resp);
    log_event(ip, port, getpid(), user, "LOGIN", "OK");
}

static void cmd_logout(int cfd, Session *sess,
                        const char *ip, int port)
{
    char resp[128];
    if (!sess->logged_in) {
        snprintf(resp, sizeof(resp),
                 "ERR 400 SID:%s Not logged in\n", SID);
        send_msg(cfd, resp);
        log_event(ip, port, getpid(), "", "LOGOUT", "NOT_LOGGED_IN");
        return;
    }

    char user[64];
    strncpy(user, sess->username, sizeof(user));

    memset(sess, 0, sizeof(Session));

    snprintf(resp, sizeof(resp),
             "OK 200 SID:%s Logged out successfully\n", SID);
    send_msg(cfd, resp);
    log_event(ip, port, getpid(), user, "LOGOUT", "OK");
}



