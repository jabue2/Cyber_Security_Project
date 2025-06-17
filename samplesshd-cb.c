/*
  samplesshd-cb.c  (modified for libssh-0.7.4)
  This example shows a minimal “pty + shell” server.
*/

#include "config.h"

#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/callbacks.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pty.h>
#include <utmp.h>
#include <pwd.h>
#include <grp.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <errno.h>

#ifndef KEYS_FOLDER
#ifdef _WIN32
#define KEYS_FOLDER
#else
#define KEYS_FOLDER "/etc/ssh/"
#endif
#endif

#define USER "myuser"
#define PASSWORD "mypassword"
#define WORKDIR "/srv/sandbox-work"

static int authenticated = 0;
static int tries         = 0;
static int error_flag    = 0;

static int shell_started = 0;

static ssh_channel chan = NULL;

static int pty_master    = -1;
static int pty_slave     = -1;
static pid_t shell_pid   = -1;

static int auth_password(ssh_session session, const char *user,
                         const char *password, void *userdata)
{
    (void)userdata;
    printf("Authenticating user %s pwd %s\n", user, password);
    if (strcmp(user, USER) == 0 && strcmp(password, PASSWORD) == 0) {
        authenticated = 1;
        printf("Authenticated via password.\n");
        return SSH_AUTH_SUCCESS;
    }
    if (tries >= 3) {
        printf("Too many authentication tries. Disconnecting.\n");
        ssh_disconnect(session);
        error_flag = 1;
        return SSH_AUTH_DENIED;
    }
    tries++;
    return SSH_AUTH_DENIED;
}

static int pty_request(ssh_session session, ssh_channel channel,
                       const char *term, int x, int y, int px, int py,
                       void *userdata)
{
    (void)session;
    (void)userdata;

    struct winsize ws;

    int rc;

    ws.ws_col    = x;
    ws.ws_row    = y;
    ws.ws_xpixel = px;
    ws.ws_ypixel = py;

    /* 1) Allocate a new pty pair: master & slave */
    rc = openpty(&pty_master, &pty_slave, NULL, NULL, &ws);
    if (rc < 0) {
        perror("openpty");
        return SSH_ERROR;
    }

    printf("Allocated pty → master=%d, slave=%d, term=%s, cols=%d, rows=%d\n",
           pty_master, pty_slave, term, x, y);

    return SSH_OK;
}

static int shell_request(ssh_session session, ssh_channel channel, void *userdata)
{
    (void)session;
    (void)userdata;

    pid_t pid;

    /* Ensure that pty_slave was set by pty_request() */
    if (pty_slave < 0) {
        fprintf(stderr, "Error: shell_request called before pty_request!\n");
        return SSH_ERROR;
    }

    pid = fork();
    if (pid < 0) {
        perror("fork");
        close(pty_slave);
        close(pty_master);
        return SSH_ERROR;
    }
    if (pid == 0) {
        /* Child → become the shell process on the pty_slave */

        /* 1) Create new session & set controlling tty */
        if (setsid() < 0) {
            perror("setsid");
            _exit(1);
        }
        if (ioctl(pty_slave, TIOCSCTTY, 0) < 0) {
            perror("ioctl(TIOCSCTTY)");
            _exit(1);
        }

        /* 2) Dup slave → stdin/stdout/stderr */
        dup2(pty_slave, STDIN_FILENO);
        dup2(pty_slave, STDOUT_FILENO);
        dup2(pty_slave, STDERR_FILENO);
        if (pty_slave > STDERR_FILENO) {
            close(pty_slave);
        }
        close(pty_master);

        /* 3) Drop into an unprivileged sandbox user and exec /bin/sh */
	struct passwd *pw = getpwnam("sandbox");
	if (!pw) {
    	    perror("getpwnam");
	    _exit(1);
	}

	/* Permanently shed root */
	if (setgid(pw->pw_gid) < 0 ||
	    initgroups(pw->pw_name, pw->pw_gid) < 0 ||
	    setuid(pw->pw_uid) < 0) {
	    perror("priv-drop");
	    _exit(1);
	}

	if (chdir(WORKDIR) < 0) {
    	    perror("chdir workdir");
	    _exit(1);
	}

	/* Launch the shell */
	execl("/bin/sh", "sh", NULL);
	perror("execl");
	_exit(1);
    }

    /* Parent continues here: track child PID & close our copy of slave */
    shell_pid = pid;
    close(pty_slave);
    printf("Forked shell (pid=%d) on pty_master=%d\n", (int)shell_pid, pty_master);
    shell_started = 1;
    return SSH_OK;
}

static struct ssh_channel_callbacks_struct channel_cb = {
    .channel_pty_request_function   = pty_request,
    .channel_shell_request_function = shell_request
};

static ssh_channel new_session_channel(ssh_session session, void *userdata)
{
    (void)userdata;

    if (chan != NULL) {
        return NULL;
    }
    printf("Allocated session channel\n");
    chan = ssh_channel_new(session);
    ssh_callbacks_init(&channel_cb);
    ssh_set_channel_callbacks(chan, &channel_cb);
    return chan;
}

/*  main(): bind, accept, authenticate, I/O  */

int main(int argc, char **argv)
{
    ssh_session session;
    ssh_bind sshbind;
    ssh_event mainloop;
    int port = 22;
    int r;

    struct ssh_server_callbacks_struct cb = {
        .userdata                              = NULL,
        .auth_password_function                = auth_password,
        .channel_open_request_session_function = new_session_channel
    };

    /* Parse “-p” argument, if given */
    if (argc == 3 && strcmp(argv[1], "-p") == 0) {
        port = atoi(argv[2]);
    } else if (argc != 1) {
        fprintf(stderr, "Usage: %s [-p port]\n", argv[0]);
        return 1;
    }

    /* 1) Create sshbind + session */
    sshbind = ssh_bind_new();
    session = ssh_new();

    /* 2) Load hostkeys */
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_DSAKEY,
                         KEYS_FOLDER "ssh_host_dsa_key");
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY,
                         KEYS_FOLDER "ssh_host_rsa_key");

    /* 3) Bind to 0.0.0.0:port */
    {
        char portstr[6];
        snprintf(portstr, sizeof(portstr), "%d", port);
        ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDADDR, "0.0.0.0");
        ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT_STR, portstr);
    }

     if (ssh_bind_listen(sshbind) < 0) {
        fprintf(stderr, "Error listening to socket: %s\n", ssh_get_error(sshbind));
        return 1;
    }

    /* 4) Accept exactly one incoming connection */
    if (ssh_bind_accept(sshbind, session) == SSH_ERROR) {
        fprintf(stderr, "Error accepting: %s\n", ssh_get_error(sshbind));
        return 1;
    }

    /* 5) Install auth + channel callbacks */
    ssh_callbacks_init(&cb);
    ssh_set_server_callbacks(session, &cb);

    /* 6) Do key exchange */
    if (ssh_handle_key_exchange(session)) {
        fprintf(stderr, "Key exchange failed: %s\n", ssh_get_error(session));
        return 1;
    }

    /* 7) Allow only password */
    ssh_set_auth_methods(session, SSH_AUTH_METHOD_PASSWORD);

    /* 8) Create event loop and add the session */
    mainloop = ssh_event_new();
    ssh_event_add_session(mainloop, session);

    /*
     *  9) Wait *not just* for authentication + channel open, but also
     *  for shell_request() to fire (i.e. for shell_started == 1).
     */
    while (!(chan != NULL && shell_started)) {
        if (error_flag) {
            fprintf(stderr, "Error flag set; exiting.\n");
            break;
        }
        r = ssh_event_dopoll(mainloop, -1);
        if (r == SSH_ERROR) {
            fprintf(stderr, "Error in ssh_event_dopoll: %s\n", ssh_get_error(session));
            ssh_disconnect(session);
            return 1;
        }
        /* Loop repeats until:
           authenticated == 1  AND  chan != NULL  AND  shell_started == 1
        */
        fprintf(stdout, "Chan: %p, shell_started: %d\n", (void*)chan, shell_started);
    }
    printf("Out of Loop");

    if (error_flag) {
        fprintf(stderr, "Aborting because error_flag was set\n");
    } else {
        printf("Authenticated, channel opened, and shell started. Entering I/O loop.\n");
    }

    if (pty_master < 0 || chan == NULL) {
        fprintf(stderr, "No pty or no channel; exiting.\n");
        ssh_disconnect(session);
        ssh_bind_free(sshbind);
        ssh_finalize();
        return 1;
    }

    while (1) {
        fd_set readfds;
        int maxfd;
        int sockfd = ssh_get_fd(session);

        FD_ZERO(&readfds);
        FD_SET(pty_master, &readfds);
        FD_SET(sockfd, &readfds);

        maxfd = (pty_master > sockfd) ? pty_master : sockfd;

        if (ssh_channel_is_eof(chan)) {
            break;
        }

        if (select(maxfd + 1, &readfds, NULL, NULL, NULL) < 0) {
            if (errno == EINTR) continue;
            perror("select");
            break;
        }

        /* (a) Data from the shell’s pty → SSH channel → client */
        if (FD_ISSET(pty_master, &readfds)) {
            char buf[2048];
            ssize_t nread = read(pty_master, buf, sizeof(buf));
            if (nread > 0) {
                ssh_channel_write(chan, buf, nread);
            } else {
                break;
            }
        }

        /* (b) Data from SSH socket → channel → pty_master → shell stdin */
        if (FD_ISSET(sockfd, &readfds)) {
            char buf[2048];
            ssize_t nread = ssh_channel_read(chan, buf, sizeof(buf), 0);
            if (nread > 0) {
                write(pty_master, buf, nread);
            } else {
                break;
            }
        }
    }

    /* 10) Cleanup: wait for shell child, close fds, free libssh resources */
    if (shell_pid > 0) {
        int status;
        waitpid(shell_pid, &status, 0);
    }
    close(pty_master);

    ssh_disconnect(session);
    ssh_bind_free(sshbind);
    ssh_finalize();
    return 0;
}