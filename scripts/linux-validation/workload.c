/* Benign, bounded native Linux workload; no audit policy or privilege changes. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

static void require(int condition, const char *operation) {
    if (!condition) { perror(operation); exit(1); }
}

static void record(const char *kind, long number, long result,
                   const char *path, const char *address) {
    printf("{\"kind\":\"%s\",\"pid\":%ld,\"syscall\":%ld,"
           "\"exit\":%ld,\"success\":%s,\"path\":\"%s\",\"saddr\":\"%s\"}\n",
           kind, (long)getpid(), number, result, result >= 0 ? "true" : "false",
           path, address);
    require(fflush(stdout) == 0, "flush ground truth");
}

int main(int argc, char **argv) {
    require(argc == 2, "expected a fresh workload directory");
    /* The runner supplies a fresh directory; reject characters needing JSON escaping. */
    require(strpbrk(argv[1], "\"\\\n\r\t") == NULL, "unsupported directory characters");
    require(chdir(argv[1]) == 0, "chdir");
    long fd = syscall(SYS_openat, AT_FDCWD, "created.txt", O_CREAT | O_EXCL | O_WRONLY, 0600);
    require(fd >= 0, "create");
    record("create", SYS_openat, fd, "created.txt", "");
    require(write((int)fd, "benign-validation\n", 18) == 18, "write");
    require(close((int)fd) == 0, "close");
    long result = syscall(SYS_renameat, AT_FDCWD, "created.txt", AT_FDCWD, "renamed.txt");
    require(result == 0, "rename");
    record("rename", SYS_renameat, result, "renamed.txt", "");
    errno = 0;
    result = syscall(SYS_openat, AT_FDCWD, "missing.txt", O_RDONLY, 0);
    require(result == -1 && errno == ENOENT, "expected missing-file failure");
    record("missing", SYS_openat, -ENOENT, "missing.txt", "");

    int server = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    require(server >= 0, "server socket");
    struct sockaddr_in address = { .sin_family = AF_INET, .sin_port = 0 };
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    require(bind(server, (struct sockaddr *)&address, sizeof(address)) == 0, "loopback bind");
    require(listen(server, 1) == 0, "listen");
    socklen_t length = sizeof(address);
    require(getsockname(server, (struct sockaddr *)&address, &length) == 0, "getsockname");
    int client = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    require(client >= 0, "client socket");
    result = syscall(SYS_connect, client, &address, sizeof(address));
    require(result == 0, "loopback connect");
    char hex[sizeof(address) * 2 + 1];
    const unsigned char *bytes = (const unsigned char *)&address;
    for (size_t i = 0; i < sizeof(address); ++i) snprintf(hex + i * 2, 3, "%02x", bytes[i]);
    record("connect", SYS_connect, result, "", hex);
    int accepted = accept4(server, NULL, NULL, SOCK_CLOEXEC);
    require(accepted >= 0, "accept");
    require(close(accepted) == 0 && close(client) == 0 && close(server) == 0, "socket close");

    /* Set all IDs to their already-current value; never request another identity. */
    uid_t current = getuid();
    require(current == geteuid(), "real/effective uid mismatch");
    result = syscall(SYS_setresuid, current, current, current);
    require(result == 0, "same-uid setresuid");
    record("same_uid", SYS_setresuid, result, "", "");
    result = syscall(SYS_unlinkat, AT_FDCWD, "renamed.txt", 0);
    require(result == 0, "unlink");
    record("unlink", SYS_unlinkat, result, "renamed.txt", "");
    return 0;
}
