#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#ifndef IFA_F_NOPREFIXROUTE
#define IFA_F_NOPREFIXROUTE 0x200
#endif

#define DEFAULT_SOCKET "/run/cmxsafe/endpointd.sock"
#define DEFAULT_IFACE "cmxmirror0"
#define MAX_LINE 256
#define MAX_LEASES 4096U
#define MAX_PEER_LEASES 128U
#define IO_TIMEOUT_SECONDS 5

typedef struct Lease Lease;
struct Lease {
    char address[INET6_ADDRSTRLEN];
    char scope[8];
    pid_t pid;
    uid_t uid;
    gid_t gid;
    unsigned long long starttime;
    Lease *next;
};

typedef struct {
    char iface[IF_NAMESIZE];
    bool dry_run;
    bool iface_created;
    Lease *leases;
    size_t lease_count;
} State;

static volatile sig_atomic_t stopping;

static int delete_interface(const char *name);

static void signal_handler(int signo) {
    (void)signo;
    stopping = 1;
}

static int write_all(int fd, const char *s) {
    size_t left = strlen(s);
    while (left != 0) {
        ssize_t n = write(fd, s, left);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        s += (size_t)n;
        left -= (size_t)n;
    }
    return 0;
}

static void reply_error(int fd, const char *code) {
    char out[192];
    (void)snprintf(out, sizeof(out),
                   "{\"version\":1,\"ok\":false,\"error\":\"%s\"}\n", code);
    (void)write_all(fd, out);
}

static bool valid_scope(const char *scope) {
    return strcmp(scope, "peer") == 0 || strcmp(scope, "self") == 0;
}

static bool normalise_ipv6(const char *input, char output[INET6_ADDRSTRLEN]) {
    struct in6_addr address;
    return inet_pton(AF_INET6, input, &address) == 1 &&
           inet_ntop(AF_INET6, &address, output, INET6_ADDRSTRLEN) != NULL;
}

/* Field 22 of /proc/PID/stat uniquely disambiguates PID reuse for a boot. */
static int process_starttime(pid_t pid, unsigned long long *result) {
    char path[64], line[4096];
    (void)snprintf(path, sizeof(path), "/proc/%ld/stat", (long)pid);
    FILE *stream = fopen(path, "r");
    if (!stream) return -1;
    if (!fgets(line, sizeof(line), stream)) {
        (void)fclose(stream);
        return -1;
    }
    (void)fclose(stream);

    /* comm (field 2) may contain spaces and ')'; parsing starts after its last ')'. */
    char *cursor = strrchr(line, ')');
    if (!cursor || cursor[1] != ' ') return -1;
    cursor += 2;
    for (int field = 3; field <= 22; ++field) {
        char *end = NULL;
        errno = 0;
        unsigned long long value = strtoull(cursor, &end, 10);
        if (field == 3) { /* state is a character, not an integer */
            if (*cursor == '\0' || cursor[1] != ' ') return -1;
            cursor += 2;
            continue;
        }
        if (errno != 0 || end == cursor) return -1;
        if (field == 22) {
            *result = value;
            return 0;
        }
        while (*end == ' ') ++end;
        cursor = end;
    }
    return -1;
}

static bool same_owner(const Lease *lease, const struct ucred *cred,
                       unsigned long long starttime, const char *scope) {
    return lease->pid == cred->pid && lease->uid == cred->uid &&
           lease->gid == cred->gid && lease->starttime == starttime &&
           strcmp(lease->scope, scope) == 0;
}

static bool owner_alive(const Lease *lease) {
    unsigned long long now = 0;
    return process_starttime(lease->pid, &now) == 0 && now == lease->starttime;
}

static int addattr(struct nlmsghdr *header, size_t maximum, int type,
                   const void *data, size_t length) {
    size_t attr_length = RTA_LENGTH(length);
    size_t next = NLMSG_ALIGN(header->nlmsg_len) + RTA_ALIGN(attr_length);
    if (next > maximum) return EMSGSIZE;
    struct rtattr *attribute = (struct rtattr *)((char *)header + NLMSG_ALIGN(header->nlmsg_len));
    attribute->rta_type = (unsigned short)type;
    attribute->rta_len = (unsigned short)attr_length;
    if (length) memcpy(RTA_DATA(attribute), data, length);
    header->nlmsg_len = (unsigned int)next;
    return 0;
}

static int rtnl_talk(struct nlmsghdr *header) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) return errno;
    struct sockaddr_nl local = {.nl_family = AF_NETLINK};
    if (bind(fd, (struct sockaddr *)&local, sizeof(local)) != 0) {
        int error = errno; (void)close(fd); return error;
    }
    struct timeval timeout = {.tv_sec = IO_TIMEOUT_SECONDS};
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0) {
        int error = errno; (void)close(fd); return error;
    }
    static uint32_t sequence;
    header->nlmsg_seq = ++sequence;
    header->nlmsg_flags |= NLM_F_REQUEST | NLM_F_ACK;
    struct sockaddr_nl kernel = {.nl_family = AF_NETLINK};
    struct iovec iov = {.iov_base = header, .iov_len = header->nlmsg_len};
    struct msghdr message = {.msg_name = &kernel, .msg_namelen = sizeof(kernel),
                             .msg_iov = &iov, .msg_iovlen = 1};
    if (sendmsg(fd, &message, 0) < 0) {
        int error = errno; (void)close(fd); return error;
    }
    char buffer[8192];
    for (;;) {
        ssize_t length = recv(fd, buffer, sizeof(buffer), 0);
        if (length < 0 && errno == EINTR) continue;
        if (length < 0) { int error = errno; (void)close(fd); return error; }
        for (struct nlmsghdr *h = (struct nlmsghdr *)buffer;
             NLMSG_OK(h, length); h = NLMSG_NEXT(h, length)) {
            if (h->nlmsg_seq != header->nlmsg_seq) continue;
            if (h->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *error = (struct nlmsgerr *)NLMSG_DATA(h);
                int result = error->error == 0 ? 0 : -error->error;
                (void)close(fd);
                return result;
            }
        }
    }
}

static int create_interface(const char *name) {
    struct { struct nlmsghdr n; struct ifinfomsg i; char data[256]; } request;
    memset(&request, 0, sizeof(request));
    request.n.nlmsg_len = NLMSG_LENGTH(sizeof(request.i));
    request.n.nlmsg_type = RTM_NEWLINK;
    request.n.nlmsg_flags = NLM_F_CREATE | NLM_F_EXCL;
    request.i.ifi_family = AF_UNSPEC;
    int rc = addattr((struct nlmsghdr *)&request, sizeof(request), IFLA_IFNAME, name, strlen(name) + 1);
    if (rc) return rc;
    struct rtattr *nest = (struct rtattr *)((char *)&request.n + NLMSG_ALIGN(request.n.nlmsg_len));
    rc = addattr((struct nlmsghdr *)&request, sizeof(request), IFLA_LINKINFO, NULL, 0);
    if (rc) return rc;
    const char kind[] = "dummy";
    rc = addattr((struct nlmsghdr *)&request, sizeof(request), IFLA_INFO_KIND, kind, sizeof(kind));
    if (rc) return rc;
    nest->rta_len = (unsigned short)((char *)&request + request.n.nlmsg_len - (char *)nest);
    rc = rtnl_talk(&request.n);
    if (rc) return rc; /* EEXIST is deliberately fatal: never adopt an unmanaged link. */

    unsigned int index = if_nametoindex(name);
    if (!index) return ENODEV;
    struct { struct nlmsghdr n; struct ifinfomsg i; } up;
    memset(&up, 0, sizeof(up));
    up.n.nlmsg_len = NLMSG_LENGTH(sizeof(up.i));
    up.n.nlmsg_type = RTM_NEWLINK;
    up.i.ifi_family = AF_UNSPEC;
    up.i.ifi_index = (int)index;
    up.i.ifi_flags = IFF_UP;
    up.i.ifi_change = IFF_UP;
    rc = rtnl_talk(&up.n);
    if (rc != 0) (void)delete_interface(name);
    return rc;
}

static int delete_interface(const char *name) {
    unsigned int index = if_nametoindex(name);
    if (!index) return 0;
    struct { struct nlmsghdr n; struct ifinfomsg i; } request;
    memset(&request, 0, sizeof(request));
    request.n.nlmsg_len = NLMSG_LENGTH(sizeof(request.i));
    request.n.nlmsg_type = RTM_DELLINK;
    request.i.ifi_family = AF_UNSPEC;
    request.i.ifi_index = (int)index;
    return rtnl_talk(&request.n);
}

static int change_address(const char *operation, const char *iface, const char *text) {
    struct in6_addr address;
    if (inet_pton(AF_INET6, text, &address) != 1) return EINVAL;
    unsigned int index = if_nametoindex(iface);
    if (!index) return ENODEV;
    struct { struct nlmsghdr n; struct ifaddrmsg i; char data[128]; } request;
    memset(&request, 0, sizeof(request));
    request.n.nlmsg_len = NLMSG_LENGTH(sizeof(request.i));
    request.n.nlmsg_type = strcmp(operation, "add") == 0 ? RTM_NEWADDR : RTM_DELADDR;
    if (strcmp(operation, "add") == 0) request.n.nlmsg_flags = NLM_F_CREATE | NLM_F_EXCL;
    request.i.ifa_family = AF_INET6;
    request.i.ifa_prefixlen = 128;
    request.i.ifa_scope = RT_SCOPE_UNIVERSE;
    request.i.ifa_index = index;
    uint32_t flags = IFA_F_PERMANENT | IFA_F_NOPREFIXROUTE;
    int rc = addattr((struct nlmsghdr *)&request, sizeof(request), IFA_LOCAL, &address, sizeof(address));
    if (!rc) rc = addattr((struct nlmsghdr *)&request, sizeof(request), IFA_ADDRESS, &address, sizeof(address));
    if (!rc) rc = addattr((struct nlmsghdr *)&request, sizeof(request), IFA_FLAGS, &flags, sizeof(flags));
    return rc ? rc : rtnl_talk(&request.n);
}

static int ensure_iface(State *state) {
    if (state->dry_run || state->iface_created) return 0;
    int rc = create_interface(state->iface);
    if (rc == 0) state->iface_created = true;
    return rc;
}

static size_t address_refs(const State *state, const char *address) {
    size_t count = 0;
    for (const Lease *l = state->leases; l; l = l->next)
        if (strcmp(l->address, address) == 0) ++count;
    return count;
}

static size_t peer_refs(const State *state, const struct ucred *cred,
                        unsigned long long starttime) {
    size_t count = 0;
    for (const Lease *l = state->leases; l; l = l->next)
        if (l->pid == cred->pid && l->uid == cred->uid && l->gid == cred->gid &&
            l->starttime == starttime) ++count;
    return count;
}

static Lease *find_lease(State *state, const struct ucred *cred,
                         unsigned long long starttime, const char *scope,
                         const char *address) {
    for (Lease *l = state->leases; l; l = l->next)
        if (same_owner(l, cred, starttime, scope) && strcmp(l->address, address) == 0) return l;
    return NULL;
}

static void ensure_address(State *state, int fd, const struct ucred *cred,
                           unsigned long long starttime, const char *scope,
                           const char *address) {
    Lease *existing = find_lease(state, cred, starttime, scope, address);
    if (existing) {
        char out[192];
        (void)snprintf(out, sizeof(out),
            "{\"version\":1,\"ok\":true,\"created\":false,\"scope\":\"%s\",\"ipv6\":\"%s\",\"refcount\":%zu}\n",
            scope, address, address_refs(state, address));
        (void)write_all(fd, out);
        return;
    }
    if (state->lease_count >= MAX_LEASES) { reply_error(fd, "lease_limit"); return; }
    if (peer_refs(state, cred, starttime) >= MAX_PEER_LEASES) { reply_error(fd, "peer_lease_limit"); return; }
    Lease *lease = calloc(1, sizeof(*lease));
    if (!lease) { reply_error(fd, "out_of_memory"); return; }
    (void)snprintf(lease->address, sizeof(lease->address), "%s", address);
    (void)snprintf(lease->scope, sizeof(lease->scope), "%s", scope);
    lease->pid = cred->pid; lease->uid = cred->uid; lease->gid = cred->gid;
    lease->starttime = starttime;

    int rc = ensure_iface(state);
    bool first = address_refs(state, address) == 0;
    if (rc == 0 && first && !state->dry_run) rc = change_address("add", state->iface, address);
    if (rc != 0) {
        free(lease); /* State is unchanged when the kernel operation fails. */
        reply_error(fd, rc == EEXIST ? "address_not_managed" : "netlink_add_failed");
        return;
    }
    lease->next = state->leases;
    state->leases = lease;
    ++state->lease_count;
    char out[192];
    (void)snprintf(out, sizeof(out),
        "{\"version\":1,\"ok\":true,\"created\":true,\"scope\":\"%s\",\"ipv6\":\"%s\",\"refcount\":%zu}\n",
        scope, address, address_refs(state, address));
    (void)write_all(fd, out);
}

static void release_address(State *state, int fd, const struct ucred *cred,
                            unsigned long long starttime, const char *scope,
                            const char *address) {
    Lease **cursor = &state->leases;
    while (*cursor && !(same_owner(*cursor, cred, starttime, scope) &&
                        strcmp((*cursor)->address, address) == 0)) cursor = &(*cursor)->next;
    if (!*cursor) { reply_error(fd, "not_owner"); return; }
    size_t refs = address_refs(state, address);
    if (refs == 1 && !state->dry_run) {
        int rc = change_address("del", state->iface, address);
        if (rc != 0) { reply_error(fd, "netlink_delete_failed"); return; }
    }
    Lease *removed = *cursor;
    *cursor = removed->next;
    free(removed);
    --state->lease_count;
    char out[192];
    (void)snprintf(out, sizeof(out),
        "{\"version\":1,\"ok\":true,\"released\":true,\"scope\":\"%s\",\"ipv6\":\"%s\",\"refcount\":%zu}\n",
        scope, address, refs - 1);
    (void)write_all(fd, out);
}

static void reap_dead(State *state) {
    Lease **cursor = &state->leases;
    while (*cursor) {
        Lease *lease = *cursor;
        if (owner_alive(lease)) { cursor = &lease->next; continue; }
        size_t refs = address_refs(state, lease->address);
        if (refs == 1 && !state->dry_run && change_address("del", state->iface, lease->address) != 0) {
            cursor = &lease->next; /* Preserve state so a later reap can retry. */
            continue;
        }
        *cursor = lease->next;
        free(lease);
        --state->lease_count;
    }
}

static int read_frame(int fd, char line[MAX_LINE]) {
    size_t used = 0;
    for (;;) {
        char byte;
        ssize_t n = read(fd, &byte, 1);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return n == 0 ? -2 : -1;
        if (byte == '\n') { line[used] = '\0'; return 0; }
        if (byte == '\r' || byte == '\0') return -3;
        if (used + 1 >= MAX_LINE) return -4;
        line[used++] = byte;
    }
}

static void handle_client(State *state, int fd) {
    struct timeval timeout = {.tv_sec = IO_TIMEOUT_SECONDS};
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    struct ucred cred;
    socklen_t length = sizeof(cred);
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &length) != 0 || length != sizeof(cred)) {
        reply_error(fd, "peer_credentials_unavailable"); return;
    }
    unsigned long long starttime = 0;
    if (process_starttime(cred.pid, &starttime) != 0) { reply_error(fd, "peer_identity_unavailable"); return; }
    char line[MAX_LINE];
    int frame = read_frame(fd, line);
    if (frame != 0) { reply_error(fd, frame == -4 ? "frame_too_large" : "invalid_frame"); return; }

    char *parts[5] = {0};
    size_t count = 0;
    char *save = NULL;
    for (char *p = strtok_r(line, " \t", &save); p && count < 5; p = strtok_r(NULL, " \t", &save))
        parts[count++] = p;
    size_t offset = count > 0 && strcmp(parts[0], "v1") == 0 ? 1U : 0U;
    if (count == offset + 1 && strcmp(parts[offset], "ping") == 0) {
        (void)write_all(fd, "{\"version\":1,\"ok\":true}\n"); return;
    }
    if (count != offset + 3 ||
        (strcmp(parts[offset], "ensure") != 0 && strcmp(parts[offset], "release") != 0) ||
        !valid_scope(parts[offset + 1])) {
        reply_error(fd, "invalid_request"); return;
    }
    char address[INET6_ADDRSTRLEN];
    if (!normalise_ipv6(parts[offset + 2], address)) { reply_error(fd, "invalid_ipv6"); return; }
    if (strcmp(parts[offset], "ensure") == 0)
        ensure_address(state, fd, &cred, starttime, parts[offset + 1], address);
    else
        release_address(state, fd, &cred, starttime, parts[offset + 1], address);
}

static int safe_socket_path(const char *path) {
    if (!path || path[0] != '/' || strlen(path) >= sizeof(((struct sockaddr_un *)0)->sun_path)) return -1;
    struct stat st;
    /* Never unlink a live or stale pathname implicitly; an administrator must
     * resolve it. This also closes the lstat/unlink replacement race. */
    if (lstat(path, &st) == 0) return -1;
    return errno == ENOENT ? 0 : -1;
}

static int serve(const char *socket_path, const char *iface, bool dry_run) {
    if (safe_socket_path(socket_path) != 0) { fputs("unsafe socket path\n", stderr); return 1; }
    if (strlen(iface) == 0 || strlen(iface) >= IF_NAMESIZE || strchr(iface, '/')) {
        fputs("invalid interface name\n", stderr); return 1;
    }
    struct stat parent;
    char directory[sizeof(((struct sockaddr_un *)0)->sun_path)];
    (void)snprintf(directory, sizeof(directory), "%s", socket_path);
    char *slash = strrchr(directory, '/');
    if (!slash) return 1;
    if (slash == directory) slash[1] = '\0'; else *slash = '\0';
    if (stat(directory, &parent) != 0 || !S_ISDIR(parent.st_mode) ||
        (parent.st_mode & 0022) != 0 || (parent.st_uid != 0 && parent.st_uid != geteuid())) {
        fputs("socket parent must be trusted, owned, and not group/world-writable\n", stderr); return 1;
    }

    mode_t old_umask = umask(0077);
    int server = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (server < 0) { perror("socket"); return 1; }
    struct sockaddr_un address;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    (void)snprintf(address.sun_path, sizeof(address.sun_path), "%s", socket_path);
    if (bind(server, (struct sockaddr *)&address, sizeof(address)) != 0) {
        perror("bind"); (void)close(server); return 1;
    }
    (void)umask(old_umask);
    if (chmod(socket_path, 0660) != 0 || listen(server, 32) != 0) {
        perror("socket setup"); (void)close(server); (void)unlink(socket_path); return 1;
    }

    State state = {.dry_run = dry_run};
    (void)snprintf(state.iface, sizeof(state.iface), "%s", iface);
    signal(SIGINT, signal_handler); signal(SIGTERM, signal_handler); signal(SIGPIPE, SIG_IGN);
    time_t last_reap = time(NULL);
    while (!stopping) {
        struct pollfd pfd = {.fd = server, .events = POLLIN};
        int ready = poll(&pfd, 1, 1000);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0) { perror("poll"); break; }
        time_t now = time(NULL);
        if (now - last_reap >= 5) { reap_dead(&state); last_reap = now; }
        if (!ready) continue;
        int client = accept4(server, NULL, NULL, SOCK_CLOEXEC);
        if (client < 0) { if (errno != EINTR) perror("accept"); continue; }
        handle_client(&state, client);
        (void)close(client);
    }
    while (state.leases) {
        Lease *next = state.leases->next;
        if (address_refs(&state, state.leases->address) == 1 && !dry_run)
            (void)change_address("del", state.iface, state.leases->address);
        free(state.leases); state.leases = next;
    }
    if (state.iface_created) (void)delete_interface(state.iface);
    (void)close(server); (void)unlink(socket_path);
    return 0;
}

int main(int argc, char **argv) {
    const char *socket_path = DEFAULT_SOCKET;
    const char *iface = DEFAULT_IFACE;
    bool dry_run = false;
    if (argc < 2 || strcmp(argv[1], "serve") != 0) {
        fprintf(stderr, "usage: %s serve [--socket PATH] [--iface NAME] [--dry-run]\n", argv[0]);
        return 2;
    }
    for (int i = 2; i < argc; ++i) {
        if (strcmp(argv[i], "--socket") == 0 && i + 1 < argc) socket_path = argv[++i];
        else if (strcmp(argv[i], "--iface") == 0 && i + 1 < argc) iface = argv[++i];
        else if (strcmp(argv[i], "--dry-run") == 0) dry_run = true;
        else { fprintf(stderr, "unknown or incomplete option: %s\n", argv[i]); return 2; }
    }
    return serve(socket_path, iface, dry_run);
}
