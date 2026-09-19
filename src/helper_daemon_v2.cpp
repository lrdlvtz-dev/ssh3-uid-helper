#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "protocol.h"

#include <arpa/inet.h>
#include <endian.h>
#include <fcntl.h>
#include <grp.h>
#include <netinet/in.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <cctype>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using cmxsafe::ssh3_helper::Operation;
using cmxsafe::ssh3_helper::RequestV1;
using cmxsafe::ssh3_helper::ResponseV1;
using cmxsafe::ssh3_helper::Status;
using cmxsafe::ssh3_helper::kMagic;
using cmxsafe::ssh3_helper::kMinServicePort;
using cmxsafe::ssh3_helper::kVersion;

struct Fd {
    int value = -1;
    Fd() = default;
    explicit Fd(int fd) : value(fd) {}
    ~Fd() {
        if (value >= 0) {
            close(value);
        }
    }
    Fd(const Fd &) = delete;
    Fd &operator=(const Fd &) = delete;
    Fd(Fd &&other) noexcept : value(other.value) { other.value = -1; }
    Fd &operator=(Fd &&other) noexcept {
        if (this != &other) {
            if (value >= 0) {
                close(value);
            }
            value = other.value;
            other.value = -1;
        }
        return *this;
    }
    int release() {
        int result = value;
        value = -1;
        return result;
    }
    explicit operator bool() const { return value >= 0; }
};

struct Config {
    std::string socket_path = "/run/ssh3-helper/helper.sock";
    std::string socket_group = "ssh3-helper";
    uid_t allowed_uid = 0;
    unsigned int max_children = 64;
    int request_timeout_ms = 3000;
    int connect_timeout_ms = 5000;
};

struct Identity {
    uid_t uid = 0;
    gid_t gid = 0;
    std::string username;
    in6_addr source{};
};

volatile sig_atomic_t g_active_children = 0;

void reap_children(int) {
    int saved_errno = errno;
    while (waitpid(-1, nullptr, WNOHANG) > 0) {
        if (g_active_children > 0) {
            --g_active_children;
        }
    }
    errno = saved_errno;
}

unsigned long parse_unsigned(const char *value, const char *name, unsigned long max) {
    char *end = nullptr;
    errno = 0;
    unsigned long parsed = std::strtoul(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0' || parsed > max) {
        throw std::runtime_error(std::string("invalid ") + name);
    }
    return parsed;
}

Config parse_args(int argc, char **argv) {
    Config config;
    for (int i = 1; i < argc; ++i) {
        auto require_value = [&](const char *option) -> const char * {
            if (++i >= argc) {
                throw std::runtime_error(std::string("missing value for ") + option);
            }
            return argv[i];
        };
        std::string arg = argv[i];
        if (arg == "--socket") {
            config.socket_path = require_value("--socket");
        } else if (arg == "--socket-group") {
            config.socket_group = require_value("--socket-group");
        } else if (arg == "--allowed-uid") {
            config.allowed_uid = static_cast<uid_t>(
                parse_unsigned(require_value("--allowed-uid"), "allowed uid", std::numeric_limits<uid_t>::max()));
        } else if (arg == "--max-children") {
            config.max_children = static_cast<unsigned int>(
                parse_unsigned(require_value("--max-children"), "max children", 4096));
            if (config.max_children == 0) {
                throw std::runtime_error("max children must be greater than zero");
            }
        } else if (arg == "--request-timeout-ms") {
            config.request_timeout_ms = static_cast<int>(
                parse_unsigned(require_value("--request-timeout-ms"), "request timeout", 60000));
            if (config.request_timeout_ms == 0) {
                throw std::runtime_error("request timeout must be greater than zero");
            }
        } else if (arg == "--connect-timeout-ms") {
            config.connect_timeout_ms = static_cast<int>(
                parse_unsigned(require_value("--connect-timeout-ms"), "connect timeout", 60000));
            if (config.connect_timeout_ms == 0) {
                throw std::runtime_error("connect timeout must be greater than zero");
            }
        } else {
            throw std::runtime_error("unknown option: " + arg);
        }
    }
    sockaddr_un path_limit{};
    if (config.socket_path.empty() || config.socket_path.size() >= sizeof(path_limit.sun_path)) {
        throw std::runtime_error("invalid Unix socket path");
    }
    return config;
}

timeval milliseconds_to_timeval(int milliseconds) {
    timeval value{};
    value.tv_sec = milliseconds / 1000;
    value.tv_usec = (milliseconds % 1000) * 1000;
    return value;
}

void set_io_timeout(int fd, int milliseconds) {
    timeval timeout = milliseconds_to_timeval(milliseconds);
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0 ||
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0) {
        throw std::runtime_error("failed to set IPC timeout");
    }
}

bool canonical_username_to_ipv6(const std::string &username, in6_addr *address) {
    if (username.size() != 32) {
        return false;
    }
    for (unsigned char ch : username) {
        if (!std::isdigit(ch) && !(ch >= 'a' && ch <= 'f')) {
            return false;
        }
    }
    std::string rendered;
    rendered.reserve(39);
    for (std::size_t offset = 0; offset < username.size(); offset += 4) {
        if (!rendered.empty()) {
            rendered.push_back(':');
        }
        rendered.append(username, offset, 4);
    }
    if (inet_pton(AF_INET6, rendered.c_str(), address) != 1) {
        return false;
    }
    return !IN6_IS_ADDR_UNSPECIFIED(address) && !IN6_IS_ADDR_LOOPBACK(address) &&
           !IN6_IS_ADDR_MULTICAST(address) && !IN6_IS_ADDR_V4MAPPED(address) &&
           !IN6_IS_ADDR_LINKLOCAL(address);
}

bool resolve_identity(uid_t uid, Identity *identity) {
    long hint = sysconf(_SC_GETPW_R_SIZE_MAX);
    std::size_t buffer_size = hint > 0 ? static_cast<std::size_t>(hint) : 16384;
    std::vector<char> buffer(buffer_size);
    passwd entry{};
    passwd *result = nullptr;
    int rc = getpwuid_r(uid, &entry, buffer.data(), buffer.size(), &result);
    if (rc != 0 || result == nullptr || result->pw_name == nullptr) {
        return false;
    }
    Identity resolved;
    resolved.uid = uid;
    resolved.gid = result->pw_gid;
    resolved.username = result->pw_name;
    if (!canonical_username_to_ipv6(resolved.username, &resolved.source)) {
        return false;
    }
    *identity = resolved;
    return true;
}

bool drop_privileges(const Identity &identity) {
    if (prctl(PR_SET_KEEPCAPS, 0L, 0L, 0L, 0L) < 0 ||
        setgroups(0, nullptr) < 0 ||
        setresgid(identity.gid, identity.gid, identity.gid) < 0 ||
        setresuid(identity.uid, identity.uid, identity.uid) < 0 ||
        prctl(PR_SET_NO_NEW_PRIVS, 1L, 0L, 0L, 0L) < 0) {
        return false;
    }
    uid_t real_uid = 0, effective_uid = 0, saved_uid = 0;
    gid_t real_gid = 0, effective_gid = 0, saved_gid = 0;
    if (getresuid(&real_uid, &effective_uid, &saved_uid) < 0 ||
        getresgid(&real_gid, &effective_gid, &saved_gid) < 0) {
        return false;
    }
    return real_uid == identity.uid && effective_uid == identity.uid && saved_uid == identity.uid &&
           real_gid == identity.gid && effective_gid == identity.gid && saved_gid == identity.gid;
}

ResponseV1 make_response(Status status, std::uint64_t request_id, int system_errno) {
    ResponseV1 response{};
    response.magic = htonl(kMagic);
    response.version = htons(kVersion);
    response.status = htons(static_cast<std::uint16_t>(status));
    response.request_id = htobe64(request_id);
    response.system_errno = htonl(static_cast<std::uint32_t>(system_errno));
    return response;
}

bool send_response(int client_fd, const ResponseV1 &response, int passed_fd = -1) {
    iovec iov{const_cast<ResponseV1 *>(&response), sizeof(response)};
    msghdr message{};
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    char control[CMSG_SPACE(sizeof(int))]{};
    if (passed_fd >= 0) {
        message.msg_control = control;
        message.msg_controllen = sizeof(control);
        cmsghdr *header = CMSG_FIRSTHDR(&message);
        header->cmsg_level = SOL_SOCKET;
        header->cmsg_type = SCM_RIGHTS;
        header->cmsg_len = CMSG_LEN(sizeof(int));
        std::memcpy(CMSG_DATA(header), &passed_fd, sizeof(passed_fd));
    }
    ssize_t sent = sendmsg(client_fd, &message, MSG_NOSIGNAL);
    return sent == static_cast<ssize_t>(sizeof(response));
}

bool peer_is_authorized(int client_fd, uid_t allowed_uid) {
    ucred credentials{};
    socklen_t size = sizeof(credentials);
    if (getsockopt(client_fd, SOL_SOCKET, SO_PEERCRED, &credentials, &size) < 0 || size != sizeof(credentials)) {
        return false;
    }
    return credentials.uid == allowed_uid;
}

Status receive_request(int client_fd, RequestV1 *request, std::uint64_t *request_id, Fd *received_fd) {
    char packet[sizeof(RequestV1)]{};
    char control[CMSG_SPACE(sizeof(int) * 2)]{};
    iovec iov{packet, sizeof(packet)};
    msghdr message{};
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    message.msg_control = control;
    message.msg_controllen = sizeof(control);
    ssize_t received = recvmsg(client_fd, &message, MSG_TRUNC | MSG_CMSG_CLOEXEC);
    Fd incoming;
    bool ancillary_valid = true;
    for (cmsghdr *header = CMSG_FIRSTHDR(&message); header != nullptr;
         header = CMSG_NXTHDR(&message, header)) {
        if (header->cmsg_level != SOL_SOCKET || header->cmsg_type != SCM_RIGHTS ||
            header->cmsg_len != CMSG_LEN(sizeof(int)) || incoming) {
            if (header->cmsg_level == SOL_SOCKET && header->cmsg_type == SCM_RIGHTS &&
                header->cmsg_len >= CMSG_LEN(sizeof(int))) {
                const std::size_t count =
                    (header->cmsg_len - CMSG_LEN(0)) / sizeof(int);
                const int *descriptors = reinterpret_cast<const int *>(CMSG_DATA(header));
                for (std::size_t index = 0; index < count; ++index) {
                    close(descriptors[index]);
                }
            }
            ancillary_valid = false;
            continue;
        }
        int passed_fd = -1;
        std::memcpy(&passed_fd, CMSG_DATA(header), sizeof(passed_fd));
        incoming = Fd(passed_fd);
    }
    if (received != static_cast<ssize_t>(sizeof(RequestV1)) ||
        (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) != 0 || !ancillary_valid) {
        return Status::kMalformed;
    }
    std::memcpy(request, packet, sizeof(*request));
    *request_id = be64toh(request->request_id);
    if (ntohl(request->magic) != kMagic || ntohs(request->version) != kVersion ||
        ntohs(request->reserved) != 0) {
        return Status::kMalformed;
    }
    const auto operation = static_cast<Operation>(ntohs(request->operation));
    if (operation != Operation::kConnectTcp && operation != Operation::kConnectUdp &&
        operation != Operation::kListenTcp && operation != Operation::kBindUdp &&
        operation != Operation::kAcceptTcp) {
        return Status::kMalformed;
    }
    const bool requires_fd = operation == Operation::kAcceptTcp;
    if (requires_fd != static_cast<bool>(incoming)) {
        return Status::kMalformed;
    }
    if (ntohs(request->destination_port) == 0) {
        return Status::kInvalidDestination;
    }
    const bool service_operation = operation == Operation::kListenTcp ||
                                   operation == Operation::kBindUdp ||
                                   operation == Operation::kAcceptTcp;
    if (service_operation && ntohs(request->destination_port) < kMinServicePort) {
        return Status::kInvalidDestination;
    }
    in6_addr destination{};
    std::memcpy(&destination, request->destination_ipv6, sizeof(destination));
    if (operation == Operation::kConnectTcp || operation == Operation::kConnectUdp) {
        if (IN6_IS_ADDR_UNSPECIFIED(&destination) || IN6_IS_ADDR_LOOPBACK(&destination) ||
            IN6_IS_ADDR_MULTICAST(&destination) || IN6_IS_ADDR_V4MAPPED(&destination) ||
            IN6_IS_ADDR_LINKLOCAL(&destination)) {
            return Status::kInvalidDestination;
        }
    } else if (!IN6_IS_ADDR_UNSPECIFIED(&destination)) {
        // A service request may choose only its port. Its bind address is
        // always derived from the authenticated account.
        return Status::kInvalidDestination;
    }
    if (incoming) {
        *received_fd = std::move(incoming);
    }
    return Status::kOk;
}

bool validate_listener(int listener_fd, const Identity &identity, std::uint16_t network_port) {
    struct stat state{};
    if (fstat(listener_fd, &state) < 0 || state.st_uid != identity.uid) {
        return false;
    }
    int socket_type = 0;
    int accepting = 0;
    int ipv6_only = 0;
    socklen_t integer_size = sizeof(int);
    if (getsockopt(listener_fd, SOL_SOCKET, SO_TYPE, &socket_type, &integer_size) < 0 ||
        socket_type != SOCK_STREAM) {
        return false;
    }
    integer_size = sizeof(int);
    if (getsockopt(listener_fd, SOL_SOCKET, SO_ACCEPTCONN, &accepting, &integer_size) < 0 ||
        accepting != 1) {
        return false;
    }
    integer_size = sizeof(int);
    if (getsockopt(listener_fd, IPPROTO_IPV6, IPV6_V6ONLY, &ipv6_only, &integer_size) < 0 ||
        ipv6_only != 1) {
        return false;
    }
    sockaddr_in6 local{};
    socklen_t local_size = sizeof(local);
    return getsockname(listener_fd, reinterpret_cast<sockaddr *>(&local), &local_size) == 0 &&
           local_size == sizeof(local) && local.sin6_family == AF_INET6 &&
           local.sin6_port == network_port &&
           std::memcmp(&local.sin6_addr, &identity.source, sizeof(local.sin6_addr)) == 0;
}

Fd accept_identity_socket(int listener_fd, int timeout_ms, int *error) {
    int flags = fcntl(listener_fd, F_GETFL, 0);
    if (flags < 0 || fcntl(listener_fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        *error = errno;
        return {};
    }
    pollfd descriptor{listener_fd, POLLIN, 0};
    int rc = poll(&descriptor, 1, timeout_ms);
    if (rc <= 0) {
        *error = rc == 0 ? ETIMEDOUT : errno;
        return {};
    }
    Fd accepted(accept4(listener_fd, nullptr, nullptr, SOCK_CLOEXEC));
    if (!accepted) {
        *error = errno;
        return {};
    }
    return accepted;
}

Fd create_identity_socket(const RequestV1 &request, const Identity &identity, int timeout_ms, int *error) {
    const auto operation = static_cast<Operation>(ntohs(request.operation));
    const bool tcp = operation == Operation::kConnectTcp || operation == Operation::kListenTcp;
    const bool connecting = operation == Operation::kConnectTcp || operation == Operation::kConnectUdp;
    int type = tcp ? SOCK_STREAM : SOCK_DGRAM;
    Fd socket_fd(socket(AF_INET6, type | SOCK_CLOEXEC | SOCK_NONBLOCK, 0));
    if (!socket_fd) {
        *error = errno;
        return {};
    }
    int enabled = 1;
    if (setsockopt(socket_fd.value, IPPROTO_IPV6, IPV6_V6ONLY, &enabled, sizeof(enabled)) < 0) {
        *error = errno;
        return {};
    }
    sockaddr_in6 source{};
    source.sin6_family = AF_INET6;
    source.sin6_addr = identity.source;
    if (!connecting) {
        source.sin6_port = request.destination_port;
        if (operation == Operation::kListenTcp) {
            int reuse = 1;
            if (setsockopt(socket_fd.value, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
                *error = errno;
                return {};
            }
        }
    }
    if (bind(socket_fd.value, reinterpret_cast<sockaddr *>(&source), sizeof(source)) < 0) {
        *error = errno;
        return {};
    }
    if (operation == Operation::kListenTcp) {
        if (listen(socket_fd.value, 128) < 0) {
            *error = errno;
            return {};
        }
    }
    if (!connecting) {
        int flags = fcntl(socket_fd.value, F_GETFL, 0);
        if (flags < 0 || fcntl(socket_fd.value, F_SETFL, flags & ~O_NONBLOCK) < 0) {
            *error = errno;
            return {};
        }
        return socket_fd;
    }
    sockaddr_in6 destination{};
    destination.sin6_family = AF_INET6;
    destination.sin6_port = request.destination_port;
    std::memcpy(&destination.sin6_addr, request.destination_ipv6, sizeof(destination.sin6_addr));
    int rc = connect(socket_fd.value, reinterpret_cast<sockaddr *>(&destination), sizeof(destination));
    if (rc < 0 && errno != EINPROGRESS) {
        *error = errno;
        return {};
    }
    if (rc < 0) {
        pollfd descriptor{socket_fd.value, POLLOUT, 0};
        rc = poll(&descriptor, 1, timeout_ms);
        if (rc <= 0) {
            *error = rc == 0 ? ETIMEDOUT : errno;
            return {};
        }
        int connect_error = 0;
        socklen_t connect_error_size = sizeof(connect_error);
        if (getsockopt(socket_fd.value, SOL_SOCKET, SO_ERROR, &connect_error, &connect_error_size) < 0 ||
            connect_error != 0) {
            *error = connect_error != 0 ? connect_error : errno;
            return {};
        }
    }
    int flags = fcntl(socket_fd.value, F_GETFL, 0);
    if (flags < 0 || fcntl(socket_fd.value, F_SETFL, flags & ~O_NONBLOCK) < 0) {
        *error = errno;
        return {};
    }
    return socket_fd;
}

void handle_client(int client_fd, const Config &config) {
    try {
        set_io_timeout(client_fd, config.request_timeout_ms);
    } catch (...) {
        _exit(1);
    }
    RequestV1 request{};
    std::uint64_t request_id = 0;
    Fd supplied_socket;
    Status status = receive_request(client_fd, &request, &request_id, &supplied_socket);
    if (status != Status::kOk) {
        send_response(client_fd, make_response(status, request_id, EINVAL));
        _exit(1);
    }
    Identity identity;
    uid_t requested_uid = static_cast<uid_t>(ntohl(request.uid));
    if (!resolve_identity(requested_uid, &identity)) {
        send_response(client_fd, make_response(Status::kInvalidIdentity, request_id, ENOENT));
        _exit(1);
    }
    const auto operation = static_cast<Operation>(ntohs(request.operation));
    if (operation == Operation::kAcceptTcp &&
        !validate_listener(supplied_socket.value, identity, request.destination_port)) {
        send_response(client_fd, make_response(Status::kInvalidSocket, request_id, EBADF));
        _exit(1);
    }
    if (!drop_privileges(identity)) {
        send_response(client_fd, make_response(Status::kInternal, request_id, EPERM));
        _exit(1);
    }
    int socket_error = 0;
    Fd identity_socket = operation == Operation::kAcceptTcp
        ? accept_identity_socket(supplied_socket.value, config.connect_timeout_ms, &socket_error)
        : create_identity_socket(request, identity, config.connect_timeout_ms, &socket_error);
    if (!identity_socket) {
        send_response(client_fd, make_response(Status::kSocketFailed, request_id, socket_error));
        _exit(1);
    }
    if (!send_response(client_fd, make_response(Status::kOk, request_id, 0), identity_socket.value)) {
        _exit(1);
    }
    _exit(0);
}

gid_t resolve_group(const std::string &name) {
    group *entry = getgrnam(name.c_str());
    if (entry == nullptr) {
        throw std::runtime_error("socket group does not exist: " + name);
    }
    return entry->gr_gid;
}

void safely_unlink_socket(const std::string &path) {
    struct stat state{};
    if (lstat(path.c_str(), &state) < 0) {
        if (errno == ENOENT) {
            return;
        }
        throw std::runtime_error("cannot inspect existing socket path");
    }
    if (!S_ISSOCK(state.st_mode) || state.st_uid != geteuid()) {
        throw std::runtime_error("refusing to unlink non-socket or foreign-owned path");
    }
    if (unlink(path.c_str()) < 0) {
        throw std::runtime_error("cannot remove stale socket");
    }
}

Fd create_server(const Config &config) {
    safely_unlink_socket(config.socket_path);
    Fd server(socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0));
    if (!server) {
        throw std::runtime_error("cannot create Unix socket");
    }
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    std::memcpy(address.sun_path, config.socket_path.c_str(), config.socket_path.size() + 1);
    mode_t old_mask = umask(0077);
    int rc = bind(server.value, reinterpret_cast<sockaddr *>(&address), sizeof(address));
    umask(old_mask);
    if (rc < 0) {
        throw std::runtime_error("cannot bind Unix socket");
    }
    gid_t socket_gid = resolve_group(config.socket_group);
    if (chown(config.socket_path.c_str(), 0, socket_gid) < 0 || chmod(config.socket_path.c_str(), 0660) < 0) {
        throw std::runtime_error("cannot secure Unix socket ownership");
    }
    if (listen(server.value, 128) < 0) {
        throw std::runtime_error("cannot listen on Unix socket");
    }
    return server;
}

}  // namespace

int main(int argc, char **argv) {
    if (geteuid() != 0) {
        std::fprintf(stderr, "cmxsafe-ssh3-helper must run as root\n");
        return 1;
    }
    Config config;
    try {
        config = parse_args(argc, argv);
    } catch (const std::exception &error) {
        std::fprintf(stderr, "configuration error: %s\n", error.what());
        return 2;
    }

    signal(SIGPIPE, SIG_IGN);
    struct sigaction child_action{};
    child_action.sa_handler = reap_children;
    child_action.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    sigemptyset(&child_action.sa_mask);
    if (sigaction(SIGCHLD, &child_action, nullptr) < 0) {
        std::perror("sigaction");
        return 1;
    }

    Fd server;
    try {
        server = create_server(config);
    } catch (const std::exception &error) {
        std::fprintf(stderr, "startup error: %s (%s)\n", error.what(), std::strerror(errno));
        return 1;
    }
    std::printf("cmxsafe-ssh3-helper listening on %s\n", config.socket_path.c_str());
    std::fflush(stdout);

    for (;;) {
        Fd client(accept4(server.value, nullptr, nullptr, SOCK_CLOEXEC));
        if (!client) {
            if (errno != EINTR) {
                std::perror("accept4");
            }
            continue;
        }
        if (!peer_is_authorized(client.value, config.allowed_uid)) {
            send_response(client.value, make_response(Status::kUnauthorized, 0, EACCES));
            continue;
        }
        if (g_active_children >= static_cast<sig_atomic_t>(config.max_children)) {
            send_response(client.value, make_response(Status::kBusy, 0, EBUSY));
            continue;
        }

        sigset_t blocked{};
        sigset_t previous{};
        sigemptyset(&blocked);
        sigaddset(&blocked, SIGCHLD);
        sigprocmask(SIG_BLOCK, &blocked, &previous);
        pid_t child = fork();
        if (child == 0) {
            sigprocmask(SIG_SETMASK, &previous, nullptr);
            close(server.value);
            handle_client(client.value, config);
        }
        if (child > 0) {
            ++g_active_children;
        } else {
            send_response(client.value, make_response(Status::kInternal, 0, errno));
        }
        sigprocmask(SIG_SETMASK, &previous, nullptr);
    }
}
