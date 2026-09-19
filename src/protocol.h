#pragma once

#include <cstdint>

namespace cmxsafe::ssh3_helper {

constexpr std::uint32_t kMagic = 0x434d5848U;  // "CMXH"
constexpr std::uint16_t kVersion = 1;
constexpr std::uint16_t kMinServicePort = 1024;

enum class Operation : std::uint16_t {
    kConnectTcp = 1,
    kConnectUdp = 2,
    kListenTcp = 3,
    kBindUdp = 4,
    kAcceptTcp = 5,
};

enum class Status : std::uint16_t {
    kOk = 0,
    kMalformed = 1,
    kUnauthorized = 2,
    kInvalidIdentity = 3,
    kInvalidDestination = 4,
    kSocketFailed = 5,
    kBusy = 6,
    kInternal = 7,
    kInvalidSocket = 8,
};

#pragma pack(push, 1)
struct RequestV1 {
    std::uint32_t magic;
    std::uint16_t version;
    std::uint16_t operation;
    std::uint64_t request_id;
    std::uint32_t uid;
    std::uint16_t destination_port;
    std::uint16_t reserved;
    std::uint8_t destination_ipv6[16];
};

struct ResponseV1 {
    std::uint32_t magic;
    std::uint16_t version;
    std::uint16_t status;
    std::uint64_t request_id;
    std::uint32_t system_errno;
    std::uint32_t reserved;
};
#pragma pack(pop)

static_assert(sizeof(RequestV1) == 40, "unexpected RequestV1 size");
static_assert(sizeof(ResponseV1) == 24, "unexpected ResponseV1 size");

}  // namespace cmxsafe::ssh3_helper
