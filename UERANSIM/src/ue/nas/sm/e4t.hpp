//
// E4_TIMING=1: one-line timestamps of the EAP-EDHOC secondary authentication
// for the full-stack benchmark (benchmark/fullstack_bench.sh):
//   [E4T] <tag> t_us=<CLOCK_MONOTONIC, us> sess=<psi> len=<bytes> [k=v ...]
// All processes run on the same host, so t_us is comparable across them.
// Off by default. No key material is printed, only 8 bytes of SHA-256(MSK).
//

#pragma once

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <ctime>

#include <sodium.h>

namespace nr::ue
{

inline bool E4TimingOn()
{
    static const bool on = [] {
        const char *v = std::getenv("E4_TIMING");
        return v && std::atoi(v) > 0;
    }();
    return on;
}

inline uint64_t E4NowUs()
{
    timespec ts{};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000ull + (uint64_t)ts.tv_nsec / 1000ull;
}

// extra: "" or " k=v ..." appended to the line
inline void E4T(const char *tag, int sess, long long len, const char *extra = "")
{
    if (!E4TimingOn())
        return;
    std::fprintf(stderr, "[E4T] %s t_us=%llu sess=%d len=%lld%s\n", tag, (unsigned long long)E4NowUs(), sess,
                 len, extra);
}

inline void E4TDuration(const char *tag, int sess, uint64_t t0)
{
    if (!E4TimingOn())
        return;
    char extra[48];
    std::snprintf(extra, sizeof(extra), " dur_us=%llu", (unsigned long long)(E4NowUs() - t0));
    E4T(tag, sess, 0, extra);
}

// first 8 bytes of SHA-256(MSK), to check that UE and DN-AAA derived the same MSK
inline void E4TMskTag(int sess, const uint8_t *msk, size_t len)
{
    if (!E4TimingOn())
        return;
    uint8_t h[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(h, msk, len);
    char extra[32];
    std::snprintf(extra, sizeof(extra), " tag=%02x%02x%02x%02x%02x%02x%02x%02x", h[0], h[1], h[2], h[3], h[4],
                  h[5], h[6], h[7]);
    E4T("msk_tag", sess, (long long)len, extra);
}

} // namespace nr::ue
