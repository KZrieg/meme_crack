#pragma once
// ---------------------------------------------------------------------------
// Build provenance marker.
//
// Purpose: make a binary traceable back to the build that produced it, without
// leaving a greppable string behind. `strings`, `findstr` and casual inspection
// find nothing: the tag is XOR-encoded into a dedicated PE section and only
// ever compared as a hash, so the plaintext never exists in the image.
//
// This is a provenance stamp, NOT an authorisation check. Nothing here gates
// execution; Verify() returns a bool that callers log and move on from.
//
// Regenerating the stamp (new tag, new key):
//   python src/tools/stamp_gen.py --tag "Krieg1337"
//   -> paste the emitted blob/key/hash into the constants below.
//
// The section is linked by #pragma section / __declspec(allocate) rather than
// a linker option, so it stays stable across optimisation levels.
// ---------------------------------------------------------------------------

#include <cstdint>
#include <cstring>

// __declspec(allocate) requires the section to be declared first. `read` keeps
// it out of the writable data set, so the stamp cannot be patched at run time
// without changing page protections.
#pragma section(".K1337", read)

namespace prov {

    // XOR payload, 29 bytes. Plaintext is "K1337|Krieg1337|meme_crack|v1".
    // Kept in .K1337 so it is addressable independently of the code section and
    // cannot be folded away as an unused constant.
    __declspec(allocate(".K1337")) const unsigned char kBlob[] = {
        0xD5, 0x0A, 0x42, 0xF7, 0x32, 0xA6, 0x29, 0x6D, 0xF7, 0x5E, 0x16, 0xF5,
        0x36, 0xE9, 0x55, 0x63, 0xF3, 0x5E, 0x1C, 0xA1, 0x5A, 0xB9, 0x10, 0x7E,
        0xFD, 0x50, 0x0D, 0xB2, 0x34,
    };

    // Decode key. Splitting it from the blob means neither half is meaningful
    // on its own if a single array is spotted.
    __declspec(allocate(".K1337")) const unsigned char kKey[] = {
        0x9E, 0x3B, 0x71, 0xC4, 0x05, 0xDA, 0x62, 0x1F,
    };

    constexpr std::size_t kBlobLen = sizeof(kBlob);
    constexpr std::size_t kKeyLen  = sizeof(kKey);

    // FNV-1a of the plaintext. Decoding and comparing against this avoids ever
    // materialising the tag as a C string literal.
    constexpr std::uint64_t kExpected = 0x25F17246A761790CULL;

    // Decode into a caller-supplied buffer. Returns the number of bytes written
    // (no terminator). Returns 0 if the buffer is too small.
    inline std::size_t Decode(char* out, std::size_t cap) {
        if (!out || cap < kBlobLen) return 0;
        for (std::size_t i = 0; i < kBlobLen; ++i)
            out[i] = static_cast<char>(kBlob[i] ^ kKey[i % kKeyLen]);
        return kBlobLen;
    }

    // FNV-1a 64-bit over an arbitrary byte range.
    inline std::uint64_t Fnv1a(const void* data, std::size_t len) {
        const auto* p = static_cast<const unsigned char*>(data);
        std::uint64_t h = 0xCBF29CE484222325ULL;
        for (std::size_t i = 0; i < len; ++i) {
            h ^= p[i];
            h *= 0x100000001B3ULL;
        }
        return h;
    }

    // True when the embedded stamp decodes to the expected tag. Pure function of
    // the image bytes, so it also answers "was this binary tampered with?" in the
    // narrow sense of the stamp region.
    inline bool Verify() {
        char buf[kBlobLen];
        const std::size_t n = Decode(buf, sizeof(buf));
        if (n != kBlobLen) return false;
        return Fnv1a(buf, n) == kExpected;
    }

} // namespace prov
