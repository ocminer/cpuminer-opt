// C++ wrapper for tip5xx library - provides C interface for cpuminer
#include "algo/tip5/tip5xx.hpp"
#include "algo/tip5/digest.hpp"
#include "algo/tip5/b_field_element.hpp"
#include <vector>
#include <cstring>

extern "C" {

// C-compatible types
typedef struct {
    uint64_t value;
} CBFieldElement;

typedef struct {
    CBFieldElement elements[5];
} CDigest;

// Convert bytes to BFieldElements (Neptune uses 8 bytes per element, little-endian u64)
std::vector<tip5xx::BFieldElement> bytesToBFieldElements(const uint8_t* data, size_t length) {
    std::vector<tip5xx::BFieldElement> elements;
    
    // Pad to multiple of 8 if necessary
    size_t paddedLength = ((length + 7) / 8) * 8;
    std::vector<uint8_t> padded(paddedLength, 0);
    std::memcpy(padded.data(), data, length);
    
    // Convert each 8 bytes to a BFieldElement
    for (size_t i = 0; i < paddedLength; i += 8) {
        uint64_t value = 0;
        for (int j = 0; j < 8; j++) {
            value |= static_cast<uint64_t>(padded[i + j]) << (j * 8);
        }
        elements.push_back(tip5xx::BFieldElement::new_element(value));
    }
    
    return elements;
}

// Neptune BlockPow hash: Hash(auth_paths || nonce_digest)
void tip5xx_hash_block_pow(const uint8_t* auth_paths, size_t auth_paths_len,
                           const uint8_t* nonce_digest, // 40 bytes
                           CDigest* output) {
    // Concatenate: auth_paths || nonce_digest
    std::vector<uint8_t> combined;
    combined.reserve(auth_paths_len + 40);
    
    combined.insert(combined.end(), auth_paths, auth_paths + auth_paths_len);
    combined.insert(combined.end(), nonce_digest, nonce_digest + 40);
    
    // Convert to BFieldElements
    auto elements = bytesToBFieldElements(combined.data(), combined.size());
    
    // Hash with Tip5 varlen
    tip5xx::Digest digest = tip5xx::Tip5::hash_varlen(elements);
    
    // Convert to C struct
    auto bytes = digest.to_bytes();
    for (int i = 0; i < 5; i++) {
        uint64_t value = 0;
        for (int j = 0; j < 8; j++) {
            value |= static_cast<uint64_t>(bytes[i * 8 + j]) << (j * 8);
        }
        output->elements[i].value = value;
    }
}

} // extern "C"
