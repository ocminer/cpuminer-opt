// C header for tip5xx wrapper
#ifndef TIP5XX_WRAPPER_H
#define TIP5XX_WRAPPER_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint64_t value;
} CBFieldElement;

typedef struct {
    CBFieldElement elements[5];
} CDigest;

// Neptune BlockPow hash
void tip5xx_hash_block_pow(const uint8_t* auth_paths, size_t auth_paths_len,
                           const uint8_t* nonce_digest,
                           CDigest* output);

#ifdef __cplusplus
}
#endif

#endif // TIP5XX_WRAPPER_H
