/**
 * Neptune Algorithm Integration for cpuminer-opt
 * Uses the Neptune Tip5 library from algo/tip5/
 * 
 * This file provides the cpuminer-opt algo-gate integration layer
 * and uses the Neptune protocol implementation from algo/tip5/neptune.{c,h}
 */

#include "miner.h"
#include "algo-gate-api.h"
#include "algo/tip5/tip5xx_wrapper.h"  // Official tip5xx C++ library via wrapper
#include <string.h>
#include <stdlib.h>
#include <jansson.h>
#include <time.h>
#include <pthread.h>

// Neptune job structure
typedef struct {
    char job_id[64];
    uint32_t difficulty;
    bool clean_jobs;
    
    uint8_t* auth_paths_buffer;
    size_t auth_paths_len;
    size_t pow_count;
    size_t header_count;
    size_t kernel_count;
} neptune_job_t;

// Forward declarations
static void neptune_build_stratum_request(char *req, struct work *work, struct stratum_ctx *sctx);

// Helper functions
static void neptune_job_init(neptune_job_t* job) {
    memset(job, 0, sizeof(neptune_job_t));
}

static void neptune_job_free(neptune_job_t* job) {
    if (job->auth_paths_buffer) {
        free(job->auth_paths_buffer);
        job->auth_paths_buffer = NULL;
    }
    job->auth_paths_len = 0;
}

// Parse auth paths from arrays
static bool neptune_parse_auth_paths(neptune_job_t* job,
                                     const char** pow_paths, size_t pow_count,
                                     const char** header_paths, size_t header_count,
                                     const char** kernel_paths, size_t kernel_count) {
    size_t total_count = pow_count + header_count + kernel_count;
    size_t total_bytes = total_count * 40;  // Each path is 40 bytes
    
    if (job->auth_paths_buffer) {
        free(job->auth_paths_buffer);
    }
    
    job->auth_paths_buffer = (uint8_t*)malloc(total_bytes);
    if (!job->auth_paths_buffer) {
        return false;
    }
    
    job->auth_paths_len = total_bytes;
    job->pow_count = pow_count;
    job->header_count = header_count;
    job->kernel_count = kernel_count;
    
    uint8_t* ptr = job->auth_paths_buffer;
    
    // Copy pow paths (use miner.h's hex2bin)
    for (size_t i = 0; i < pow_count; i++) {
        if (!hex2bin(ptr, pow_paths[i], 40)) {
            return false;
        }
        ptr += 40;
    }
    
    // Copy header paths
    for (size_t i = 0; i < header_count; i++) {
        if (!hex2bin(ptr, header_paths[i], 40)) {
            return false;
        }
        ptr += 40;
    }
    
    // Copy kernel paths
    for (size_t i = 0; i < kernel_count; i++) {
        if (!hex2bin(ptr, kernel_paths[i], 40)) {
            return false;
        }
        ptr += 40;
    }
    
    return true;
}

// External variables from miner.h
extern char *rpc_user;
extern uint32_t accepted_share_count;
extern uint32_t rejected_share_count;

// Global Neptune job storage (shared across all threads, protected by job_lock)
static neptune_job_t thread_job;
static bool job_initialized = false;
static pthread_mutex_t job_lock = PTHREAD_MUTEX_INITIALIZER;

/**
 * Initialize Neptune algorithm for a thread
 */
bool neptune_miner_thread_init(void)
{
    if (!job_initialized) {
        neptune_job_init(&thread_job);
        job_initialized = true;
    }
    return true;
}

/**
 * Cleanup Neptune thread resources
 */
void neptune_thread_cleanup(void)
{
    if (job_initialized) {
        neptune_job_free(&thread_job);
        job_initialized = false;
    }
}

/**
 * Parse JSON array of hex strings into auth paths
 */
static bool parse_path_array(json_t *array, char ***paths_out, size_t *count_out)
{
    if (!json_is_array(array)) {
        return false;
    }
    
    size_t count = json_array_size(array);
    if (count == 0) {
        *paths_out = NULL;
        *count_out = 0;
        return true;
    }
    
    char **paths = (char**)malloc(count * sizeof(char*));
    if (!paths) {
        applog(LOG_ERR, "Neptune: Failed to allocate path array");
        return false;
    }
    
    for (size_t i = 0; i < count; i++) {
        json_t *path = json_array_get(array, i);
        const char *hex = json_string_value(path);
        
        if (!hex) {
            applog(LOG_ERR, "Neptune: Invalid path at index %zu", i);
            for (size_t j = 0; j < i; j++) {
                free(paths[j]);
            }
            free(paths);
            return false;
        }
        
        paths[i] = strdup(hex);
        if (!paths[i]) {
            applog(LOG_ERR, "Neptune: Failed to duplicate path string");
            for (size_t j = 0; j < i; j++) {
                free(paths[j]);
            }
            free(paths);
            return false;
        }
    }
    
    *paths_out = paths;
    *count_out = count;
    return true;
}

/**
 * Free path array
 */
static void free_path_array(char **paths, size_t count)
{
    if (paths) {
        for (size_t i = 0; i < count; i++) {
            if (paths[i]) {
                free(paths[i]);
            }
        }
        free(paths);
    }
}

/**
 * Handle Neptune JSON-RPC job result
 * This handles the actual format from npt.suprnova.cc
 * 
 * Format:
 * {
 *   "id": 0,
 *   "jsonrpc": "2.0",
 *   "result": {
 *     "job": {
 *       "id": "job_id",
 *       "difficulty": "100000",
 *       "paths": { ... }
 *     }
 *   }
 * }
 */
bool neptune_handle_job_result(json_t *result)
{
    if (!result || !json_is_object(result)) {
        return false;
    }
    
    // Get the job object
    json_t *job = json_object_get(result, "job");
    if (!job || !json_is_object(job)) {
        return false;
    }
    
    // Get job ID
    json_t *job_id_json = json_object_get(job, "id");
    const char *job_id = json_string_value(job_id_json);
    if (!job_id) {
        applog(LOG_ERR, "Neptune: Invalid job ID in result");
        return false;
    }
    
    // Get difficulty (as string in this format)
    json_t *diff_json = json_object_get(job, "difficulty");
    uint32_t difficulty;
    if (json_is_string(diff_json)) {
        difficulty = (uint32_t)atol(json_string_value(diff_json));
    } else if (json_is_integer(diff_json)) {
        difficulty = (uint32_t)json_integer_value(diff_json);
    } else {
        applog(LOG_ERR, "Neptune: Invalid difficulty in result");
        return false;
    }
    
    // Get paths object
    json_t *paths = json_object_get(job, "paths");
    if (!paths || !json_is_object(paths)) {
        applog(LOG_ERR, "Neptune: Invalid paths object in result");
        return false;
    }
    
    // Get individual path arrays
    json_t *pow_paths_json = json_object_get(paths, "pow");
    json_t *header_paths_json = json_object_get(paths, "header");
    json_t *kernel_paths_json = json_object_get(paths, "kernel");
    
    if (!pow_paths_json || !header_paths_json || !kernel_paths_json) {
        applog(LOG_ERR, "Neptune: Missing path arrays in result");
        return false;
    }
    
    // Parse path arrays
    char **pow_paths = NULL, **header_paths = NULL, **kernel_paths = NULL;
    size_t pow_count = 0, header_count = 0, kernel_count = 0;
    
    if (!parse_path_array(pow_paths_json, &pow_paths, &pow_count) ||
        !parse_path_array(header_paths_json, &header_paths, &header_count) ||
        !parse_path_array(kernel_paths_json, &kernel_paths, &kernel_count)) {
        applog(LOG_ERR, "Neptune: Failed to parse path arrays from result");
        free_path_array(pow_paths, pow_count);
        free_path_array(header_paths, header_count);
        free_path_array(kernel_paths, kernel_count);
        return false;
    }
    
    // Debug: show what we got
    if (opt_debug) {
        applog(LOG_DEBUG, "Neptune: Parsed %zu pow, %zu header, %zu kernel paths", 
               pow_count, header_count, kernel_count);
        if (pow_count > 0 && pow_paths[0]) {
            applog(LOG_DEBUG, "Neptune: First pow path (len %zu): %.20s...", 
                   strlen(pow_paths[0]), pow_paths[0]);
        }
    }
    
    // Lock and update thread job
    pthread_mutex_lock(&job_lock);
    
    // Free old job data
    neptune_job_free(&thread_job);
    
    // Set new job data
    strncpy(thread_job.job_id, job_id, sizeof(thread_job.job_id) - 1);
    thread_job.job_id[sizeof(thread_job.job_id) - 1] = '\0';
    thread_job.difficulty = difficulty;
    thread_job.clean_jobs = true;  // Always treat as clean for new jobs
    
    // Parse auth paths into job structure
    bool success = neptune_parse_auth_paths(&thread_job,
                                           (const char**)pow_paths, pow_count,
                                           (const char**)header_paths, header_count,
                                           (const char**)kernel_paths, kernel_count);
    
    if (opt_debug) {
        applog(LOG_DEBUG, "Neptune: parse_auth_paths returned %s, buffer=%p, len=%zu",
               success ? "true" : "false",
               thread_job.auth_paths_buffer,
               thread_job.auth_paths_len);
    }
    
    pthread_mutex_unlock(&job_lock);
    
    // Free temporary path arrays
    free_path_array(pow_paths, pow_count);
    free_path_array(header_paths, header_count);
    free_path_array(kernel_paths, kernel_count);
    
    if (!success) {
        applog(LOG_ERR, "Neptune: Failed to parse auth paths from result");
        return false;
    }
    
    applog(LOG_INFO, "Neptune: New job '%s', difficulty %u, paths %zu bytes (%zu pow, %zu header, %zu kernel)",
           job_id, difficulty, thread_job.auth_paths_len,
           thread_job.pow_count, thread_job.header_count, thread_job.kernel_count);
    
    // Update global stratum job to signal work is ready
    extern struct stratum_ctx stratum;
    
    if (opt_debug) {
        applog(LOG_DEBUG, "Neptune: Updating stratum job_id");
    }
    
    pthread_mutex_lock(&stratum.work_lock);
    
    // Free old job_id if exists
    if (stratum.job.job_id) {
        free(stratum.job.job_id);
        stratum.job.job_id = NULL;
    }
    
    // Duplicate new job_id
    stratum.job.job_id = strdup(job_id);
    if (!stratum.job.job_id) {
        pthread_mutex_unlock(&stratum.work_lock);
        applog(LOG_ERR, "Neptune: Failed to allocate job_id");
        return false;
    }
    
    // Mark new job available (if field exists)
    // stratum.new_job = true;
    
    pthread_mutex_unlock(&stratum.work_lock);
    
    if (opt_debug) {
        applog(LOG_DEBUG, "Neptune: Signaling work restart");
    }
    
    // Signal work restart - this will wake up mining threads
    extern struct work_restart *work_restart;
    extern int opt_n_threads;
    for (int i = 0; i < opt_n_threads; i++) {
        work_restart[i].restart = 1;
    }
    
    if (opt_debug) {
        applog(LOG_DEBUG, "Neptune: Job update complete");
    }
    
    return true;
}

/**
 * Handle Neptune mining.notify stratum message
 * 
 * Expected format:
 * params: [
 *   "job_id",
 *   {
 *     "difficulty": 1000,
 *     "paths": {
 *       "pow": ["hex80char", ...],
 *       "header": ["hex80char", ...],
 *       "kernel": ["hex80char", ...]
 *     }
 *   },
 *   clean_jobs
 * ]
 */
bool neptune_stratum_notify(struct stratum_ctx *sctx, json_t *params)
{
    // This function is not used - Neptune uses JSON-RPC format handled by neptune_handle_job_result
    // The pool sends jobs in a different format, so this handler should not process anything
    if (opt_debug) {
        applog(LOG_DEBUG, "Neptune: neptune_stratum_notify called but not used (JSON-RPC format handled separately)");
    }
    return false;  // Return false so standard stratum doesn't try to process it
}

/**
 * Main Neptune mining function
 */
int scanhash_neptune(struct work *work, uint32_t max_nonce,
                    uint64_t *hashes_done, struct thr_info *mythr)
{
    const int thr_id = mythr->id;
    uint64_t nonce = work->data[19];  // Starting nonce
    const uint64_t first_nonce = nonce;
    CDigest hash;  // Using tip5xx wrapper type
    
    // Check if we have an active job
    pthread_mutex_lock(&job_lock);
    
    if (opt_debug && thr_id == 0) {
        applog(LOG_DEBUG, "Neptune: Thread %d checking job: buffer=%p, len=%zu, job_id=%s",
               thr_id, thread_job.auth_paths_buffer, thread_job.auth_paths_len, 
               thread_job.job_id[0] ? thread_job.job_id : "(empty)");
        
        // Debug: Show first 40 bytes of auth_paths_buffer
        if (thread_job.auth_paths_buffer && thread_job.auth_paths_len >= 40) {
            char hex_preview[81];
            for (int i = 0; i < 40; i++) {
                sprintf(hex_preview + (i * 2), "%02x", thread_job.auth_paths_buffer[i]);
            }
            hex_preview[80] = '\0';
            applog(LOG_DEBUG, "Neptune: First 40 bytes of auth_paths: %s", hex_preview);
        }
    }
    
    if (!thread_job.auth_paths_buffer || thread_job.auth_paths_len == 0) {
        pthread_mutex_unlock(&job_lock);
        applog(LOG_WARNING, "Neptune: No active job for thread %d", thr_id);
        *hashes_done = 0;
        return 0;
    }
    
    // Copy job data for mining (to avoid holding lock)
    uint32_t difficulty = thread_job.difficulty;
    size_t paths_len = thread_job.auth_paths_len;
    char current_job_id[64];
    strncpy(current_job_id, thread_job.job_id, sizeof(current_job_id) - 1);
    current_job_id[sizeof(current_job_id) - 1] = '\0';
    
    uint8_t *paths_buffer = (uint8_t*)malloc(paths_len);
    if (!paths_buffer) {
        pthread_mutex_unlock(&job_lock);
        applog(LOG_ERR, "Neptune: Failed to allocate mining buffer");
        *hashes_done = 0;
        return 0;
    }
    memcpy(paths_buffer, thread_job.auth_paths_buffer, paths_len);
    pthread_mutex_unlock(&job_lock);
    
    if (opt_debug && nonce == first_nonce) {
        applog(LOG_DEBUG, "Neptune: Thread %d mining, start nonce %lu, difficulty %u",
               thr_id, nonce, difficulty);
    }
    
    // Mining loop
    while (nonce < max_nonce && !work_restart[thr_id].restart) {
        
        // Debug: Show what we're hashing for specific nonce
        if (nonce == 4563 && thr_id == 0) {
            applog(LOG_INFO, "Neptune: [DEBUG] Hashing nonce %lu, paths_len=%zu", nonce, paths_len);
            // Show first 40 bytes of paths
            char hex[81];
            for (int i = 0; i < 40 && i < paths_len; i++) {
                sprintf(hex + (i*2), "%02x", paths_buffer[i]);
            }
            hex[80] = '\0';
            applog(LOG_INFO, "  First 40 bytes of paths: %s", hex);
        }
        
        // Create nonce digest (40 bytes: nonce as first u64, rest zeros)
        uint8_t nonce_digest[40] = {0};
        for (int i = 0; i < 8; i++) {
            nonce_digest[i] = (nonce >> (i * 8)) & 0xFF;
        }
        
        // Compute hash using tip5xx library wrapper
        tip5xx_hash_block_pow(paths_buffer, paths_len, nonce_digest, &hash);
        
        // Re-read current difficulty (may have changed via vardiff)
        pthread_mutex_lock(&job_lock);
        uint32_t current_difficulty = thread_job.difficulty;
        pthread_mutex_unlock(&job_lock);
        
        // Check difficulty using FULL hash comparison
        // Neptune uses 40-byte (320-bit) hashes, we need to check all of it
        // Compare as big-endian 320-bit number: hash <= threshold
        uint64_t hash_value = hash.elements[0].value;
        uint64_t threshold = 0xFFFFFFFFFFFFFFFFULL / current_difficulty;
        
        // For now, just check first element (may need full comparison later)
        // TODO: If pool uses 256-bit threshold, compare all elements
        if (hash_value <= threshold) {
            // Found valid share!
            work->data[19] = nonce;
            
            // Convert Digest to byte array for submission
            uint8_t hash_bytes[40];  // 5 BFieldElements × 8 bytes each
            for (int i = 0; i < 5; i++) {
                uint64_t val = hash.elements[i].value;
                for (int j = 0; j < 8; j++) {
                    hash_bytes[i * 8 + j] = (val >> (j * 8)) & 0xFF;
                }
            }
            
            if (opt_debug) {
                // Show hash in hex
                char hash_hex[81];
                for (int i = 0; i < 40; i++) {
                    sprintf(hash_hex + (i*2), "%02x", hash_bytes[i]);
                }
                hash_hex[80] = '\0';
                applog(LOG_DEBUG, "Neptune: Share found! Nonce %lu, hash %s", nonce, hash_hex);
            }
            
            // Found a valid share!
            work->data[19] = nonce;
            work->data[17] = (uint32_t)time(NULL);  // Set ntime
            
            applog(LOG_NOTICE, "Neptune: Share found! Nonce %lu (difficulty %u, threshold %016lx)", 
                   nonce, current_difficulty, threshold);
            
            // CRITICAL: Re-check difficulty before submitting
            // Difficulty may have increased while we were hashing
            pthread_mutex_lock(&job_lock);
            uint32_t submit_difficulty = thread_job.difficulty;
            
            // CRITICAL: Verify job hasn't changed!
            // If job changed, this share was found with old auth_paths and is invalid
            if (strcmp(current_job_id, thread_job.job_id) != 0) {
                pthread_mutex_unlock(&job_lock);
                if (opt_debug) {
                    applog(LOG_DEBUG, "Neptune: Share found but job changed (%s -> %s), discarding", 
                           current_job_id, thread_job.job_id);
                }
                // Job changed - abort this mining round
                break;
            }
            
            pthread_mutex_unlock(&job_lock);
            
            // Recalculate threshold with current difficulty
            uint64_t submit_threshold = 0xFFFFFFFFFFFFFFFFULL / submit_difficulty;
            
            if (hash_value > submit_threshold) {
                // Share no longer meets current difficulty - skip it
                if (opt_debug) {
                    applog(LOG_DEBUG, "Neptune: Share nonce %lu discarded (difficulty increased to %u)", 
                           nonce, submit_difficulty);
                }
                nonce++;
                continue;
            }
            
            // Build submission using our proper function
            char submit_msg[8192];
            neptune_build_stratum_request(submit_msg, work, NULL);
            
            // Send directly via socket without blocking
            extern struct stratum_ctx stratum;
            bool sent = false;
            
            if (stratum.sock != -1) {
                pthread_mutex_lock(&stratum.sock_lock);
                
                // Log what we're sending (like stratum_send_line does)
                if (opt_protocol) {
                    applog(LOG_DEBUG, "> %s", submit_msg);
                }
                
                // Use raw send() to avoid blocking in stratum_send_line
                size_t msg_len = strlen(submit_msg);
                ssize_t n = send(stratum.sock, submit_msg, msg_len, 0);
                sent = (n == (ssize_t)msg_len);
                
                pthread_mutex_unlock(&stratum.sock_lock);
                
                if (sent) {
                    applog(LOG_NOTICE, "Neptune: ✓ Share submitted! Nonce %lu (%zu bytes sent)", nonce, msg_len);
                } else {
                    applog(LOG_ERR, "Neptune: ✗ send() failed for nonce %lu (sent %zd/%zu bytes)", nonce, n, msg_len);
                }
            } else {
                applog(LOG_ERR, "Neptune: ✗ Invalid socket (%d), cannot send share", stratum.sock);
            }
            
            // Continue mining
            nonce++;
            continue;
        }
        
        nonce++;
    }
    
    free(paths_buffer);
    *hashes_done = nonce - first_nonce;
    work->data[19] = nonce;
    
    return 0;
}

/**
 * Update difficulty (called when pool sends mining.set_difficulty)
 */
bool neptune_update_difficulty(uint32_t difficulty) {
    pthread_mutex_lock(&job_lock);
    
    uint32_t old_diff = thread_job.difficulty;
    
    if (old_diff != difficulty) {
        thread_job.difficulty = difficulty;
        
        if (opt_debug) {
            applog(LOG_DEBUG, "Neptune: Difficulty changed %u -> %u", old_diff, difficulty);
        }
        
        pthread_mutex_unlock(&job_lock);
        
        // Don't restart threads - they will pick up new difficulty on next share check
        return true;
    }
    
    pthread_mutex_unlock(&job_lock);
    return false;
}

/**
 * Build Neptune stratum submit message - SIMPLE 5 param version
 * Format: [username, job_id, xnonce2, ntime_hex, nonce_hex]
 * Pool will reconstruct hash from stored auth_paths + nonce
 */
void neptune_build_stratum_request(char *req, struct work *work, struct stratum_ctx *sctx)
{
    char ntime_hex[9], nonce_hex[9];
    uint32_t nonce_le = work->data[19];  // Little-endian nonce (u32)
    
    // ntime - current unix timestamp
    snprintf(ntime_hex, sizeof(ntime_hex), "%08x", (uint32_t)time(NULL));
    
    // nonce - just the simple hex value (8 chars for u32)
    snprintf(nonce_hex, sizeof(nonce_hex), "%08x", nonce_le);
    
    pthread_mutex_lock(&job_lock);
    
    const char *username = rpc_user ? rpc_user : "";
    
    // Build standard 5-param stratum submit (like test-miner)
    snprintf(req, 8192,
        "{\"method\":\"mining.submit\",\"params\":[\"%s\",\"%s\",\"00000000\",\"%s\",\"%s\"],\"id\":4}\n",
        username,
        thread_job.job_id,
        ntime_hex,
        nonce_hex);
    
    pthread_mutex_unlock(&job_lock);
    
    if (opt_debug) {
        applog(LOG_DEBUG, "Neptune: Built simple submit: job=%s, nonce=%s", 
               thread_job.job_id, nonce_hex);
    }
}

/**
 * Neptune custom stratum response handler
 * Intercepts JSON-RPC responses to handle job notifications
 * 
 * This should be called from stratum_handle_response() in cpu-miner.c
 * when Neptune algo is active
 */
bool neptune_stratum_handle_response(char *buf)
{
    json_t *val;
    json_error_t err;
    
    val = json_loads(buf, 0, &err);
    if (!val) {
        return false;
    }
    
    // Check if this is a result with a job
    json_t *result = json_object_get(val, "result");
    if (result && json_is_object(result)) {
        json_t *job = json_object_get(result, "job");
        if (job && json_is_object(job)) {
            // This is a Neptune job notification
            bool success = neptune_handle_job_result(result);
            json_decref(val);
            return success;
        }
    }
    
    json_decref(val);
    return false;
}

// Declare this function in miner.h for Neptune
// Add: bool neptune_stratum_handle_response(char *buf);

/**
 * Neptune work decode - checks if we have an active job
 */
bool neptune_work_decode(struct work *work)
{
    pthread_mutex_lock(&job_lock);
    bool has_job = (thread_job.auth_paths_buffer != NULL && thread_job.auth_paths_len > 0);
    pthread_mutex_unlock(&job_lock);
    
    return has_job;
}

/**
 * Neptune get_new_work - signals work is available
 */
void neptune_get_new_work(struct work *work, struct work *g_work,
                         int thr_id, uint32_t *end_nonce_ptr)
{
    pthread_mutex_lock(&job_lock);
    
    // Check if we have a job
    if (thread_job.auth_paths_buffer && thread_job.auth_paths_len > 0) {
        // We have a job - set up work structure
        uint32_t saved_nonce = work->data[19];  // Save current nonce
        memset(work, 0, sizeof(struct work));
        
        // Restore nonce to continue from where we left off
        // Only reset to thread starting position if nonce is 0 (first time/new job)
        if (saved_nonce != 0) {
            work->data[19] = saved_nonce;  // Continue from saved position
        } else {
            work->data[19] = thr_id * 0x10000000;  // Initial nonce for this thread
        }
        
        pthread_mutex_unlock(&job_lock);
        
        if (opt_debug && thr_id == 0) {
            applog(LOG_DEBUG, "Neptune: Thread %d got work, job '%s'", thr_id, thread_job.job_id);
        }
    } else {
        pthread_mutex_unlock(&job_lock);
        // No job yet - wait a bit
        sleep(1);
    }
}

/**
 * Register Neptune algorithm with cpuminer-opt
 */
bool register_neptune_algo(algo_gate_t *gate)
{
    // Set mandatory functions
    gate->scanhash = (void*)&scanhash_neptune;
    
    // Set optional functions
    gate->miner_thread_init     = (void*)&neptune_miner_thread_init;
    gate->work_decode           = (void*)&neptune_work_decode;
    gate->get_new_work          = (void*)&neptune_get_new_work;
    gate->build_stratum_request = (void*)&neptune_build_stratum_request;
    
    // CRITICAL: Disable standard stratum work generation
    // Neptune uses custom JSON-RPC job format, not standard stratum
    gate->gen_merkle_root       = NULL;  // Prevent stratum_gen_work from being called
    
    // Neptune uses custom stratum, these don't apply
    gate->ntime_index       = -1;
    gate->nbits_index       = -1;
    gate->nonce_index       = 19;  // Standard nonce location
    gate->work_cmp_size     = 0;
    
    // Set optimizations (CPU only for now)
    gate->optimizations = EMPTY_SET;
    
    applog(LOG_INFO, "Neptune Tip5 quantum-resistant algorithm registered");
    
    return true;
}
