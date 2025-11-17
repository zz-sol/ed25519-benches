/*
 * Minimal stubs for Firedancer logging functions
 * These are needed to link the ed25519 library without pulling in
 * the entire Firedancer util library
 */

#include <stdint.h>

/* Stub implementations for fd_log functions */
void fd_log_private_0(uint64_t ignore) {
    (void)ignore;
    /* No-op: We don't need logging for ed25519 operations */
}

void fd_log_private_1(uint64_t ignore1, void* ignore2) {
    (void)ignore1;
    (void)ignore2;
    /* No-op: We don't need logging for ed25519 operations */
}

long fd_log_wallclock(void) {
    /* Return a dummy value */
    return 0;
}
