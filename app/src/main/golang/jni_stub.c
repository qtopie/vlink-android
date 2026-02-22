// +build linux,!android

#include <stdio.h>

// Provide a C stub for protect_fd so linker succeeds on desktop Linux.
int protect_fd(int fd) {
    // Uncomment for debug: printf("[MOCK] protect_fd called for fd %d\n", fd);
    (void)fd;
    return 1; // success
}
