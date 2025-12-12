/**
 * @file process_hardening.h
 * @brief Process hardening utilities for sensitive operations
 *
 * This module provides functions to harden a process against memory inspection
 * attacks. It should be called early in main() before any secrets are loaded.
 *
 * ## Protections Applied
 *
 * 1. **PR_SET_DUMPABLE=0**: Prevents core dumps and restricts /proc/pid/mem access
 * 2. **PR_SET_PTRACER**: Restricts which processes can ptrace this process
 * 3. **mlockall**: Locks all memory pages to prevent swapping to disk
 * 4. **RLIMIT_CORE=0**: Additional core dump prevention
 *
 * ## Effective Against
 *
 * - Core dump analysis after crashes
 * - /proc/<pid>/mem reading (requires CAP_SYS_PTRACE when non-dumpable)
 * - ptrace attach from other processes
 * - Memory pages being written to swap
 * - GDB/debugger attachment
 *
 * ## NOT Effective Against
 *
 * - Root with CAP_SYS_PTRACE (can still read memory during operation)
 * - Kernel modules with direct memory access
 * - Physical memory attacks (cold boot, DMA)
 *
 * ## Usage
 *
 * @code
 * int main() {
 *     // Apply hardening FIRST, before any secrets
 *     auto result = harden_process();
 *     print_hardening_status(result);
 *
 *     // Now safe to load secrets...
 *     KeyVault vault(...);
 * }
 * @endcode
 *
 * @see CONCEPT_DOCUMENTATION.md for full security architecture
 */

#pragma once

#include <string>

/**
 * @brief Options for process hardening
 *
 * All options default to true for maximum protection.
 * Disable specific options only if you understand the security implications.
 */
struct HardeningOptions {
    /** Prevent core dumps and /proc/mem access */
    bool disable_dumps = true;

    /** Prevent ptrace attach from other processes */
    bool disable_ptrace = true;

    /**
     * Lock all memory pages (prevent swapping)
     * @note Requires CAP_IPC_LOCK or sufficient RLIMIT_MEMLOCK
     */
    bool lock_memory = true;

    /** Reserved for future use */
    size_t memory_lock_limit = 0;
};

/**
 * @brief Result of hardening operations
 *
 * Check individual fields to verify which protections were applied.
 * Some protections may fail without elevated privileges.
 */
struct HardeningResult {
    /** True if core dumps are disabled */
    bool dumps_disabled = false;

    /** True if ptrace is restricted */
    bool ptrace_disabled = false;

    /** True if memory is locked (mlockall succeeded) */
    bool memory_locked = false;

    /** Error messages for any failed operations */
    std::string error_message;
};

/**
 * @brief Apply process hardening measures
 *
 * Should be called early in main(), before loading any secrets.
 * This function applies multiple layers of protection to make it
 * harder for attackers to inspect process memory.
 *
 * @param opts Hardening options (defaults to all protections enabled)
 * @return HardeningResult indicating which protections were applied
 *
 * @note Some protections may fail without root/capabilities, but the
 *       function will continue and report partial success.
 *
 * @code
 * int main() {
 *     HardeningResult result = harden_process();
 *     if (!result.dumps_disabled) {
 *         // Handle reduced security...
 *     }
 * }
 * @endcode
 */
HardeningResult harden_process(const HardeningOptions& opts = {});

/**
 * @brief Check current hardening status
 *
 * Query the current process to determine which hardening measures
 * are currently active.
 *
 * @return HardeningResult with current status
 */
HardeningResult check_hardening_status();

/**
 * @brief Print hardening status to stdout
 *
 * Utility function to display the hardening status in a human-readable format.
 *
 * @param result The hardening result to display
 */
void print_hardening_status(const HardeningResult& result);
