/**
 * @file process_hardening.cpp
 * @brief Implementation of process hardening utilities
 *
 * @see process_hardening.h for API documentation
 */

#include "process_hardening.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>
#include <cerrno>
#include <stdexcept>

#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <unistd.h>

/**
 * @brief Check if a debugger is attached by reading TracerPid
 *
 * Linux maintains TracerPid in /proc/self/status.
 * A value of 0 means no debugger, non-zero is the PID of the tracer.
 */
bool is_debugger_attached() {
    std::ifstream status("/proc/self/status");
    if (!status.is_open()) {
        return false;  // Can't determine, assume safe
    }

    std::string line;
    while (std::getline(status, line)) {
        if (line.compare(0, 10, "TracerPid:") == 0) {
            int tracer_pid = std::stoi(line.substr(10));
            return tracer_pid != 0;
        }
    }
    return false;
}

/**
 * @brief Assert no debugger is attached, throw if detected
 */
void assert_no_debugger() {
    if (is_debugger_attached()) {
        throw std::runtime_error("Debugger detected - aborting for security");
    }
}

/**
 * @brief Apply all process hardening measures
 *
 * This function applies multiple layers of protection:
 *
 * 1. PR_SET_DUMPABLE=0
 *    - Prevents core dump generation on crash
 *    - Restricts /proc/<pid>/mem access (requires CAP_SYS_PTRACE)
 *    - Restricts ptrace attach from non-root processes
 *
 * 2. RLIMIT_CORE=0
 *    - Defense in depth: also prevent core dumps via resource limit
 *
 * 3. PR_SET_PTRACER
 *    - On systems with Yama LSM, restricts ptrace attachment
 *    - Value of 0 means no process can ptrace us
 *
 * 4. mlockall(MCL_CURRENT | MCL_FUTURE)
 *    - Locks all current and future memory pages
 *    - Prevents memory from being swapped to disk
 *    - Requires CAP_IPC_LOCK or sufficient RLIMIT_MEMLOCK
 */
HardeningResult harden_process(const HardeningOptions& opts) {
    HardeningResult result;
    std::ostringstream errors;

    // =========================================================================
    // Layer 1: Disable core dumps and /proc/pid/mem access
    // =========================================================================
    if (opts.disable_dumps) {
        /*
         * PR_SET_DUMPABLE = 0 has multiple effects:
         *
         * 1. Core dumps are not generated on crashes
         * 2. /proc/<pid>/mem becomes unreadable except by processes with
         *    CAP_SYS_PTRACE capability
         * 3. ptrace() attach is restricted to processes with CAP_SYS_PTRACE
         *
         * This is the single most important hardening measure.
         */
        if (prctl(PR_SET_DUMPABLE, 0) == 0) {
            result.dumps_disabled = true;
        } else {
            errors << "PR_SET_DUMPABLE failed: " << strerror(errno) << "; ";
        }

        /*
         * Also set RLIMIT_CORE to 0 as defense in depth.
         * This prevents core dumps even if PR_SET_DUMPABLE is somehow bypassed.
         */
        struct rlimit core_limit = {0, 0};
        if (setrlimit(RLIMIT_CORE, &core_limit) != 0) {
            errors << "RLIMIT_CORE failed: " << strerror(errno) << "; ";
        }
    }

    // =========================================================================
    // Layer 2: Restrict ptrace attachment
    // =========================================================================
    if (opts.disable_ptrace) {
        /*
         * PR_SET_PTRACER with value 0 means no process can ptrace us.
         *
         * This works on systems with Yama LSM enabled (default on Ubuntu).
         * On systems without Yama, this call may fail with EINVAL, but
         * PR_SET_DUMPABLE=0 provides similar protection.
         *
         * Yama ptrace_scope levels:
         * 0 = classic ptrace permissions (any process can ptrace)
         * 1 = restricted ptrace (only parent can ptrace)
         * 2 = admin-only ptrace (requires CAP_SYS_PTRACE)
         * 3 = no ptrace (completely disabled)
         */
#ifdef PR_SET_PTRACER
        if (prctl(PR_SET_PTRACER, 0) == 0) {
            result.ptrace_disabled = true;
        } else {
            // EINVAL typically means Yama LSM isn't enabled
            // This is OK - PR_SET_DUMPABLE provides similar protection
            if (errno != EINVAL) {
                errors << "PR_SET_PTRACER failed: " << strerror(errno) << "; ";
            } else {
                // Rely on PR_SET_DUMPABLE for ptrace protection
                result.ptrace_disabled = result.dumps_disabled;
            }
        }
#else
        // PR_SET_PTRACER not available on this system
        // Rely on PR_SET_DUMPABLE for protection
        result.ptrace_disabled = result.dumps_disabled;
#endif
    }

    // =========================================================================
    // Layer 3: Lock memory to prevent swapping
    // =========================================================================
    if (opts.lock_memory) {
        /*
         * mlockall() locks all current and future memory pages in RAM.
         * This prevents sensitive data from being written to swap.
         *
         * MCL_CURRENT: Lock all pages currently mapped
         * MCL_FUTURE: Lock all pages mapped in the future
         *
         * This requires either:
         * - CAP_IPC_LOCK capability, or
         * - RLIMIT_MEMLOCK set high enough for the process's memory usage
         *
         * On most systems, unprivileged processes have a small MEMLOCK limit
         * (e.g., 64KB), which may cause mlockall() to fail.
         */

        // Try to increase memory lock limit (best effort)
        struct rlimit memlock_limit;
        if (getrlimit(RLIMIT_MEMLOCK, &memlock_limit) == 0) {
            // Attempt to set unlimited (requires CAP_SYS_RESOURCE or root)
            struct rlimit new_limit = {RLIM_INFINITY, RLIM_INFINITY};
            setrlimit(RLIMIT_MEMLOCK, &new_limit);  // Ignore failure
        }

        // Lock all memory
        if (mlockall(MCL_CURRENT | MCL_FUTURE) == 0) {
            result.memory_locked = true;
        } else {
            /*
             * mlockall() commonly fails without elevated privileges.
             * This is not critical because:
             * 1. SecureBuffer uses mlock() for individual sensitive allocations
             * 2. The brief operation window minimizes exposure
             */
            errors << "mlockall failed: " << strerror(errno)
                   << " (individual secrets still protected via mlock); ";
        }
    }

    // =========================================================================
    // Layer 4: Anti-debug measures
    // =========================================================================
    if (opts.anti_debug) {
        /*
         * First check if a debugger is already attached.
         * TracerPid in /proc/self/status will be non-zero if traced.
         */
        if (is_debugger_attached()) {
            result.debugger_detected = true;
            errors << "DEBUGGER DETECTED - security compromised; ";

            /*
             * PRODUCTION: Uncomment to abort when debugger detected
             *
             * std::cerr << "FATAL: Debugger detected - aborting for security" << std::endl;
             * std::abort();
             */
        }

        /*
         * PTRACE_TRACEME makes this process trace itself.
         * Side effect: no other process can ptrace us (only one tracer allowed).
         *
         * If a debugger is already attached, this will fail with EPERM.
         * This serves as both detection and prevention.
         */
        if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) == 0) {
            result.anti_debug_active = true;
        } else {
            if (errno == EPERM) {
                // Already being traced (debugger attached)
                result.debugger_detected = true;
                errors << "PTRACE_TRACEME failed (debugger attached?); ";

                /*
                 * PRODUCTION: Uncomment to abort when debugger detected
                 *
                 * std::cerr << "FATAL: Debugger detected - aborting for security" << std::endl;
                 * std::abort();
                 */
            } else {
                errors << "PTRACE_TRACEME failed: " << strerror(errno) << "; ";
            }
        }
    }

    result.error_message = errors.str();
    return result;
}

/**
 * @brief Query current hardening status
 *
 * Checks the current state of hardening measures by querying
 * system APIs. Useful for verification and debugging.
 */
HardeningResult check_hardening_status() {
    HardeningResult result;

    // Check if process is dumpable
    int dumpable = prctl(PR_GET_DUMPABLE);
    result.dumps_disabled = (dumpable == 0);

    // Check memory lock limits (approximate check)
    struct rlimit memlock_limit;
    if (getrlimit(RLIMIT_MEMLOCK, &memlock_limit) == 0) {
        // Consider memory locked if limit is very high or unlimited
        result.memory_locked = (memlock_limit.rlim_cur == RLIM_INFINITY) ||
                               (memlock_limit.rlim_cur > 64 * 1024 * 1024);
    }

    // ptrace status is tied to dumpable on most systems
    result.ptrace_disabled = result.dumps_disabled;

    // Check for debugger
    result.debugger_detected = is_debugger_attached();

    return result;
}

/**
 * @brief Display hardening status in human-readable format
 */
void print_hardening_status(const HardeningResult& result) {
    std::cout << "Process Hardening Status:" << std::endl;

    std::cout << "  Core dumps disabled:  "
              << (result.dumps_disabled ? "YES" : "NO") << std::endl;

    std::cout << "  Ptrace restricted:    "
              << (result.ptrace_disabled ? "YES" : "NO") << std::endl;

    std::cout << "  Memory locked:        "
              << (result.memory_locked ? "YES" : "NO (secrets still mlock'd individually)")
              << std::endl;

    std::cout << "  Anti-debug active:    "
              << (result.anti_debug_active ? "YES" : "NO") << std::endl;

    if (result.debugger_detected) {
        std::cout << "  *** WARNING: DEBUGGER DETECTED ***" << std::endl;
    }

    if (!result.error_message.empty()) {
        std::cout << "  Notes: " << result.error_message << std::endl;
    }
}
