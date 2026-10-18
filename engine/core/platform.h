// Compile-time platform identification (first release: x86-64 only; ARM64 / 32-bit / macOS are NOT supported).
#pragma once

#if defined(_WIN32)
#  define APG_OS_NAME "windows"
#elif defined(__linux__)
#  define APG_OS_NAME "linux"
#else
#  define APG_OS_NAME "other"
#endif

#if defined(__x86_64__) || defined(_M_X64) || defined(__amd64__)
#  define APG_ARCH_NAME "x86_64"
#else
#  define APG_ARCH_NAME "other"
#endif
