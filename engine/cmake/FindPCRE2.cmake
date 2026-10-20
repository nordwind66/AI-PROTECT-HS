# FindPCRE2.cmake -- locate PCRE2 (8-bit library) and expose the imported target PCRE2::8BIT.
#
# Search order: -DPCRE2_ROOT=<prefix>, pkg-config (libpcre2-8), CMAKE_PREFIX_PATH / system paths.
# Result variables: PCRE2_FOUND, PCRE2_INCLUDE_DIR, PCRE2_LIBRARY

find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
  pkg_check_modules(PC_PCRE2 QUIET libpcre2-8)
endif()

find_path(PCRE2_INCLUDE_DIR
  NAMES pcre2.h
  HINTS ${PCRE2_ROOT}/include $ENV{PCRE2_ROOT}/include ${PC_PCRE2_INCLUDE_DIRS})

# APG_STATIC_DEPS (Linux): link the static archive into the shared library
if(APG_STATIC_DEPS)
  set(_pcre2_names libpcre2-8.a pcre2-8-static)
else()
  set(_pcre2_names pcre2-8 pcre2-8-static pcre2-8d)
endif()
find_library(PCRE2_LIBRARY
  NAMES ${_pcre2_names}
  HINTS ${PCRE2_ROOT}/lib $ENV{PCRE2_ROOT}/lib ${PC_PCRE2_LIBRARY_DIRS})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(PCRE2 REQUIRED_VARS PCRE2_LIBRARY PCRE2_INCLUDE_DIR)

if(PCRE2_FOUND AND NOT TARGET PCRE2::8BIT)
  add_library(PCRE2::8BIT UNKNOWN IMPORTED)
  set_target_properties(PCRE2::8BIT PROPERTIES
    IMPORTED_LOCATION "${PCRE2_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${PCRE2_INCLUDE_DIR}")
  # a static PCRE2 needs this define on Windows
  if(WIN32 AND PCRE2_LIBRARY MATCHES "static")
    set_property(TARGET PCRE2::8BIT APPEND PROPERTY INTERFACE_COMPILE_DEFINITIONS PCRE2_STATIC)
  endif()
endif()
mark_as_advanced(PCRE2_INCLUDE_DIR PCRE2_LIBRARY)
