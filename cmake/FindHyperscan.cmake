# FindHyperscan.cmake -- locate Intel Hyperscan (libhs) and expose the imported target Hyperscan::hs.
#
# Search order: -DHYPERSCAN_ROOT=<prefix> / $ENV{HYPERSCAN_ROOT}, pkg-config (libhs), CMAKE_PREFIX_PATH / system paths
# (vcpkg and distro packages install <prefix>/include/hs/hs.h and <prefix>/lib/libhs.*).
#
# Result variables: Hyperscan_FOUND, Hyperscan_INCLUDE_DIR, Hyperscan_LIBRARY

find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
  pkg_check_modules(PC_HS QUIET libhs)
endif()

find_path(Hyperscan_INCLUDE_DIR
  NAMES hs/hs.h
  HINTS ${HYPERSCAN_ROOT}/include $ENV{HYPERSCAN_ROOT}/include ${PC_HS_INCLUDE_DIRS})

find_library(Hyperscan_LIBRARY
  NAMES hs libhs hs_static
  HINTS ${HYPERSCAN_ROOT}/lib $ENV{HYPERSCAN_ROOT}/lib ${PC_HS_LIBRARY_DIRS})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Hyperscan REQUIRED_VARS Hyperscan_LIBRARY Hyperscan_INCLUDE_DIR)

if(Hyperscan_FOUND AND NOT TARGET Hyperscan::hs)
  add_library(Hyperscan::hs UNKNOWN IMPORTED)
  set_target_properties(Hyperscan::hs PROPERTIES
    IMPORTED_LOCATION "${Hyperscan_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${Hyperscan_INCLUDE_DIR}")
endif()
mark_as_advanced(Hyperscan_INCLUDE_DIR Hyperscan_LIBRARY)
