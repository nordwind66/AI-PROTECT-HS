cmake_minimum_required(VERSION 3.16)
project(ai_prompt_guard VERSION 1.0.0 LANGUAGES C CXX)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# ------------------------------------------------------------------------------------------------------------
# Options
# ------------------------------------------------------------------------------------------------------------
option(APG_WITH_HYPERSCAN "Use Hyperscan as the matching engine (production). OFF builds only the explicit pcre2_fallback backend" ON)
option(APG_BUILD_CLI      "Build the ai-prompt-guard command line tool (needs SQLite3)" ON)
option(APG_BUILD_TESTS    "Build the C++ unit tests and register the CTest tests" ON)
option(APG_BUILD_EXAMPLES "Build the C / C++ / dlopen / LoadLibrary examples" ON)
option(APG_STATIC_DEPS    "Linux: link Hyperscan, PCRE2, libstdc++ and libgcc statically into libai_prompt_guard.so (and the CLI), so the target machine needs only glibc. Needs libhs.a / libpcre2-8.a built with -fPIC. Use a fresh build directory when changing this option" OFF)
option(APG_STATIC_RUNTIME "MSVC: link the static CRT (/MT) instead of the DLL CRT (/MD)" OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)
set(CMAKE_VISIBILITY_INLINES_HIDDEN ON)

# One flat output directory on every platform: <build>/bin holds the shared library (.so / .dll), the CLI, the tests and the
# examples side by side (on Windows the DLL must be next to the executables that load it); static archives and the DLL
# import library go to <build>/lib. Multi-config generators (Visual Studio) append the configuration: <build>/bin/Release.
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
if(MSVC AND APG_STATIC_RUNTIME)
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

# ------------------------------------------------------------------------------------------------------------
# Dependencies (nothing is installed by this build; missing pieces produce a clear error)
# ------------------------------------------------------------------------------------------------------------
find_package(Threads REQUIRED)
find_package(PCRE2 REQUIRED)
if(APG_WITH_HYPERSCAN)
  find_package(Hyperscan REQUIRED)
endif()
if(APG_BUILD_CLI OR APG_BUILD_TESTS)
  find_package(SQLite3 REQUIRED)
endif()

# ------------------------------------------------------------------------------------------------------------
# Engine sources: the SAME files build the shared library (DLL / .so) and the static library used by the CLI
# ------------------------------------------------------------------------------------------------------------
set(APG_ENGINE_SOURCES
  engine/core/fileio.cpp
  engine/core/sha256.cpp
  engine/core/utf8.cpp
  engine/core/json.cpp
  engine/core/normalize.cpp
  engine/core/pcre2_set.cpp
  engine/core/pcre_backend.cpp
  engine/core/hs_backend.cpp
  engine/core/config.cpp
  engine/core/scanner.cpp
  engine/ruleset/ruleset_model.cpp
  engine/ruleset/loaded_ruleset.cpp
  engine/ruleset/manifest.cpp
  engine/api/engine.cpp
  engine/api/apg_api.cpp)

function(apg_configure target vis)
  target_compile_features(${target} PUBLIC cxx_std_17)
  target_include_directories(${target} PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)
  target_link_libraries(${target} ${vis} PCRE2::8BIT Threads::Threads)
  if(APG_WITH_HYPERSCAN)
    target_compile_definitions(${target} ${vis} APG_WITH_HYPERSCAN=1)
    target_link_libraries(${target} ${vis} Hyperscan::hs)
  endif()
  if(MSVC)
    target_compile_options(${target} PRIVATE /utf-8 /W4 /permissive- /Zc:__cplusplus /EHsc)
    target_compile_definitions(${target} PRIVATE _CRT_SECURE_NO_WARNINGS NOMINMAX)
  else()
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wno-unused-parameter)
  endif()
  if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9.1)
    target_link_libraries(${target} ${vis} stdc++fs)   # std::filesystem on GCC 8 (RHEL 8)
  endif()
endfunction()

# static library: used by the CLI and the tests (and shipped as libai_prompt_guard.a on Linux)
add_library(apg_core_static STATIC ${APG_ENGINE_SOURCES})
apg_configure(apg_core_static PUBLIC)
target_compile_definitions(apg_core_static PUBLIC APG_STATIC)
if(WIN32)
  set_target_properties(apg_core_static PROPERTIES OUTPUT_NAME ai_prompt_guard_static)
else()
  set_target_properties(apg_core_static PROPERTIES OUTPUT_NAME ai_prompt_guard)
endif()

# shared library: ai_prompt_guard.dll + ai_prompt_guard.lib (Windows) / libai_prompt_guard.so (Linux)
add_library(ai_prompt_guard SHARED ${APG_ENGINE_SOURCES})
apg_configure(ai_prompt_guard PRIVATE)
target_compile_definitions(ai_prompt_guard PRIVATE APG_BUILD_DLL)
set_target_properties(ai_prompt_guard PROPERTIES
  OUTPUT_NAME ai_prompt_guard VERSION ${PROJECT_VERSION} SOVERSION 1
  CXX_VISIBILITY_PRESET hidden VISIBILITY_INLINES_HIDDEN ON)
if(APG_STATIC_DEPS AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
  # the C++ runtime travels inside the library too; --exclude-libs keeps the archived Hyperscan / PCRE2 symbols private
  target_link_options(ai_prompt_guard PRIVATE -static-libstdc++ -static-libgcc "LINKER:--exclude-libs,ALL")
endif()
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  target_link_options(ai_prompt_guard PRIVATE "LINKER:--version-script=${CMAKE_CURRENT_SOURCE_DIR}/engine/api/exports.map")
endif()

# ------------------------------------------------------------------------------------------------------------
# Build-time tooling (compiler for rule sets, CLI): needs SQLite, is NOT part of the runtime library
# ------------------------------------------------------------------------------------------------------------
if(APG_BUILD_CLI OR APG_BUILD_TESTS)
  add_library(apg_build STATIC engine/ruleset/compiler.cpp engine/storage/sqlite_store.cpp)
  apg_configure(apg_build PUBLIC)
  target_link_libraries(apg_build PUBLIC apg_core_static SQLite::SQLite3)
endif()

if(APG_BUILD_CLI)
  add_executable(ai-prompt-guard cli/main.cpp cli/bench.cpp)
  apg_configure(ai-prompt-guard PRIVATE)
  target_link_libraries(ai-prompt-guard PRIVATE apg_build apg_core_static)
  if(APG_STATIC_DEPS AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_options(ai-prompt-guard PRIVATE -static-libstdc++ -static-libgcc)
  endif()
  if(MINGW)
    target_link_options(ai-prompt-guard PRIVATE -municode)
  endif()
endif()

# ------------------------------------------------------------------------------------------------------------
# Tests
# ------------------------------------------------------------------------------------------------------------
if(APG_BUILD_TESTS)
  enable_testing()
  add_executable(apg_tests tests/cpp/test_main.cpp tests/cpp/test_core.cpp tests/cpp/test_engine.cpp)
  apg_configure(apg_tests PRIVATE)
  target_link_libraries(apg_tests PRIVATE apg_build apg_core_static)
  target_compile_definitions(apg_tests PRIVATE APG_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}")
  add_test(NAME cpp_unit COMMAND apg_tests WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

  find_package(Python3 COMPONENTS Interpreter QUIET)
  if(Python3_Interpreter_FOUND)
    add_test(NAME python_unit
      COMMAND ${Python3_EXECUTABLE} -X utf8 -m unittest discover -s tests/python -v
      WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
    if(APG_BUILD_CLI)
      if(APG_WITH_HYPERSCAN)
        set(APG_E2E_BACKEND hyperscan)
      else()
        set(APG_E2E_BACKEND pcre2_fallback)
      endif()
      add_test(NAME e2e_compile_scan
        COMMAND ${Python3_EXECUTABLE} -X utf8 tests/e2e/run_e2e.py --cli $<TARGET_FILE:ai-prompt-guard>
                --workdir ${CMAKE_CURRENT_BINARY_DIR}/e2e --backend ${APG_E2E_BACKEND} --clean
                --lib $<TARGET_FILE:ai_prompt_guard> --examples-dir $<TARGET_FILE_DIR:ai-prompt-guard>
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
      set_tests_properties(e2e_compile_scan PROPERTIES TIMEOUT 3600)
    endif()
  endif()
endif()

# ------------------------------------------------------------------------------------------------------------
# Examples
# ------------------------------------------------------------------------------------------------------------
if(APG_BUILD_EXAMPLES)
  add_subdirectory(examples)
endif()

# ------------------------------------------------------------------------------------------------------------
# Install
# ------------------------------------------------------------------------------------------------------------
include(GNUInstallDirs)
install(TARGETS ai_prompt_guard
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(TARGETS apg_core_static ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES include/ai_prompt_guard.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
if(APG_BUILD_CLI)
  install(TARGETS ai-prompt-guard RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

message(STATUS "ai_prompt_guard ${PROJECT_VERSION}: Hyperscan=${APG_WITH_HYPERSCAN} CLI=${APG_BUILD_CLI} tests=${APG_BUILD_TESTS} examples=${APG_BUILD_EXAMPLES}")
