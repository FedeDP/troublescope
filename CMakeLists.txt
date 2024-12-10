cmake_minimum_required(VERSION 3.22)

if(NOT DEFINED CMAKE_BUILD_TYPE OR CMAKE_BUILD_TYPE STREQUAL "")
  set(CMAKE_BUILD_TYPE "release")
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules")

# compiler related configs
include(compiler)

# project metadata
project(
  troublescope
  VERSION 0.1.0
  DESCRIPTION "Falco diagnostic Plugin"
  LANGUAGES CXX)

# dependencies
include(plugin-sdk-cpp)

# vcpkg dependencies
find_package(spdlog CONFIG REQUIRED)
# libfuse is vcpkg installed but comes with pkg-config
find_package(PkgConfig REQUIRED)
pkg_check_modules(FUSE3 REQUIRED IMPORTED_TARGET fuse3)

file(GLOB_RECURSE SOURCES src/*.cpp)

# project target
add_library(troublescope SHARED ${SOURCES})
set_target_properties(troublescope PROPERTIES CXX_EXTENSIONS OFF)

# project compilation options
target_compile_options(troublescope PRIVATE "-fPIC")
target_compile_options(troublescope PRIVATE "-Wl,-z,relro,-z,now")
target_compile_options(troublescope PRIVATE "-fstack-protector-strong")
# When compiling in Debug mode, this will define the DEBUG symbol for use in
# your code.
target_compile_options(troublescope PUBLIC "$<$<CONFIG:DEBUG>:-DDEBUG>")
target_compile_features(troublescope PUBLIC cxx_std_17)

# project includes
target_include_directories(troublescope PRIVATE ${PLUGIN_SDK_INCLUDE}
                                                ${PLUGIN_SDK_DEPS_INCLUDE})

# project linked libraries
target_link_libraries(troublescope PRIVATE spdlog::spdlog_header_only
                                           PkgConfig::FUSE3)
