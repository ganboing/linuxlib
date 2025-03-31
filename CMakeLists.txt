cmake_minimum_required(VERSION 3.5)

project(linuxlib)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE -save-temps=obj -std=gnu++17 \
-fno-strict-aliasing \
-fno-exceptions \
-ffunction-sections \
-fdata-sections \
-fvisibility=hidden \
-Wall \
-Wno-multichar \
-Wno-reorder \
-Wno-pessimizing-move \
-Werror=maybe-uninitialized")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE -save-temps=obj -std=gnu11 \
-fno-strict-aliasing \
-ffunction-sections \
-fdata-sections \
-fvisibility=hidden \
-Wall \
-Wno-multichar")

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -D_FORTIFY_SOURCE=2")
set(CMAKE_CXX_FLAGS_RELASAN "${CMAKE_CXX_FLAGS_RELASAN} -D_FORTIFY_SOURCE=2")

set(CMAKE_EXE_LINKER_FLAGS -Wl,--gc-sections)

include(cmake/FindAsan.cmake)
include(GNUInstallDirs)

message("CMAKE_SHARED_LIBRARY_LINK_C_FLAGS = ${CMAKE_SHARED_LIBRARY_LINK_C_FLAGS}, will be mitigated")
set(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "${CMAKE_SHARED_LIBRARY_LINK_C_FLAGS} -Wl,--no-export-dynamic")
message("CMAKE_SHARED_LIBRARY_LINK_CXX_FLAGS = ${CMAKE_SHARED_LIBRARY_LINK_CXX_FLAGS}, will be mitigated")
set(CMAKE_SHARED_LIBRARY_LINK_CXX_FLAGS "${CMAKE_SHARED_LIBRARY_LINK_CXX_FLAGS} -Wl,--no-export-dynamic")

cmake_policy(SET CMP0074 NEW)

add_subdirectory(perftool)
add_subdirectory(utilities)
add_subdirectory(net)
