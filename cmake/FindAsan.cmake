#
# The MIT License (MIT)
#
# Copyright (c) 2013 Matthew Arsenault
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#
# This module tests if address sanitizer is supported by the compiler,
# and creates a ASan build type (i.e. set CMAKE_BUILD_TYPE=ASan to use
# it). This sets the following variables:
#
# CMAKE_C_FLAGS_ASAN - Flags to use for C with asan
# CMAKE_CXX_FLAGS_ASAN  - Flags to use for C++ with asan
# HAVE_ADDRESS_SANITIZER - True or false if the ASan build type is available

include(CheckCCompilerFlag)

set(CMAKE_REQUIRED_LIBRARIES -lrt)
set(CMAKE_REQUIRED_FLAGS "-Werror -fsanitize=address") # Also needs to be a link flag for test to pass
check_c_compiler_flag("-fsanitize=address" HAVE_FLAG_SANITIZE_ADDRESS)

unset(CMAKE_REQUIRED_FLAGS)
unset(CMAKE_REQUIRED_LIBRARIES)

if(HAVE_FLAG_SANITIZE_ADDRESS)
  set(ADDRESS_SANITIZER_FLAG "-fsanitize=address")
else()
  return()
endif()

set(HAVE_ADDRESS_SANITIZER TRUE)

set(CMAKE_C_FLAGS_DEBUGASAN "${CMAKE_C_FLAGS_DEBUG} ${ADDRESS_SANITIZER_FLAG}"
    CACHE STRING "Flags used by the C compiler during Debug+ASan builds."
    FORCE)
set(CMAKE_CXX_FLAGS_DEBUGASAN "${CMAKE_CXX_FLAGS_DEBUG} ${ADDRESS_SANITIZER_FLAG}"
    CACHE STRING "Flags used by the C++ compiler during Debug+ASan builds."
    FORCE)
set(CMAKE_EXE_LINKER_FLAGS_DEBUGASAN "${CMAKE_EXE_LINKER_FLAGS_DEBUG} ${ADDRESS_SANITIZER_FLAG} -lrt"
    CACHE STRING "Flags used for linking binaries during Debug+ASan builds."
    FORCE)
set(CMAKE_SHARED_LINKER_FLAGS_DEBUGASAN "${CMAKE_SHARED_LINKER_FLAGS_DEBUG} ${ADDRESS_SANITIZER_FLAG} -lrt"
    CACHE STRING "Flags used by the shared libraries linker during Debug+ASan builds."
    FORCE)
mark_as_advanced(CMAKE_C_FLAGS_DEBUGASAN
    CMAKE_CXX_FLAGS_DEBUGASAN
    CMAKE_EXE_LINKER_FLAGS_DEBUGASAN
    CMAKE_SHARED_LINKER_FLAGS_DEBUGASAN)

set(CMAKE_C_FLAGS_RELASAN "${CMAKE_C_FLAGS_RELEASE} ${ADDRESS_SANITIZER_FLAG}"
    CACHE STRING "Flags used by the C compiler during Release+ASan builds."
    FORCE)
set(CMAKE_CXX_FLAGS_RELASAN "${CMAKE_CXX_FLAGS_RELEASE} ${ADDRESS_SANITIZER_FLAG}"
    CACHE STRING "Flags used by the C++ compiler during Release+ASan builds."
    FORCE)
set(CMAKE_EXE_LINKER_FLAGS_RELASAN "${CMAKE_EXE_LINKER_FLAGS_RELEASE} ${ADDRESS_SANITIZER_FLAG} -lrt"
    CACHE STRING "Flags used for linking binaries during Release+ASan builds."
    FORCE)
set(CMAKE_SHARED_LINKER_FLAGS_RELASAN "${CMAKE_SHARED_LINKER_FLAGS_RELEASE} ${ADDRESS_SANITIZER_FLAG} -lrt"
    CACHE STRING "Flags used by the shared libraries linker during Release+ASan builds."
    FORCE)
mark_as_advanced(CMAKE_C_FLAGS_RELASAN
    CMAKE_CXX_FLAGS_RELASAN
    CMAKE_EXE_LINKER_FLAGS_RELASAN
    CMAKE_SHARED_LINKER_FLAGS_RELASAN)
