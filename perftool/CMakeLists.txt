execute_process(
        COMMAND sed -n "s/ *\\(if\\|ifn\\)def NO_\\(.*\\)/NO_\\2=1/p" Makefile.config
        COMMAND sort
        COMMAND uniq
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}/linux/tools/perf"
        OUTPUT_VARIABLE PERFTOOL_MAKE_OPTS
)

separate_arguments(PERFTOOL_MAKE_OPTS UNIX_COMMAND "${PERFTOOL_MAKE_OPTS}")

if ("${CMAKE_BUILD_TYPE}" STREQUAL "")
    set(PERFTOOL_BUILD_TYPE "DEBUG")
else()
    string(TOUPPER "${CMAKE_BUILD_TYPE}" PERFTOOL_BUILD_TYPE)
endif()

set(PERFTOOL_VERSION "0.0.1" CACHE STRING "version string of perftool")
set(PERFTOOL_LIBNAME "perftool" CACHE STRING "library file name of perftool")
set(PERFTOOL_SO "lib${PERFTOOL_LIBNAME}.so")
set(PERFTOOL_SONAME "lib${PERFTOOL_LIBNAME}.so.${PERFTOOL_VERSION}")

set(PERFTOOL_CFLAGS
        "-fPIC"
)
if (PERFTOOL_BUILD_TYPE MATCHES ".*ASAN$")
    list(APPEND PERFTOOL_CFLAGS "-fsanitize=address")
endif()

list(JOIN PERFTOOL_CFLAGS " " PERFTOOL_EXTRA_CFLAGS)

set(PERFTOOL_LIBS
        "-shared"
        "-Wl,-soname,${PERFTOOL_SONAME}"
        "-Xlinker"
        "--version-script=${CMAKE_CURRENT_SOURCE_DIR}/perftool_ver.txt"
)
list(JOIN PERFTOOL_LIBS " " PERFTOOL_EXTRA_PERFLIBS)

list(APPEND PERFTOOL_MAKE_OPTS "EXTRA_CFLAGS=${PERFTOOL_EXTRA_CFLAGS}")
list(APPEND PERFTOOL_MAKE_OPTS "EXTRA_PERFLIBS=${PERFTOOL_EXTRA_PERFLIBS}")
list(APPEND PERFTOOL_MAKE_OPTS "CC=${CMAKE_C_COMPILER}")

if (PERFTOOL_BUILD_TYPE MATCHES "^DEBUG.*")
    list(APPEND PERFTOOL_MAKE_OPTS "DEBUG=1")
endif()

message("Using PERFTOOL_MAKE_OPTS - ${PERFTOOL_MAKE_OPTS}")

set(PERFTOOL_OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/perf-build")

add_custom_command(
        OUTPUT perf-build/perf
        COMMAND mkdir -p "${PERFTOOL_OUTPUT}"
        COMMAND make "O=${PERFTOOL_OUTPUT}" ${PERFTOOL_MAKE_OPTS}
        BYPRODUCTS "${PERFTOOL_OUTPUT}"
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}/linux/tools/perf"
        VERBATIM
)
add_custom_target(build_perf DEPENDS perf-build/perf)

add_custom_command(
        OUTPUT ${PERFTOOL_SONAME}
        COMMAND ln perf-build/perf ${PERFTOOL_SONAME}
        DEPENDS perf-build/perf build_perf
        VERBATIM
)
add_custom_target(link_lib_soname DEPENDS ${PERFTOOL_SONAME})

add_custom_command(
        OUTPUT ${PERFTOOL_SO}
        COMMAND ln -s ${PERFTOOL_SONAME} ${PERFTOOL_SO}
        DEPENDS ${PERFTOOL_SONAME} link_lib_soname
        VERBATIM
)
add_custom_target(link_lib_so DEPENDS ${PERFTOOL_SO})

set(PERFEXE_FLAGS
        "-Wl,-rpath"
        "-Wl,\$ORIGIN/../${CMAKE_INSTALL_LIBDIR}"
        "-L."
        "-l${PERFTOOL_LIBNAME}"
)
if (PERFTOOL_BUILD_TYPE MATCHES ".*ASAN$")
    list(APPEND PERFEXE_FLAGS "-fsanitize=address")
endif()

add_custom_command(
        OUTPUT perf.exe
        COMMAND "${CMAKE_C_COMPILER}" -o perf.exe ${PERFEXE_FLAGS}
        DEPENDS ${PERFTOOL_SO} link_lib_so
        VERBATIM
)
add_custom_target(build_perf_exe DEPENDS perf.exe)

add_executable(perf_mock perf_mock.cpp)
add_dependencies(perf_mock link_lib_so build_perf_exe)
target_link_directories(perf_mock PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
target_link_libraries(perf_mock -l${PERFTOOL_LIBNAME})
set_target_properties(perf_mock PROPERTIES
        INSTALL_RPATH "\$ORIGIN/../${CMAKE_INSTALL_LIBDIR}"
)

file(GLOB PERFTOOL_HEADERS "${CMAKE_CURRENT_SOURCE_DIR}/*.h")
foreach(header ${PERFTOOL_HEADERS})
    get_filename_component(PERFTOOL_HDR_NAME "${header}" NAME)
    get_filename_component(PERFTOOL_HDR_REALPATH "${header}" REALPATH)
    install(FILES "${PERFTOOL_HDR_REALPATH}"
            DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/linuxlib"
            RENAME "${PERFTOOL_HDR_NAME}"
    )
endforeach()

install(FILES
            "${CMAKE_CURRENT_BINARY_DIR}/${PERFTOOL_SONAME}"
            "${CMAKE_CURRENT_BINARY_DIR}/${PERFTOOL_SO}"
        DESTINATION ${CMAKE_INSTALL_LIBDIR}
        PERMISSIONS OWNER_EXECUTE OWNER_READ GROUP_EXECUTE GROUP_READ WORLD_EXECUTE WORLD_READ
)

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/perf.exe"
        DESTINATION ${CMAKE_INSTALL_BINDIR}
        RENAME perf
        PERMISSIONS OWNER_EXECUTE OWNER_READ GROUP_EXECUTE GROUP_READ WORLD_EXECUTE WORLD_READ
)

install(TARGETS perf_mock
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
