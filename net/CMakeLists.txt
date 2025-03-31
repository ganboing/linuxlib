add_library(ts_shim SHARED ts_shim.cpp interceptors.cpp context.cpp capture.cpp)
target_compile_options(ts_shim PRIVATE -Wno-ignored-attributes)
target_link_options(ts_shim PRIVATE -z now -Wl,--no-as-needed -lresolv -ldl)

add_library(ts_shim_x32 SHARED ts_shim.cpp interceptors.cpp context.cpp capture.cpp)
target_compile_options(ts_shim_x32 PRIVATE -mx32 -Wno-ignored-attributes)
target_link_options(ts_shim_x32 PRIVATE -mx32 -z now -Wl,--no-as-needed -lresolv -ldl)

add_executable(ts_dump ts_dump.cpp capture.cpp)
add_executable(ts_diff ts_diff.cpp capture.cpp)

install(TARGETS ts_shim ts_shim_x32 ts_dump ts_diff
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        )
