find_package(PkgConfig REQUIRED)

pkg_check_modules(LIBELF REQUIRED libelf)

add_executable(linux_bundle
        linux_bundle.cpp
        kallsyms.c
        symbol-elf.c
        symbol.c
        util.c
        vdso.c
        pgcore.cpp
        ../common/tar.cpp)

target_include_directories(linux_bundle PRIVATE ${LIBELF_INCLUDE_DIRS})
target_include_directories(linux_bundle PRIVATE "${CMAKE_SOURCE_DIR}/thirdparty")
target_link_directories(linux_bundle PRIVATE ${LIBELF_LIBRARY_DIRS})
target_link_libraries(linux_bundle PRIVATE -lelf)
target_link_libraries(linux_bundle PRIVATE -lrt -lpthread)
target_link_options(linux_bundle PRIVATE -static-libstdc++)

install(TARGETS linux_bundle
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

add_executable(vdso_test vdso_test.c vdso.c util.c)
target_include_directories(vdso_test PRIVATE "${CMAKE_SOURCE_DIR}/thirdparty")
target_link_libraries(vdso_test PRIVATE -lrt -lpthread)
install(TARGETS vdso_test
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

add_executable(stack_resolv stack_resolv.cpp kallsyms.c)
target_include_directories(stack_resolv PRIVATE "${CMAKE_SOURCE_DIR}/thirdparty")
install(TARGETS stack_resolv
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

add_executable(pgcore pgcore_test.cpp pgcore.cpp util.c)
target_include_directories(pgcore PRIVATE "${CMAKE_SOURCE_DIR}/thirdparty")
install(TARGETS pgcore
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

add_library(vdso_hook SHARED vdso_hook.cpp util.c)
target_include_directories(vdso_hook PRIVATE "${CMAKE_SOURCE_DIR}/thirdparty")
#target_compile_options(vdso_hook PRIVATE -fno-builtin-strlen -fno-builtin-memcmp -fno-builtin-memmove -fno-builtin-strcmp -fno-stack-protector)
#target_link_options(vdso_hook PRIVATE -fno-plt -nodefaultlibs -Wl,--gc-sections -l:libc.a)
target_link_options(vdso_hook PRIVATE -Wl,--gc-sections "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/vdso_hook.ver")
