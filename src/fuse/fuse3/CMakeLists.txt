######## Find packages
find_package(PkgConfig)
pkg_check_modules(FUSE3 fuse3 REQUIRED)

remove_definitions(
    -std=c++11
    -std=c++0x
    )

include_directories(
    ${CMAKE_BINARY_DIR}/src
    ${FUSE3_INCLUDE_DIRS}
    ../common/
)

set(SOURCES
    kmre_fuse3.c)

add_definitions(${FUSE3_CFLAGS}
    -DHAVE_COPY_FILE_RANGE
    -DHAVE_FSTATAT
    -DHAVE_LIBULOCKMGR
    -DHAVE_FDATASYNC
    -DHAVE_POSIX_FALLOCATE
    -DHAVE_SETXATTR
    -DHAVE_UTIMENSAT)

add_executable(kylin-kmre-fuse3 ${SOURCES})
target_link_libraries(kylin-kmre-fuse3 
    ${FUSE3_LIBRARIES}
    fuse-common
    ulockmgr)

install(
    TARGETS kylin-kmre-fuse3
    RUNTIME DESTINATION bin)
