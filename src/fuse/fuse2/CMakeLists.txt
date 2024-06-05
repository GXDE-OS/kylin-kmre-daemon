######## Find packages
find_package(PkgConfig)
pkg_check_modules(FUSE2 fuse REQUIRED)

remove_definitions(
    -std=c++11
    -std=c++0x
    )

include_directories(
    ${CMAKE_BINARY_DIR}/src
    ${FUSE2_INCLUDE_DIRS}
    ../common/
)

set(SOURCES
    kmre_fuse.c)

add_definitions(${FUSE2_CFLAGS}
    -DHAVE_FDATASYNC
    -DHAVE_POSIX_FALLOCATE
    -DHAVE_SETXATTR
    -DHAVE_UTIMENSAT)

add_executable(kylin-kmre-fuse ${SOURCES})
target_link_libraries(kylin-kmre-fuse 
    ${FUSE2_LIBRARIES}
    fuse-common
    ulockmgr)

install(
    TARGETS kylin-kmre-fuse
    RUNTIME DESTINATION bin)
