remove_definitions(
    -std=c++11
    -std=c++0x
    )

set(SOURCES
    groups.c
    groups.h
    lock_file.c
    lock_file.h
    misc.c
    misc.h)

add_library(fuse-common STATIC ${SOURCES})
