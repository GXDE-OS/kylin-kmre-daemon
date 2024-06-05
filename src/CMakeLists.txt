# Updating and generating kmre-server-glue.h
# dbusxx-xml2cpp kmre-introspect.xml --adaptor=kmre-server-glue.h

######## Find packages
find_package(PkgConfig)
pkg_check_modules(DBUS_CPP dbus-c++-1 REQUIRED)
pkg_check_modules(GLIBMM glibmm-2.4 REQUIRED)
pkg_check_modules(LIBCRYPTO libcrypto REQUIRED)
pkg_check_modules(JSONCPP jsoncpp REQUIRED)

include_directories(
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_BINARY_DIR}/src
    ${DBUS_CPP_INCLUDE_DIRS}
    ${GLIBMM_INCLUDE_DIRS}
    ${LIBCRYPTO_INCLUDE_DIRS}
    ${JSONCPP_INCLUDE_DIRS}
)

set(SOURCES
    utils.h
    utils.cpp
    utils/async_task.h
    utils/async_task.cpp
    utils/load_module_task.h
    utils/load_module_task.cpp
    utils/load_module_manager.h
    utils/load_module_manager.cpp
    utils/prepare_modules.cpp
    utils/rfkill_unblock_task.h
    utils/rfkill_unblock_task.cpp
    utils/rfkill_unblock_manager.h
    utils/rfkill_unblock_manager.cpp
    kmre-server.h
    kmre-daemon.cpp
    kmre-server.cpp
    kmre-server-glue.h
    systemd-service-proxy.h
    systemd-service-proxy.cpp
    dbus-daemon-proxy.h
    dbus-daemon-proxy.cpp
    kydroid-daemon-proxy.h
    kydroid-daemon-proxy.cpp
    container/container.h
    container/container.cpp
    container/container_manager.h
    container/container_manager.cpp
    container/container_utils.h
    container/container_utils.cpp
    container/image-info.h
    container/image-info.cpp
    container/property-map.h
    container/property-map.cpp
    container/rfkillprocessor.h
    container/rfkillprocessor.cpp
    simpleIni/SimpleIni.h
    simpleIni/ConvertUTF.h
    simpleIni/ConvertUTF.c
    )
add_executable(kylin-kmre-daemon ${SOURCES})
target_link_libraries(kylin-kmre-daemon
    ${DBUS_CPP_LIBRARIES}
    ${GLIBMM_LIBRARIES}
    ${LIBCRYPTO_LIBRARIES}
    ${JSONCPP_LIBRARIES}
    fuse-common
)

install(
    TARGETS kylin-kmre-daemon
    RUNTIME DESTINATION bin)

install(
    PROGRAMS ${CMAKE_CURRENT_SOURCE_DIR}/kylin-kmre-load-image
    DESTINATION bin)

add_subdirectory(fuse)
