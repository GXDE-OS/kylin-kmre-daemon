######## Project settings
project(kylin-kmre-daemon)
cmake_minimum_required(VERSION 2.8)

######## Directory

set (DIR_PREFIX ${CMAKE_INSTALL_PREFIX})
set (DIR_INCLUDE ${DIR_PREFIX}/include/)
set (DIR_SHARE ${DIR_PREFIX}/share/)
set (DIR_ETC ${CMAKE_INSTALL_SYSCONFDIR})
set (DIR_LIBRARY ${CMAKE_INSTALL_LIBDIR})
set (DIR_SYSTEMD /lib/systemd)
set (DIR_UDEV /lib/udev)

if (DEFINED SHARE_INSTALL_PREFIX)
  set (DIR_SHARE ${SHARE_INSTALL_PREFIX})
endif (DEFINED SHARE_INSTALL_PREFIX)

if (DEFINED INCLUDE_INSTALL_DIR)
  set (DIR_INCLUDE ${INCLUDE_INSTALL_DIR})
endif (DEFINED INCLUDE_INSTALL_DIR)

if (DEFINED SYSCONF_INSTALL_DIR)
  set (DIR_ETC ${SYSCONF_INSTALL_DIR})
endif (DEFINED SYSCONF_INSTALL_DIR)


#set (CMAKE_CXX_COMPILER g++-9)
set (CMAKE_CXX_COMPILER_ID "GNU")

######## Compiler flags

if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
  add_definitions(
    -std=c++11
    -Wall
  )
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pthread")
  if (CMAKE_BUILD_TYPE MATCHES Debug)
    add_definitions(-O0 -g3)
  endif ()
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
  add_definitions(
    -std=c++11
    -Wall
    -fno-lto
  )
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pthread")
  if (CMAKE_BUILD_TYPE MATCHES Debug)
    add_definitions(-O0 -g3)
  endif ()
endif()

######## Uninstall target

if(NOT TARGET uninstall)
    configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/cmake_uninstall.cmake.in"
        "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
        IMMEDIATE @ONLY)
    add_custom_target(uninstall
        COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)
endif()

add_subdirectory(src)
add_subdirectory(data)
