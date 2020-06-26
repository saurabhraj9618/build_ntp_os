cmake_minimum_required (VERSION 2.8)
project (super_mediator C)

add_definitions( )

#option(pkgConfigPath "Set the path to search for required libraries (e.g. glib, fixbuf)")
#
#if (pkgConfigPath)
#       set(CMAKE_MODULE_PATH ${pkgConfigPath})
#endif(pkgConfigPath)

include(FindPkgConfig)
include(CheckIncludeFiles)
include(CheckFunctionExists)
include(CheckLibraryExists)

pkg_check_modules(GLIB REQUIRED glib-2.0)
pkg_check_modules(FIXBUF REQUIRED libfixbuf>=1.4.0)

FIND_PACKAGE(BISON)
FIND_PACKAGE(FLEX)

SET(CMAKE_C_FLAGS_DEBUG)
SET(CMAKE_BUILD_TYPE Debug)

add_subdirectory(src)



