include_directories(${super_mediator_SOURCE_DIR}/include)
link_directories(${super_mediator_BINARY_DIR}/src)

LINK_DIRECTORIES(${FIXBUF_LIBRARY_DIRS})
LINK_DIRECTORIES(${GLIB_LIBRARY_DIRS})

set (mediator_VERSION_MAJOR 1)
set (mediator_VERSION_MINOR 1)

set(VERSION \"1.5.3\")

BISON_TARGET(mediatorConfigParse mediator_config_parse.y 
${CMAKE_CURRENT_BINARY_DIR}/mediator_config_parse.c)

FLEX_TARGET(mediatorConfigLex mediator_config_lex.l 
${CMAKE_CURRENT_BINARY_DIR}/mediator_config_lex.c)

find_library(SPREAD_LIBRARY spread)
find_path(SPREAD_INCLUDE_DIR
	 NAMES
         sp.h
         PATHS
         ${SPREAD_INCLUDE_DIR}
         /usr/local/include
         /opt/local/include
         /usr/include)


find_path(MYSQL_INCLUDE_DIR
	NAMES
	   mysql.h
	PATHS
           ${MYSQL_INCLUDE_DIR}
	   /usr/include
	   /usr/include/mysql
	   /usr/local/include
	   /usr/local/include/mysql
	   /usr/local/mysql/include
           /opt/local/include
	   /opt/local/include/mysql
           /opt/local/include/mysql5
	   /opt/local/include/mysql5/mysql)

find_library(MYSQL_LIBRARY mysqlclient)
#find_package(Threads)

MESSAGE(STATUS "MySQL INCLUDE DIR: " ${MYSQL_INCLUDE_DIR})

CHECK_INCLUDE_FILES(${MYSQL_INCLUDE_DIR}/mysql.h HAVE_MYSQL)

IF(MYSQL_LIBRARY)
   INCLUDE_DIRECTORIES(${MYSQL_INCLUDE_DIR})
   MESSAGE(STATUS "MySQL libraries: " ${MYSQL_LIBRARY})
   add_executable(super_table_creator mediator_mysql.c)
   TARGET_LINK_LIBRARIES(super_table_creator ${MYSQL_LIBRARY})
   TARGET_LINK_LIBRARIES(super_table_creator ${GLIB_LIBRARIES})
   SET(CMAKE_C_FLAGS -DHAVE_MYSQL)
ELSE()
   MESSAGE(STATUS "super_table_creator not built due to lack of MySQL Library")
   SET(HAVE_MYSQL 0)
ENDIF()

find_library(SKIPSET_LIB skipset)

find_path(SKIPSET_INCLUDE_DIR
          NAMES
            skipset.h
          PATHS
            ${SKIPSET_INCLUDE_DIR}
            /usr/include/silk-ipset
            /usr/local/include/silk-ipset
            /opt/include/silk-ipset
            /opt/local/include/silk-ipset)

CHECK_INCLUDE_FILES(${SKIPSET_INCLUDE_DIR}/skipset.h ENABLE_SKIPSET)

IF(SKIPSET_LIB)
   INCLUDE_DIRECTORIES(${SKIPSET_INCLUDE_DIR})
   MESSAGE(STATUS "SKIPSET Libraries: " ${SKIPSET_LIB})
ELSE()
   MESSAGE(STATUS "Super mediator not compiled with IPset support")
   SET(ENABLE_SKIPSET 0)
ENDIF()   

INCLUDE_DIRECTORIES(${FIXBUF_INCLUDE_DIRS})
INCLUDE_DIRECTORIES(${GLIB_INCLUDE_DIRS})

SET(MED_SRC
    mediator.c
    mediator_core.c
    mediator_export.c
    mediator_open.c
    mediator_dns.c
    mediator_filter.c
    mediator_stat.c
    mediator_log.c
    mediator_print.c
    mediator_util.c
    mediator_json.c
    mediator_dedup.c
    mediator_ssl.c
    )


add_executable (super_mediator ${MED_SRC} ${BISON_mediatorConfigParse_OUTPUTS} ${FLEX_mediatorConfigLex_OUTPUTS})

#TARGET_LINK_LIBRARIES(super_mediator ${CMAKE_THREAD_LIBS_INIT})
TARGET_LINK_LIBRARIES(super_mediator pthread)
TARGET_LINK_LIBRARIES(super_mediator ${GLIB_LIBRARIES})
TARGET_LINK_LIBRARIES(super_mediator ${FIXBUF_LIBRARIES})
IF(HAVE_MYSQL)
  TARGET_LINK_LIBRARIES(super_mediator ${MYSQL_LIBRARY})
ELSE()
  MESSAGE(STATUS "SUPER MEDIATOR NOT COMPILED WITH MYSQL SUPPORT")
ENDIF()

IF(ENABLE_SKIPSET)
   TARGET_LINK_LIBRARIES(super_mediator ${SKIPSET_LIB})
ENDIF()

CONFIGURE_FILE(${super_mediator_SOURCE_DIR}/include/mediator/config.h.cmake ${super_mediator_SOURCE_DIR}/include/mediator/config.h)

MESSAGE(STATUS "FIXBUF include dirs: " ${FIXBUF_INCLUDE_DIRS})
MESSAGE(STATUS "FIXBUF link dirs: " ${FIXBUF_LIBRARY_DIRS})
MESSAGE(STATUS "FIXBUF libraries: " ${FIXBUF_LIBRARIES})

CHECK_LIBRARY_EXISTS(fixbuf fbExporterAllocSpread "" HAVE_SPREAD)
IF (HAVE_SPREAD)
   SET(CMAKE_C_FLAGS "-DHAVE_SPREAD")
   INCLUDE_DIRECTORIES(${SPREAD_INCLUDE_DIR})
   TARGET_LINK_LIBRARIES(super_mediator ${SPREAD_LIBRARY})
   TARGET_LINK_LIBRARIES(super_mediator pthread)
ELSE()
   MESSAGE(STATUS "FIXBUF NOT COMPILED WITH SPREAD SUPPORT")
ENDIF()


MESSAGE(STATUS "GLIB include dirs: " ${GLIB_INCLUDE_DIRS})
MESSAGE(STATUS "GLIB link dirs: " ${GLIB_LIBRARY_DIRS})
MESSAGE(STATUS "GLIB libraries: " ${GLIB_LIBRARIES})

