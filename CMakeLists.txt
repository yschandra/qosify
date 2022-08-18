cmake_minimum_required(VERSION 3.10)

PROJECT(qosify C)

ADD_DEFINITIONS(-Os -Wall -Wno-unknown-warning-option -Wno-array-bounds -Wno-format-truncation -Werror --std=gnu99)

SET(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")

IF (NOT DEFINED LIBNL_LIBS)
	include(FindPkgConfig)
	pkg_search_module(LIBNL libnl-3.0 libnl-3 libnl nl-3 nl)
	IF (LIBNL_FOUND)
		include_directories(${LIBNL_INCLUDE_DIRS})
		SET(LIBNL_LIBS ${LIBNL_LIBRARIES})
	ENDIF()
ENDIF()

add_custom_command(
  OUTPUT ${PROJECT_SOURCE_DIR}/dnstap.pb-c.c
  DEPENDS ${PROJECT_SOURCE_DIR}/dnstap.proto
  COMMAND protoc-c --c_out=${PROJECT_SOURCE_DIR} --proto_path=${PROJECT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}/dnstap.proto
  )

add_custom_target(DNSTAP ALL
  DEPENDS ${PROJECT_SOURCE_DIR}/dnstap.pb-c.c
  )

find_library(bpf NAMES bpf)
find_library(protobuf-c NAMES protobuf-c)
find_library(fstrm NAMES fstrm)
ADD_EXECUTABLE(qosify main.c loader.c map.c ubus.c interface.c dns.c dnstap.pb-c.c)
TARGET_LINK_LIBRARIES(qosify ${bpf} ubox ubus ${fstrm} ${protobuf-c} ${LIBNL_LIBS})

INSTALL(TARGETS qosify
	RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR}
)
