cmake_minimum_required(VERSION 3.10)
project(netplan_config VERSION 0.1.0)
find_package(Poco REQUIRED COMPONENTS Foundation Util Net XML JSON)
find_package(yaml-cpp REQUIRED)
add_library(bm_library STATIC
    bm/word_analyse.c
    bm/util.c
    bm/sys_os.c
    bm/sys_log.c
    bm/sys_buf.c
    bm/ppstack.c
    bm/base64.c
    bm/sha1.c
    bm/linked_list.c
    bm/hqueue.c
    bm/rfc_md5.c
    bm/xml_node.c
    bm/hxml.c
)
target_include_directories(bm_library
    PUBLIC bm)
target_compile_options(bm_library PRIVATE -fPIC)
add_library(netplan_config SHARED
    src/NetplanManager.cpp
    src/netplan_manager_c_api.cpp

)
target_link_libraries(bm_library
PRIVATE pthread)

target_include_directories(netplan_config
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE ${Poco_INCLUDE_DIRS}
)
target_link_libraries(netplan_config PRIVATE yaml-cpp bm_library ${Poco_LIBRARIES})
target_compile_definitions(netplan_config
    # PUBLIC NETPLAN_MANAGER_API
    PRIVATE HT_EXPORTS
)

add_executable(netplan_config_exe src/main.cpp)

target_link_libraries(netplan_config_exe netplan_config bm_library)