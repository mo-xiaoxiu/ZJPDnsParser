cmake_minimum_required(VERSION 3.16)
project(ZJPDnsParser VERSION 1.0.0 LANGUAGES CXX)

# 设置C++标准
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 编译选项
option(BUILD_SHARED_LIBS "Build shared libraries" ON)
option(BUILD_STATIC_LIBS "Build static libraries" ON)

# 源文件
set(SOURCES
    src/dns_parser.cpp
    src/dns_packet.cpp
    src/dns_resolver.cpp
    src/async_resolver.cpp
)

set(HEADERS
    include/dns_parser.h
    include/dns_packet.h
    include/dns_resolver.h
    include/async_resolver.h
)

# 创建库
if(BUILD_SHARED_LIBS)
    add_library(zjpdns_shared SHARED ${SOURCES})
    set_target_properties(zjpdns_shared PROPERTIES
        OUTPUT_NAME zjpdns
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
    )
    target_include_directories(zjpdns_shared PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
endif()

if(BUILD_STATIC_LIBS)
    add_library(zjpdns_static STATIC ${SOURCES})
    set_target_properties(zjpdns_static PROPERTIES
        OUTPUT_NAME zjpdns
    )
    target_include_directories(zjpdns_static PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
endif()

# 安装规则
install(TARGETS zjpdns_shared zjpdns_static
    EXPORT ZJPDnsTargets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
    INCLUDES DESTINATION include
)

install(FILES ${HEADERS} DESTINATION include/zjpdns)

# 导出目标
install(EXPORT ZJPDnsTargets
    FILE ZJPDnsTargets.cmake
    NAMESPACE ZJPDns::
    DESTINATION lib/cmake/ZJPDns
)

# 创建配置文件
include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    ZJPDnsConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY AnyNewerVersion
)

configure_package_config_file(
    ZJPDnsConfig.cmake.in
    ZJPDnsConfig.cmake
    INSTALL_DESTINATION lib/cmake/ZJPDns
)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/ZJPDnsConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/ZJPDnsConfigVersion.cmake
    DESTINATION lib/cmake/ZJPDns
)

# 创建pkg-config文件
configure_file(zjpdns.pc.in zjpdns.pc @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/zjpdns.pc DESTINATION lib/pkgconfig)

# 示例程序
add_executable(dns_example examples/dns_example.cpp)
if(BUILD_SHARED_LIBS)
    target_link_libraries(dns_example zjpdns_shared)
else()
    target_link_libraries(dns_example zjpdns_static)
endif()

# 测试
enable_testing()
add_subdirectory(tests) 