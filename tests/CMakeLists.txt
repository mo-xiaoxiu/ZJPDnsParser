# 测试可执行文件
add_executable(dns_test dns_test.cpp)

# 链接库
if(BUILD_SHARED_LIBS)
    target_link_libraries(dns_test zjpdns_shared)
else()
    target_link_libraries(dns_test zjpdns_static)
endif()

# 添加测试
add_test(NAME dns_test COMMAND dns_test) 