#include "dns_parser.h"
#include <iostream>
#include <iomanip>
#include <chrono>
#include <thread>

void printResult(const zjpdns::DnsResult& result) {
    std::cout << "查询域名: ";
    if (result.domains.empty()) {
        std::cout << "无";
    } else {
        for (size_t i = 0; i < result.domains.size(); ++i) {
            if (i > 0) std::cout << ", ";
            std::cout << result.domains[i];
        }
    }
    std::cout << std::endl;
    std::cout << "解析成功: " << (result.success ? "是" : "否") << std::endl;
    
    if (!result.success) {
        std::cout << "错误信息: " << result.error_message << std::endl;
        return;
    }
    
    std::cout << "IP地址:" << std::endl;
    for (const auto& addr : result.addresses) {
        std::cout << "  " << addr << std::endl;
    }
    
    std::cout << "DNS记录:" << std::endl;
    for (const auto& record : result.records) {
        std::cout << "  名称: " << record.name << std::endl;
        std::cout << "  类型: " << static_cast<int>(record.type) << std::endl;
        std::cout << "  类: " << static_cast<int>(record.class_) << std::endl;
        std::cout << "  TTL: " << record.ttl << std::endl;
        std::cout << "  数据长度: " << record.data.length() << std::endl;
        std::cout << "  ---" << std::endl;
    }
    std::cout << std::endl;
}

int main() {
    std::cout << "=== ZJP DNS解析器示例 ===" << std::endl;
    
    // 创建同步解析器
    auto resolver = zjpdns::createDnsResolver();
    
    // 设置DNS服务器和超时
    resolver->setDnsServer("8.8.8.8", 53);
    resolver->setTimeout(5000);
    
    std::vector<std::string> domains = {
        "www.google.com",
        "www.baidu.com",
        "www.github.com"
    };
    
    // 测试同步解析
    std::cout << "=== 同步解析测试 ===" << std::endl;
    for (const auto& domain : domains) {
        std::cout << "解析域名: " << domain << std::endl;
        
        // 使用gethostbyname方式
        auto result1 = resolver->resolve(domain, zjpdns::DnsRecordType::A, 
                                       zjpdns::ResolveMethod::GETHOSTBYNAME);
        std::cout << "gethostbyname方式:" << std::endl;
        printResult(result1);
        
        // 使用DNS数据包方式
        auto result2 = resolver->resolve(domain, zjpdns::DnsRecordType::A, 
                                       zjpdns::ResolveMethod::DNS_PACKET);
        std::cout << "DNS数据包方式:" << std::endl;
        printResult(result2);
    }
    
    // 测试自定义DNS数据包
    std::cout << "=== 自定义DNS数据包测试 ===" << std::endl;
    zjpdns::DnsPacket custom_packet;
    custom_packet.id = 12345;
    custom_packet.flags = 0x0100; // 标准查询
    custom_packet.qdcount = 1;
    custom_packet.questions.push_back("www.example.com");
    
    auto result3 = resolver->resolveWithPacket(custom_packet);
    std::cout << "自定义数据包解析:" << std::endl;
    printResult(result3);
    
    // 测试异步解析
    std::cout << "=== 异步解析测试 ===" << std::endl;
    auto async_resolver = zjpdns::createAsyncDnsResolver();
    async_resolver->setDnsServer("8.8.8.8", 53);
    async_resolver->setTimeout(5000);
    
    std::vector<std::future<zjpdns::DnsResult>> futures;
    
    // 启动多个异步解析
    for (const auto& domain : domains) {
        auto future = async_resolver->resolveAsync(domain, zjpdns::DnsRecordType::A, 
                                                 zjpdns::ResolveMethod::DNS_PACKET);
        futures.push_back(std::move(future));
    }
    
    // 等待所有解析完成
    for (size_t i = 0; i < futures.size(); ++i) {
        auto result = futures[i].get();
        std::cout << "异步解析 " << domains[i] << ":" << std::endl;
        printResult(result);
    }

    // 测试自定义数据包异步解析
    std::cout << "=== 自定义数据包异步解析测试 ===" << std::endl;
    auto custom_packet_future = async_resolver->resolveWithPacketAsync(custom_packet);
    auto custom_packet_result = custom_packet_future.get();
    std::cout << "自定义数据包异步解析结果:" << std::endl;
    printResult(custom_packet_result);

    // 测试回调式异步解析
    std::cout << "=== 回调式异步解析测试 ===" << std::endl;
    std::atomic<int> completed_count{0};
    int total_count = domains.size();
    
    for (const auto& domain : domains) {
        async_resolver->resolveWithCallback(domain, 
            [&completed_count, total_count](const zjpdns::DnsResult& result) {
                std::cout << "回调解析完成: ";
                if (!result.domains.empty()) {
                    std::cout << result.domains[0];
                } else {
                    std::cout << "无域名";
                }
                std::cout << std::endl;
                printResult(result);
                completed_count++;
                
                if (completed_count >= total_count) {
                    std::cout << "所有回调解析完成!" << std::endl;
                }
            },
            zjpdns::DnsRecordType::A,
            zjpdns::ResolveMethod::DNS_PACKET);
    }
    
    // 等待回调完成
    while (completed_count < total_count) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    completed_count.store(0);
    for (const auto& domain : domains) {
        async_resolver->resolveWithCallback(domain, 
            [&completed_count, total_count](const zjpdns::DnsResult& result) {
                std::cout << "回调解析完成: ";
                if (!result.domains.empty()) {
                    std::cout << result.domains[0];
                } else {
                    std::cout << "无域名";
                }
                std::cout << std::endl;
                printResult(result);
                completed_count++;
                
                if (completed_count >= total_count) {
                    std::cout << "所有回调解析完成!" << std::endl;
                }
            },
            zjpdns::DnsRecordType::A,
            zjpdns::ResolveMethod::GETHOSTBYNAME);
    }

    while (completed_count < total_count) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    // 测试gethostbyname异步解析
    std::cout << "测试gethostbyname异步解析:" << std::endl;
    auto gethostbyname_future = async_resolver->resolveAsync("www.google.com", zjpdns::DnsRecordType::A,
                                                            zjpdns::ResolveMethod::GETHOSTBYNAME);
    auto gethostbyname_result = gethostbyname_future.get();
    std::cout << "gethostbyname异步解析结果:" << std::endl;
    printResult(gethostbyname_result);
    
    // 测试自定义数据包回调式异步解析
    std::cout << "测试自定义数据包回调式异步解析:" << std::endl;
    zjpdns::DnsPacket custom_packet2;
    custom_packet2.id = 54321;
    custom_packet2.flags = 0x0100; // 标准查询
    custom_packet2.qdcount = 1;
    custom_packet2.questions.push_back("www.example.com");
    
    std::atomic<bool> packet_callback_called{false};
    async_resolver->resolveWithPacketCallback(custom_packet2,
        [&packet_callback_called](const zjpdns::DnsResult& result) {
            std::cout << "自定义数据包回调解析完成: ";
            if (!result.domains.empty()) {
                std::cout << result.domains[0];
            } else {
                std::cout << "无域名";
            }
            std::cout << std::endl;
            printResult(result);
            packet_callback_called = true;
        });
    
    // 等待自定义数据包回调完成
    while (!packet_callback_called) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    std::cout << "=== 测试完成 ===" << std::endl;
    return 0;
} 