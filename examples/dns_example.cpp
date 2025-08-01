#include "dns_parser.h"
#include <iostream>
#include <iomanip>
#include <chrono>
#include <thread>

void printResult(const zjpdns::DnsResult& result) {
    std::cout << "query domain: ";
    if (result.domains.empty()) {
        std::cout << "no domain";
    } else {
        for (size_t i = 0; i < result.domains.size(); ++i) {
            if (i > 0) std::cout << ", ";
            std::cout << result.domains[i];
        }
    }
    std::cout << std::endl;
    std::cout << "resolve success: " << (result.success ? "yes" : "no") << std::endl;
    
    if (!result.success) {
        std::cout << "error message: " << result.error_message << std::endl;
        return;
    }
    
    std::cout << "IP addresses:" << std::endl;
    for (const auto& addr : result.addresses) {
        std::cout << "  " << addr << std::endl;
    }
    
    std::cout << "DNS records:" << std::endl;
    for (const auto& record : result.records) {
        std::cout << "  name: " << record.name << std::endl;
        std::cout << "  type: " << static_cast<int>(record.type) << std::endl;
        std::cout << "  class: " << static_cast<int>(record.class_) << std::endl;
        std::cout << "  TTL: " << record.ttl << std::endl;
        std::cout << "  data length: " << record.data.length() << std::endl;
        std::cout << "  ---" << std::endl;
    }
    std::cout << std::endl;
}

int main() {
    std::cout << "=== ZJP DNS parser example ===" << std::endl;
    
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
    std::cout << "=== sync resolve test ===" << std::endl;
    for (const auto& domain : domains) {
        std::cout << "resolve domain: " << domain << std::endl;
        
        // 使用gethostbyname方式
        auto result1 = resolver->resolve(domain, zjpdns::DnsRecordType::A, 
                                       zjpdns::ResolveMethod::GETHOSTBYNAME);
        std::cout << "gethostbyname method:" << std::endl;
        printResult(result1);
        
        // 使用DNS数据包方式
        auto result2 = resolver->resolve(domain, zjpdns::DnsRecordType::A, 
                                       zjpdns::ResolveMethod::DNS_PACKET);
        std::cout << "DNS packet method:" << std::endl;
        printResult(result2);
    }
    
    // 测试自定义DNS数据包
    std::cout << "=== custom DNS packet test ===" << std::endl;
    zjpdns::DnsPacket custom_packet;
    custom_packet.id = 12345;
    custom_packet.flags = 0x0100; // 标准查询
    custom_packet.qdcount = 1;
    custom_packet.questions.push_back("www.example.com");
    
    auto result3 = resolver->resolveWithPacket(custom_packet);
    std::cout << "custom DNS packet resolve:" << std::endl;
    printResult(result3);
    
    // 测试异步解析
    std::cout << "=== async resolve test ===" << std::endl;
    auto async_resolver = zjpdns::createAsyncDnsResolver();
    async_resolver->setDnsServer("8.8.8.8", 53);
    async_resolver->setTimeout(5000);
    
    std::vector<std::future<zjpdns::DnsResult>> futures;
    
    // 异步解析 使用默认DNS数据包方式
    for (const auto& domain : domains) {
        auto future = async_resolver->resolveAsync(domain, zjpdns::DnsRecordType::A, 
                                                 zjpdns::ResolveMethod::DNS_PACKET);
        futures.push_back(std::move(future));
    }
    
    // 等待所有解析完成
    for (size_t i = 0; i < futures.size(); ++i) {
        auto result = futures[i].get();
        std::cout << "async resolve " << domains[i] << ":" << std::endl;
        printResult(result);
    }

    // 测试gethostbyname异步解析
    std::cout << "=== gethostbyname async resolve test ===" << std::endl;
    auto gethostbyname_future = async_resolver->resolveAsync("www.google.com", zjpdns::DnsRecordType::A,
                                                            zjpdns::ResolveMethod::GETHOSTBYNAME);
    auto gethostbyname_result = gethostbyname_future.get();
    std::cout << "gethostbyname async resolve result:" << std::endl;
    printResult(gethostbyname_result);

    // 测试自定义数据包异步解析
    std::cout << "=== custom DNS packet async resolve test ===" << std::endl;
    auto custom_packet_future = async_resolver->resolveWithPacketAsync(custom_packet);
    auto custom_packet_result = custom_packet_future.get();
    std::cout << "custom DNS packet async resolve result:" << std::endl;
    printResult(custom_packet_result);

    // 测试默认DNS数据包回调式异步解析
    std::cout << "=== callback async resolve test ===" << std::endl;
    std::atomic<int> completed_count{0};
    int total_count = domains.size();
    
    for (const auto& domain : domains) {
        async_resolver->resolveWithCallback(domain, 
            [&completed_count, total_count](const zjpdns::DnsResult& result) {
                std::cout << "callback async resolve completed: ";
                if (!result.domains.empty()) {
                    std::cout << result.domains[0];
                } else {
                    std::cout << "no domain";
                }
                std::cout << std::endl;
                printResult(result);
                completed_count++;
                
                if (completed_count >= total_count) {
                    std::cout << "all callback async resolve completed!" << std::endl;
                }
            },
            zjpdns::DnsRecordType::A,
            zjpdns::ResolveMethod::DNS_PACKET);
    }
    
    // 等待回调完成
    while (completed_count < total_count) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    // 测试gethostbyname回调式异步解析
    std::cout << "=== gethostbyname callback async resolve test ===" << std::endl;
    completed_count.store(0);
    for (const auto& domain : domains) {
        async_resolver->resolveWithCallback(domain, 
            [&completed_count, total_count](const zjpdns::DnsResult& result) {
                std::cout << "callback async resolve completed: ";
                if (!result.domains.empty()) {
                    std::cout << result.domains[0];
                } else {
                    std::cout << "no domain";
                }
                std::cout << std::endl;
                printResult(result);
                completed_count++;
                
                if (completed_count >= total_count) {
                    std::cout << "all callback async resolve completed!" << std::endl;
                }
            },
            zjpdns::DnsRecordType::A,
            zjpdns::ResolveMethod::GETHOSTBYNAME);
    }

    while (completed_count < total_count) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    // 测试自定义数据包回调式异步解析
    std::cout << "=== test custom DNS packet callback async resolve ===" << std::endl;
    zjpdns::DnsPacket custom_packet2;
    custom_packet2.id = 54321;
    custom_packet2.flags = 0x0100; // 标准查询
    custom_packet2.qdcount = 1;
    custom_packet2.questions.push_back("www.example.com");
    
    std::atomic<bool> packet_callback_called{false};
    async_resolver->resolveWithPacketCallback(custom_packet2,
        [&packet_callback_called](const zjpdns::DnsResult& result) {
            std::cout << "custom DNS packet callback async resolve completed: ";
            if (!result.domains.empty()) {
                std::cout << result.domains[0];
            } else {
                std::cout << "no domain";
            }
            std::cout << std::endl;
            printResult(result);
            packet_callback_called = true;
        });
    
    // 等待自定义数据包回调完成
    while (!packet_callback_called) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    std::cout << "=== test completed ===" << std::endl;
    return 0;
} 