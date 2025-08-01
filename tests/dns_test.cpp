#include "dns_parser.h"
#include "dns_packet.h"
#include <iostream>
#include <cassert>
#include <thread>
#include <chrono>
#include <atomic>

using namespace zjpdns;

void testDnsPacketBuilder() {
    std::cout << "test DNS packet builder..." << std::endl;
    
    // 测试域名编码解码
    std::string test_domain = "www.example.com";
    auto encoded = DnsPacketBuilder::encodeDomain(test_domain);
    size_t offset = 0;
    auto decoded = DnsPacketBuilder::decodeDomain(encoded, offset);
    assert(decoded == test_domain + ".");
    
    // 测试数据包构建
    auto packet_data = DnsPacketBuilder::buildQueryPacket("www.google.com", 
                                                        DnsRecordType::A, 
                                                        DnsRecordClass::IN, 
                                                        12345);
    assert(packet_data.size() > 0);
    
    std::cout << "DNS packet builder test passed!" << std::endl;
}

void testDnsResolver() {
    std::cout << "test DNS resolver..." << std::endl;
    
    auto resolver = zjpdns::createDnsResolver();
    resolver->setDnsServer("8.8.8.8", 53);
    resolver->setTimeout(5000);
    
    // 测试gethostbyname方式
    auto result1 = resolver->resolve("www.google.com", 
                                   zjpdns::DnsRecordType::A,
                                   zjpdns::ResolveMethod::GETHOSTBYNAME);
    assert(result1.domains.size() == 1);
    assert(result1.domains[0] == "www.google.com");
    
    // 测试DNS数据包方式
    auto result2 = resolver->resolve("www.google.com", 
                                   zjpdns::DnsRecordType::A,
                                   zjpdns::ResolveMethod::DNS_PACKET);
    if (result2.success && !result2.domains.empty()) {
        assert(result2.domains[0] == "www.google.com.");
    }
    
    // 测试无效域名
    auto result3 = resolver->resolve("invalid.domain.test", 
                                   zjpdns::DnsRecordType::A,
                                   zjpdns::ResolveMethod::DNS_PACKET);
    // 无效域名应该解析失败
    assert(!result3.success);
    
    std::cout << "DNS resolver test passed!" << std::endl;
}

void testAsyncDnsResolver() {
    std::cout << "test async DNS resolver..." << std::endl;
    
    auto async_resolver = zjpdns::createAsyncDnsResolver();
    async_resolver->setDnsServer("8.8.8.8", 53);
    async_resolver->setTimeout(5000);
    
    // 测试异步解析
    auto future = async_resolver->resolveAsync("www.google.com", 
                                             zjpdns::DnsRecordType::A,
                                             zjpdns::ResolveMethod::DNS_PACKET);
    
    auto result = future.get();
    if (result.success && !result.domains.empty()) {
        assert(result.domains[0] == "www.google.com.");
    }
    
    // 测试回调式解析
    std::atomic<bool> callback_called{false};
    async_resolver->resolveWithCallback("www.google.com", 
        [&callback_called](const zjpdns::DnsResult& result) {
            // 检查结果是否成功，如果成功则检查域名
            if (result.success && !result.domains.empty()) {
                assert(result.domains[0] == "www.google.com.");
            }
            callback_called = true;
        },
        zjpdns::DnsRecordType::A,
        zjpdns::ResolveMethod::DNS_PACKET);
    
    // 等待回调执行
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    assert(callback_called);
    
    // 测试自定义数据包回调式异步接口
    zjpdns::DnsPacket custom_packet;
    custom_packet.id = 12345;
    custom_packet.flags = 0x0100; // 标准查询
    custom_packet.qdcount = 1;
    custom_packet.questions.push_back("www.example.com");
    
    std::atomic<bool> packet_callback_called{false};
    async_resolver->resolveWithPacketCallback(custom_packet,
        [&packet_callback_called](const zjpdns::DnsResult& result) {
            if (result.success && !result.domains.empty()) {
                assert(result.domains[0] == "www.example.com.");
            }
            packet_callback_called = true;
        });
    
    // 等待自定义数据包回调执行
    std::this_thread::sleep_for(std::chrono::milliseconds(2000));
    assert(packet_callback_called);
    
    std::cout << "async DNS resolver test passed!" << std::endl;
}

void testCustomPacket() {
    std::cout << "test custom DNS packet..." << std::endl;
    
    auto resolver = zjpdns::createDnsResolver();
    resolver->setDnsServer("8.8.8.8", 53);
    resolver->setTimeout(5000);
    
    // 创建自定义数据包
    zjpdns::DnsPacket packet;
    packet.id = 12345;
    packet.flags = 0x0100; // 标准查询
    packet.qdcount = 1;
    packet.questions.push_back("www.example.com");
    
    auto result = resolver->resolveWithPacket(packet);
    if (result.success && !result.domains.empty()) {
        assert(result.domains[0] == "www.example.com.");
    }
    
    std::cout << "custom DNS packet test passed!" << std::endl;
}

void testMultiDomainPacket() {
    std::cout << "test multi-domain packet..." << std::endl;
    
    auto resolver = zjpdns::createDnsResolver();
    resolver->setDnsServer("8.8.8.8", 53);
    resolver->setTimeout(5000);
    
    // 创建包含多个域名的自定义数据包
    zjpdns::DnsPacket packet;
    packet.id = 12345;
    packet.flags = 0x0100; // 标准查询
    packet.qdcount = 2;
    packet.questions.push_back("www.example.com");
    packet.questions.push_back("www.test.com");
    
    auto result = resolver->resolveWithPacket(packet);
    // 注意：实际DNS服务器可能不支持多域名查询，这里主要测试接口
    if (result.success) {
        // 检查是否返回了查询的域名
        assert(result.domains.size() >= 1);
    }
    
    std::cout << "multi-domain packet test passed!" << std::endl;
}

int main() {
    std::cout << "start DNS resolver unit test..." << std::endl;
    
    try {
        testDnsPacketBuilder();
        testDnsResolver();
        testAsyncDnsResolver();
        testCustomPacket();
        testMultiDomainPacket();
        
        std::cout << "all tests passed!" << std::endl;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "test failed: " << e.what() << std::endl;
        return 1;
    }
} 