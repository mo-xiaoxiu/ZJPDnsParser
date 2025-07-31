#pragma once

#include "dns_parser.h"
#include "dns_packet.h"
#include <string>
#include <memory>

namespace zjpdns {

#define DNS_SERVER "8.8.8.8"
#define DNS_PORT 53
#define DNS_TIMEOUT 5000

// DNS解析器实现类
class DnsResolverImpl : public DnsResolver {
public:
    DnsResolverImpl();
    ~DnsResolverImpl() override;
    
    // 同步解析接口
    DnsResult resolve(const std::string& domain, 
                     DnsRecordType type = DnsRecordType::A,
                     ResolveMethod method = ResolveMethod::GETHOSTBYNAME) override;
    
    // 使用自定义DNS数据包解析
    DnsResult resolveWithPacket(const DnsPacket& packet) override;
    
    // 设置DNS服务器
    void setDnsServer(const std::string& server, uint16_t port = 53) override;
    
    // 设置超时时间
    void setTimeout(int timeout_ms) override;

private:
    std::string dns_server_;
    uint16_t dns_port_;
    int timeout_ms_;
    std::unique_ptr<DnsPacketSender> sender_;
    
    // 使用gethostbyname解析
    DnsResult resolveWithGethostbyname(const std::string& domain);
    
    // 使用DNS数据包解析
    DnsResult resolveWithDnsPacket(const std::string& domain, DnsRecordType type);
    
    // 验证域名格式
    bool isValidDomain(const std::string& domain);
    
    // 获取默认DNS服务器
    std::string getDefaultDnsServer();
};

} // namespace zjpdns 