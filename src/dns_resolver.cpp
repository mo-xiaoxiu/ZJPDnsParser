#include "dns_resolver.h"
#include "dns_packet.h"
#include <netdb.h>
#include <cstring>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <arpa/inet.h>

namespace zjpdns {

DnsResolverImpl::DnsResolverImpl() 
    : dns_server_(DNS_SERVER), dns_port_(DNS_PORT), timeout_ms_(DNS_TIMEOUT) {
    sender_ = std::make_unique<DnsPacketSender>();
}

DnsResolverImpl::~DnsResolverImpl() = default;

DnsResult DnsResolverImpl::resolve(const std::string& domain, 
                                  DnsRecordType type,
                                  ResolveMethod method) {
    DnsResult result;
    result.domains.push_back(domain);
    
    // 验证域名格式
    if (!isValidDomain(domain)) {
        result.error_message = "无效的域名格式";
        return result;
    }
    
    switch (method) {
        case ResolveMethod::GETHOSTBYNAME:
            return resolveWithGethostbyname(domain);
        case ResolveMethod::DNS_PACKET:
            return resolveWithDnsPacket(domain, type);
        case ResolveMethod::CUSTOM_PACKET:
            result.error_message = "CUSTOM_PACKET方法需要调用resolveWithPacket接口";
            return result;
    }
    
    result.error_message = "未知的解析方法";
    return result;
}

DnsResult DnsResolverImpl::resolveWithPacket(const DnsPacket& packet) {
    DnsResult result;
    
    // 从数据包中提取查询的域名
    for (const auto& question : packet.questions) {
        result.domains.push_back(question);
    }
    
    // 构建自定义数据包
    std::vector<uint8_t> packet_data = DnsPacketBuilder::buildCustomPacket(packet);
    
    // 发送数据包
    return sender_->sendPacket(dns_server_, dns_port_, packet_data, timeout_ms_);
}

void DnsResolverImpl::setDnsServer(const std::string& server, uint16_t port) {
    dns_server_ = server;
    dns_port_ = port;
}

void DnsResolverImpl::setTimeout(int timeout_ms) {
    timeout_ms_ = timeout_ms;
}

DnsResult DnsResolverImpl::resolveWithGethostbyname(const std::string& domain) {
    DnsResult result;
    result.domains.push_back(domain);
    
    struct hostent* he = gethostbyname(domain.c_str());
    if (!he) {
        result.error_message = "gethostbyname失败: " + std::string(hstrerror(h_errno));
        return result;
    }
    
    // 提取IP地址
    for (int i = 0; he->h_addr_list[i] != nullptr; ++i) {
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, he->h_addr_list[i], ip, INET_ADDRSTRLEN);
        result.addresses.push_back(ip);
        
        // 创建DNS记录
        DnsRecord record;
        record.name = domain;
        record.type = DnsRecordType::A;
        record.class_ = DnsRecordClass::IN;
        record.ttl = 300; // 默认TTL
        record.data = std::string(he->h_addr_list[i], he->h_length);
        result.records.push_back(record);
    }
    
    result.success = true;
    return result;
}

DnsResult DnsResolverImpl::resolveWithDnsPacket(const std::string& domain, DnsRecordType type) {
    // 构建DNS查询数据包
    std::vector<uint8_t> packet = DnsPacketBuilder::buildQueryPacket(domain, type);
    
    // 发送数据包
    return sender_->sendPacket(dns_server_, dns_port_, packet, timeout_ms_);
}

bool DnsResolverImpl::isValidDomain(const std::string& domain) {
    if (domain.empty() || domain.length() > 253) {
        return false;
    }
    
    // 检查是否包含有效字符
    for (char c : domain) {
        if (!((c >= 'a' && c <= 'z') || 
              (c >= 'A' && c <= 'Z') || 
              (c >= '0' && c <= '9') || 
              c == '-' || c == '.')) {
            return false;
        }
    }
    
    // 检查是否以点开头或结尾
    if (domain.front() == '.' || domain.back() == '.') {
        return false;
    }
    
    // 检查是否包含连续的点
    if (domain.find("..") != std::string::npos) {
        return false;
    }
    
    return true;
}

std::string DnsResolverImpl::getDefaultDnsServer() {
    // 尝试从/etc/resolv.conf读取默认DNS服务器
    std::ifstream resolv_conf("/etc/resolv.conf");
    if (resolv_conf.is_open()) {
        std::string line;
        while (std::getline(resolv_conf, line)) {
            if (line.substr(0, 8) == "nameserver") {
                size_t pos = line.find_first_not_of(" \t", 8);
                if (pos != std::string::npos) {
                    size_t end = line.find_first_of(" \t", pos);
                    if (end == std::string::npos) {
                        end = line.length();
                    }
                    return line.substr(pos, end - pos);
                }
            }
        }
    }
    
    // 默认返回Google DNS
    return "8.8.8.8";
}

} // namespace zjpdns 