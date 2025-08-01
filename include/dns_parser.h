#pragma once

#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <future>

namespace zjpdns {

// DNS记录类型
enum class DnsRecordType : uint16_t {
    A = 1,           // IPv4地址
    AAAA = 28,       // IPv6地址
    CNAME = 5,       // 规范名称
    MX = 15,         // 邮件交换
    TXT = 16,        // 文本记录
    NS = 2,          // 名称服务器
    PTR = 12,        // 指针记录
    SOA = 6,         // 起始授权
    SRV = 33,        // 服务记录
    CAA = 257        // 证书颁发机构授权
};

// DNS记录类
enum class DnsRecordClass : uint16_t {
    IN = 1,          // Internet
    CS = 2,          // CSNET
    CH = 3,          // CHAOS
    HS = 4           // Hesiod
};

// DNS解析方式
enum class ResolveMethod {
    GETHOSTBYNAME,   // 使用gethostbyname
    DNS_PACKET,      // 使用DNS数据包
    CUSTOM_PACKET    // 使用自定义DNS数据包
};

// DNS记录结构
struct DnsRecord {
    std::string name;
    DnsRecordType type;
    DnsRecordClass class_;
    uint32_t ttl;
    std::string data;
    
    DnsRecord() : type(DnsRecordType::A), class_(DnsRecordClass::IN), ttl(0) {}
};

// DNS解析结果
struct DnsResult {
    std::vector<std::string> domains;
    std::vector<std::string> addresses;  // IP地址列表
    std::vector<DnsRecord> records;      // 完整DNS记录
    bool success;
    std::string error_message;
    
    DnsResult() : success(false) {}
};

// DNS数据包结构
struct DnsPacket {
    uint16_t id;                    // 事务ID
    uint16_t flags;                 // 标志位
    uint16_t qdcount;               // 问题数量
    uint16_t ancount;               // 回答数量
    uint16_t nscount;               // 权威数量
    uint16_t arcount;               // 附加数量
    std::vector<std::string> questions;  // 问题列表
    std::vector<DnsRecord> answers;      // 回答列表
    std::vector<DnsRecord> authorities;  // 权威列表
    std::vector<DnsRecord> additionals;  // 附加列表
    
    DnsPacket() : id(0), flags(0), qdcount(0), ancount(0), nscount(0), arcount(0) {}
};

// DNS解析器接口
class DnsResolver {
public:
    virtual ~DnsResolver() = default;
    
    // 同步解析接口
    virtual DnsResult resolve(const std::string& domain, 
                             DnsRecordType type = DnsRecordType::A,
                             ResolveMethod method = ResolveMethod::GETHOSTBYNAME) = 0;
    
    // 使用自定义DNS数据包解析
    virtual DnsResult resolveWithPacket(const DnsPacket& packet) = 0;
    
    // 设置DNS服务器
    virtual void setDnsServer(const std::string& server, uint16_t port = 53) = 0;
    
    // 设置超时时间
    virtual void setTimeout(int timeout_ms) = 0;
};

// 异步DNS解析器接口
class AsyncDnsResolver {
public:
    virtual ~AsyncDnsResolver() = default;
    
    // 异步解析接口
    virtual std::future<DnsResult> resolveAsync(const std::string& domain,
                                               DnsRecordType type = DnsRecordType::A,
                                               ResolveMethod method = ResolveMethod::GETHOSTBYNAME) = 0;
    
    // 使用自定义DNS数据包异步解析
    virtual std::future<DnsResult> resolveWithPacketAsync(const DnsPacket& packet) = 0;
    
    // 使用自定义DNS数据包异步解析（回调方式）
    virtual void resolveWithPacketCallback(const DnsPacket& packet,
                                         std::function<void(const DnsResult&)> callback) = 0;
    
    // 回调式异步解析
    virtual void resolveWithCallback(const std::string& domain,
                                   std::function<void(const DnsResult&)> callback,
                                   DnsRecordType type = DnsRecordType::A,
                                   ResolveMethod method = ResolveMethod::GETHOSTBYNAME) = 0;
    
    // 设置DNS服务器
    virtual void setDnsServer(const std::string& server, uint16_t port = 53) = 0;
    
    // 设置超时时间
    virtual void setTimeout(int timeout_ms) = 0;
};

// 工厂函数
std::unique_ptr<DnsResolver> createDnsResolver();
std::unique_ptr<AsyncDnsResolver> createAsyncDnsResolver();

} // namespace zjpdns 