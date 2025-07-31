#pragma once

#include "dns_parser.h"
#include <vector>
#include <string>

namespace zjpdns {

#define DNS_TIMEOUT 5000

// DNS数据包处理类
class DnsPacketBuilder {
public:
    // 构建DNS查询数据包
    static std::vector<uint8_t> buildQueryPacket(const std::string& domain,
                                                 DnsRecordType type = DnsRecordType::A,
                                                 DnsRecordClass class_ = DnsRecordClass::IN,
                                                 uint16_t id = 0);
    
    // 构建自定义DNS数据包
    static std::vector<uint8_t> buildCustomPacket(const DnsPacket& packet);
    
    // 解析DNS响应数据包
    static DnsResult parseResponsePacket(const std::vector<uint8_t>& data);
    
    // 解析DNS数据包
    static DnsPacket parsePacket(const std::vector<uint8_t>& data);
    
    // 生成随机事务ID
    static uint16_t generateTransactionId();
    
    // 设置DNS标志位
    static uint16_t buildFlags(bool isQuery = true, bool isRecursionDesired = true);

    // 编码域名（测试用）
    static std::vector<uint8_t> encodeDomain(const std::string& domain);
    // 解码域名（测试用）
    static std::string decodeDomain(const std::vector<uint8_t>& data, size_t& offset);

private:
    // 编码DNS记录
    static std::vector<uint8_t> encodeRecord(const DnsRecord& record);
    
    // 解码DNS记录
    static DnsRecord decodeRecord(const std::vector<uint8_t>& data, size_t& offset);
};

// DNS数据包发送器
class DnsPacketSender {
public:
    DnsPacketSender();
    ~DnsPacketSender();
    
    // 发送DNS数据包
    DnsResult sendPacket(const std::string& server, uint16_t port,
                        const std::vector<uint8_t>& packet, int timeout_ms = DNS_TIMEOUT);
    
    // 设置重试次数
    void setRetryCount(int count);

private:
    int timeout_ms_;
    int retry_count_;
    
    // 创建UDP socket
    int createSocket();
    
    // 发送数据
    bool sendData(int sockfd, const std::vector<uint8_t>& data, 
                  const std::string& server, uint16_t port);
    
    // 接收数据
    std::vector<uint8_t> receiveData(int sockfd, int timeout_ms);
};

} // namespace zjpdns 