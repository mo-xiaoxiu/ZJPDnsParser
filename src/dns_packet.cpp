#include "dns_packet.h"
#include <cstring>
#include <random>
#include <algorithm>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>

namespace zjpdns {

// DNS数据包构建器实现
std::vector<uint8_t> DnsPacketBuilder::buildQueryPacket(const std::string& domain,
                                                        DnsRecordType type,
                                                        DnsRecordClass class_,
                                                        uint16_t id) {
    std::vector<uint8_t> packet;
    
    // 生成事务ID
    if (id == 0) {
        id = generateTransactionId();
    }
    
    // DNS头部 (12字节)
    uint16_t network_id = ::htons(id);
    uint16_t flags = ::htons(buildFlags(true, true));
    uint16_t qdcount = ::htons(1);
    uint16_t ancount = ::htons(0);
    uint16_t nscount = ::htons(0);
    uint16_t arcount = ::htons(0);
    
    packet.insert(packet.end(), (uint8_t*)&network_id, (uint8_t*)&network_id + 2);
    packet.insert(packet.end(), (uint8_t*)&flags, (uint8_t*)&flags + 2);
    packet.insert(packet.end(), (uint8_t*)&qdcount, (uint8_t*)&qdcount + 2);
    packet.insert(packet.end(), (uint8_t*)&ancount, (uint8_t*)&ancount + 2);
    packet.insert(packet.end(), (uint8_t*)&nscount, (uint8_t*)&nscount + 2);
    packet.insert(packet.end(), (uint8_t*)&arcount, (uint8_t*)&arcount + 2);
    
    // 编码域名
    std::vector<uint8_t> encoded_domain = encodeDomain(domain);
    packet.insert(packet.end(), encoded_domain.begin(), encoded_domain.end());
    
    // 查询类型和类
    uint16_t network_type = ::htons(static_cast<uint16_t>(type));
    uint16_t network_class = ::htons(static_cast<uint16_t>(class_));
    
    packet.insert(packet.end(), (uint8_t*)&network_type, (uint8_t*)&network_type + 2);
    packet.insert(packet.end(), (uint8_t*)&network_class, (uint8_t*)&network_class + 2);
    
    return packet;
}

std::vector<uint8_t> DnsPacketBuilder::buildCustomPacket(const DnsPacket& packet) {
    std::vector<uint8_t> data;
    
    // DNS头部
    uint16_t network_id = ::htons(packet.id);
    uint16_t network_flags = ::htons(packet.flags);
    uint16_t network_qdcount = ::htons(packet.qdcount);
    uint16_t network_ancount = ::htons(packet.ancount);
    uint16_t network_nscount = ::htons(packet.nscount);
    uint16_t network_arcount = ::htons(packet.arcount);
    
    data.insert(data.end(), (uint8_t*)&network_id, (uint8_t*)&network_id + 2);
    data.insert(data.end(), (uint8_t*)&network_flags, (uint8_t*)&network_flags + 2);
    data.insert(data.end(), (uint8_t*)&network_qdcount, (uint8_t*)&network_qdcount + 2);
    data.insert(data.end(), (uint8_t*)&network_ancount, (uint8_t*)&network_ancount + 2);
    data.insert(data.end(), (uint8_t*)&network_nscount, (uint8_t*)&network_nscount + 2);
    data.insert(data.end(), (uint8_t*)&network_arcount, (uint8_t*)&network_arcount + 2);
    
    // 问题部分
    for (const auto& question : packet.questions) {
        std::vector<uint8_t> encoded_domain = encodeDomain(question);
        data.insert(data.end(), encoded_domain.begin(), encoded_domain.end());
        
        // 添加查询类型和类（默认为A记录和IN类）
        uint16_t network_type = ::htons(static_cast<uint16_t>(DnsRecordType::A));
        uint16_t network_class = ::htons(static_cast<uint16_t>(DnsRecordClass::IN));
        data.insert(data.end(), (uint8_t*)&network_type, (uint8_t*)&network_type + 2);
        data.insert(data.end(), (uint8_t*)&network_class, (uint8_t*)&network_class + 2);
    }
    
    // 记录部分
    for (const auto& record : packet.answers) {
        std::vector<uint8_t> encoded_record = encodeRecord(record);
        data.insert(data.end(), encoded_record.begin(), encoded_record.end());
    }
    
    for (const auto& record : packet.authorities) {
        std::vector<uint8_t> encoded_record = encodeRecord(record);
        data.insert(data.end(), encoded_record.begin(), encoded_record.end());
    }
    
    for (const auto& record : packet.additionals) {
        std::vector<uint8_t> encoded_record = encodeRecord(record);
        data.insert(data.end(), encoded_record.begin(), encoded_record.end());
    }
    
    return data;
}

DnsResult DnsPacketBuilder::parseResponsePacket(const std::vector<uint8_t>& data) {
    DnsResult result;
    
    if (data.size() < 12) {
        result.error_message = "DNS响应数据包太小";
        return result;
    }
    
    size_t offset = 0;
    
    // 解析头部
    uint16_t id = ::ntohs(*reinterpret_cast<const uint16_t*>(&data[offset]));
    offset += 2;
    uint16_t flags = ::ntohs(*reinterpret_cast<const uint16_t*>(&data[offset]));
    offset += 2;
    uint16_t qdcount = ::ntohs(*reinterpret_cast<const uint16_t*>(&data[offset]));
    offset += 2;
    uint16_t ancount = ::ntohs(*reinterpret_cast<const uint16_t*>(&data[offset]));
    offset += 2;
    uint16_t nscount = ::ntohs(*reinterpret_cast<const uint16_t*>(&data[offset]));
    offset += 2;
    uint16_t arcount = ::ntohs(*reinterpret_cast<const uint16_t*>(&data[offset]));
    offset += 2;
    
    // 检查响应标志
    bool isResponse = (flags & 0x8000) != 0;
    bool isAuthoritative = (flags & 0x0400) != 0;
    bool isTruncated = (flags & 0x0200) != 0;
    bool isRecursionDesired = (flags & 0x0100) != 0;
    bool isRecursionAvailable = (flags & 0x0080) != 0;
    uint8_t responseCode = flags & 0x000F;
    
    if (!isResponse) {
        result.error_message = "不是DNS响应数据包";
        return result;
    }
    
    if (responseCode != 0) {
        result.error_message = "DNS响应错误，错误码: " + std::to_string(responseCode);
        return result;
    }
    
    // 解析问题部分，提取查询的域名
    for (uint16_t i = 0; i < qdcount; ++i) {
        if (offset >= data.size()) break;
        std::string domain = decodeDomain(data, offset);
        result.domains.push_back(domain);
        offset += 4; // 跳过类型和类
    }
    
    // 解析回答部分
    for (uint16_t i = 0; i < ancount; ++i) {
        if (offset >= data.size()) break;
        DnsRecord record = decodeRecord(data, offset);
        result.records.push_back(record);
        
        // 提取IP地址
        if (record.type == DnsRecordType::A && record.data.length() == 4) {
            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, record.data.c_str(), ip, INET_ADDRSTRLEN);
            result.addresses.push_back(ip);
        } else if (record.type == DnsRecordType::AAAA && record.data.length() == 16) {
            char ip[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, record.data.c_str(), ip, INET6_ADDRSTRLEN);
            result.addresses.push_back(ip);
        }
    }
    
    result.success = true;
    return result;
}

DnsPacket DnsPacketBuilder::parsePacket(const std::vector<uint8_t>& data) {
    DnsPacket packet;
    
    if (data.size() < 12) return packet;
    
    size_t offset = 0;
    
    // 解析头部
    packet.id = ::ntohs(*reinterpret_cast<const uint16_t*>(&data[offset]));
    offset += 2;
    packet.flags = ::ntohs(*reinterpret_cast<const uint16_t*>(&data[offset]));
    offset += 2;
    packet.qdcount = ::ntohs(*reinterpret_cast<const uint16_t*>(&data[offset]));
    offset += 2;
    packet.ancount = ::ntohs(*reinterpret_cast<const uint16_t*>(&data[offset]));
    offset += 2;
    packet.nscount = ::ntohs(*reinterpret_cast<const uint16_t*>(&data[offset]));
    offset += 2;
    packet.arcount = ::ntohs(*reinterpret_cast<const uint16_t*>(&data[offset]));
    offset += 2;
    
    // 解析问题部分
    for (uint16_t i = 0; i < packet.qdcount; ++i) {
        if (offset >= data.size()) break;
        std::string domain = decodeDomain(data, offset);
        packet.questions.push_back(domain);
        offset += 4; // 跳过类型和类
    }
    
    // 解析记录部分
    for (uint16_t i = 0; i < packet.ancount; ++i) {
        if (offset >= data.size()) break;
        packet.answers.push_back(decodeRecord(data, offset));
    }
    
    for (uint16_t i = 0; i < packet.nscount; ++i) {
        if (offset >= data.size()) break;
        packet.authorities.push_back(decodeRecord(data, offset));
    }
    
    for (uint16_t i = 0; i < packet.arcount; ++i) {
        if (offset >= data.size()) break;
        packet.additionals.push_back(decodeRecord(data, offset));
    }
    
    return packet;
}

uint16_t DnsPacketBuilder::generateTransactionId() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<uint16_t> dis(1, 65535);
    return dis(gen);
}

uint16_t DnsPacketBuilder::buildFlags(bool isQuery, bool isRecursionDesired) {
    uint16_t flags = 0;
    
    if (!isQuery) {
        flags |= 0x8000; // QR位，表示响应
    }
    
    if (isRecursionDesired) {
        flags |= 0x0100; // RD位，表示期望递归
    }
    
    return flags;
}

std::vector<uint8_t> DnsPacketBuilder::encodeDomain(const std::string& domain) {
    std::vector<uint8_t> encoded;
    std::string temp = domain;
    
    // 确保以点结尾
    if (temp.back() != '.') {
        temp += '.';
    }
    
    size_t start = 0;
    size_t pos = temp.find('.');
    
    while (pos != std::string::npos) {
        std::string label = temp.substr(start, pos - start);
        encoded.push_back(static_cast<uint8_t>(label.length()));
        encoded.insert(encoded.end(), label.begin(), label.end());
        start = pos + 1;
        pos = temp.find('.', start);
    }
    
    encoded.push_back(0); // 结束标记
    return encoded;
}

std::string DnsPacketBuilder::decodeDomain(const std::vector<uint8_t>& data, size_t& offset) {
    std::string domain;
    
    while (offset < data.size()) {
        uint8_t length = data[offset++];
        
        if (length == 0) break; // 结束标记
        
        if ((length & 0xC0) == 0xC0) {
            // 压缩指针
            uint16_t pointer = ((length & 0x3F) << 8) | data[offset++];
            size_t old_offset = offset;
            offset = pointer;
            std::string compressed = decodeDomain(data, offset);
            offset = old_offset;
            domain += compressed;
            break;
        }
        
        if (offset + length > data.size()) break;
        
        std::string label(data.begin() + offset, data.begin() + offset + length);
        domain += label + ".";
        offset += length;
    }
    
    return domain;
}

std::vector<uint8_t> DnsPacketBuilder::encodeRecord(const DnsRecord& record) {
    std::vector<uint8_t> encoded;
    
    // 编码域名
    std::vector<uint8_t> encoded_name = encodeDomain(record.name);
    encoded.insert(encoded.end(), encoded_name.begin(), encoded_name.end());
    
    // 类型和类
    uint16_t network_type = htons(static_cast<uint16_t>(record.type));
    uint16_t network_class = htons(static_cast<uint16_t>(record.class_));
    uint32_t network_ttl = htonl(record.ttl);
    
    encoded.insert(encoded.end(), (uint8_t*)&network_type, (uint8_t*)&network_type + 2);
    encoded.insert(encoded.end(), (uint8_t*)&network_class, (uint8_t*)&network_class + 2);
    encoded.insert(encoded.end(), (uint8_t*)&network_ttl, (uint8_t*)&network_ttl + 4);
    
    // 数据长度和数据
    uint16_t data_length = htons(static_cast<uint16_t>(record.data.length()));
    encoded.insert(encoded.end(), (uint8_t*)&data_length, (uint8_t*)&data_length + 2);
    encoded.insert(encoded.end(), record.data.begin(), record.data.end());
    
    return encoded;
}

DnsRecord DnsPacketBuilder::decodeRecord(const std::vector<uint8_t>& data, size_t& offset) {
    DnsRecord record;
    
    // 解码域名
    record.name = decodeDomain(data, offset);
    
    if (offset + 10 > data.size()) return record;
    
    // 类型和类
    record.type = static_cast<DnsRecordType>(ntohs(*reinterpret_cast<const uint16_t*>(&data[offset])));
    offset += 2;
    record.class_ = static_cast<DnsRecordClass>(ntohs(*reinterpret_cast<const uint16_t*>(&data[offset])));
    offset += 2;
    record.ttl = ntohl(*reinterpret_cast<const uint32_t*>(&data[offset]));
    offset += 4;
    
    // 数据长度和数据
    uint16_t data_length = ntohs(*reinterpret_cast<const uint16_t*>(&data[offset]));
    offset += 2;
    
    if (offset + data_length <= data.size()) {
        record.data = std::string(data.begin() + offset, data.begin() + offset + data_length);
        offset += data_length;
    }
    
    return record;
}



// DNS数据包发送器实现
DnsPacketSender::DnsPacketSender() : retry_count_(3) {}

DnsPacketSender::~DnsPacketSender() = default;

DnsResult DnsPacketSender::sendPacket(const std::string& server, uint16_t port,
                                     const std::vector<uint8_t>& packet, int timeout_ms) {
    DnsResult result;
    
    int sockfd = createSocket();
    if (sockfd < 0) {
        result.error_message = "Create socket failed";
        return result;
    }
    
    // 发送数据
    if (!sendData(sockfd, packet, server, port)) {
        result.error_message = "Send DNS packet failed";
        close(sockfd);
        return result;
    }
    
    // 接收响应
    std::vector<uint8_t> response = receiveData(sockfd, timeout_ms);
    close(sockfd);
    
    if (response.empty()) {
        result.error_message = "Receive DNS response timeout";
        return result;
    }
    
    // 解析响应
    return DnsPacketBuilder::parseResponsePacket(response);
}

void DnsPacketSender::setRetryCount(int count) {
    retry_count_ = count;
}

int DnsPacketSender::createSocket() {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) return -1;
    
    // 设置非阻塞模式
    int flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
    
    return sockfd;
}

bool DnsPacketSender::sendData(int sockfd, const std::vector<uint8_t>& data,
                              const std::string& server, uint16_t port) {
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, server.c_str(), &server_addr.sin_addr) <= 0) {
        return false;
    }
    
    ssize_t sent = sendto(sockfd, data.data(), data.size(), 0,
                          (struct sockaddr*)&server_addr, sizeof(server_addr));
    
    return sent == static_cast<ssize_t>(data.size());
}

std::vector<uint8_t> DnsPacketSender::receiveData(int sockfd, int timeout_ms = DNS_TIMEOUT) {
    std::vector<uint8_t> buffer(4096);
    
    struct pollfd pfd;
    pfd.fd = sockfd;
    pfd.events = POLLIN;
    
    int poll_result = poll(&pfd, 1, timeout_ms);
    if (poll_result <= 0) {
        return std::vector<uint8_t>();
    }
    
    ssize_t received = recv(sockfd, buffer.data(), buffer.size(), 0);
    if (received <= 0) {
        return std::vector<uint8_t>();
    }
    
    buffer.resize(received);
    return buffer;
}

} // namespace zjpdns 