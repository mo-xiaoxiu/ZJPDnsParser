#pragma once

#include "dns_parser.h"
#include "dns_resolver.h"
#include <thread>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <atomic>

namespace zjpdns {

// 异步DNS解析器实现类
class AsyncDnsResolverImpl : public AsyncDnsResolver {
public:
    AsyncDnsResolverImpl();
    ~AsyncDnsResolverImpl() override;
    
    // 异步解析接口
    std::future<DnsResult> resolveAsync(const std::string& domain,
                                       DnsRecordType type = DnsRecordType::A,
                                       ResolveMethod method = ResolveMethod::GETHOSTBYNAME) override;
    
    // 使用自定义DNS数据包异步解析
    std::future<DnsResult> resolveWithPacketAsync(const DnsPacket& packet) override;
    
    // 使用gethostbyname异步解析
    // std::future<DnsResult> resolveWithGethostbynameAsync(const std::string& domain);
    
    // 使用自定义DNS数据包异步解析（回调方式）
    void resolveWithPacketCallback(const DnsPacket& packet,
                                  std::function<void(const DnsResult&)> callback) override;
    
    // 回调式异步解析
    void resolveWithCallback(const std::string& domain,
                           std::function<void(const DnsResult&)> callback,
                           DnsRecordType type = DnsRecordType::A,
                           ResolveMethod method = ResolveMethod::GETHOSTBYNAME) override;
    
    // 设置DNS服务器
    void setDnsServer(const std::string& server, uint16_t port = 53) override;
    
    // 设置超时时间
    void setTimeout(int timeout_ms) override;
    
    // 启动工作线程
    void start();
    
    // 停止工作线程
    void stop();

private:
    struct Task {
        std::string domain;
        DnsRecordType type;
        ResolveMethod method;
        DnsPacket custom_packet;
        bool use_custom_packet;
        std::function<void(const DnsResult&)> callback;
        std::promise<DnsResult> promise;
        
        Task() : type(DnsRecordType::A), method(ResolveMethod::GETHOSTBYNAME), 
                 use_custom_packet(false) {}
    };
    
    std::unique_ptr<DnsResolver> resolver_;
    std::thread worker_thread_;
    std::queue<Task> task_queue_;
    std::mutex queue_mutex_;
    std::condition_variable queue_cv_;
    std::atomic<bool> running_;
    
    // 工作线程函数
    void workerThread();
    
    // 执行解析任务
    void executeTask(Task& task);
    
    // 添加任务到队列
    void addTask(Task task);
};

} // namespace zjpdns 