#include "async_resolver.h"
#include "dns_resolver.h"
#include <chrono>

namespace zjpdns {

AsyncDnsResolverImpl::AsyncDnsResolverImpl() : running_(false) {
    resolver_ = std::make_unique<DnsResolverImpl>();
}

AsyncDnsResolverImpl::~AsyncDnsResolverImpl() {
    stop();
}

std::future<DnsResult> AsyncDnsResolverImpl::resolveAsync(const std::string& domain,
                                                         DnsRecordType type,
                                                         ResolveMethod method) {
    std::promise<DnsResult> promise;
    std::future<DnsResult> future = promise.get_future();
    
    Task task;
    task.domain = domain;
    task.type = type;
    task.method = method;
    task.use_custom_packet = false;
    task.promise = std::move(promise);
    
    addTask(std::move(task));
    return future;
}

std::future<DnsResult> AsyncDnsResolverImpl::resolveWithPacketAsync(const DnsPacket& packet) {
    std::promise<DnsResult> promise;
    std::future<DnsResult> future = promise.get_future();
    
    Task task;
    task.use_custom_packet = true;
    task.custom_packet = packet;
    task.promise = std::move(promise);
    
    addTask(std::move(task));
    return future;
}

void AsyncDnsResolverImpl::resolveWithCallback(const std::string& domain,
                                             std::function<void(const DnsResult&)> callback,
                                             DnsRecordType type,
                                             ResolveMethod method) {
    Task task;
    task.domain = domain;
    task.type = type;
    task.method = method;
    task.use_custom_packet = false;
    task.callback = callback;
    
    addTask(std::move(task));
}

void AsyncDnsResolverImpl::resolveWithPacketCallback(const DnsPacket& packet,
                                                   std::function<void(const DnsResult&)> callback) {
    Task task;
    task.use_custom_packet = true;
    task.custom_packet = packet;
    task.callback = callback;
    
    addTask(std::move(task));
}

void AsyncDnsResolverImpl::setDnsServer(const std::string& server, uint16_t port) {
    if (resolver_) {
        resolver_->setDnsServer(server, port);
    }
}

void AsyncDnsResolverImpl::setTimeout(int timeout_ms) {
    if (resolver_) {
        resolver_->setTimeout(timeout_ms);
    }
}

void AsyncDnsResolverImpl::start() {
    if (!running_) {
        running_ = true;
        worker_thread_ = std::thread(&AsyncDnsResolverImpl::workerThread, this);
    }
}

void AsyncDnsResolverImpl::stop() {
    if (running_) {
        running_ = false;
        queue_cv_.notify_all();
        
        if (worker_thread_.joinable()) {
            worker_thread_.join();
        }
    }
}

void AsyncDnsResolverImpl::workerThread() {
    while (running_) {
        Task task;
        
        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            queue_cv_.wait(lock, [this] { return !task_queue_.empty() || !running_; });
            
            if (!running_ && task_queue_.empty()) {
                break;
            }
            
            if (!task_queue_.empty()) {
                task = std::move(task_queue_.front());
                task_queue_.pop();
            }
        }
        
        // 对于自定义数据包任务，不需要检查domain是否为空
        if (!task.use_custom_packet && task.domain.empty()) {
            continue;
        }
        
        executeTask(task);
    }
}

void AsyncDnsResolverImpl::executeTask(Task& task) {
    DnsResult result;
    
    if (task.use_custom_packet) {
        result = resolver_->resolveWithPacket(task.custom_packet);
    } else {
        result = resolver_->resolve(task.domain, task.type, task.method);
    }
    
    // 处理回调
    if (task.callback) {
        task.callback(result);
    }
    
    // 处理promise
    task.promise.set_value(result);
}

void AsyncDnsResolverImpl::addTask(Task task) {
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        task_queue_.push(std::move(task));
    }
    queue_cv_.notify_one();
}

} // namespace zjpdns 