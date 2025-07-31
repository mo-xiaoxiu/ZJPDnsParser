#include "dns_parser.h"
#include "dns_resolver.h"
#include "async_resolver.h"

namespace zjpdns {

// 工厂函数实现
std::unique_ptr<DnsResolver> createDnsResolver() {
    return std::make_unique<DnsResolverImpl>();
}

std::unique_ptr<AsyncDnsResolver> createAsyncDnsResolver() {
    auto resolver = std::make_unique<AsyncDnsResolverImpl>();
    resolver->start(); // 启动工作线程
    return resolver;
}

} // namespace zjpdns 