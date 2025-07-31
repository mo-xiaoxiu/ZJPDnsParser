# ZJP DNS解析器

一个功能完整的现代C++ DNS解析器库，支持同步和异步解析，提供多种解析方式。

## 功能特性

- **现代C++17**：使用最新的C++标准
- **多种解析方式**：
  - `gethostbyname` 系统调用
  - DNS数据包直接发送
  - 自定义DNS数据包
- **同步和异步接口**：
  - 同步解析接口
  - 异步解析接口（基于future/promise）
  - 回调式异步解析
- **灵活的编译选项**：
  - 支持静态库编译
  - 支持动态库编译
- **完整的工具链支持**：
  - CMake构建系统
  - pkg-config支持
  - 单元测试

## 编译要求

- CMake 3.16+
- C++17兼容的编译器
- Linux系统（支持POSIX socket）

## 编译安装

```bash
# 克隆项目
git clone <repository-url>
cd ZJPDnsParser

# 创建构建目录
mkdir build && cd build

# 配置编译选项
cmake .. -DCMAKE_BUILD_TYPE=Release

# 编译
make -j$(nproc)

# 安装
sudo make install
```

## 编译选项

- `BUILD_SHARED_LIBS=ON/OFF`：是否构建动态库（默认ON）
- `BUILD_STATIC_LIBS=ON/OFF`：是否构建静态库（默认ON）
- `CMAKE_BUILD_TYPE=Debug/Release`：构建类型

## 使用示例

### 基本使用

```cpp
#include "dns_parser.h"

int main() {
    // 创建解析器
    auto resolver = zjpdns::createDnsResolver();
    
    // 设置DNS服务器
    resolver->setDnsServer("8.8.8.8", 53);
    resolver->setTimeout(5000);
    
    // 同步解析
    auto result = resolver->resolve("www.google.com", 
                                  zjpdns::DnsRecordType::A,
                                  zjpdns::ResolveMethod::DNS_PACKET);
    
    if (result.success) {
        for (const auto& addr : result.addresses) {
            std::cout << "IP: " << addr << std::endl;
        }
    }
    
    return 0;
}
```

### 异步解析

```cpp
#include "dns_parser.h"

int main() {
    // 创建异步解析器
    auto async_resolver = zjpdns::createAsyncDnsResolver();
    
    // 异步解析
    auto future = async_resolver->resolveAsync("www.google.com");
    auto result = future.get();
    
    // 回调式解析
    async_resolver->resolveWithCallback("www.google.com", 
        [](const zjpdns::DnsResult& result) {
            std::cout << "解析完成: ";
            if (!result.domains.empty()) {
                std::cout << result.domains[0];
            } else {
                std::cout << "无域名";
            }
            std::cout << std::endl;
        });
    
    return 0;
}
```

### 新的异步接口

#### 1. 自定义数据包异步解析

```cpp
// 创建自定义DNS数据包
zjpdns::DnsPacket custom_packet;
custom_packet.id = 12345;
custom_packet.flags = 0x0100; // 标准查询
custom_packet.qdcount = 1;
custom_packet.questions.push_back("www.example.com");

// 异步解析自定义数据包
auto future = async_resolver->resolveWithPacketAsync(custom_packet);
auto result = future.get();

// 回调式解析自定义数据包
async_resolver->resolveWithPacketCallback(custom_packet,
    [](const zjpdns::DnsResult& result) {
        std::cout << "自定义数据包解析完成!" << std::endl;
        // 处理结果
    });
```

### 自定义DNS数据包

```cpp
#include "dns_parser.h"

int main() {
    auto resolver = zjpdns::createDnsResolver();
    
    // 创建自定义DNS数据包
    zjpdns::DnsPacket packet;
    packet.id = 12345;
    packet.flags = 0x0100; // 标准查询
    packet.qdcount = 1;
    packet.questions.push_back("www.example.com");
    
    // 使用自定义数据包解析
    auto result = resolver->resolveWithPacket(packet);
    
    return 0;
}
```

## API文档

### 主要类

#### DnsResolver
同步DNS解析器接口

- `resolve(domain, type, method)`：解析域名
- `resolveWithPacket(packet)`：使用自定义数据包解析
- `setDnsServer(server, port)`：设置DNS服务器
- `setTimeout(timeout_ms)`：设置超时时间

#### AsyncDnsResolver
异步DNS解析器接口

- `resolveAsync(domain, type, method)`：异步解析
- `resolveWithPacketAsync(packet)`：异步自定义数据包解析
- `resolveWithPacketCallback(packet, callback)`：自定义数据包回调式异步解析
- `resolveWithCallback(domain, callback, type, method)`：回调式解析

#### DnsPacketBuilder
DNS数据包构建工具

- `buildQueryPacket(domain, type, class, id)`：构建查询数据包
- `buildCustomPacket(packet)`：构建自定义数据包
- `parseResponsePacket(data)`：解析响应数据包

### 枚举类型

#### DnsRecordType
- `A`：IPv4地址
- `AAAA`：IPv6地址
- `CNAME`：规范名称
- `MX`：邮件交换
- `TXT`：文本记录
- `NS`：名称服务器
- `PTR`：指针记录
- `SOA`：起始授权
- `SRV`：服务记录
- `CAA`：证书颁发机构授权

#### ResolveMethod
- `GETHOSTBYNAME`：使用gethostbyname系统调用
- `DNS_PACKET`：使用DNS数据包
- `CUSTOM_PACKET`：使用自定义DNS数据包

## 测试

```bash
# 运行示例程序
./dns_example

# 运行单元测试
./tests/dns_test
```

## pkg-config使用

安装后可以通过pkg-config使用：

```bash
# 编译时
g++ -o myapp myapp.cpp $(pkg-config --cflags --libs zjpdns)

# 查看库信息
pkg-config --modversion zjpdns
pkg-config --cflags zjpdns
pkg-config --libs zjpdns
```

## 许可证

本项目采用MIT许可证。

## 贡献

欢迎提交Issue和Pull Request！

## 更新日志

### v1.0.0
- 初始版本发布
- 支持同步和异步DNS解析
- 支持多种解析方式
- 完整的CMake构建系统
- pkg-config支持 