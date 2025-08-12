# 企业微信智能客服系统

一个基于企业微信客服API和Dify AI的智能客服系统，支持自动回复、上下文记忆和多媒体消息处理。

## 🚀 功能特性

- **智能对话**：集成Dify AI引擎，提供智能问答服务
- **上下文记忆**：自动管理conversation_id，支持多轮对话
- **消息处理**：支持文本、图片、语音、文件等多种消息类型
- **实时响应**：基于企业微信Webhook实时接收和回复消息
- **缓存优化**：使用Memcache提升性能和数据持久化
- **去重机制**：防止重复处理同一消息
- **对话管理**：支持重置对话上下文

## 📋 系统架构

```
企业微信用户 → 企业微信客服 → Webhook → 本系统 → Dify AI → 智能回复
                    ↑                              ↓
                 Memcache缓存 ← ← ← ← ← ← ← ← ← ← ← ←
```

## 🛠️ 技术栈

- **Python 3.x**
- **Flask** - Web框架
- **Memcached** - 缓存和状态管理 (使用memcached.exe)
- **企业微信API** - 消息接收和发送
- **Dify API** - AI对话服务
- **PyCryptodome** - 消息加解密

## 📦 安装部署

### 1. 环境要求

- Python 3.7+
- Memcached服务 (memcached.exe)
- 企业微信应用
- Dify AI平台

### 2. 安装Memcached

**Windows环境下安装memcached.exe：**

1. **下载memcached**
   ```bash
   # 下载地址: https://www.memcached.org/downloads
   # 或使用预编译版本
   ```

2. **启动memcached服务**
   ```bash
   # 命令行启动 (默认端口11211)
   memcached.exe -p 11211 -m 64

   # 或作为Windows服务安装
   memcached.exe -d install
   memcached.exe -d start
   ```

3. **验证安装**
   ```bash
   # 使用telnet测试连接
   telnet localhost 11211
   ```

### 3. 安装依赖

```bash
pip install -r requirements.txt
```

### 4. 配置文件

复制并修改 `config.ini` 文件：

```ini
[CONFIG]
# 企业微信配置
CORP_ID = your_corp_id
AGENT_ID = your_agent_id
CORP_SECRET = your_corp_secret
TOKEN = your_webhook_token
ENCODING_AES_KEY = your_encoding_aes_key

# Dify AI配置
DIFY_API_BASE = http://your-dify-server:port/v1
DIFY_API_KEY = your_dify_api_key

[MEMCACHE]
host = localhost
port = 11211
connect_timeout = 5
timeout = 5
```

### 4. 启动服务

```bash
python AICustomerService.py
```

服务将在 `http://0.0.0.0:11850` 启动

## 🔧 配置说明

### 企业微信配置

1. **创建企业微信应用**
   - 登录企业微信管理后台
   - 创建自建应用，获取 `CORP_ID`、`AGENT_ID`、`CORP_SECRET`

2. **配置客服功能**
   - 开启客服功能
   - 设置Webhook回调URL：`http://your-server:11850/webhook`
   - 配置Token和EncodingAESKey

3. **设置接收消息**
   - 开启"接收消息"
   - 配置可信域名

### Dify配置

1. **创建AI应用**
   - 在Dify平台创建聊天助手应用
   - 获取API密钥

2. **配置API**
   - 设置 `DIFY_API_BASE` 为Dify服务地址
   - 设置 `DIFY_API_KEY` 为应用API密钥

## 🔄 工作流程

### 消息处理流程

1. **接收消息**：企业微信Webhook推送消息事件
2. **解密验证**：验证签名并解密消息内容
3. **去重检查**：检查消息是否已处理过
4. **获取对话**：从缓存获取用户的conversation_id
5. **调用AI**：发送消息到Dify获取智能回复
6. **保存上下文**：保存conversation_id到缓存
7. **发送回复**：通过企业微信API发送回复

### 上下文管理

- **首次对话**：不带conversation_id调用Dify
- **后续对话**：使用缓存的conversation_id保持上下文
- **重置对话**：用户发送"重置"等关键词清空上下文

## 📡 API接口

### Webhook接口

- `GET/POST /webhook` - 企业微信消息接收入口

### 管理接口

- `GET /status` - 查看服务状态
- `POST /clear` - 清空缓存数据
- `GET /get_conversation?user_id={用户ID}` - 查询用户对话ID
- `POST /reset_conversation` - 重置用户对话上下文

### API使用示例

```bash
# 查询用户对话状态
curl "http://localhost:11850/get_conversation?user_id=user123"

# 重置用户对话
curl -X POST http://localhost:11850/reset_conversation \
  -H "Content-Type: application/json" \
  -d '{"user_id": "user123"}'

# 查看服务状态
curl http://localhost:11850/status
```

## 💬 支持的消息类型

| 消息类型 | 处理方式 | 回复内容 |
|---------|---------|---------|
| 文本消息 | 发送到Dify AI | AI智能回复 |
| 图片消息 | 暂不支持分析 | 提示用文字描述 |
| 语音消息 | 暂不支持识别 | 提示用文字描述 |
| 文件消息 | 暂不支持分析 | 提示用文字描述 |

## 🎯 特殊指令

用户可以发送以下指令来控制对话：

- `重置` / `reset` / `重新开始` / `清空对话` - 重置对话上下文

## 🔍 日志监控

系统提供详细的日志输出，包括：

- ✅ 成功操作
- ❌ 错误信息  
- ⚠️ 警告提示
- 🔄 状态变更
- 💬 消息内容
- 📊 统计信息

## 🛡️ 安全特性

- **消息加密**：支持企业微信AES加密
- **签名验证**：验证webhook请求签名
- **去重处理**：防止重复消息处理
- **错误恢复**：完善的异常处理机制

## 📈 性能优化

- **连接池**：复用HTTP连接
- **缓存策略**：Memcache缓存热点数据
- **异步处理**：非阻塞消息处理
- **超时控制**：设置合理的请求超时

## 🔧 故障排除

### 常见问题

1. **Webhook验证失败**
   - 检查Token和EncodingAESKey配置
   - 确认企业微信回调URL设置正确

2. **Memcached连接失败**
   - 检查memcached.exe服务是否正在运行
   - 确认host和port配置正确（默认localhost:11211）
   - Windows防火墙是否阻止了memcached端口
   - 尝试重启memcached服务：
     ```bash
     # 停止服务
     memcached.exe -d stop
     # 启动服务  
     memcached.exe -d start
     ```

3. **Dify API调用失败**
   - 检查DIFY_API_BASE和DIFY_API_KEY
   - 确认Dify服务可访问

4. **消息重复处理**
   - 检查去重机制是否正常
   - 查看Memcache中的处理记录

### 调试模式

可以使用 `webhook_debug.py` 进行调试：

```bash
python webhook_debug.py
```

## 📝 开发说明

### 目录结构

```
├── AICustomerService.py     # 主服务程序
├── config.ini              # 配置文件
├── requirements.txt         # 依赖包列表
├── README.md               # 项目文档
├── webhook_debug.py        # Webhook调试工具
├── msgReader.py           # 消息读取器(基础版)
├── msgReader_with_Memcache.py # 消息读取器(缓存版)
├── wechat_message_reader.py   # 微信消息读取器
└── DifyWebhook.py         # Dify Webhook处理器
```

### 扩展开发

如需扩展功能，可以修改以下模块：

- `process_single_kf_message()` - 消息处理逻辑
- `call_dify_api()` - AI调用接口
- `send_kf_message()` - 消息发送逻辑

## 📄 许可证

本项目采用 MIT 许可证，详见 LICENSE 文件。

## 🤝 贡献

欢迎提交 Issue 和 Pull Request 来改进项目。

## 📞 支持

如有问题，请通过以下方式联系：

- 提交 GitHub Issue
- 查看项目文档
- 联系开发团队

---

*最后更新：2025年1月11日*
