# Turb GPT Register — Go 版

ChatGPT / OpenAI 账号自动化注册工具，用 Go 重写。
产物是**单个可执行文件**（约 30 MB，含前端），拷到机器上直接运行。

## 与原 Python 版的关系

本仓库对应原项目 `GPT-FERR-registration-tool` 的 Go 移植版，刻意保留了三件事：

1. **API 契约完全兼容** —— 路由路径、参数名、JSON 字段名与 `webui/app.py` 一致，
   前端 `index.html` 原样内嵌，未改一行。
2. **数据模型一致** —— SQLite 表名、字段语义不变，现有 `turb.sqlite3` 可直接读取。
3. **配置项命名不变** —— `.env` 里的 `REGISTRATION_DRIVER`、`EMAIL_SOURCE` 等键名沿用。

## 结构

```
cmd/turbd/              入口（WebUI + 控制台）
internal/
  config/               类型化配置 + atomic 热重载
  domain/               跨层类型（Stage / Account / Job / Traffic）
  store/                SQLite 仓储（单写协程串行化）
  job/                  任务池、取消、日志
  mail/                 邮箱 Provider 接口 + 各来源实现
  register/             注册驱动接口 + 注册表 + 无头路由
    protocol/           纯协议驱动（TLS 指纹 + Sentinel）
  sentinel/             Sentinel 求解器（synthetic / sdk_js）
  service/              编排：取邮箱 → 选驱动 → 执行 → 落库
  api/                  HTTP 路由、授权码鉴权
  web/                  内嵌前端（go:embed）
```

## 快速开始

### 方式一：双击一键运行（推荐）
在项目目录下直接双击：
- `启动 WebUI.bat`：使用默认配置启动并自动弹窗打开浏览器页面。
- `启动 WebUI (自定义授权码).bat`：启动前可在窗口直接输入想要的访问密码（默认 `123456`）。

### 方式二：命令行启动
```bash
# 构建（需要 Go 1.27+）
go build -o turbd.exe .\cmd\turbd

# 运行并自动弹开浏览器
./turbd.exe --open-browser --auth-code 123456
```

浏览器打开 `http://127.0.0.1:5000`，输入授权码即可进入控制台。

命令行参数优先级高于 `.env`：

| 参数 | 说明 |
|---|---|
| `--port` | 监听端口，默认 5000 |
| `--host` | 监听地址，默认 127.0.0.1 |
| `--auth-code` | 登录授权码 |
| `--open-browser` | 启动后自动调用系统默认浏览器打开 Web 页面 |
| `--root` | 项目根目录（放 .env 和数据库），默认可执行文件所在目录 |
| `--verbose` | 调试日志 |

## 配置（.env）

```dotenv
# 注册驱动：protocol 已完整移植；其余驱动当前为占位实现
REGISTRATION_DRIVER=protocol

# 邮箱
USE_EMAIL_SERVICE=true
EMAIL_SOURCE=outlook            # 支持逗号分隔的兜底链
OTP_MAX_WAIT=180
OTP_POLL_INTERVAL=5

# 免费临时邮箱（无需 API Key）
ENABLE_TEMPMAILIO=true
ENABLE_MAILTM=true              # 注意：部分网络环境下 api.mail.tm 不可达

# 代理（协议驱动强烈建议配置）
PROXY_POOL='["http://user:pass@host:port"]'
PROTOCOL_PROXY=

# Sentinel 求解器：synthetic（纯 Go，默认）| sdk_js（需要 Node + sentinel/sentinel-runner.js）
SENTINEL_SOLVER=synthetic

# WebUI
WEBUI_AUTH_CODE=你的授权码
```

## 已移植 / 待移植

| 能力 | 状态 |
|---|---|
| 纯协议注册（TLS 指纹 + Sentinel + 邮箱 OTP） | ✅ 端到端跑通，可真实创建账号并发码 |
| 任务池、并发调整、手动停止、崩溃恢复 | ✅ |
| SQLite 存储、分页查询、邮箱池原子领取 | ✅ |
| 授权码鉴权（Cookie / X-Auth-Code / Bearer） | ✅ |
| 配置热重载（写 .env + 原子替换快照） | ✅ |
| 邮箱来源：outlook / generic_api / imap / cloudflare / mailalias / gptmail / mailnest / remail / xigua（池取码） | ✅ |
| 邮箱来源：temp-mail.io / mail.tm | ✅ |
| MailCode 域名邮箱、域名池、邮箱导入与状态管理 | ✅ |
| Sentinel：合成指纹 / Node 执行真 sdk.js（均已随仓库提供） | ✅ |
| Roxy / Cloak / Ant / Browser Use / Skyvern | ⬜ 占位，选中时返回明确提示 |
| Codex OAuth、补跑、CPA 下载与导出 | ✅ |
| 2FA / 换绑邮箱 / 密码补设 / 查活 / 套餐查询 / 支付信息 / Plus 试用提链 | ✅ |

## 与 Python 版的关键改进

- **并发模型**：Python 用 `ThreadPoolExecutor + ThreadLocal + StopEvent 字典 + 自定义异常` 五套机制；
  Go 版只有 `context.Context` 和 `semaphore`。
- **配置热重载**：Python 的 `apply_env_overrides(globals())` 改完必须重新 import 模块；
  Go 版整份配置存在 `atomic.Pointer` 里，替换即生效，无半更新状态。
- **驱动扩展**：Python 新增驱动必须改 `main.run_registration` 的分发链；
  Go 版实现 `register.Driver` 接口并在注册表登记即可，调度层零改动。
- **邮箱来源**：Python 十几个客户端各导出三个同名函数，靠 if-else 分发；
  Go 版统一为 `mail.Provider` 接口，池与外部 API 是同一抽象。
- **数据库并发**：Python 每个调用开短连接；Go 版用单写协程 + WAL，彻底避免 `SQLITE_BUSY`。

## 测试

```bash
go test ./...
```

覆盖：账号 upsert、邮箱原子领取的互斥性、任务生命周期与重复抢占、崩溃恢复、
验证码提取、邮箱来源兜底链、取码重试与超时、驱动别名解析、无头路由。

## 已知限制

- `protocol` 驱动依赖 OpenAI 线上接口，页面/接口变更时需要同步调整
  `internal/register/protocol/driver.go`。
- `SENTINEL_SOLVER=sdk_js` 需要本机安装 Node.js；默认的 `synthetic` 不依赖 Node。
- temp-mail.io / mail.tm 的域名可能被目标服务拒收，生产环境建议使用自有域名邮箱。
