# 配置与运维命令参考

服务端的环境变量与 `admin` CLI 的命令参考。部署步骤本身见 [Docker 部署指引](deployment.md)。

## 环境变量

中继与管理端读取同一份配置。

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `NM_ADDRESS` | `127.0.0.1:8080` | HTTP 监听地址 |
| `NM_DATABASE_PATH` | `data/syncnotifications.db` | SQLite registry 与迁移数据库 |
| `NM_AUTHORITY_KEY_DIR` | 数据库旁目录 `authority-keys` | 存放工作区权威 PKCS#8 私钥的属主独占目录。只有 admin CLI 与按需启动的管理端进程使用，中继永不读取 |
| `NM_BACKUP_DIR` | 未设置 | 工作区备份目录的挂载点。设了就把该目录收成 `0700`，不设则保持挂载时的模式 |
| `NM_SHUTDOWN_TIMEOUT_SECONDS` | `10` | 关闭前的等待超时 |
| `NM_READ_HEADER_TIMEOUT_SECONDS` | `5` | 接收完整 HTTP 请求头的时限 |
| `NM_REQUEST_READ_TIMEOUT_SECONDS` | `10` | 接收完整 HTTP 请求（含受限正文）的时限 |
| `NM_MEMBERSHIP_ATTEMPTS_PER_MINUTE` | `10` | 每个已解析客户端地址允许的成员 register／prove／state 尝试次数 |
| `NM_ROTATION_ATTEMPTS_PER_MINUTE` | `10` | 每个已解析客户端地址允许的凭据轮换尝试次数 |
| `NM_RATE_LIMIT_MAX_CLIENT_BUCKETS` | `4096` | 每个限流器允许的成员与轮换客户端地址桶上限 |
| `NM_RELAY_AUTH_ATTEMPTS_PER_MINUTE` | `20` | 每个已解析客户端地址允许的中继 WebSocket 升级与认证尝试次数 |
| `NM_RELAY_AUTH_MAX_CLIENT_BUCKETS` | `4096` | 中继认证的客户端地址桶上限 |
| `NM_RELAY_AUTH_MAX_CONCURRENT` | `64` | 等待认证的已升级连接并发上限 |
| `NM_RELAY_AUTH_FRAME_TIMEOUT_SECONDS` | `5` | 已升级 WebSocket 等待确切 `SNA1` 认证的时限 |
| `NM_TLS_CERT_FILE` | 未设置 | 可选的本地 HTTPS／WSS PEM 证书链 |
| `NM_TLS_KEY_FILE` | 未设置 | 与证书匹配的 PEM 私钥，必须与 `NM_TLS_CERT_FILE` 同时配置 |
| `NM_TRUSTED_PROXY_CIDRS` | 未设置 | 允许提供单个规范 `X-Forwarded-For` 客户端地址的 CIDR 前缀，逗号分隔。直连或本地 TLS 部署时留空 |

管理端另有自己的变量，见 [管理端](admin-web.md)。

## 不使用反代时的直连部署

需要同时配置两个 TLS 文件并显式绑定：

```sh
NM_ADDRESS=0.0.0.0:8443 \
NM_TLS_CERT_FILE=/run/secrets/server-cert.pem \
NM_TLS_KEY_FILE=/run/secrets/server-key.pem \
go run ./cmd/server
```

证书必须对客户端填入的主机名或 IP 有效。服务端从不自行生成证书，不会把明文注册重定向到 HTTPS，也会拒绝证书与私钥只配置其一的组合。私钥要放在仓库之外，并设置最小权限。

在主机本地终止代理时，保持默认回环绑定，并用 [Caddy 反代](caddy-reverse-proxy.md) 里的生产形态基线；只有确切配置的代理 socket 对端可以提供单个规范的客户端地址。真机验证步骤与通过标准见 [非回环 HTTPS 恢复](non-loopback-https-recovery.md)。

## 命令参考

所有命令通过 `cmd/admin` 运行，读取同一份数据库路径：

就绪探针是 `server` 二进制的子命令，不是 admin 命令：

```sh
/app/server healthcheck
```

它读取 `NM_ADDRESS` 与 TLS 配置，请求 `/readyz`，非 `200` 即返回非零退出码。
镜像内没有 shell、curl 或 wget，容器 healthcheck 用它代替。

```sh
NM_DATABASE_PATH=data/syncnotifications.db go run ./cmd/admin <子命令>
```

### 初始化与入网

```sh
go run ./cmd/admin init-workspace
NM_DATABASE_PATH=data/syncnotifications.db go run ./cmd/admin \
  issue-pairing-code --workspace <base64url-id> --type android --name Pixel
```

`init-workspace` 只在没有工作区时创建；已有工作区时它会打印现有 ID、输出 `result=already-initialized` 后正常退出。因此它可以安全地每次启动都跑一次，部署文件里的 `prepare` 服务就是这么用的。查现有工作区用 `list-workspaces`。

`init-workspace` 只在 SQLite 里存权威公钥，私钥写入属主独占的 PKCS#8 文件。CLI 会打印它的位置与经过域分隔的公钥 ID，从不打印私钥材料。早于 schema v3 的工作区不会被静默分配权威。

原始加入码只打印一次，SQLite 只保存它的 SHA-256 哈希。注册成功时返回一次随机的 32 字节设备凭据，同样只持久化哈希。

### 设备清单与管理

```sh
NM_DATABASE_PATH=data/syncnotifications.db go run ./cmd/admin \
  list-devices --workspace <base64url-workspace-id>
NM_DATABASE_PATH=data/syncnotifications.db go run ./cmd/admin \
  list-pending-devices --workspace <base64url-workspace-id>
NM_DATABASE_PATH=data/syncnotifications.db go run ./cmd/admin \
  approve-device --workspace <base64url-workspace-id> --device-ref <redacted-ref>
NM_DATABASE_PATH=data/syncnotifications.db go run ./cmd/admin \
  revoke-device --workspace <base64url-workspace-id> --device-ref <redacted-ref>
NM_DATABASE_PATH=data/syncnotifications.db go run ./cmd/admin \
  rename-device --workspace <base64url-workspace-id> \
  --device-ref <redacted-ref> --name <display-name>
```

设备用 96 位、经过脱敏的管理引用标识。`list`、`revoke`、`rename` 都不会打印完整设备 ID、传输凭据或 E2EE 公钥。

`approve-device` 从 `NM_AUTHORITY_KEY_DIR` 读取确切的工作区权威私钥，套用产品固定的 Android `send` 或 Chrome `receive,invoke` 角色模板，签署设备证书，推进并签署名册，再把证书、设备状态与名册在一次 SQLite 事务里提交。它只打印脱敏设备引用与名册 epoch。

`revoke-device` 走同一条权威托管路径：一次事务把确切证书从活跃集合中移除、追加撤销记录、推进并签署名册，并把设备标为已撤销。历史遗留的未认证设备一律 fail-closed，直接迁移为撤销状态，必须用新的加入码与身份才能重新入网。

`rename-device` 用一次事务签发替代证书、推进并携带该次变更签署名册、更新设备记录，任何一步失败都不会留下半套改名。显示名是权威签署的工作区事实，不是本地别名，Android 与 Chrome 都只读展示。管理端页面可以完成同样的操作，该命令供习惯终端的运维者使用。

撤销是持久且幂等的。新认证立即失败；运行中的服务端每 250 毫秒复核一次活跃对端，把已撤销对端原子地移出密文路由，并用固定的策略响应关闭它的 WebSocket。授权查询失败只断开受影响的那个对端，按 fail-closed 处理。

### 凭据轮换

```sh
NM_DATABASE_PATH=data/syncnotifications.db go run ./cmd/admin \
  issue-rotation-code --workspace <base64url-workspace-id> \
  --device-ref <redacted-ref> --ttl 10m
```

`POST /v1/devices/rotate` 遵循 [传输凭据轮换](../protocol/transport-credential-rotation-v1.md)。客户端在请求之前生成并持久保留一个 32 字节的待处理凭据。一次事务消费授权码、只替换凭据哈希并递增凭据版本，因此响应丢失不会丢失待处理凭据。旧版本的活跃会话随后由同一套 250 毫秒授权监视移除；设备元组与 E2EE 公钥不变。原始授权码只打印一次，原始凭据与授权码都不落盘。

### 备份与恢复

```sh
NM_DATABASE_PATH=data/syncnotifications.db go run ./cmd/admin \
  backup-workspace --workspace <base64url-workspace-id> --output <new-directory>
go run ./cmd/admin verify-workspace-backup \
  --workspace <base64url-workspace-id> --backup <directory>
NM_DATABASE_PATH=data/syncnotifications.db go run ./cmd/admin \
  restore-workspace-backup \
  --workspace <base64url-workspace-id> --backup <directory> \
  --database /data/restored.db --authority-key-directory /authority/restored
```

备份使用 SQLite 的在线备份接口，而不是复制正在使用的 WAL 数据库。受保护的输出把一份一致的 registry 快照，与从该快照中选出的确切权威 PKCS#8 私钥绑定在一起。校验会检查 registry 摘要与完整性、schema、规范清单、工作区与公钥和密钥 ID 的绑定、密钥派生、文件类型与权限。

SevenMirror 有意不加密这个目录，请把它移入受访问控制且加密的离机备份系统。`restore-workspace-backup` 只恢复到新的 registry 路径，永不覆盖已有的 registry 或权威私钥。

### 权威密钥轮换

```sh
NM_DATABASE_PATH=data/syncnotifications.db go run ./cmd/admin prepare-authority-rotation
NM_DATABASE_PATH=data/syncnotifications.db go run ./cmd/admin \
  rotate-authority --workspace <base64url-workspace-id> --new-key-file <prepared-path>
```

新旧权威联合签署一份规范过渡。过渡记录、活跃证书重签、激活名册与当前权威指针在同一步原子提交。用同一把已准备好的密钥重试会校验已提交结果并返回 `already-rotated`。在每台受支持的客户端都接受过渡之前，请保留旧密钥与一致备份。完整流程见 [权威密钥生命周期](workspace-authority-key-lifecycle.md)。
