# SevenMirror Server

SevenMirror 的中继服务端。它在你自己的主机上路由手机与浏览器之间的端到端加密通知，并持有决定哪些设备可以加入的私有空间权威。三个独立仓库之一。

仓库地址：<https://github.com/huaxianyan/SevenMirror-Server>

> 状态：日常自托管已经可用。密文中继、权威签名的成员管理、持久投递与快照恢复、管理端页面、Docker 部署资产都已实现。生产级安全评审与协议兼容性政策尚未完成。

## 能做什么

- **只转发密文**：服务端看不懂通知内容。它能看到密文长度与投递时序，看不到标题、正文、应用名或回复。
- **私有空间**：默认没有任何公开注册。设备用一次性的加入码申请，运维者批准后才生效。
- **权威成员管理**：设备身份、角色与撤销状态来自一把 Ed25519 权威私钥，私钥始终由你保管。
- **持久投递**：接收端离线期间的通知会留在队列里，并按累计确认推进，客户端恢复后不必重放已确认内容。
- **快照恢复**：出现历史缺口时按权威签名的快照收敛，不会静默跳过。
- **管理端页面**：按需启动的管理界面，可以查看设备状态、签发加入码、批准、拒绝、重命名与移除设备。
- **一条命令完成部署**：仓库自带 Compose 文件与首次运行指引，管理端仅在需要时启动。

## 怎么部署

需要一台 Linux 主机、Docker Engine 与 Compose v2。如果要让手机和浏览器从外网连入，还需要一个带有效 TLS 证书的域名。

仓库自带一份可以直接启动的 Compose 文件。持久化状态放在 Compose 文件旁边，备份就是把那个目录复制走。

```sh
cd deploy/compose
cp .env.example .env
# 编辑 .env，至少改 SEVENMIRROR_IMAGE
install -d -m 0700 data authority backups
docker compose up -d relay
```

只需要决定一个值：

```ini
SEVENMIRROR_IMAGE=ghcr.io/huaxianyan/sevenmirror-server:0.1.0
```

也可以钉摘要，或换成 `latest`。三者指向同一个镜像，区别是摘要不会移动。

接着初始化私有空间，并把它备份一次：

```sh
docker compose run --rm admin init-workspace
```

这一步会输出一个工作区 ID 与一把权威私钥。私钥文件必须离线备份，丢了就无法再批准设备。

之后为每台设备签发加入码，并在管理端批准：

```sh
docker compose run --rm admin list-pending-devices --workspace <工作区 ID>
docker compose run --rm admin approve-device --workspace <工作区 ID> --device-ref <设备引用>
docker compose up -d admin-web        # 默认只监听 127.0.0.1:8081
docker compose stop admin-web         # 用完就停
```

签发加入码用 `issue-pairing-code`：

```sh
docker compose run --rm admin issue-pairing-code \
  --workspace <工作区 ID> --type android --name Pixel
```

加入码只打印一次，数据库只存它的哈希。管理端不对外暴露，通过 SSH 隧道访问。完整参数见 [配置与运维命令](docs/operator-reference.md)。

### 反向代理

中继只绑定主机回环地址，不终止 TLS，也不需要发布端口。它直接使用主机的网络命名空间，所以你不用在启动后去查任何网桥地址。

反代必须满足两条。第一条是替换而不是追加 `X-Forwarded-For`，否则调用方可以自己挑限流桶。第二条是转发 WebSocket 升级头，否则设备连接会被静默掐断。

仓库提供两份可用的起点，按你用哪个反代选一份：

| 反代 | 示例文件 |
| --- | --- |
| Caddy | [`deploy/caddy/Caddyfile`](deploy/caddy/Caddyfile) |
| nginx | [`deploy/nginx/mirror.conf`](deploy/nginx/mirror.conf) |

以 nginx 为例，把示例里的域名换成自己的，放进 `sites-available` 并签发证书：

```nginx
location / {
    proxy_pass http://127.0.0.1:18081;
    proxy_http_version 1.1;

    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection $connection_upgrade;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_set_header Host $host;

    proxy_read_timeout 3600s;
    proxy_buffering off;
}
```

`$connection_upgrade` 需先用 `map` 定义，完整文件含 TLS、证书路径与日志策略。

### 验证

```sh
docker compose ps
curl -fsS http://127.0.0.1:18081/healthz
curl -fsS http://127.0.0.1:18081/readyz
```

两个接口都返回 `200`，且 `ss -ltn` 里只出现回环地址、没有 `0.0.0.0`，才算就绪。

管理端与设备 API **不共用同一个公开入口**，请分别用子域。逐条说明与故障处理见 [Docker 部署指引](docs/deployment.md)。

## 运行要求

- Linux 主机，Docker Engine 与 Compose v2
- Go 1.25.13 或更高版本（仅自行构建二进制时需要）
- 对外服务时需要一个带有效 TLS 证书的域名

## 自行构建与运行

```sh
go run ./cmd/server
```

管理端是独立进程：

```sh
NM_DATABASE_PATH=data/syncnotifications.db go run ./cmd/admin-web
```

默认监听 `http://127.0.0.1:8081`。凭据存在 registry 里而不是环境变量里：尚未设置凭据时，内置默认账号可以进入初始化页面，其他页面都不可达。每次启动还会打印一个十分钟有效的应急登录码，用于丢失验证器的情况。凭据生命周期见 [管理端](docs/admin-web.md)。

## 发布

推送形如 `v0.1.0` 的标签即触发发布。标签必须与 `protocol/PROTOCOL_VERSION` 一致，带 `-dev` 的版本不能按标签发布。

发布页只放二进制产物集，容器产物集继续通过容器镜像仓库分发。发布页正文来自 `docs/release-notes/<标签>.md`，标题只写标签本身。完整规则见 [发布溯源](docs/server-release-provenance.md)。

## 更多文档

面向运维与开发的细节拆到独立文档，不放在这里。

| 主题 | 文档 |
| --- | --- |
| 部署步骤与首次运行 | [Docker 部署](docs/deployment.md) |
| 环境变量与命令参考 | [配置与运维命令](docs/operator-reference.md) |
| 管理端凭据与使用方式 | [管理端](docs/admin-web.md) |
| 反向代理与 TLS 基线 | [Caddy 反代](docs/caddy-reverse-proxy.md) |
| 权威私钥的备份、恢复与轮换 | [权威密钥生命周期](docs/workspace-authority-key-lifecycle.md) |
| 成员入网 HTTP 接口 | [成员接口](docs/membership-http-v1.md) |
| 会话恢复与诊断口径 | [中继会话恢复](docs/relay-session-recovery.md) |
| 中继容量基线 | [容量基线](docs/relay-capacity-baseline.md) |
| 二进制发布产物与回滚 | [发布溯源](docs/server-release-provenance.md) |
| 容器产物、基础镜像与 registry 边界 | [容器溯源](docs/server-container-provenance.md) |
| 镜像保留、删除与应急撤销 | [仓库治理](docs/registry-release-governance.md) |
| 漏洞证据与例外政策 | [漏洞管理](docs/vulnerability-management.md) |
| 支持包与终端留存边界 | [部署产物边界](docs/deployment-artifact-boundary.md) |
| 独立评审清单与威胁模型 | [安全评审](docs/security-review/README.md) |
| 协议资产、版本与校验方式 | [协议资产](protocol/README.md) |

## 许可证

当前修订版使用 [`GPL-3.0-only`](LICENSE)。允许商业使用，但分发时必须遵守 GPLv3。此前已经发布的 MIT 版本不受追溯影响，精确的 MIT 到 GPL 边界见 [`LICENSE-TRANSITION.md`](LICENSE-TRANSITION.md)，该边界修订及其祖先仍按 MIT 提供。
