# SevenMirror Server 管理端

> 状态：设备任务优先的产品界面，用户名密码加 TOTP 登录，复用 UX-002 authority 管理闭环

`admin-web` 是与公开 relay 分离的按需管理进程。它直接读取同一个 SQLite registry 和 authority key 目录：列表页面不需要私钥，批准、重命名和移除设备时由 `internal/adminservice` 读取对应 authority private key 并签发成员事实。它不会挂载到设备注册、Membership 或 WebSocket Handler，也不会读取通知业务密文。常驻 relay 容器不得挂载 authority key 目录。

当前切片提供：

- 用户名加密码加 TOTP 动态验证码；
- 单次使用、十分钟有效的应急登录码；
- 仅存内存、最长八小时的管理员会话；
- 设备任务首页，待处理申请优先于已接入设备；
- Android／Chrome、待批准和已拒绝或移除数量；
- 待处理申请卡片、已接入设备详情及已拒绝或移除历史；
- 设备申请、批准、最近认证、采样活动和移除时间；
- Android／Chrome 十分钟单次加入码；
- 待处理申请的固定产品权限模板批准；
- 待处理申请拒绝；
- 已接入设备的 certified removal；
- 已接入设备的 authority-certified 名称变更；
- 严格 Origin、CSRF、CSP、frame、按客户端地址的登录限速与管理操作限速边界。

加入码、批准、拒绝、重命名和移除统一通过 `internal/adminservice` 实现。管理网页和 `cmd/admin` 不复制 authority key 加载、角色模板、事务或 roster 签名逻辑。名称是 authority-signed 全工作区权威事实，只能由 Server 管理端修改；Android 和 Chrome 只读展示，不建立本地别名。已批准设备重命名时，Server 在一个 SQLite transaction 中签发 replacement certificate、包含 exact `DeviceCertificateTransition` 的下一份 roster，并更新设备记录；任一步失败都不会留下部分生效的名称。页面提供设备、部署与维护、关于三个任务入口。设备详情使用原生可展开区域，窄屏不依赖七列宽表；批准／拒绝、重命名、移除和加入码仍提交到原有 POST 入口。当前界面先提供简体中文；英文资源与完整文案审校仍需在管理端发布验收前完成。

## 启动

在与 Server 相同的数据卷、authority key 目录和版本下按需运行：

```bash
NM_DATABASE_PATH=/var/lib/sevenmirror/syncnotifications.db \
NM_ADMIN_ADDRESS=127.0.0.1:8081 \
NM_ADMIN_ORIGIN=http://127.0.0.1:8081 \
NM_ADMIN_USERNAME=operator \
NM_ADMIN_PASSWORD_HASH='$scrypt$ln=15,r=8,p=1$<salt>$<digest>' \
NM_ADMIN_TOTP_SECRET=<base32 密钥> \
./admin-web
```

官方 Server 镜像同时包含 `/app/admin-web`，但默认入口仍是 `/app/server`，不会自动启动管理页面。使用容器时为独立的按需容器覆盖入口，并仅挂载管理所需的数据与 authority key 目录；不要把该目录挂载到常驻 relay 容器。

进程启动时会在管理员终端显示一次应急登录码：

```text
admin_login_code=<应急登录码>
```

应急登录码只在本次进程启动后的十分钟内有效，成功使用一次即失效，且不进入 URL、数据库或支持包。它是验证器设备丢失后的应急入口；日常登录走用户名、密码和动态验证码，不需要重启进程。重新启动 `admin-web` 会注销全部管理会话并生成新的应急登录码。

## 管理员凭据

管理端只有一个账号，凭据完全来自环境变量。它不建立用户表，改密码或更换验证器仍需要与读取 authority key 相同的宿主访问权限。

密码以 scrypt 的 PHC 串保存，代价参数随值一起传递，所以以后提高参数不会让已有凭据失效：

```text
$scrypt$ln=15,r=8,p=1$<salt base64 无填充>$<digest base64 无填充>
```

- `ln` 接受 10 到 20，`r` 接受 1 到 32，`p` 接受 1 到 8。超出范围的配置会被拒绝：一次登录请求不允许变成内存或时间上的拒绝服务。
- 盐至少 16 字节，摘要至少 32 字节。
- 口令比较是常量时间比较，失败时不区分是用户名、密码还是动态验证码错误。

TOTP 使用 RFC 6238 的 SHA1、六位、三十秒一步，接受前后各一步的时钟偏移，并记住已经接受过的最大时间步，因此同一个动态验证码无法重放。共享密钥是任意验证器都能录入的标准 base32。

两个值推荐用 `sevenmirror-usage-ops` 技能里的 `admin-credentials.py` 生成（纯标准库，不依赖服务端环境）。

## 配置

| 环境变量 | 默认值 | 说明 |
|---|---|---|
| `NM_DATABASE_PATH` | `data/syncnotifications.db` | 与 Server 共用的 registry 路径 |
| `NM_ADMIN_ADDRESS` | `127.0.0.1:8081` | 必须是明确的 loopback IP 和端口 |
| `NM_ADMIN_ORIGIN` | `http://<NM_ADMIN_ADDRESS>` | 浏览器访问时的 exact origin |
| `NM_ADMIN_USERNAME` | 无 | 管理员账号名，1 到 64 字节，不含空格与控制字符 |
| `NM_ADMIN_PASSWORD_HASH` | 无 | scrypt 口令的 PHC 串 |
| `NM_ADMIN_TOTP_SECRET` | 无 | TOTP 共享密钥，base32，至少 16 字节 |
| `NM_ADMIN_RECOVERY_CODE` | `on` | 是否保留启动时打印的应急登录码，只接受 `on` 或 `off` |
| `NM_ADMIN_TRUSTED_PROXY_CIDRS` | 空 | 可信反向代理的规范 CIDR 前缀，逗号分隔 |

`NM_ADMIN_ADDRESS` 拒绝 `0.0.0.0`、`::`、主机名和非 loopback IP。HTTP origin 也必须是 loopback；非 loopback 管理 origin 必须使用 HTTPS。

`NM_ADMIN_USERNAME`、`NM_ADMIN_PASSWORD_HASH` 与 `NM_ADMIN_TOTP_SECRET` 必须同时提供：缺任意一项进程直接退出，不会退回到较弱的登录方式。

## 远程访问

管理监听地址始终是 loopback，浏览器访问有两种形态。

**SSH 端口转发**（不经过反向代理，Origin 是 `http://127.0.0.1:8081`）：

```bash
ssh -L 8081:127.0.0.1:8081 user@server
```

**独立 HTTPS 管理域名**（反向代理上游仍为 loopback）：

```text
NM_ADMIN_ORIGIN=https://admin.example.com
NM_ADMIN_TRUSTED_PROXY_CIDRS=127.0.0.1/32
```

- 反向代理必须保留原始 `Host`，不得把管理端与设备 API 放在同一公开 origin。路径前缀形式（`https://server.example.com/admin`）就是同一 origin，不要这样做。HTTPS origin 下管理端自动为会话 cookie 设置 `Secure`。
- `NM_ADMIN_TRUSTED_PROXY_CIDRS` 只在直连对端命中该前缀时才采信 `X-Forwarded-For`，用于把登录限速键到真实客户端地址。留空会让所有经代理的请求共用一个限速桶。不要放宽成整段子网。
- 两种形态的 `Origin` 不同，因此**不能同时可用**：切换形态要同时改 `NM_ADMIN_ORIGIN` 并重启进程。
- 不要把管理监听直接暴露到局域网或公网。

## 时间语义

- 「最近认证」来自设备最近一次成功 transport authentication；
- 「最近活动」来自成功解析的已认证客户端 frame；
- Server 最多每分钟为同一设备持久化一次活动时间；
- 页面显示的是采样后的最近活动，不表示严格实时在线。

schema v9 新增 nullable `last_authenticated_at_ms` 和 `last_activity_at_ms`。升级前已经存在的设备会显示尚无记录，直到设备下一次成功连接；系统不会用注册时间伪造历史认证时间。

## 设备操作语义

- Android 使用固定 `send` 权限模板；
- Chrome 使用固定 `receive,invoke` 权限模板；
- 普通页面不允许编辑裸 role；
- 拒绝只接受 `pending_proof` 或 `pending_approval` 设备；
- 移除只接受已批准设备，并签发递增 roster 中的 certified revocation；
- 重命名只接受已批准且未移除的设备，并要求名称发生变化；
- replacement certificate 只改变 display name、签发时间和 membership epoch，保持设备类型、角色、identity key／key ID、expiry、workspace 和 device ID；
- 页面表单只携带进程内 HMAC 派生的短期 action reference，不把 workspace ID 或持久化 device reference 放进 HTML；
- 加入码通过会话 flash 只显示一次，刷新后消失。

## 当前发布边界

`cmd/admin-web` 已进入源码构建、`Makefile` 和 release provenance artifact set。Release workflow 分别生成 `sevenmirror-admin-web-linux-amd64` 与 `sevenmirror-admin-web-linux-arm64`，将二者写入 exact manifest／`SHA256SUMS`，并与其他 Server 二进制一起生成 GitHub provenance attestation。下载后必须按 [`server-release-provenance.md`](server-release-provenance.md) 校验每个文件。纳入 artifact set 不代表管理端已经通过独立安全评审，也不改变默认不启动、仅监听 loopback 的部署边界。
