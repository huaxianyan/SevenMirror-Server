# SevenMirror Server 管理端

> 状态：UX-002 设备准入闭环；设备重命名待 certificate transition 三端实现

`admin-web` 是与公开 relay 分离的按需管理进程。它直接读取同一个 SQLite registry，但不会挂载到设备注册、Membership 或 WebSocket Handler，也不会读取通知业务密文或 authority private key。

当前切片提供：

- 一次性登录码；
- 仅存内存、最长一小时的管理员会话；
- 工作区概览；
- Android／Chrome、待批准和已拒绝或移除数量；
- 设备申请、批准、最近认证、采样活动和移除时间；
- Android／Chrome 十分钟单次加入码；
- 待处理申请的固定产品权限模板批准；
- 待处理申请拒绝；
- 已接入设备的 certified removal；
- 严格 Origin、CSRF、CSP、frame、登录和管理操作限速边界。

加入码、批准、拒绝和移除统一通过 `internal/adminservice` 实现。管理网页和 `cmd/admin` 不复制 authority key 加载、角色模板、事务或 roster 签名逻辑。当前仍不提供设备重命名。名称模型已冻结为 authority-signed 全工作区权威名称，只能由 Server 管理端修改；Android 和 Chrome 只读展示，不建立本地别名。已批准设备的名称变更必须通过可验证的 certificate transition 和下一份 signed roster 原子生效，待三端接受逻辑完成后再开放网页入口。当前界面先提供简体中文；英文资源与完整文案审校仍需在管理端发布验收前完成。

## 启动

在与 Server 相同的数据卷和版本下运行：

```bash
NM_DATABASE_PATH=/var/lib/sevenmirror/syncnotifications.db \
NM_ADMIN_ADDRESS=127.0.0.1:8081 \
NM_ADMIN_ORIGIN=http://127.0.0.1:8081 \
./admin-web
```

进程会在管理员终端显示一次：

```text
admin_login_code=<一次性登录码>
```

登录码不进入 URL、数据库、结构化日志或支持包，十分钟后过期，成功登录后立即失效。重新启动 `admin-web` 会注销全部管理会话并生成新登录码。

## 配置

| 环境变量 | 默认值 | 说明 |
|---|---|---|
| `NM_DATABASE_PATH` | `data/syncnotifications.db` | 与 Server 共用的 registry 路径 |
| `NM_ADMIN_ADDRESS` | `127.0.0.1:8081` | 必须是明确的 loopback IP 和端口 |
| `NM_ADMIN_ORIGIN` | `http://<NM_ADMIN_ADDRESS>` | 浏览器访问时的 exact origin |

`NM_ADMIN_ADDRESS` 拒绝 `0.0.0.0`、`::`、主机名和非 loopback IP。HTTP origin 也必须是 loopback；非 loopback 管理 origin 必须使用 HTTPS。

## 远程访问

首选 SSH 端口转发：

```bash
ssh -L 8081:127.0.0.1:8081 user@server
```

随后访问 `http://127.0.0.1:8081`。不要把管理监听直接暴露到局域网或公网。

如果使用独立 HTTPS 管理域名，反向代理的上游仍为 loopback，并设置：

```text
NM_ADMIN_ORIGIN=https://admin.example.com
```

反向代理必须保留原始 `Host`，不得把管理端与设备 API 放在同一公开 origin。HTTPS origin 下管理端自动为会话 cookie 设置 `Secure`。

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
- 页面表单只携带进程内 HMAC 派生的短期 action reference，不把 workspace ID 或持久化 device reference 放进 HTML；
- 加入码通过会话 flash 只显示一次，刷新后消失。

## 当前发布边界

`cmd/admin-web` 已进入源码构建和 `Makefile`，但尚未加入既有 release provenance artifact set。完成 UX-002 和管理端发布审查前，不宣称当前签名 Server release candidate 已包含管理网页。
