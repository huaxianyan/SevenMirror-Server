# SevenMirror Server 管理端

> 状态：左侧分类导航加右侧面板的任务界面，内置默认账号加首次登录凭据设置，复用 UX-002 authority 管理闭环

`admin-web` 是与公开 relay 分离的按需管理进程。它直接读取同一个 SQLite registry 和 authority key 目录：列表页面不需要私钥，批准、重命名和移除设备时由 `internal/adminservice` 读取对应 authority private key 并签发成员事实。它不会挂载到设备注册、Membership 或 WebSocket Handler，也不会读取通知业务密文。常驻 relay 容器不得挂载 authority key 目录。

当前切片提供：

- 内置默认账号加首次登录强制凭据设置，凭据入库并支持随时更换；
- 用户名加密码加 TOTP 动态验证码；
- 单次使用、十分钟有效的应急登录码；
- 仅存内存、最长八小时的管理员会话；
- 左侧分类导航加右侧面板，五个分类由服务端路由切换，不依赖脚本；
- 设备面板：待处理申请优先于已接入设备；
- Android／Chrome、待批准和已拒绝或移除数量；
- 待处理申请卡片、已接入设备详情及已拒绝或移除历史；
- 设备申请、批准、最近认证、采样活动和移除时间；
- Android／Chrome 十分钟单次加入码；
- 待处理申请的固定产品权限模板批准；
- 待处理申请拒绝；
- 已接入设备的 certified removal；
- 已接入设备的 authority-certified 名称变更；
- 设置面板：只改前端显示的时间时区，服务端记录不变；
- 严格 Origin、CSRF、CSP、frame、按客户端地址的登录限速与管理操作限速边界。

加入码、批准、拒绝、重命名和移除统一通过 `internal/adminservice` 实现。管理网页和 `cmd/admin` 不复制 authority key 加载、角色模板、事务或 roster 签名逻辑。名称是 authority-signed 全工作区权威事实，只能由 Server 管理端修改；Android 和 Chrome 只读展示，不建立本地别名。已批准设备重命名时，Server 在一个 SQLite transaction 中签发 replacement certificate、包含 exact `DeviceCertificateTransition` 的下一份 roster，并更新设备记录；任一步失败都不会留下部分生效的名称。

界面按左侧分类导航组织，右侧显示所选分类的面板，导航项是链接而不是脚本：CSP 是 `default-src 'none'`，页面里没有任何 JavaScript 能力。分类固定为设备、凭据、设置、部署与维护、关于五项，选中项由服务端路由 `/?section=<分类>` 决定，未知取值落回设备。管理操作成功后重定向回发起操作的那个分类，避免确认动作把管理员弹到别的面板。设备面板内部包含「私有空间」区块：它只有一个，不显示编号，也不提供改名，管理端不建立多账号或多工作区概念，因此区块内只显示工作区创建时间。

顶栏左侧的产品名与客户端设置页保持同一规格：18px、粗体、正文色，与它并列的「管理端」是次要灰色小字，对应扩展顶栏里版本号所在的位置。样式表根部设了 `font-synthesis: none`，字体族若不带所声明的字重不会由浏览器合成加粗，因此品牌名的字重必须落在字体真实携带的字重上，且不得退回小号细体或全大写。

工作区名称不进入任何页面。设备详情使用原生可展开区域，窄屏不依赖七列宽表；批准／拒绝、重命名、移除和加入码仍提交到原有 POST 入口。当前界面先提供简体中文；英文资源与完整文案审校仍需在管理端发布验收前完成。

## 启动

在与 Server 相同的数据卷、authority key 目录和版本下按需运行：

```bash
NM_DATABASE_PATH=/var/lib/sevenmirror/syncnotifications.db \
NM_ADMIN_ADDRESS=127.0.0.1:8081 \
NM_ADMIN_ORIGIN=http://127.0.0.1:8081 \
./admin-web
```

官方 Server 镜像同时包含 `/app/admin-web`，但默认入口仍是 `/app/server`，不会自动启动管理页面。使用容器时为独立的按需容器覆盖入口，并仅挂载管理所需的数据与 authority key 目录；不要把该目录挂载到常驻 relay 容器。

进程启动时会在管理员终端显示一次应急登录码：

```text
admin_login_code=<应急登录码>
```

应急登录码只在本次进程启动后的十分钟内有效，成功使用一次即失效，且不进入 URL、数据库或支持包。它是验证器设备丢失后的应急入口；日常登录走用户名、密码和动态验证码，不需要重启进程。重新启动 `admin-web` 会注销全部管理会话并生成新的应急登录码。

## 管理员凭据

管理端只有一个账号，凭据保存在 registry 数据库的 `administrator_credentials` 单行表里。它不来自环境变量，也没有多账号：口令和动态验证码在管理网页里设置和更换。

### 首次登录

数据库还没有凭据行时，管理端使用内置默认账号，并在登录页说明这是首次使用。默认账号名是 `admin`，默认口令是 `sevenmirror`。

用默认账号登录后**只能**进入凭据设置：设备首页、管理操作和加入码都会跳回设置页。两步完成后凭据才写入数据库：

1. 第一步设置账号名与新口令。账号名 1 到 64 字节，不含空格和控制字符；口令 12 到 256 字节，不能只由空格组成，也不能沿用默认口令；
2. 第二步显示新生成的 TOTP 共享密钥和对应的 `otpauth://` 链接，输入验证器应用里显示的六位验证码确认；
3. 确认成功后立刻可以管理设备，之后登录需要新账号名、新口令和当前动态验证码。

**共享密钥只在第二步显示一次。** 没记下来就重走一次凭据设置，旧密钥随即失效。

### 更换凭据

登录后在「凭据」页点「重新设置凭据」，重走上面的两步即可同时更换账号名、口令和动态验证码密钥。更换成功后其他已经登录的管理会话立即失效。

验证器丢失时先用启动时打印的应急登录码进入，再重设凭据。口令和验证器同时不可用时，删除数据库里的那一行即可回到默认账号，然后按首次登录流程重设：

```sql
DELETE FROM administrator_credentials;
```

### 存储与限速

口令以 scrypt 的 PHC 串保存，每条凭据自带随机盐，代价参数随值一起传递，所以以后提高参数不会让已有凭据失效：

```text
$scrypt$ln=15,r=8,p=1$<salt base64 无填充>$<digest base64 无填充>
```

- 写入时固定使用 `ln=15,r=8,p=1`、16 字节盐、32 字节摘要；解析时 `ln` 接受 10 到 20，`r` 接受 1 到 32，`p` 接受 1 到 8。超出范围的值会被拒绝：一次登录请求不允许变成内存或时间上的拒绝服务。
- 口令比较是常量时间比较，失败时不区分是用户名、密码还是动态验证码错误。
- 第二因子只在账号名和口令都匹配后才校验，所以打错口令不会消耗当前时间步、导致同一窗口内的正确重试被拒。

TOTP 使用 RFC 6238 的 SHA1、六位、三十秒一步，接受前后各一步的时钟偏移，并记住已经接受过的最大时间步，因此同一个动态验证码无法重放。确认凭据设置时用的那一个验证码也会被记入，不能紧接着当登录码再用一次。共享密钥是任意验证器都能录入的标准 base32。

登录限速 5 次/分钟；凭据设置与确认共有另一个 20 次/分钟的窗口，因此协商口令策略时的多次重试不会挤掉登录额度。两个窗口都按客户端地址计数，可信反代配置见「远程访问」。

## 安全响应头

每个响应都带 `Cache-Control: no-store`、CSP（`default-src 'none'`，只放行同源样式与同源表单提交）、`Referrer-Policy: same-origin`、`X-Content-Type-Options: nosniff` 与 `X-Frame-Options: DENY`。

`Referrer-Policy` **不要改成 `no-referrer`**。Chromium 会用 referrer 推导导航请求的 `Origin`，而表单提交就是导航：在 `no-referrer` 下浏览器提交表单时发的是 `Origin: null`，严格的 `Origin` 校验会先于凭据校验把它拒掉，现场表现是「登录后显示 request rejected」，且换浏览器、换设备、换网络都一样。`same-origin` 仍然保证任何跨源请求都不带 Referer，这正是这里要的性质。

## 配置

| 环境变量 | 默认值 | 说明 |
|---|---|---|
| `NM_DATABASE_PATH` | `data/syncnotifications.db` | 与 Server 共用的 registry 路径 |
| `NM_ADMIN_ADDRESS` | `127.0.0.1:8081` | 必须是明确的 loopback IP 和端口 |
| `NM_ADMIN_ORIGIN` | `http://<NM_ADMIN_ADDRESS>` | 浏览器访问时的 exact origin |
| `NM_ADMIN_RECOVERY_CODE` | `on` | 是否保留启动时打印的应急登录码，只接受 `on` 或 `off` |
| `NM_ADMIN_TRUSTED_PROXY_CIDRS` | 空 | 可信反向代理的规范 CIDR 前缀，逗号分隔 |

`NM_ADMIN_ADDRESS` 拒绝 `0.0.0.0`、`::`、主机名和非 loopback IP。HTTP origin 也必须是 loopback；非 loopback 管理 origin 必须使用 HTTPS。

管理端**不再读取任何凭据环境变量**。设了 `NM_ADMIN_USERNAME`、`NM_ADMIN_PASSWORD_HASH` 或 `NM_ADMIN_TOTP_SECRET` 也不会改变行为，账号一律来自数据库或内置默认账号。

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

### 显示时区

页面上的时间只按一个时区换算显示，默认是 UTC，用来避免管理员自己心算。时间戳一律按 `2006-01-02 15:04:05 -07:00` 打印偏移量，所以同一个时刻在任何设置下含义相同，只有可读性变化。

改时区在「设置」页，选择结果只写进当前浏览器的 `sevenmirror_admin_timezone` cookie（`HttpOnly`、`SameSite=Strict`、一年有效）：它不进 registry、不进管理会话，也不参与任何服务端判断。数据库、设备 API、roster 与 release artifact 仍然只认 UTC，切时区不会改动任何历史数据，其他浏览器或设备要各自设置一次。

镜像里没有 zoneinfo 数据库（distroless 基础镜像不带），所以 `internal/adminweb` 通过 `import _ "time/tzdata"` 把时区数据编进二进制。去掉这个 import 会让除 UTC 以外的任何名字都加载失败，时区设置会静默退回 UTC。

schema v9 新增 nullable `last_authenticated_at_ms` 和 `last_activity_at_ms`。升级前已经存在的设备会显示尚无记录，直到设备下一次成功连接；系统不会用注册时间伪造历史认证时间。

schema v10 新增 `administrator_credentials` 单行表。v9 及更早的数据库升级后该表为空，所以管理端第一次启动会进入首次登录的凭据设置。

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
