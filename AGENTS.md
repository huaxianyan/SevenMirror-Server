# SevenMirror Server 约定

## 先读共同约定

- 仓库为 `huaxianyan/SevenMirror-Server`，本机工作区为 `E:/Dev/SevenMirror-Project/repos/server`。
- 开始任务前完整读取 `E:/Dev/SevenMirror-Project/AGENTS.md`；跨端进度以总仓库 `docs/STATUS.md` 为准，服务端技术文档在本仓库 `docs/`。

## 工具链与命令

- Go 版本由 `go.mod` 的 `go` 指令决定，本机默认 Go 较旧，命令前显式 `GOTOOLCHAIN=go1.27.4`（或与 `go.mod` 一致），否则会拉到别的工具链。
- 拉依赖与工具链需要代理：`HTTPS_PROXY=http://127.0.0.1:37777 HTTP_PROXY=http://127.0.0.1:37777 GOPROXY=https://proxy.golang.org,direct`。
- 本地验证：`go test ./...`、`go vet ./...`。合入门禁是仓库 CI 的 `test`，含 `govulncheck`（对实时漏洞库查询，会随时间出现新告警）。
- 升级 Go 必须同时改三处：`go.mod`、`Dockerfile` 里按 digest 固定的 `golang:*-alpine`、`docs/server-container-provenance.md`；`govulncheck` 的固定版本也要一起升，否则会在新语法树上直接 panic。

## 代码度量工具

本机装了 `crapper`、`dryer`、`mutator`（包装脚本在 `~/bin`，PATH 里可直接调用）。三件工具只认 Clojure／Java／Go／TS-JS／Rust／Python。

**它们看不到模板与样式。** `internal/adminweb/templates/*.html` 与 `internal/adminweb/assets/admin.css` 不在解析范围内，所以任何“审过界面代码”的说法都不成立，界面问题只能靠真机／浏览器截图判断。

两个必踩的坑：

1. `--root` 同时决定扫描根和产物位置。要审当前仓库必须显式给 `--source-root`，且用 Windows 绝对路径，相对路径会被解析到 `--root` 之下，表现为 `No source files to analyze`。
2. `mutator` 要求被变异的文件位于 `--root` 之内，与上一条冲突。做法是把仓库（排除 `.git`、`target`、`.metrics`）复制到临时根，在副本里跑；或在仓库根跑完立刻删掉 `.metrics`。

产物默认写进项目根 `.metrics/`，度量时把 `--root` 指到临时目录，别把 `.metrics` 带进仓库。

常用命令（以 `internal/adminweb` 为例，`WORK` 指临时根）：

```bash
export GOTOOLCHAIN=go1.27.4
crapper --root "$WORK" --source-root "E:\Dev\SevenMirror-Project\repos\server" internal/adminweb cmd/admin-web
dryer   --root "$WORK" --source-root "E:\Dev\SevenMirror-Project\repos\server" internal/adminweb cmd/admin-web
mutator --root "$WORK" --source-root "E:\Dev\SevenMirror-Project\repos\server" internal/adminweb --scan
```

已知问题（2026-11-09 实测）：

- `crapper` 的 Go 覆盖率归因失败：`go test` 明确报 `internal/adminweb` 76.4%，但报告里每个函数都是 `0.0%`，`--use-existing-coverage` 与把 `coverage.out` 放到 `<root>/coverage.out`、`<root>/target/coverage/go/coverage.out` 都不生效。于是 CRAP 退化成 `CC²`，只能当复杂度看。
- 同一原因让 `mutator` 选不出“被覆盖”的变异点，输出全是 `n/a`；加 `--no-coverage` 才真正跑。它会把编译失败的变异体也计为“检出”，所以存活率 0% 不代表行为覆盖充分。
- `dryer` 的 1.00 相似对多为同一处理器的两行包装（`rejectDevice`／`removeDevice`）或同一静态资源处理器（`stylesheet`／`favicon`），属可接受重复，不是待抽取的重复逻辑。

## 组件文档

- 部署、发布、镜像溯源：`docs/deployment.md`、`docs/server-release-provenance.md`、`docs/registry-release-governance.md`。
- 运维命令与加入码：`docs/operator-reference.md`。
- 管理端行为与安全边界：`docs/admin-web.md`。

## 测试与验收

- 既有测试覆盖授权、会话、TOTP、CSRF、限流与错误路径，改动这些边界时不要为了“跑得快”减少断言。
- 界面改动以本机起实例 + 浏览器截图为验收依据（见总仓库 `AGENTS.md` 的浏览器验证条目）。
