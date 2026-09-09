# 光帆控制中心 · Lightsail Control

基于 **Komari 1.4.3** 的中文私人服务器控制中心，为 AWS Lightsail 的远程安装和流量查看定制。

复用 Komari 的数据库初始化、服务器模型、监控指标校验及历史指标存储；加入专用中文页面、受限 HTTP 接口、任务状态机和轻量 Python Agent。构建时下载并核对上游提交 `bf6b45ec3abfc56bba5e9223650a47a72f665371`，再应用本仓库代码及依赖修复。保留上游 MIT 许可与 NOTICE。

## 功能

- 登录后查看服务器 IP、架构、核心数、CPU、内存、磁盘、在线状态、实时上下行。
- 每台服务器默认 **1000 GB（1 TB，十进制）**，可以单独修改额度。
- 本月入站＋出站估算、剩余流量与 80% 用量颜色提醒；按 UTC 自然月重置。
- 生成少于 16 KB 的光帆启动代码，一次性令牌，15 分钟有效。
- 网页粘贴 Bash 脚本，执行时显示实时日志、脚本上报的进度、结果链接。
- 同一台服务器同时只允许一个活动任务；关闭网页不影响执行。
- 支持停止任务、执行超时、失败状态、领取去重、事件去重与操作记录。
- 撤销单台服务器的密钥；重启或回传中断不会自动重复安装。

## 首次部署（控制中心服务器）

准备一台**常开、全新的 Ubuntu 24.04 LTS 光帆**作为控制中心。建议至少 2 GB 内存用于首次源码编译；更小套餐可以在其他机器构建镜像后迁入。不要直接复用一个已安装其他 Komari 版本的数据目录。

1. 将一个域名的 A 记录指向控制中心的固定公网 IPv4；如果配置 AAAA，IPv6 也必须正确可达。
2. 在光帆放行 **TCP 80 和 443**。如果已启用 UFW 等系统防火墙，也要放行对应端口。不要公开 8080；保留原有 SSH 管理方式。
3. 在 SSH 中执行（把域名改成你的）：

```bash
sudo apt-get update
sudo apt-get install -y git
git clone https://github.com/SKTTheking/lightsail-control.git
cd lightsail-control
sudo bash scripts/setup.sh panel.example.com
```

安装程序会安装 Docker/Compose（仅自动处理 Ubuntu 24.04）、编译控制中心、启动 Caddy 并申请 HTTPS 证书。不会修改 SSH 或防火墙规则。第一次编译需要下载依赖，时间取决于网络和机器性能。

4. 查看首次密码：

```bash
sudo cat data/secrets/admin_password
```

打开 `https://你的域名`，账号为 **admin**，密码是上述文件中的随机值。请保存在你自己的密码管理器里。

**首次启动后，数据库里的密码才是实际登录密码；修改初始化密码文件不会重置已有账号。**

仓库如果改成私有，需要先在这台机器上配置你的 GitHub 只读访问，再执行 clone。不要把 GitHub 访问令牌写进启动代码、README 或提交到仓库。

## 接入其他光帆

1. 控制中心点击“添加服务器”，填写名称及额度。
2. 复制生成的代码，15 分钟内放入新光帆实例的 **启动脚本 / Launch script**。
3. 选择 Ubuntu 22.04 / 24.04 或 Debian 12 / 13，创建实例。
4. 系统启动并安装完依赖后，服务器自动出现在控制中心。现有服务器也可用 root 执行这段代码。

Agent **只向控制中心主动发起 HTTPS 请求**，没有监听公网端口。这里不需要额外开放“远程执行端口”；实际搭建的服务使用哪些端口，再放行那些端口。

接入脚本显示已过期或已使用时，在网页重新生成。网络在一次性令牌兑换后中断时，同样重新生成，避免重放旧令牌。重新兑换会替换旧 Agent 密钥。

Agent 文件：

- 配置 `/etc/lightsail-control/agent.json`（root 可读，含单台服务器密钥）。
- 程序 `/opt/lightsail-control/agent.py`。
- 状态 `/var/lib/lightsail-control/`（流量与任务日志，**不要删除或用空目录覆盖**）。
- 服务 `lightsail-control.service`。

## 删除服务器记录

服务器卡片点击“删除服务器”并确认，即从列表移除该服务器，并使其接入密钥和未使用的接入代码失效。未结束任务会被撤销；远端正在执行的脚本在回传失败后停止，不保证立即停止。保留历史任务、结果链接和操作记录，历史监控数据按原保留策略清理。

此操作不会删除 AWS 实例，也不会卸载 x-ui 或其他已安装服务。在被管理服务器上执行 `sudo systemctl disable --now lightsail-control` 可停止 Agent 后续连接。

## 下发搭建脚本

服务器卡片点击“执行脚本”。脚本以 **root** 执行，标准输入关闭；需要填写所有参数，不能等待交互式回答。设置 60–7200 秒的超时。建议 Bash 开头使用 `set -euo pipefail`，并在末尾检查你实际搭建的服务是否正常。

普通脚本会显示日志与状态。进度需要在相应步骤完成后输出标记：

```bash
#!/bin/bash
set -euo pipefail
echo 'LC_PROGRESS=10|检查系统'
uname -a

# 你的安装命令……
echo 'LC_PROGRESS=70|安装完成，检查服务'

# 替换为你的实际服务名称：
# systemctl is-active --quiet your-service

# 你的脚本生成节点后输出实际链接：
# echo "LC_LINK=$NODE_URL"
# echo "LC_LINK=$PANEL_URL"
echo 'LC_PROGRESS=95|检查结束'
```

支持 `http://`、`https://`、`vless://`、`vmess://`、`trojan://`、`ss://` 结果链接，其他协议不会作为结果展示。`LC_PROGRESS` 和 `LC_LINK` 必须各占一行并以换行结束。

只有**退出码 0** 才显示完成和 100%，即使脚本提前输出 `LC_PROGRESS=100`，运行中也最多显示 99%。退出码仅代表脚本的判断，不保证节点从你的电脑可达；脚本要自行完成服务健康检查。

脚本不得把安装主流程放到后台、通过 `nohup`/`setsid` 脱离执行器，或把安装交给后台 systemd 任务后立即退出。正常安装并启动常驻服务可以使用 systemctl，但服务本身不会因点击“停止任务”而卸载。控制中心不会自动回滚已执行的安装步骤。

## 流量口径

- 使用 Linux 默认路由网卡计数，排除 loopback、Docker bridge、veth 等重复统计。
- 自 Agent 首次接入起统计，不会补齐接入前已经消耗的流量。
- 计数持久化并处理系统重启、网卡计数回退；采样间隔为 5 秒，强制断电可能损失最后一次未落盘采样。
- 跨月采样差值记入新 UTC 月份。服务器时钟必须准确。跨月长时间停机或 Agent 停止会使月度分配产生误差。
- 额度只作显示和提醒，不会自动限制带宽、停机或修改 AWS 套餐。
- AWS 可能对同区域同套餐实例聚合额度；本页单机额度和全体合计不等于 AWS 计费池。最终以 AWS 控制台/账单为准。

官方口径：[Lightsail 流量规则](https://docs.aws.amazon.com/lightsail/latest/userguide/amazon-lightsail-faq-data-transfer-allowance.html)。

## 维护和排查

控制中心日志：

```bash
sudo docker compose ps
sudo docker compose logs --tail=60 control caddy
```

Agent 日志和状态：

```bash
sudo systemctl status lightsail-control --no-pager
sudo journalctl -u lightsail-control -n 60 --no-pager
```

- HTTPS 打不开：检查域名解析、TCP 80/443、Caddy 日志，以及是否已有服务占用这两个端口。
- 服务器一直离线：检查 Agent 日志、服务器时间、控制中心 HTTPS 可达性；不要关闭证书校验。
- 安装卡住：查看日志是否等待交互输入。超时或中断后先确认实际服务状态，再决定是否重新下发。
- 回传中断超过约 120 秒，网页标记“结果未知”；Agent 连续回传失败约 60 秒会终止它的脚本进程组。
- 如果删除了 Agent 流量文件，服务端会拒绝同月倒退的计数；不要通过清空服务端记录掩盖真实用量，应保留并恢复备份。

备份时先 `sudo docker compose stop control`，完整复制 `data/control` 和 `.env`、`data/secrets`，随后 `sudo docker compose start control`。日志和结果链接可能包含节点凭据，备份同样需要保密。

卸载 Agent：先在网页撤销密钥，再在该服务器执行 `sudo systemctl disable --now lightsail-control`。这不会卸载你之前用脚本安装的其他服务。

## 开发与验证

使用 Go **1.25.13**、Python 3.9+、Node.js 和 GCC。所有本地构建文件位于 `.build/`，不提交到仓库。

```bash
bash scripts/check.sh
python3 tests/integration.py
cd .build/komari
go run golang.org/x/vuln/cmd/govulncheck@v1.1.4 ./lightsail
```

测试覆盖：管理员认证、CSRF、Agent 越权、一次性接入、任务不重放、事件去重、成功退出码、危险链接过滤、月度计数与重启、真实后端＋执行器集成流程。

详见 [安全检查记录](SECURITY_REVIEW.md)。测试环境没有 AWS 实例和域名证书，实际云端部署仍需验证。
