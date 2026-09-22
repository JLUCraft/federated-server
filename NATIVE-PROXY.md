# Rust 原生比赛代理

实现位于 `src/native.rs` 与 `src/wire.rs`，运行在 game-server 内。无 Velocity 进程、代理插件、游戏认证插件依赖。Paper 计分模板独立，只提供 score/finish API。

## 连接路径

Minecraft 客户端 → SJMCL 的 loopback 入口 → union-core 加密流 → 原生代理 → union-core 加密流 → 房间节点的 TCP 桥 → Paper。最后两个进程可以在同机，也可以在不同学校/家宽；房间之间不要求能直接 TCP 互访。远程房间使用 `union` endpoint，可使用 Circuit Relay 地址，不能改用暴露的裸 TCP 后端。

代理把受认证 PeerId、联赛成员、配置的游戏 UUID/名称绑定。启用 `student_policy` 时还强制学校凭据与 UUID 一致。Minecraft 客户端到启动器仅走本机；跨主机传输由 libp2p QUIC/Noise 加密。MC 协议自身无需重复登录加密，也不允许后端要求加密而退回不透明透传。

房间变化时，代理停止向旧房间转发，发出原生 Transfer 包。客户端重连到启动器同一个 loopback 入口，代理重新鉴权并选择目标房间。比赛席位包含 epoch；旧连接和迟到重连不能夺回已被替补占用的位置。不承诺无加载画面的切换。

房间健康由实际状态查询检测；故障时冻结替补时钟。玩家掉线宽限使用 RTT、平滑抖动与最近恢复耗时。每个玩家只允许一个活动连接，断开和转移清理由连接代次约束，避免旧连接清理新连接。

## Paper 内置身份转发

Paper 后端绑定 `127.0.0.1`，`server.properties` 设置 `online-mode=false`、`enforce-secure-profile=false`。`config/paper-global.yml` 配置：

```yaml
proxies:
  velocity:
    enabled: true
    online-mode: false
    secret: "填写该房间的独立转发密钥"
```

这里的配置名与 `velocity:player_info` 是 **Paper 内置接口的线协议名称**，不是运行 Velocity。Rust 实现 HMAC-SHA256 身份转发，只有后端确认转发并返回预期 UUID/名称后才放行。不要关闭转发检查或把离线模式的 Paper 端口暴露公网。配置 `properties` 可以携带皮肤站返回的签名材质属性。

接口依据：[Paper 内置接收器](https://github.com/PaperMC/Paper/blob/main/paper-server/src/main/java/com/destroystokyo/paper/proxy/VelocityProxy.java)。MC 包 ID 来自官方 26.3 server JAR 的 `net.minecraft.data.Main --reports`，原始报告保存在 `protocol/26.3-packets.json`；协议版本为 777。

## 配置

先通过治理创建成员、联赛、组队与报名，再使用同一个治理日志重启，增加 `--native-config /path/to/native.json`。该节点 key 必须等于联赛 host。角色 UUID/名称必须取自身份提供方，不能让玩家自行提交任意角色映射。

```json
{
  "league": "jlu-cup",
  "service": "00000000-0000-4000-8000-000000000001",
  "waiting": {
    "endpoint": {
      "transport": "union",
      "peer": "WAITING_NODE_PEER",
      "addresses": ["/dns4/relay.jlucraft.com/tcp/4001/p2p/RELAY_PEER/p2p-circuit/p2p/WAITING_NODE_PEER"],
      "service": "00000000-0000-4000-8000-000000000002"
    },
    "forwarding_secret": "/etc/jlucraft/waiting-forwarding.secret"
  },
  "arena": {
    "endpoint": {"transport": "local", "address": "127.0.0.1:25567"},
    "forwarding_secret": "/etc/jlucraft/arena-forwarding.secret"
  },
  "players": {
    "member-id": {"uuid": "游戏角色 UUID", "name": "PlayerName", "properties": []}
  }
}
```

异机房间使用 `game-server serve --key 房间节点.key --service 房间服务UUID --backend 127.0.0.1:25565 --allow-peer 原生代理PeerId` 发布，按网络需要追加 `--reserve`。两个房间均可使用 union endpoint。

学校身份策略是可选的 `student_policy: {trust, minimum, current_enrollment}`，其中 trust 与 unionctl verify-student 相同。学院邮箱所有权不是当前学籍；仅有邮箱证据时不要设置 `current_enrollment=true`。

SJMCL 连接链接形如 `jlucraft://connect?peer=网关PeerId&service=服务UUID&address=URL编码后的multiaddr`。要求学校凭据时追加 `school=1`，并选择已登录的学校账号。启动器从该账号已保存的 HTTPS 身份提供方取得绑定本设备的凭据，每十分钟刷新；失败会停止连接，要求重新认证。

## 验证边界

集成测试使用真实 union 节点与模拟 Paper 协议端点，覆盖压缩、转发 MAC、冒用 UUID 拒绝、跨节点等待/比赛切换、掉线替补和原玩家回到等待室。还需要真实 26.3 客户端、Paper 26.3 与校园网络联调。当前 Paper 26.3 只有 ALPHA 构建；版本锁的 releaseReady 为 false。
