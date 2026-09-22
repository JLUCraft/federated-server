# game-server

`serve` 发布已有 Minecraft TCP 后端，`status` 通过本地 minecraftd 查询状态，`govern` 运行签名联赛日志。用 `cargo run -- --help` 查看参数。

```sh
game-server govern --key host.key --listen /ip4/127.0.0.1/tcp/4002 \
  --journal league.json --admin ADMIN_PEER_ID \
  --scoring-bind 127.0.0.1:8091 --scorer-key scorer.key --scoring-token scoring-token.txt
```

创建联赛时将 scorer.key 的 PeerId 指为 scorer。scoring-token.txt 使用至少 32 字节随机值；将相同值通过 Paper 的 `UNION_SCORING_TOKEN` 环境变量传入。Paper 模板 `paper-scoring-template` 已针对 Java 25 / Paper 26.3 alpha API 编译。

插件接口 `score(eventId, players, teams)` 和 `finish()` 返回 CompletableFuture；游戏模式应持久保存 eventId，发送失败时用相同载荷重试，等成功后再提交 finish。ID 使用联盟成员/队伍标识，不能直接假设游戏昵称就是成员 ID。模板不默认对击杀、死亡等游戏事件赋分，不负责身份认证或房间切换。

`govern --native-config` 启用原生 Minecraft 26.3 协议代理，负责身份验证、等待室/比赛房间路由和自动替补。房间可通过 Union 位于不同节点；客户端收到 Transfer 包后自动重连启动器的本地入口。实现与部署见 [原生协议代理](NATIVE-PROXY.md)。无需 Velocity，也无需身份或切服插件。

目前跨节点自动化验证使用模拟 Paper 协议端；真实客户端、真实 Paper 对局和校园网络仍需上线验收。当前 Paper 26.3 只有 alpha 构建，发布门禁未解除。

## 复制治理

`govern` 支持 `--raft-peers initial-peers.json --raft-id 1`，`--journal` 此时指向独立 Raft 存储文件。所有副本使用完全相同的初始管理员和初始节点表；表内节点 ID 是正整数，对应 `{ "peer": "PeerId", "addresses": ["带 /p2p/PeerId 的 multiaddr"] }`。初始投票节点数为 1、3、5 或 7。仅首次在其中一个初始节点添加 `--initialize`，正常重启必须去掉此参数。单写者日志与 Raft 文件不能互换。

节点表与创世状态共同绑定集群标识。改变成员使用签名治理动作 `set_consensus_members`，设立议事会后必须经提案批准。复制层自动先追赶 learner，再提交联合成员变更；已移除 ID 永久停用。新增节点使用原始创世配置和自己的新 ID 启动，不重新初始化。新增节点首次同步需要仍在原始信任集合中的节点提供复制连接；完全更换所有原始节点前应另行安排创世信任迁移，当前未实现此迁移流程。

快照读取和签名提交可连接任一现有副本，由副本向当前主节点转发并保持原签名、revision 与过期检查。选举期间操作可能暂时返回错误，不能把提交超时当作未提交；先刷新状态确认结果。Raft 只处理崩溃故障，不提供恶意多数节点下的安全保证。游戏代理和计分接口使用同一 `Authority` 接口，`--native-config`、`--scoring-bind` 可与 Raft 同时启用；每场比赛仍须只有其登记的 host 身份运行权威游戏入口。

`/jlucraft/union/events/1` 提供经过成员鉴权的状态变更通知，通知包含 revision 和状态哈希。通知只使缓存失效，客户端仍应补拉权威快照。`unionctl watch` 可直接订阅。
