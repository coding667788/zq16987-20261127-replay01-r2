# eraseanchor

`eraseanchor` 是一个纯 Python 3.12 标准库实现的**合成备份擦除锚点规划、事务重放与验证工具**。

题目不使用、也不接触任何真实密钥或磁盘密钥服务：

- 密文只是不可变合成 ID（如 `ct-target`）。
- 密钥只是图节点 ID（如 `root-a`、`kek-1`、`dek-1`）。
- 包封是有向边 `wrapper_key -> wrapped_key`。
- 所有持久化镜像是本仓库生成的 JSON / JSONL 合成事务记录。
- 审核与测试不会调用 DPAPI、密钥库、TPM、云 KMS 或真实磁盘密钥。

## 1. 核心可读模型

一个逻辑引用（工单、快照、路径）可读，当且仅当：

1. 快照 COW 目录能把逻辑名解析到一个合成密文内容；
2. 存在该 `content_id` 的完整密文副本，且在故障域丢失后仍有副本；
3. 从一个**已持久、未被有效撤回的根密钥**出发；
4. 存在一条每条包封都未删除、且在当前恢复镜像/故障域中可用的有向路径；
5. 路径终点是该密文的内容密钥。

包封图允许环。可达性使用带 `visited` 集合的 BFS，因此：

- 有根入口的环可以到达环上的密钥；
- 与根集合不连通的自环/互封环不能解封；
- 一个密文的多条包封路径是“或”关系，必须全部切断或使其根失效。

BFS 同时给出最短可读证明，例如：

```text
root-old --env-root-kek-old--> kek-old --env-kek-accounts--> dek-accounts
```

## 2. COW 快照、去重与工单

案例中的 `snapshots` 支持：

- `parent` 快照链；
- 子快照同名覆盖；
- `null` 或 `{"deleted": true}` 形成 COW 删除墓碑；
- 多个路径/快照引用相同 `ciphertext` ID，即内容去重。

因此，在新版本删除一个逻辑名，不会影响仍引用同一底块的旧快照。

工单分为：

- `preserve` / `preservation` / `hold`：所有指定引用必须保持可读；
- `erase` / `erasure`：计划完成及承诺后的所有允许恢复镜像中必须不可读。

如果保全工单与擦除工单引用相同 `content_id`（尤其是同一去重密文），则冲突是无条件的：任何使保全内容可读的完整密文 + 根包封证明，也会证明擦除目标可读。`plan` 会返回 `status: "conflict"`、冲突目标和最小 BFS 可读证明，而不会输出虚假的可行计划。

## 3. 有限动作菜单

一个案例最多包含 18 个候选动作、6 个故障域。动作类型：

| 类型 | 作用 | 持久边界 |
|---|---|---|
| `migrate_ciphertext` | 增加/移除密文副本所在故障域；密文 ID 保持不可变 | 先 `data_write`，后 `commit` |
| `add_envelope` | 增加一条已授权包封路径 | 元数据提交 |
| `delete_envelope` | 删除旧包封；可写持久墓碑锚点 | 不可逆元数据提交 |
| `revoke_root` | 废止根密钥并写持久撤回记录 | 不可逆元数据提交 |

根废止动作可用以下任一字段声明依赖迁移：

```json
"requires": ["a01-migrate-keep"],
"migration_dependencies": ["a01-migrate-keep"]
```

也支持别名 `dependent_migrations`、`depends_on_migrations`、`migration_dependency`、`migration`。验证器要求这些迁移的提交严格排在根废止之前。

### 规划排序

规划器枚举最多 `2^18` 个子集，并用位掩码 DP 求每个子集的最小合法动作 ID 字典序。所有顺序合法计划按以下键排序：

```text
(total_cost, action_count, action_id_sequence)
```

随后按该顺序执行完整的断电/故障域/恢复镜像验证；第一个通过的计划即全局最省成本的健壮计划。

## 4. 持久化、恢复与故障模型

### 4.1 合成追加事务镜像

`replay` 写 JSONL 事务镜像，每条记录包含单调 LSN、前哈希和 SHA-256 哈希链。迁移动作明确分成：

1. `stage: "data_write"`：数据副本已写，但元数据尚未提交；
2. `stage: "commit"`：目录/包封/撤回等元数据效果提交。

在两个边界之间掉电后，恢复器：

- 重放最后一条有效哈希链记录；
- 忽略末尾撕裂 JSON；
- 找到已写但未提交的迁移；
- 写 `recovery` 记录；
- 幂等重试数据写并提交，或跳过已提交动作；
- 继续剩余计划并追加 `erasure_commitment` 记录。

### 4.2 断电边界

`verify` / `replay --all-boundaries` 遍历：

- 初始状态；
- 每个数据写边界；
- 每个元数据提交边界；
- 最终擦除承诺边界。

每个边界后都检查全部保全引用是否可读；恢复并继续后再次检查最终保全/擦除目标。

### 4.3 单故障域与允许恢复镜像

对象和事务记录可用 `domains` / `record_domains` / `journal_domains` 标注所在故障域。`"*"` 表示全局对象。

对每个故障域 `d`，验证器检查：

1. 当前已提交状态卸掉 `d`；
2. 仅保留至少有一份事务记录幸存的合并日志镜像；
3. 每个幸存恢复域 `r != d` 的本地追加镜像；
4. 每个历史快照的悲观恢复：旧快照中的包封可重新出现，但所有幸存的根撤回记录和显式持久墓碑锚点必须带入恢复；
5. 每条根撤回记录本身必须在卸掉任意一个域后仍有副本。

因此，只把撤回记录写到一个域的低成本“假省”动作会被拒绝；把持久锚点复制到全部恢复域的动作才会通过。

## 5. 本地 JSON CLI

无需安装第三方依赖。Windows PowerShell 中可使用：

```powershell
python -m eraseanchor --help
```

也可使用显式仓库启动器（兼容 `python -I`）：

```powershell
python .\eraseanchor_cli.py plan --case .\fixtures\root_revocation.json
.\eraseanchor.cmd verify --case .\fixtures\root_revocation.json
```

仓库根还提供等价的 `plan.py` / `replay.py` / `verify.py` 以及 `plan.cmd` / `replay.cmd` / `verify.cmd` 薄包装。`--case` 也可换成位置参数或 `--input`，`--out` 可换成 `--output`。

### 5.1 plan

```powershell
python -m eraseanchor plan `
  --case .\fixtures\cow_hold_erase.json `
  --out .\out\plan.json `
  --limit 1 `
  --rank-limit 25
```

输出包含：

- `status`: `feasible` / `conflict` / `infeasible`；
- `optimal.action_ids`；
- `optimal.total_cost`；
- 排序后的 `ranking`；
- 每个不可逆边界前后的完整可读性见证；
- 冲突目标及最小可读证明；
- 枚举/验证统计。

`--strict` 会在 `conflict` 或 `infeasible` 时返回退出码 `3`。

### 5.2 replay

遍历全部断电边界，并为每个边界写真实 JSONL 镜像：

```powershell
python -m eraseanchor replay `
  --case .\fixtures\root_revocation.json `
  --all-boundaries `
  --journal-dir .\out\journals `
  --out .\out\replay.json
```

模拟某一个边界的“掉电 → 读日志恢复 → 重试 → 完成”：

```powershell
python -m eraseanchor replay `
  --case .\fixtures\root_revocation.json `
  --boundary 1 `
  --journal .\out\boundary-1.jsonl
```

手动两进程重试：

```powershell
# 写完前 2 条持久事件后模拟掉电
python -m eraseanchor replay `
  --case .\fixtures\root_revocation.json `
  --crash-after 2 `
  --journal .\out\manual.jsonl

# 之后恢复并继续
python -m eraseanchor replay `
  --case .\fixtures\root_revocation.json `
  --resume `
  --journal .\out\manual.jsonl `
  --out .\out\manual-resume.json
```

### 5.3 verify

```powershell
python -m eraseanchor verify `
  --case .\fixtures\root_revocation.json `
  --plan .\out\plan.json `
  --replay .\out\replay.json `
  --out .\out\verify.json
```

不提供 `--plan` 时会重新规划并独立验证最优计划。对冲突计划，它会重算并校验最小证明，返回 `status: "conflict_verified"`。

退出码：

- `0`：命令成功且验证通过 / 冲突证明有效；
- `1`：重放或验证发现不变量违反；
- `2`：JSON、参数或案例模式错误；
- `3`：仅 `plan --strict` 用于冲突/不可行结果。

## 6. 合成夹具

| 文件 | 覆盖点 | 预期最优动作 |
|---|---|---|
| `fixtures/cow_hold_erase.json` | COW 继承、逻辑名删除、去重、安全/不安全删除与撤回变体 | `a01-migrate-accounts`, `a03-delete-temp-safe` |
| `fixtures/root_revocation.json` | 迁移 + 新增包封 + 持久根撤回、依赖排序、单域撤回记录丢失 | `a01`, `a02`, `a03-...-safe` |
| `fixtures/multiple_paths.json` | 同一密文多条包封路径、同成本动作 ID 排序 | `a01-delete-path-a`, `a02-delete-path-b-dek` |
| `fixtures/shared_block_conflict.json` | 保全/擦除共享去重内容的不可调和冲突及最小证明 | `status: conflict` |
| `fixtures/key_cycle.json` | 有根环可读、无根环不可读、空动作最优计划 | `[]` |

## 7. 测试

```powershell
python -m unittest discover -s tests -v
```

测试覆盖：

- COW 快照解析与逻辑名删除；
- 内容去重冲突；
- 有根/无根包封环；
- 多包封路径；
- 最优成本和动作 ID 字典序；
- 根撤回依赖迁移的顺序；
- 对每个断电边界写真实临时 JSONL、恢复和继续；
- 卸掉每个故障域；
- 拒绝只写单域的撤回记录；
- `plan` / `replay` / `verify` 子进程 JSON CLI。

## 8. JSON 案例模式（v1 摘要）

```jsonc
{
  "schema": "eraseanchor.case/v1",
  "case_id": "example",
  "domains": ["d0", "d1"],          // <= 6
  "policy": {
    "hold_survives_domain_loss": true,
    "commit_domains": ["d0", "d1"],
    "recovery_domains": ["d0", "d1"]
  },
  "roots": [
    {"id": "root-a", "domains": ["d0", "d1"], "persisted": true}
  ],
  "ciphertexts": {
    "ct-1": {
      "content_id": "logical-record-1",
      "key_id": "dek-1",
      "domains": ["d0"],
      "complete": true
    }
  },
  "envelopes": [
    {"id": "env-1", "wrapper": "root-a", "wrapped": "dek-1",
     "domains": ["d0", "d1"]}
  ],
  "snapshots": {
    "snap-1": {"parent": "snap-0", "names": {"/a": "ct-1", "/old": null}}
  },
  "tickets": [
    {"id": "hold", "kind": "preserve", "snapshot": "snap-1"},
    {"id": "erase", "kind": "erase", "snapshot": "snap-2", "paths": ["/b"]}
  ],
  "actions": [
    {
      "id": "a01",
      "type": "revoke_root",       // migrate_ciphertext | add_envelope |
                                   // delete_envelope | revoke_root
      "cost": 5,
      "root_id": "root-a",
      "migration_dependencies": ["m01"],
      "record_domains": ["d0", "d1"]
    }
  ]
}
```

未标注域的对象默认是 `"*"` 全局合成对象；密文也可用 `"domain": "d0"` 或 `"domains": ["d0", "d1"]`。

## 9. 设计边界

这是一个用于规划和审计的**形式化合成模型**，不是真实加密实现：

- 不生成、保护或擦除真实密钥；
- 不解析真实磁盘/备份格式；
- 不把 JSONL 哈希链声称为密码学安全删除；
- “可读”只表示合成图中存在完整密文副本和有根包封路径；
- 真实系统还需要密钥仪式、访问控制、传输安全和经过认证的销毁流程。
