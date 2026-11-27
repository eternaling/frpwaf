# P2 · 收紧「同段自动升级为整段可信（/24）」门槛 — 交付报告

- 日期：2026-11-27
- 范围：仅仓库代码 + 测试 + 文档；未提交、未 push、未 tag、未触碰服务器
- 基线：`python -m unittest discover -s tests -t .` → 344 OK
- 交付后：同一条命令 → **348 OK**

## 1. 最终采用的门槛与理由

**采用：同段未过期强证据 `/32` 达到 3 个才升级为整段可信**（原 2 个）。
即 `app/ai.py::_TRUST_SUBNET_MIN_IPS = 3`。

理由（与业主判断一致，未推翻）：

- 风险点确实只在放大器上。`/32` 记错只影响单个 IP，且 `model` 来源 14 天、
  `keyword` 来源 30 天自然过期；而 `/24` 一旦写出，同段**所有**未见过的新 IP
  在 24h 内都免处置（`app/ai.py:501-517` 的 `mode=cdn` 与 `app/ai.py:197-221`
  的 `_in_learned_cidrs` 命中路径）。
- 强证据存在「通胀」通道：`model` 层的旁证允许 `web_multi`
  （`app/ai.py:455` `web_multi = bool(types) and len(names) >= 2`），
  于是一个多站探测的 Web 来源只要模型判 `cdn_origin` 就能占一个强证据名额。
  门槛为 2 时，同段两个此类来源即让整段信任 24h。
- 用「数量门槛」而不是「必须至少一条 keyword 证据」：2026-11 事故里 ESA 回源
  IP 的归属地文本只写「阿里云」、不含 CDN 字样，关键字层完全落空
  （`docs/13:632` 的历史记录、`app/ai.py:442-445` 的 `_cdn_origin_hit` 文档串），
  只能靠 model 层 + 行为旁证识别。要求 keyword ⇒ 该类来源永远升不了级
  ⇒ 522 会重演。数量门槛把这个场景完整保留。

### 为什么不在 `model` 层就收紧 `web_multi`（不改 ≥2 → ≥3 个代理名）

给出代码证据，结论是**不动**：

1. `app/ai.py:455` 的 `web_multi` 是**单一变量、两层共用**：
   - model 层把它当「无关键字旁证时的唯一旁证」（`app/ai.py:457-463`）；
   - behavior 层（第 3 层）也直接用它（`app/ai.py:466-467`）。
   改它等于同时收窄两层识别能力，而不是只收紧学习入口。
2. model 层在「无关键字旁证」时直接返回未命中（`app/ai.py:463`
   `return False, "", ""`）。该返回会让 `_apply_action` 既不跳过、也不学习
   （`app/ai.py:501` 只在 `cdn_hit` 为真时才算，`app/ai.py:509` 才学习），
   也就是这类来源会被正常自动处置。
3. 事故形态正是「只服务 2 个站点、归属地不带 CDN 字样」：`docs/13:632`
   记录的原始判据就是「同一 IP 混访 **2+** 个站点代理」。要求 ≥3 个代理名
   意味着必须有 3 个站点同时挂在该回源 IP 上才能被认出来——仓库内没有
   「回源 IP 必然同时服务 ≥3 个代理」的任何证据，收紧属于凭猜测削弱防线。
4. 对 522 事故场景的影响对比：
   - 只提数量门槛（本次做法）：识别能力不变（2 个代理名仍算旁证），
     只是需要同段 3 个强证据 IP 才放大到 `/24`；事故里 `61.241.14.x`
     一次出现 26 个同段 IP（`docs/13:634`），升级路径依旧成立。
   - 同时把 `web_multi` 提到 3：事故里那批「只有阿里云字样 + 2 个站点」的
     回源 IP 会退化为未命中 ⇒ 重新被批量封 ⇒ 522 复现风险。
5. 残余风险（如实记录）：门槛 3 只是提高了成本，不是绝对阻断。若攻击者能在
   同一 `/24` 内凑出 3 个「模型判 cdn_origin + ≥2 个 Web 代理」的来源，仍可
   换来 24h 整段豁免。缓解手段仍是短 TTL（24h）+ 只能数 `/32`
   （`app/store.py::count_trusted_in_subnet`）+ 面板可逐条删除。若后续要再收紧，
   可考虑「3 个强证据需跨时间窗口分布」而非「限定证据来源」，后者会重开事故口子。

### 门槛为什么不做成 `config.DEFAULTS` 配置项

- 这是安全内部阈值，不是运维旋钮：业主不会去调，且误配成 `1` 等于把放大器开满。
- 加配置项要同步 `index.html` + `web/index.html` 两个设置页、配置校验、
  `docs/04` §3.8 与 `docs/08` §6 的表格，而收益接近零。
- 因此用模块级常量 `_TRUST_SUBNET_MIN_IPS`（与仓库既有 `_BATCH_SIZE` /
  `_SPLIT_BUDGET` / `_MIN_SPLIT` 同类），可读、可测、不散落魔法数字。

## 2. 每处改动的文件与行号

### `app/ai.py`

| 行号 | 改动 |
|---|---|
| 226-236 | 新增门槛常量 `_TRUST_SUBNET_MIN_IPS = 3`，附「为什么是 3 / 为什么不用 keyword / 为什么不做成配置项」的注释 |
| 249-253 | `_learn_trusted()` 文档串改为「达到 `_TRUST_SUBNET_MIN_IPS`（当前 3）个」，并把「更高的数量门槛」写进动机 |
| 266 | 行内注释改为「同段强证据回源 IP 达到门槛」 |
| 273 | `if n >= 2:` → `if n >= _TRUST_SUBNET_MIN_IPS:`（唯一的门槛判断点） |

### `app/store.py`

| 行号 | 改动 |
|---|---|
| 831-842 | `count_trusted_in_subnet()` 文档串重写：明确「本函数只数，不含门槛」、门槛在 `ai._learn_trusted`；并写明 `/24` 行自身与 `behavior` 来源都不计入 |
| 846-853 | SQL 的强证据来源列表由字面量 `IN ('keyword','model','manual')` 改为引用既有常量 `TRUST_STRONG_SOURCES`（`app/store.py:665`，此前定义后无人使用，等于第二份硬编码）；占位符拼接用显式 `+`，值仍全部参数绑定 |

### 无第二处硬编码门槛（已核查）

`grep` 全仓仅两处 `>= 2`：`app/ai.py:273`（本次改掉）与 `app/ai.py:455`
（`web_multi` 的代理个数判据，语义不同、本次不动）。`app/store.py` 只负责计数，
不含阈值；引擎侧 `app/engine.py` 无同段升级逻辑；面板（`index.html` /
`web/index.html` / `frpwaf_main.py`）不含该阈值。

### 文档

| 文件:行 | 改动 |
|---|---|
| `docs/08-AI自动IP审查.md:219`（新增 §5.2.2） | 新增「自动学习可信回源网段（`ai_learn_cdn`）」：只记强证据、同段升级门槛 3、24h TTL、计数只数 `/32`、门槛为何是 3、为何不要求 keyword、误学可自愈 |
| `docs/13-变更历史与版本.md:633` | 1.5.2 历史表格保留原表述，补注「现行门槛已提高到**第 3 个**，见 08 §5.2.2」 |
| `docs/tasks/active/2026-11-27-trusted-subnet-escalate-threshold.md`（新增） | 任务卡：需求、方案、关键决策、问题记录、变更记录 |

## 3. 新增/修改的用例清单与断言内容

文件：`tests/test_ai_cdn_guard.py`

### 模块文档串

- L14-15：保护清单新增第 5 条「自动学习表 `trusted_cidr`：强证据 `/32` 才学；
  同段达到 `ai._TRUST_SUBNET_MIN_IPS`（当前 3）个才升级为整段可信（24h TTL）」。

### 新增辅助方法（`LearnTrustedTest`）

- L260 `_apply_model_web_multi(ip)`：模型判 `cdn_origin` + 全 `https` +
  2 个代理名（`geo="中国 移动"` 不含 CDN 关键字），构造「只能靠 `web_multi`
  旁证命中」的强证据来源。
- L271 `_trust_row(cidr)`：取学习表里指定 CIDR 的唯一一行。

### 改写（原 `test_second_ip_in_subnet_escalates_to_24` 删除）

| 用例 | 位置 | 断言 |
|---|---|---|
| `test_second_ip_in_subnet_does_not_escalate` | L292 | 同段 2 个 keyword 强证据后，`"61.241.14.0/24"` **不在** `store.list_trusted_cidr_strings()` |
| `test_third_ip_in_subnet_escalates_to_24` | L298 | 第 2 个后仍不在；第 3 个（`.52`）后 `/24` **在**表中 |

### 新增反例

| 用例 | 位置 | 断言 |
|---|---|---|
| `test_two_model_web_multi_sources_do_not_escalate` | L306 | 同段两条「model + web_multi」（`.33`/`.41`）→ `/24` 不出现；`count_trusted_in_subnet` 恰为 2；`.33/32` 的 `source == "model"`（单条仍学习）；第 3 条（`.52`）后 `/24` 出现（门槛边界精确） |

### 新增「不能被破坏的性质」

| 用例 | 位置 | 断言 |
|---|---|---|
| `test_escalated_24_keeps_short_ttl_and_is_deletable` | L319 | `/24` 行 `source == "subnet"`；`expires_at - now ≤ 86400` 且 `> 86400 - 120`（仍是 24h TTL）；`store.del_trusted_cidr("61.241.14.0/24") == 1`（面板可删）；删除后 `ai._in_learned_cidrs("61.241.14.200") == ""` |
| `test_escalated_24_not_counted_itself` | L331 | 升级后 `count_trusted_in_subnet("61.241.14.0/24") == 3`（已学到的 `/24` 行不参与自身计数，不会自膨胀） |

### 随新口径调整的旧用例

| 用例 | 位置 | 改动 |
|---|---|---|
| `test_unseen_ip_in_learned_subnet_not_banned` | L337 | 由 2 次 `_apply` 改为 3 次，先真正学成 `/24` 再验证同段新 IP 命中 `mode=learned` 且未被封 |
| `test_other_subnet_still_banned` | L346 | 同上改为 3 次，确保「`/24` 已存在」的前提下其它段仍被封（否则用例会退化为只测 `/32`） |

未改动但已复核仍然成立的用例：`WeakEvidenceNoLearnTest.test_two_weak_ips_in_subnet_no_24`、
`test_weak_sources_do_not_count_toward_24`（弱证据仍不计入）、
`test_behavior_hit_skips_but_not_learned`、`test_subnet_fuse_not_learned`、
`test_learning_off_learns_nothing`。

## 4. 全套测试结果

| 检查 | 结果 |
|---|---|
| 基线 `python -m unittest discover -s tests -t .` | 344 tests **OK** |
| 交付后同一条命令 | **348 tests OK**（+5 新增、−1 被改写合并 ⇒ 净 +4） |
| `python -m unittest tests.test_ai_cdn_guard -v` | 51 tests **OK** |
| `LearnTrustedTest` 单类 | 10 tests **OK** |
| 判别力反证（临时把常量改回 2） | `test_second_ip_in_subnet_does_not_escalate`、`test_third_ip_in_subnet_escalates_to_24`、`test_two_model_web_multi_sources_do_not_escalate` 三条**变红**；改回 3 后全绿 |
| `python -m py_compile app/ai.py app/store.py tests/test_ai_cdn_guard.py` | OK |
| `node scripts/sync-agent-skills.cjs --check` | ✅ 34 skills / 6 command mirrors / 6 pi prompts / 8 hook wrappers / 2 codex agents 同步 |
| `node scripts/test-hooks.cjs` | ✅ 60/60 |
| `node scripts/audit-agent-migration.cjs` | ✅ 审计通过 |

注：pi-lens 的 LSP 在本环境被配置禁用（返回「no primary language server answer」），
因此以编辑时的 pi-lens 检查（Python clean）+ `py_compile` + 全量 `unittest` 作为验证依据。
另有一条**改动前就存在**的 pi-lens 质量提示（`app/ai.py` 内 `_apply_action` 的
`except` 顺序），不在本次改动范围内，未触碰。

## 5. 未做 / 留给业主

- 未提交、未 push、未 tag。
- 未触碰服务器；无表结构变化，生产库**无需迁移**（只是判定阈值）。
- 部署后若要观察效果：`trusted_cidr` 里 `source='subnet'` 的新增条目应明显减少，
  且出现时对应同段至少 3 个 `source IN ('keyword','model','manual')` 的 `/32`。
- 旧任务卡 `docs/tasks/active/2026-11-26-cdn-origin-tighten.md` 里仍写着
  「同段再学到 1 个即整段可信」，那是当时（上一个任务）的历史描述，本次未改动它。
