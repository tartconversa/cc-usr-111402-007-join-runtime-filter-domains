# 动态运行时过滤（rtf/v1）

在现有扫描—联接执行链上增加的分页执行器：构建侧（右侧筛选后的维度）生成完整键域，
扫描侧（排放事实）按页读取，已经确定不可能匹配的页提前排掉。
假阳性允许多读，假阴性禁止漏行；任何停用路径都不改变查询答案。

## 计划格式 rtf/v1

在现有输入之上扩展，单独声明版本；现有`app.service.inspect`语义不变。

| 字段 | 含义 |
| --- | --- |
| `format` | 固定`rtf/v1` |
| `query.keys/mode/null_safe` | 与现有语义一致；`build_side`：`right`（默认）或`left` |
| `query.build_where` | 构建侧筛选（app.semantics受限谓词），先于域构建应用 |
| `scan.page_size` / `scan.eager_pages` | 页大小；前N页不过滤（模拟完成通知晚于数据） |
| `build.snapshot` | 业务声明的构建快照/维度版本；缺席时取构建输入内容摘要 |
| `build.fragments` / `fail` / `seal` | 预期片段数；失败片段id；`seal:false`表示完成通知缺席 |
| `build.domain_identity` | 目录声明的完整域身份，构建后校验，不一致以构建结果为准 |
| `build.filter` | `{kind: auto\|exact\|bloom, memory_bytes}`容量预算 |
| `verify` | `true`时附带与不启用过滤的完整多重集对照 |

`semi/anti/not_in`探测侧固定为left，仅支持`build_side=right`；`not_in`仍仅支持普通单键。

## 键编码与两种空值规则

复合键逐分量编码（app/keys.py）：`None/bool/int/float/str`分标签，与baseline的
`type(v) is not type(w)`一致——`True≠1`、`1≠1.0`；`-0.0`归一为`0.0`；非有限数值拒绝。
编码相等当且仅当baseline键匹配成立，因此成员判定无假阴性。

- `null_safe=false`：含null键永不匹配。构建侧含null键不进过滤器（记入`has_null`）；
  扫描侧含null键对inner/semi直接丢弃，对anti直接保留。
- `null_safe=true`：null作为普通值进域，null=null可匹配。

## 安全矩阵（每次启用或拒用都写入decisions并附依据）

| 联接 | 构建方向 | 决策 | 依据 |
| --- | --- | --- | --- |
| inner/semi | right | `drop_not_in_domain`（精确或Bloom） | 扫描侧键不在完整域中则不可能匹配 |
| inner/semi | right | `empty_result`（域为空） | 结果恒为空，跳过全部页 |
| inner | left | `drop_not_in_domain` | 对称，过滤right扫描 |
| left | right | **拒用** | 保留侧全部行必须输出，过滤不能节省页 |
| left | left | `drop_not_in_domain`/`empty_pairs` | 扫描侧right为非保留侧 |
| anti | right | `drop_if_definitely_in_domain`，**仅精确集合** | 反联接保留的正是无匹配行，方向相反；Bloom无法证明存在→停用 |
| not_in | right | 域空→拒用（全通过）；域含null→`empty_result`；否则`not_in_exact`，**仅精确集合** | 三值语义：左null或非空域含null→unknown，WHERE只留true |

## 域生命周期、合并与容量退化

`DomainBuilder`累积片段：数据先于完成通知到达时只暂存；`seal`仅在收齐全部预期片段
且无一失败时发布完整域，否则返回None；任一片段失败即置failed，半成品丢弃，永不发布。
各片段按键摘要登记，域身份=字段+空值规则+各片段摘要+行数+has_null的内容摘要，
与片段到达顺序无关。

片段键集并入同一个域过滤器（精确集为集合并；同参数Bloom可按位或合并）。
容量退化单向：`exact→bloom→none`。精确集按每键96字节估计，超容量且策略允许时整体
转Bloom；Bloom位密度低于1比特/键时停用。内存不足即停用优化，扫描退化全量，答案不变。

## 调度

默认先封存后扫描。`scan.eager_pages>0`模拟完成通知晚于数据：前N页不过滤，
封存到达后剩余页使用过滤器；封存不到达或域失败则全程不过滤。只影响节省，不影响答案。

## 缓存

`FilterCache`键=构建快照+扫描快照+条件（keys/mode/null_safe/build_where/build_side/
过滤器配置）+完整域身份。域身份由实际构建内容计算，命中即内容相同，可安全复用；
新事实（扫描侧变化）、新维度版本（快照或内容变化）都会得到新键，旧过滤器不会沿用。
LRU加内存预算，超预算的过滤器不缓存；驱逐只影响性能。

## 决策与指标

输出含`decisions`（每个启用/拒用/退化/缓存命中的依据）、`metrics.savings`
（节省的页与行：跳过的整页行数+已读页内被过滤行数）、`metrics.filter`
（种类、键数、内存估计、Bloom位数/哈希数/假阳率估计）、`metrics.build`
（片段状态、行数、has_null）、`domain`（完整域身份）与`cache`。

## 验证

`verify:true`时以baseline.join在不启用过滤的输入上执行，双方结果canonical排序后做
完整多重集对照（`verification.equal`）。`build_side=right`时顺序与内容都应逐行一致。
tests/test_rtf.py含160组随机小实例（混合类型、null、重复、各预算与各联接类型）的全量对照。

## 限制

键分量限null/bool/int/float/str；页为扫描侧行的顺序切片；本地执行器以`fail`/`seal`/
`eager_pages`建模分布式的片段失败与通知延迟。
