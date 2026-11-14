# 资料与接口

## 内容身份

入口app.service.inspect(data)不修改调用方资料，返回input_digest及result。
input_digest是对完整输入JSON按键排序、UTF-8、无空白序列化的SHA-256。数组顺序保留；禁止NaN和无穷，磁盘JSON重复字段拒绝。
app.storage.freeze返回独立副本。输入快照和对象版本由业务字段明确声明，内容摘要不会替调用方创造版本。

## 现有业务约定

left/right为行数组，每行rid唯一；keys给各侧字段对。query.mode为inner、left、semi、anti、not_in，null_safe表示IS NOT DISTINCT FROM，否则null不等。inner/left输出{left,right}行键对，semi/anti/not_in每个左行最多一次。not_in只在普通相等单键支持，左null或右集合含null且没有匹配时结果unknown，WHERE只留true；右空集时包括左null在内均通过。baseline.join保留这些语义，输入标量按显式schema统一类型。

## 受限谓词

app.semantics.evaluate(row, expression)返回True/False/None，None为unknown。
eq/lt/le/gt/ge含field和value，缺字段按null；比较双方必须同类型，null比较结果unknown。
is_null只有field；and/or含args数组，not含arg，按三值逻辑计算。空and为true，空or为false。
where只接受结果严格为true的行。expression为null表示不限制。

## 现有执行链

app.service.inspect → storage.freeze/digest → baseline.execute。sample.json描述的是现有可执行输入，服务输出附资料摘要。
新增能力可以增加入口和计划结构，保留现有调用及输出语义；扩展格式应单独声明版本。

## 运行时过滤计划（rtf/v1）

app.service.inspect_filtered → storage.freeze/digest → paged.execute_plan。
输入须声明format为rtf/v1，在left/right/query之上扩展query.build_where、query.build_side、
scan分页与build片段/封存/过滤器预算，字段含义见[运行时过滤](docs/runtime-filter.md)。
输出在result之外附decisions（每次启用或拒用的依据）、metrics（节省的页和行）、domain
（完整域身份）与cache；verify为true时附与不启用过滤的完整多重集对照。
过滤器只由完整域发布：片段失败或完成通知缺席时退化为不过滤，查询答案不变。
缓存键绑定构建快照、扫描快照、条件与完整域身份，新事实或新维度版本不会沿用旧过滤器。
