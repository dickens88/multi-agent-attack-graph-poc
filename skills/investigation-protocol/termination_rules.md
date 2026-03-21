# Termination Rules for Attack Tracing
# 从原项目终止判断提示词迁移
# 优先级：STOP 条件按顺序检查，满足第一个即终止

## STOP Conditions（按顺序检查，首个满足即停止）

### STOP-1: 攻击源头已确认
**触发条件：**
- 已通过 `find_attacker_origin()` 找到与某 IP 关联的 `Attacker` 节点
- 或 `ATTR_FIND_ATTACKER_FOR_IP` 查询返回非空结果

**置信度：** HIGH

**处置：** 记录 attacker_id、group、ttps。将该 IP 标为 origin_ip。终止所有迭代。

---

### STOP-2: 路径终结（死路）
**触发条件（同时满足）：**
- 当前 frontier 节点集合与上一迭代完全相同（无新节点）
- 所有 frontier 节点的出向 `[:ATTACKED]` / `[:LATERAL_MOVE]` 边均已查询过

**置信度：** MEDIUM（攻击源可能在图数据库范围之外）

**处置：** 将最后已知 hop 记为 best-effort origin。在 data_gaps 中注明"origin may be external"。

---

### STOP-3: 达到最大迭代次数
**触发条件：** `iteration_count >= 5`

**置信度：** 取决于已发现内容

**处置：** 编译已有发现生成 partial findings。在报告中标注"investigation incomplete — max iterations reached"。

---

### STOP-4: 循环路径检测
**触发条件：** 当前路径中出现此前已访问过的节点（环路）

**处置：** 跳过该分支，继续处理其他 frontier 节点。若所有分支均为环路，则触发 STOP-2。

---

### STOP-5: 低置信度路径
**触发条件（同时满足）：**
- 所有 frontier 节点的 `risk_score < 0.2`
- 该路径上未发现任何 `[:EXPLOITED]` 关系
- 迭代次数 >= 3

**置信度：** LOW

**处置：** 停止该分支。在 data_gaps 中注明"low-confidence path, insufficient evidence"。

---

## CONTINUE Conditions（无 STOP 条件命中时评估）

满足以下任一条件时继续迭代：

- 本轮发现了上一轮未见过的新节点
- 发现了 `[:EXPLOITED]` 关系 → 必须继续追踪该漏洞路径
- 疑似攻击者节点存在（group 名称部分匹配）但未完全确认
- 当前迭代次数 < 3（前3轮强制执行，即使看起来路径已终结）

---

## 终止决策输出格式

每次评估后必须输出（供 write_todos 更新使用）：

```json
{
  "decision": "STOP" | "CONTINUE",
  "rule_matched": "STOP-1" | "STOP-2" | "STOP-3" | "STOP-4" | "STOP-5" | "continue_new_nodes" | "continue_exploit_found" | "continue_min_iterations",
  "confidence": "high" | "medium" | "low" | null,
  "iteration": 3,
  "frontier_node_count": 4,
  "new_nodes_this_iteration": 2,
  "attacker_found": false,
  "summary": "one sentence description of current state"
}
```
