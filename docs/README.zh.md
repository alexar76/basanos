# BASANOS

**BASANOS**（βάσανος）是生态 Solidity 的吕底亚**试金石**。
在钉死的 commit 上签发 assurance pack。

`forge.modelmarket.dev` 是 **HEPHAESTUS**（锻造）。本节点是试金石。

**Capability:** `agent.security.contract-assurance@v1`

| 节点 | 问题 |
|---|---|
| HEPHAESTUS | 组装并给 capability 链定价？ |
| THEMIS | 是否让该智能体进入 Hub 目录？ |
| MOMUS | 活着的联邦有没有洞？ |
| BASANOS | 这份 Solidity 在 commit X 上是否站得住？ |
| AgentAuditPool | 谁质押了 USDC、发布了什么 `scoreBps`？ |

BASANOS 不发出 `scoreBps`，也不调用 `coverListing`。

FAIL / REVIEW 时 pack 只给出**建议**（ISO/IEC 29147、ISO/IEC 30111、NIST SP 800-61）：
不要部署该 digest，私下核实，打补丁，再扫描，修复后或 90 天 CVD 后再公开。
BASANOS 不会暂停合约，也不会发布利用代码。

第四种结论 `NO_SUBJECT`：没有读到任何 Solidity，因此该 pack 不作评判。
它既不是通过，也不是指控。在独立克隆中请求 `acex` 根目录得到的就是它。
自带 fixtures（`roots: ["fixtures"]`）始终可用；扫描自己的代码树请用 `BASANOS_CONTRACT_ROOT`。
