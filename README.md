# Merkle 根算法自动化测试

基于 **Python + pytest** 的 Merkle 根算法测试项目，围绕功能正确性、边界场景、差分测试、真实区块测试向量和安全回归设计测试。当前按 `parametrize` 展开后共 **72 条 pytest 测试项**。

项目同时包含 CVE-2012-2459 相关重复交易场景的算法级回归：构造交易列表不同但 Merkle 根相同的输入，验证 `mutated` 检测标志符合预期。

## 1. 测试对象

被测代码位于 `merkle.py`，主要包括：

- `dsha256(data)`：对输入字节连续执行两次 SHA-256，返回 32 字节结果。
- `compute_merkle_root(tx_hashes)`：迭代计算 Merkle 根，并检测配对位置的相邻重复哈希。
  - 返回 `(root, mutated)`。
  - 空输入返回 32 个零字节，`mutated=False`。
  - 奇数节点在配对前复制末尾节点。
  - `mutated` 检测发生在奇数节点补齐之前。

> 当前实现通过复制输入列表并逐层生成新的哈希列表完成计算，额外空间复杂度为 O(n)，不是原地常数空间实现。

## 2. 测试设计

| 测试类别 | 数量 | 设计方法 | 主要覆盖内容 |
|---|---:|---|---|
| 手工已知答案 | 3 | 已知答案测试、错误推测 | 双叶子、三叶子奇数补齐、相邻重复叶子及 `mutated` 检测 |
| 差分测试 | 64 | 独立参考实现、固定种子随机数据 | 1～64 笔交易规模，与递归参考实现逐组对拍 |
| 真实区块测试向量 | 1 | 真实数据回归 | 比特币高度 170 区块的交易列表与 Merkle 根 |
| 边界测试 | 2 | 边界值分析 | 空输入、单叶子输入 |
| CVE 安全回归 | 2 | 对照输入、错误推测 | 5/6、6/8 笔交易两组构造，验证根相同且 `mutated` 相反 |
| **合计** | **72** |  |  |

这里的数量是 pytest 参数化展开后的测试项数量，不是测试函数数量。

### 2.1 差分测试

`test_merkle.py` 中实现了一个不使用 `mutated` 检测的递归参考算法 `reference_root()`，作为独立参照：

1. 使用 `random.Random(2024 + n)` 设置固定随机种子。
2. 对每个 `n ∈ [1, 64]` 生成 `n` 个随机的 32 字节交易哈希。
3. 分别调用被测迭代实现与递归参考实现。
4. 比较两组 Merkle 根是否一致。

固定种子使失败输入可以重复生成，便于定位问题和补充回归用例。

### 2.2 真实区块数据与离线回归

`fetch_block_data.py` 通过 Blockstream 公开 API 获取真实区块数据：

1. 根据区块高度获取区块哈希。
2. 获取区块交易 ID 列表。
3. 获取区块头中的 Merkle 根。
4. 将上述信息保存为本地 JSON 测试向量。

当前保存的 `data/block_170.json` 对应高度 170 区块，包含 2 个交易 ID 及预期 Merkle 根。日常 pytest 执行只读取该本地文件，**无需访问网络**；只有重新采集数据时才需要联网并安装 `requests`。

测试中还处理了比特币 RPC 展示字节序与内部计算字节序的差异：读取交易 ID 后反转为内部字节序，计算完成后再将 Merkle 根反转回展示字节序进行比较。

### 2.3 CVE-2012-2459 相关回归

项目包含两组算法级对照测试：

- 诚实输入 5 笔交易，对照输入 6 笔交易。
- 诚实输入 6 笔交易，对照输入 8 笔交易。

两组测试均验证：

- 对照输入通过重复末尾交易，得到与诚实输入逐字节一致的 Merkle 根。
- 诚实输入的 `mutated=False`，构造输入的 `mutated=True`。

**验证边界**：本项目验证的是重复交易构造及 Python 实现中的 `mutated` 检测逻辑，未启动 `bitcoind`，也未验证真实节点拒绝区块或网络共识行为，不应表述为完整复现真实网络的共识漏洞。

## 3. 项目结构

```text
merkle_lab/
├─ merkle.py             # 双 SHA-256、Merkle 根及 mutated 检测
├─ test_merkle.py        # pytest 测试与递归参考实现
├─ fetch_block_data.py   # 可选：重新采集真实区块数据
├─ data/
│  └─ block_170.json     # 本地真实区块测试向量
└─ README.md
```

## 4. 环境准备

建议使用 Python 3.9 及以上版本（随机数据生成使用了 `random.Random.randbytes`）。

在项目根目录创建并激活虚拟环境：

```bash
python -m venv .venv
```

Windows：

```bash
.venv\Scripts\activate
python -m pip install pytest
```

macOS / Linux：

```bash
source .venv/bin/activate
python -m pip install pytest
```

`requests` 仅在重新采集区块数据时需要：

```bash
python -m pip install requests
```

## 5. 运行测试

请在项目根目录执行，确保测试能够读取 `data/block_170.json`：

```bash
python -m pytest -q
```

Windows 下也可以不激活虚拟环境，直接运行：

```bash
.venv\Scripts\python.exe -m pytest -q
```

如需只查看测试收集结果：

```bash
python -m pytest --collect-only -q
```

实际通过数和执行耗时以本机完整运行结果为准，本项目说明不预填未经核验的通过率或耗时。

## 6. 可选：重新采集区块数据

安装 `requests` 后，在项目根目录执行：

```bash
python fetch_block_data.py
```

该命令会访问 Blockstream 公开 API，并覆盖 `data/block_170.json`。正常执行测试不需要运行此脚本。

## 7. 可复现性说明

- 随机差分测试使用固定种子，能够重复生成相同输入。
- 真实区块数据已保存为本地 JSON，避免外部服务波动影响日常回归。
- 每个测试类别均位于 `test_merkle.py`，可结合测试名称快速定位对应场景。
- 测试范围以算法和输入构造为主，不替代 Bitcoin Core 的完整节点、区块验证或网络共识测试。
