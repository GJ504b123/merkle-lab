import json
import random

import pytest

from merkle import dsha256, compute_merkle_root


def make_txs(n):
    """造 n 个互不相同的 32 字节假交易哈希。"""
    return [dsha256(f"tx{i}".encode()) for i in range(n)]


# ---------- 第 1 组：手工推导的已知答案 ----------

def test_two_leaves():
    a, b = dsha256(b"a"), dsha256(b"b")
    root, mutated = compute_merkle_root([a, b])
    assert root == dsha256(a + b)      # 两个叶子：根就是 dsha256(左+右)
    assert mutated is False


def test_three_leaves():
    a, b, c = dsha256(b"a"), dsha256(b"b"), dsha256(b"c")
    # 手工推导：c 触发奇数自我复制 → [H(ab), H(cc)] → 根 = H(H(ab) + H(cc))
    expected = dsha256(dsha256(a + b) + dsha256(c + c))
    root, mutated = compute_merkle_root([a, b, c])
    assert root == expected
    assert mutated is False


def test_two_identical_leaves():
    a = dsha256(b"a")
    root, mutated = compute_merkle_root([a, a])
    assert root == dsha256(a + a)      # 根照常计算
    assert mutated is True             # 但配对时检测到相邻重复


# ---------- 第 2 组：差分测试，笨实现当裁判 ----------

def reference_root(leaves):
    """最直观的递归建树版（不做 mutated 检测），作为独立参照。"""
    if len(leaves) == 1:
        return leaves[0]
    if len(leaves) % 2 == 1:
        leaves = leaves + [leaves[-1]]
    return reference_root(
        [dsha256(leaves[i] + leaves[i + 1]) for i in range(0, len(leaves), 2)]
    )


@pytest.mark.parametrize("n", range(1, 65))   # 1~64 笔交易全覆盖
#装饰器：pytest在收集用例的时候读到，把下面函数从1到64执行64次，n从1到64
def test_against_reference(n):
    rng = random.Random(2024 + n)             # 固定种子：随机但可复现
    leaves = [rng.randbytes(32) for _ in range(n)]
    # _代表我只是想要循环次数，并不用这个变量

    root, _ = compute_merkle_root(leaves)
    #_代表我知道它返回两个值，第二个是我主动不要
    assert root == reference_root(leaves)


# ---------- 第 3 组：真实区块 / 官方测试向量 ----------

@pytest.mark.parametrize("path,expect_mutated", [
    ("data/block_170.json", False),

])
def test_vectors(path, expect_mutated):
    with open(path) as f:
        data = json.load(f)
        #json.load(f) 从文件对象读，json.loads(s) 从字符串解析
    leaves = [bytes.fromhex(t)[::-1] for t in data["txids"]]
    # hex 字符串 → bytes
    # 翻转字符串和翻转 bytes 是两回事，结果完全不同，字符翻转会把每个字节内部的两个十六进制位也搅乱
    # [::-1] 是切片语法 整体翻转
    root, mutated = compute_merkle_root(leaves)
    assert root[::-1].hex() == data["merkle_root"]
    # 字节到字符
    assert mutated is expect_mutated


# ---------- 第 4 组：边界值 ----------

class TestBoundary:
    def test_empty(self):
        root, mutated = compute_merkle_root([])
        assert root == b"\x00" * 32
        assert mutated is False

    def test_single_leaf(self):
        # 创世区块的 coinbase，单节点树：根就是叶子本身
        a = bytes.fromhex(
            "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
        )[::-1]
        root, mutated = compute_merkle_root([a])
        assert root == a
        assert mutated is False


# ---------- 第 5 组：CVE-2012-2459 安全回归（实验二核心） ----------

class TestCve20122459:
    def test_honest_5_vs_attack_6(self):
        tx = make_txs(5)
        root5, m5 = compute_merkle_root(tx)              # 诚实块
        root6, m6 = compute_merkle_root(tx + [tx[-1]])   # 攻击块：末尾重复 tx4
        assert (m5, m6) == (False, True)                 # mutated 恰好相反
        assert root5 == root6                            # 但根逐字节相同

    def test_honest_6_vs_attack_8(self):                 # 进阶：形态二
        tx = make_txs(6)
        root6, m6 = compute_merkle_root(tx)
        root8, m8 = compute_merkle_root(tx + [tx[-2], tx[-1]])
        assert (m6, m8) == (False, True)
        assert root6 == root8
