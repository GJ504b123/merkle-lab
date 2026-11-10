"""
一次性脚本：从 Blockstream 公开 API 拉取真实比特币区块数据，存成本地 fixture。
只在准备数据时运行一次，之后的测试完全不联网。
"""
import json

import requests
API = "https://blockstream.info/api"

def dump_block(height, path):
    # 1. 用区块高度换区块哈希（00000000d1145790a8694403d4063f323d499e655c83426834d4ce2f8dd4a2ee）
    block_hash = requests.get(f"{API}/block-height/{height}").text.strip()
    # 2. 用区块哈希换交易 id 列表（展示字节序的十六进制字符串）（https://blockstream.info/api/block/00000000d1145790a8694403d4063f323d499e655c83426834d4ce2f8dd4a2ee）
    txids = requests.get(f"{API}/block/{block_hash}/txids").json()
    # 3. 取区块头信息，拿到官方 merkle_root 作为标准答案
    header = requests.get(f"{API}/block/{block_hash}").json()

    data = {
        "height": height,
        "txids": txids,
        "merkle_root": header["merkle_root"],
    }
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"已保存区块 {height}：共 {len(txids)} 笔交易 -> {path}")


if __name__ == "__main__":
    dump_block(170, "data/block_170.json")
