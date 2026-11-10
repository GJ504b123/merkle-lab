import hashlib


def dsha256(data: bytes) -> bytes:
    """双重 SHA-256：对 data 连续做两次 SHA-256，返回 32 字节。"""
# python的类型注解：声明函数参数和返回类型是bytes，但是只是注解，python运行不会强制执行
# 本质是给“读者”看的文档
# “读者”：1. IDE读到能在调用函数时提示类型，在传错类型画出黄色波浪线警告
#2. 静态检查工具（mypy）可以在不运行代码前提下扫描整个项目，把所有类型不匹配的地方列成报告
#3. 人，不用读代码就知道传什么数据，拿到什么数据

# bytes字节类型：装的是数据本身，二进制，表示256种状态，索引取出来是0-255整数，通过编码转为人看得懂的文本，编码规则往往是：UTF-8

    # hashlib:提供各种hash算法的库，python标准库，无需pip下载
    # .sha256():返回哈希对象，有三种方法：.digest():输出原始字节结果 hexdigest()：输出十六进制字符串 update(b"a"):继续追加a再hash
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()
# hash：单向不可逆，没有密钥，得到的是数据指纹；加密：双向可逆，有密钥，可以解密还原
# 存密码：哈希后存储，且要加盐（给每个用户单独生成一段随机字符串，把盐和密码一起hash）
# 为什么要加盐：避免黑客提前把常见密码的hash算好，还原明文，即彩虹表攻击；也防止撞库检查（发现很多用户密码一样）
# 盐不需要加密（1. 只为了让每个用户hash独一无二，验证登录可以直接用）
# 测试登录功能可以做安全测试：注册两个密码相同的账号，检查数据库2条记录的hash是否不同，相同代表没加盐是缺陷，还可以检查盐是否每次随机，接口返回和日志是否泄露了hash或盐
# MD5以及sha-1以及被证实存在碰撞，安全场景禁止使用，但是做文件完整性校验，去重这类场景还是可以使用，现在主流是sha-256

def compute_merkle_root(tx_hashes):
    """
    Merkle 根计算（含 mutated 检测，对应 CVE-2012-2459 修复逻辑）
    参数:
        tx_hashes: list[bytes]，每个元素是 32 字节的交易哈希（内部字节序）
    返回:
        (root, mutated)
        root   : 32 字节的 Merkle 根；空列表时返回 32 个零字节
        mutated: True 表示某层配对位置出现相邻重复哈希，树被"变异"
    """

    hashes = list(tx_hashes)   # 浅拷贝，只复制外层容器，内部的元素不变：不改动调用方的列表
    # list()：内置类的构造器调用，创建全新列表对象
    # list(a)、a.copy()、a[:]（切片）、copy.copy(a)——全都是浅拷贝
    mutated = False

    if len(hashes) == 0:
        return b"\x00" * 32, False

    while len(hashes) > 1:
    #为什么要大于1
        # 步骤A：mutated 检测（必须在奇数补齐之前）
        for i in range(0, len(hashes) - 1, 2):
            if hashes[i] == hashes[i + 1]:
                # 好的接口设计会主动给测试留证据，而不是把证据销毁在中断里。
                mutated = True

        # 步骤B：奇数自我配对，末尾元素复制一份
        if len(hashes) % 2 == 1:
            hashes.append(hashes[-1])

        # 步骤C：两两拼接做 dsha256，列表长度减半
        hashes = [dsha256(hashes[i] + hashes[i + 1])
                  for i in range(0, len(hashes), 2)]
    return hashes[0], mutated

















