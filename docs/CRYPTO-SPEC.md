# GeneralZip SM4-GM 加密 ZIP 容器规范（v1）

> 状态：**稳定** · 本规范定义 GeneralZip 组件对 ZIP 格式的国密（SM4/SM3）加密扩展。
> ZIP/APPNOTE 无官方 SM4 加密标准，本规范为自定义 vendor 扩展；按本规范实现的任意第三方库可与 GeneralZip 互通。

## 1. 设计原则

1. **符合国密标准**：算法符合 GB/T 32907-2016（SM4）、GB/T 32905-2016（SM3）；KDF 为 HMAC-SM3 上的标准 PBKDF2（RFC 8018）。
2. **不侵入 ZIP 结构**：条目仍为标准 Local Header / Central Directory / Zip64 结构；加密信息全部承载于 extra field。
3. **认证加密**：Encrypt-then-MAC，篡改任何字节（含 extra field 参数）均可检出。
4. **错误口令快速失败**：extra field 携带 4 字节口令校验值，解密前先验证，避免全量解密后才失败。

## 2. 总体数据流

```
加密（写入）：
  明文 → Deflate 压缩 → SM4-CTR(K_enc, IV) 加密 → [密文 ‖ SM3-HMAC(K_mac) 尾部]
  extra field(0x4D53) 记录：盐 / IV / 迭代数 / 口令校验值

解密（读取）：
  读 extra field → SM3-PBKDF2 派生密钥 → 校验口令校验值
  → 验证 HMAC 尾部 → SM4-CTR 解密 → Inflate → 明文
```

## 3. 密钥派生（KDF）

```
salt     = 16 字节 CSPRNG 随机（每条目独立）
password = UTF-8 编码的口令字节
DK = PBKDF2-HMAC-SM3(password, salt, iterations, dkLen = 52)
     K_enc = DK[ 0..16)   // SM4 密钥
     K_mac = DK[16..48)   // HMAC-SM3 密钥
     K_ver = DK[48..52)   // 口令校验值（整段存入 extra field）
iterations 默认 10_000（可配置，范围 1_000 ~ 10_000_000）
```

说明：dkLen=52 > SM3 输出 32 字节，PBKDF2 标准块拼接（T1‖T2）产生域分离的三个子密钥。

## 4. 条目数据布局

条目的 `compression method` 固定为 **99**（与 WinZip AES 惯例一致，提示"主数据已加密，真实方法见 extra field"）；
本条目**不得**再携带 WinZip AES extra field（0x9901），二者互斥。

```
┌──────────────────────────────────────────────┐
│ SM4-CTR(K_enc, IV, deflate(明文))   密文 C     │  C 长度 = 压缩后长度（CTR 无填充）
│ SM3-HMAC(K_mac, AAD ‖ C)            尾部 32B  │  AAD = extra field 数据区（§5 [4..4+n)）
└──────────────────────────────────────────────┘
```

- **IV**：16 字节 CSPRNG 随机（每条目独立），存于 extra field。
- **计数器**：128 位大端整数，初始值 = IV，每加密 16 字节块 +1（标准 CTR，与 BouncyCastle `SM4Engine`+`CTR mode` 一致）。
- **MAC 覆盖范围**：AAD（extra field 数据区全部字节）‖ 密文 C。不覆盖 Local Header 的名称/时间等元数据（它们受 Central Directory CRC/结构约束）。
- **CRC32 字段**：Local/Central Header 中置 0（AE-2 同款约定，避免泄露明文信息）；完整性由 HMAC 保证。
- 未压缩大小 / 压缩后大小照常记录（密文长度 = 压缩后长度 + 32 字节 HMAC 尾部）。

## 5. Extra Field 二进制格式

Header ID：**0x4D53**（"SM"），小端存储于 extra field 起始两字节。

```
偏移  长度  字段                 说明
──── ──── ─────────────────── ──────────────────────────────
0    2    Header ID            = 0x4D53 (LE)
2    2    DataSize n           (LE) 本 extra field 数据区长度
4    4    Magic                = 'G''M''S''M' (0x47 0x4D 0x53 0x4D)
8    1    Version              = 1
9    1    CipherMode           1 = SM4-CTR（当前唯一值；保留扩展）
10   1    KdfId                1 = PBKDF2-HMAC-SM3
11   4    Iterations           (LE uint32)
15   1    SaltLen              = 16
16   s    Salt                 s = SaltLen 字节
…    1    IvecLen              = 16
…    v    IV                   v = IvecLen 字节
…    4    PasswordVerifier     = K_ver 原值（4 字节，LE 存储无转换）
…    2    RealMethod           (LE) 条目真实压缩方法（8=Deflate / 0=Store）
```

- `AAD` = 自偏移 4 起至数据区末尾（即 Magic..RealMethod 全部字节）。
- `PasswordVerifier` 校验：派生 `K_ver` 后与存储值**常数时间比较**（`CryptographicOperations.FixedTimeEquals`）；不匹配抛 `InvalidPasswordException`。

## 6. 解密端算法（规范性伪码）

```
1. 解析 extra field(0x4D53)，校验 Magic/Version/CipherMode/KdfId
2. DK  = PBKDF2-HMAC-SM3(password, Salt, Iterations, 52)
3. 若 DK[48..52] != PasswordVerifier（常数时间）→ InvalidPasswordException
4. C  = 密文数据（去掉末尾 32B）
5. 若 H = SM3-HMAC(K_mac, AAD ‖ C) != 尾部（常数时间）→ ArchiveCorruptedException
6. P_deflate = SM4-CTR-Decrypt(K_enc, IV, C)
7. 明文 = Inflate(P_deflate)
```

加密端为逆过程；盐、IV 均由 `RandomNumberGenerator` 生成。

## 7. 测试向量（已知答案）

### 7.1 SM4 单块（GB/T 32907-2016 示例 1）

```
Key:        01 23 45 67 89 AB CD EF FE DC BA 98 76 54 32 10
Plaintext:  01 23 45 67 89 AB CD EF FE DC BA 98 76 54 32 10
Ciphertext: 68 1E DF 34 D2 06 96 5E 86 B3 E9 4F 53 6E 42 46
```

### 7.2 SM3（GB/T 32905-2016 示例）

```
SM3("abc") = 66 C7 F0 F4 62 EE ED D9 D1 F2 D4 6B DC 10 E4 E2
              41 67 C4 87 5C F2 F7 A2 29 7D A0 2B 8F 4B A8 E0
SM3("abcd" 重复 16 次，共 64 字节)
           = DE BE 9F F9 22 75 B8 A1 38 60 48 89 C1 8E 5A 4D
             6F DB 70 E5 38 7E 57 65 29 3D CB A3 9C 0C 57 32
```### 7.3 PBKDF2-HMAC-SM3

以 §3 参数自测：固定 password/salt/iterations，断言 DK 十六进制与组件内生成值一致
（测试用例锁定输出，防止 KDF 漂移破坏既有加密包的向后兼容）。

### 7.4 往返与互操作

- 组件加密 → 组件解密（Deflate/Store × 长度 0/1/15/16/17/1KB/10MB 边界）
- 组件加密的包 → SharpZipLib 可列出条目结构（extra field 不影响标准解析）
- 错误口令 → `InvalidPasswordException`（快速失败，不解密全量）
- 密文单字节翻转 → `ArchiveCorruptedException`（HMAC 拦截）

## 8. 安全边界与限制

| 项 | 说明 |
|---|---|
| 口令强度 | 安全性受限于口令熵；建议 ≥ 12 字符随机口令 |
| 条目名/大小泄露 | 文件名、时间戳、大小为明文（与 WinZip AES 相同）；需元数据保密请用 v2 规划的"整包头加密容器" |
| 多接收方 | v1 仅口令加密；SM2 数字信封（一人加密、多人解密）为预留扩展点 |
| 防暴力破解 | Iterations 仅提升成本；在线场景应配合应用层限速 |

## 9. 版本策略

- Version 字节变更即不兼容；新增算法模式（如 SM4-CBC、SM4-GCM 类 AEAD）以新 CipherMode/KdfId 值表达，读取端遇到未知值抛 `UnsupportedFormatException`。
- 本规范与组件同版本演进；规范级变更记录于文档顶部"状态"行。
