//! Trae 客户端 Km 加密条目的编解码 + JWT 解析（移植自 trae-switch src/km.js）。
//!
//! Trae（VS Code 衍生）把登录态写进 `storage.json`，值为 Base64 密文，形如：
//!   `dGMFEAAA....`   6 字节固定前缀 + 32 字节盐 + AES-128-CBC 密文
//! 密钥调度是客户端硬编码的（与机器/账号无关），因此可离线编解码：
//!   keySeed = buf[6 .. 6+32]
//!   seedHash = SHA512(keySeed)
//!   hash = SHA512(seedHash ‖ (SEG_A ⊕ SEG_B))
//!   aesKey = hash[0..16]   iv = hash[16..32]
//!   plain  = AES-128-CBC(aesKey, iv, buf[38..])
//!   明文 = SHA512(body) ‖ body     ← 前 64 字节是正文摘要，客户端解密时会校验
//!
//! 只处理「客户端登录态」这一层；ai-agent 会话数据库是另一套 SQLCipher 加密。

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use sha2::{Digest, Sha512};

/// 密文条目 Base64 特征前缀（`[0x74 0x63 0x05 0x10 0x00 0x00]` 的 Base64）。
pub const KM_PREFIX: &str = "dGMFEAAA";

const AES_KEY_LEN: usize = 16;
const IV_LEN: usize = 16;
const SALT_LEN: usize = 32;
/// 明文头部长度 = SHA-512 摘要长度，同时用于密钥派生里 XOR 段的长度。
const HASH_LEN: usize = 64;
const PREFIX_LEN: usize = 6;

const SEG_A: [u8; 64] = [
    82, 9, 106, 213, 48, 54, 165, 56, 191, 64, 163, 158, 129, 243, 215, 251, 124, 227, 57, 130,
    155, 47, 255, 135, 52, 142, 67, 68, 196, 222, 233, 203, 84, 123, 148, 50, 166, 194, 35, 61,
    238, 76, 149, 11, 66, 250, 195, 78, 8, 46, 161, 102, 40, 217, 36, 178, 118, 91, 162, 73,
    109, 139, 209, 37,
];

const SEG_B: [u8; 64] = [
    31, 221, 168, 51, 136, 7, 199, 49, 177, 18, 16, 89, 39, 128, 236, 95, 96, 81, 127, 169,
    25, 181, 74, 13, 45, 229, 122, 159, 147, 201, 156, 239, 160, 224, 59, 77, 174, 42, 245, 176,
    200, 235, 187, 60, 131, 83, 153, 97, 23, 43, 4, 126, 186, 119, 214, 38, 225, 105, 20, 99,
    85, 33, 12, 125,
];

/// 判断值是否为 Km 加密条目。
pub fn is_km_value(v: &str) -> bool {
    v.starts_with(KM_PREFIX)
}

/// 由 32 字节盐派生 AES 密钥与 IV（客户端 `Moe`）。
fn derive_key_iv(salt: &[u8]) -> ([u8; AES_KEY_LEN], [u8; IV_LEN]) {
    let seed_hash = Sha512::digest(salt);
    let mut mixed = [0u8; HASH_LEN];
    for i in 0..HASH_LEN {
        mixed[i] = SEG_A[i] ^ SEG_B[i];
    }
    let mut hasher = Sha512::new();
    hasher.update(seed_hash);
    hasher.update(mixed);
    let hash = hasher.finalize();
    let mut key = [0u8; AES_KEY_LEN];
    let mut iv = [0u8; IV_LEN];
    key.copy_from_slice(&hash[0..AES_KEY_LEN]);
    iv.copy_from_slice(&hash[AES_KEY_LEN..AES_KEY_LEN + IV_LEN]);
    (key, iv)
}

/// 无填充 CBC 解密（输入必须是块对齐；SQLCipher 页面与 Km 密文均满足）。
pub(crate) fn aes_cbc_decrypt<C>(key: &[u8], iv: &[u8; 16], data: &[u8]) -> Vec<u8>
where
    C: KeyInit + BlockDecrypt,
    C::BlockSize: aes::cipher::generic_array::ArrayLength<u8>,
{
    let cipher = C::new(GenericArray::from_slice(key));
    let mut prev: [u8; 16] = *iv;
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks_exact(16) {
        let mut block = GenericArray::<u8, C::BlockSize>::clone_from_slice(chunk);
        cipher.decrypt_block(&mut block);
        for i in 0..16 {
            out.push(block[i] ^ prev[i]);
        }
        prev.copy_from_slice(chunk);
    }
    out
}

/// 无填充 CBC 加密（对称方向）。
pub(crate) fn aes_cbc_encrypt<C>(key: &[u8], iv: &[u8; 16], data: &[u8]) -> Vec<u8>
where
    C: KeyInit + BlockEncrypt,
    C::BlockSize: aes::cipher::generic_array::ArrayLength<u8>,
{
    let cipher = C::new(GenericArray::from_slice(key));
    let mut prev: [u8; 16] = *iv;
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks_exact(16) {
        let mut block = GenericArray::<u8, C::BlockSize>::clone_from_slice(chunk);
        for i in 0..16 {
            block[i] ^= prev[i];
        }
        cipher.encrypt_block(&mut block);
        out.extend_from_slice(&block);
        prev.copy_from_slice(&block);
    }
    out
}

/// 解码 Km 条目，返回原始明文字符串（未经 JSON 解析）。
pub fn decrypt_km(b64: &str) -> Result<String, String> {
    let buf = STANDARD
        .decode(b64.trim())
        .map_err(|e| format!("Km Base64 解码失败: {e}"))?;
    if buf.len() <= PREFIX_LEN + SALT_LEN {
        return Err("Km 密文长度不足".into());
    }
    let key_seed = &buf[PREFIX_LEN..PREFIX_LEN + SALT_LEN];
    let (key, iv) = derive_key_iv(key_seed);
    let cipher_text = &buf[PREFIX_LEN + SALT_LEN..];
    let mut plain = aes_cbc_decrypt::<Aes128>(&key, &iv, cipher_text);
    // 客户端加密用 PKCS#7 填充（WebCrypto AES-CBC 默认），链式无填充解密会把它
    // 一起解出，导致明文尾部多出填充字节、JSON 解析失败。此处按 PKCS#7 规则剥除：
    // 末字节 n(1..=16) 表示补了 n 个值为 n 的字节；无填充数据不受影响。
    if let Some(&last) = plain.last() {
        let pad = last as usize;
        if (1..=16).contains(&pad) && plain.len() >= pad + HASH_LEN {
            let start = plain.len() - pad;
            if plain[start..].iter().all(|&b| b == last) {
                plain.truncate(start);
            }
        }
    }
    if plain.len() <= HASH_LEN {
        return Err("Km 明文长度不足".into());
    }
    String::from_utf8(plain[HASH_LEN..].to_vec()).map_err(|e| format!("Km 明文非 UTF-8: {e}"))
}

/// 解码并 JSON.parse；失败返回 None（不抛，便于批量探测）。
pub fn decrypt_km_json(b64: &str) -> Option<serde_json::Value> {
    let plain = decrypt_km(b64).ok()?;
    serde_json::from_str(&plain).ok()
}

/// 加密成 Km 条目（客户端 `Km` / `BUe`）。
/// 结构：6 字节前缀 ‖ 32 字节随机盐 ‖ AES-128-CBC-PKCS7( SHA512(body) ‖ body )。
/// 必须 PKCS#7 填充：客户端用 WebCrypto AES-CBC 解密（默认带 PKCS7），
/// 无填充产物会被解出填充残留、JSON 解析失败（见 decrypt_km 的剥填充注释）。
pub fn encrypt_km(plain: &str) -> Result<String, String> {
    let body = plain.as_bytes();
    let salt = random_32();
    let (key, iv) = derive_key_iv(&salt);
    let mut block_input = Sha512::digest(body).to_vec();
    block_input.extend_from_slice(body);
    let pad = 16 - (block_input.len() % 16);
    block_input.extend(std::iter::repeat(pad as u8).take(pad));
    let cipher_text = aes_cbc_encrypt::<Aes128>(&key, &iv, &block_input);
    let mut out = Vec::with_capacity(PREFIX_LEN + SALT_LEN + cipher_text.len());
    out.extend_from_slice(&[0x74, 0x63, 0x05, 0x10, 0x00, 0x00]);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&cipher_text);
    Ok(STANDARD.encode(out))
}

/// 加密 JSON。
pub fn encrypt_km_json(obj: &serde_json::Value) -> Result<String, String> {
    encrypt_km(&serde_json::to_string(obj).map_err(|e| e.to_string())?)
}

/// 模拟客户端的解密校验：前缀匹配 + 明文头 64 字节 == SHA512(正文)。
pub fn client_accepts_km(b64: &str) -> bool {
    let Ok(buf) = STANDARD.decode(b64.trim()) else {
        return false;
    };
    if buf.len() <= PREFIX_LEN + SALT_LEN {
        return false;
    }
    if buf[..PREFIX_LEN] != [0x74, 0x63, 0x05, 0x10, 0x00, 0x00] {
        return false;
    }
    let (key, iv) = derive_key_iv(&buf[PREFIX_LEN..PREFIX_LEN + SALT_LEN]);
    let mut plain = aes_cbc_decrypt::<Aes128>(&key, &iv, &buf[PREFIX_LEN + SALT_LEN..]);
    if let Some(&last) = plain.last() {
        let pad = last as usize;
        if (1..=16).contains(&pad) && plain.len() >= pad + HASH_LEN {
            let start = plain.len() - pad;
            if plain[start..].iter().all(|&b| b == last) {
                plain.truncate(start);
            }
        }
    }
    if plain.len() <= HASH_LEN {
        return false;
    }
    let body = &plain[HASH_LEN..];
    Sha512::digest(body).as_slice() == &plain[..HASH_LEN]
}

// ---------------------------------------------------------------------------
// JWT 解析（不验签，只读 payload）
// ---------------------------------------------------------------------------

/// 解 JWT 中间段（base64url）。失败返回 None。
pub fn jwt_payload(token: &str) -> Option<serde_json::Value> {
    let seg = token.trim().split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(seg).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// 取出 JWT 的过期时间戳（毫秒）；无 exp 返回 0。
pub fn jwt_exp(token: &str) -> i64 {
    jwt_payload(token)
        .and_then(|p| p.get("exp")?.as_i64())
        .map(|exp| exp * 1000)
        .unwrap_or(0)
}

/// 从一个 Cloud-IDE-JWT 里取出所属账号 id（payload.data.id）。
pub fn jwt_user_id(token: &str) -> Option<String> {
    let p = jwt_payload(token)?;
    let d = p.get("data")?;
    let uid = d.get("id").or_else(|| d.get("user_id"))?;
    uid.as_i64()
        .map(|v| v.to_string())
        .or_else(|| uid.as_str().map(String::from))
}

/// 去掉值上可能带的 "Cloud-IDE-JWT " 前缀。
pub fn strip_cloud_prefix(v: &str) -> &str {
    v.strip_prefix("Cloud-IDE-JWT ").unwrap_or(v)
}

// ---------------------------------------------------------------------------
// 随机盐
// ---------------------------------------------------------------------------

/// 生成 32 字节随机盐（用于 Km 加密）。失败回退到时间戳派生的伪随机值。
fn random_32() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    let ok = getrandom::getrandom(&mut salt).is_ok();
    if ok {
        return salt;
    }
    // 兜底：以系统时间为种子（仅当 getrandom 不可用时；正常平台不会走到这里）
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let mut h = Sha512::new();
    h.update(now.as_nanos().to_le_bytes());
    h.update(std::process::id().to_le_bytes());
    let digest = h.finalize();
    salt.copy_from_slice(&digest[..SALT_LEN]);
    salt
}
