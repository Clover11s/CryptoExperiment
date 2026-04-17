using System.Numerics;

namespace CryptoMathLib;

public interface IRsaCoreMath
{
    // 1. 密钥对生成：返回格式约定为字符串元组 ("公钥指数e|模数n", "私钥指数d|模数n")
    // 注意：内部必须手动实现扩展欧几里得算法求私钥 d
    (string publicKey, string privateKey) GenerateKeyPair();

    // 2. RSA 分组加解密：处理大于 16bit 消息的核心逻辑（1变2，2变1）
    byte[] RsaProcessBlock(byte[] inputData, string key, bool isEncrypt);

    // 3. 基础模幂运算接口：供同组协议工程师(D-H协议)复用
    string ModPow(string baseNum, string exp, string mod);
}
