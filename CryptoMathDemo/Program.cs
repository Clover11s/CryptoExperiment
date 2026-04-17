using System.Diagnostics;
using System.Text;
using CryptoMathLib;

const int MaxModulus = 65535;
const int StressDataSize = 1024 * 1024; // 1MB

IRsaCoreMath rsa = new RsaMath();

Console.OutputEncoding = Encoding.UTF8;
PrintHeader("CryptoMathDemo - RSA 小模数分组验证");

// 场景一：模数合规性测试
PrintSection("场景一：模数合规性测试");
(string publicKey, string privateKey) = rsa.GenerateKeyPair();
Console.WriteLine($"公钥: {publicKey}");
Console.WriteLine($"私钥: {privateKey}");

int modulus = ExtractModulus(publicKey);
bool isModulusValid = modulus < MaxModulus;
Console.WriteLine($"提取到模数 n = {modulus}");
Console.WriteLine(isModulusValid
    ? $"[通过] 模数 n < {MaxModulus}，满足 16bit 限制。"
    : $"[失败] 模数 n >= {MaxModulus}，不满足 16bit 限制。");

if (!isModulusValid)
{
    throw new InvalidOperationException("密钥模数不符合实验限制。");
}

// 场景二：普通中文字符串测试
PrintSection("场景二：中文字符串加解密往返测试");
const string plainText = "机密数据：RSA_128位测试_!@#";
byte[] textBytes = Encoding.UTF8.GetBytes(plainText);
byte[] encryptedText = rsa.RsaProcessBlock(textBytes, publicKey, isEncrypt: true);
byte[] decryptedText = rsa.RsaProcessBlock(encryptedText, privateKey, isEncrypt: false);
string recoveredText = Encoding.UTF8.GetString(decryptedText);

bool textRoundTripOk = plainText == recoveredText;
Console.WriteLine($"原文: {plainText}");
Console.WriteLine($"还原: {recoveredText}");
Console.WriteLine($"原文字节长度: {textBytes.Length}，密文字节长度: {encryptedText.Length}");
Console.WriteLine(textRoundTripOk
    ? "[通过] 中文与特殊符号往返完全一致。"
    : "[失败] 往返后字符串不一致。");

if (!textRoundTripOk)
{
    throw new InvalidOperationException("字符串往返校验失败。");
}

// 场景三：1MB 极限大文件流模拟压测
PrintSection("场景三：1MB 随机字节数组压测");
byte[] sourceData = new byte[StressDataSize];
Random.Shared.NextBytes(sourceData);

Stopwatch encryptWatch = Stopwatch.StartNew();
byte[] encryptedData = rsa.RsaProcessBlock(sourceData, publicKey, isEncrypt: true);
encryptWatch.Stop();

Stopwatch decryptWatch = Stopwatch.StartNew();
byte[] decryptedData = rsa.RsaProcessBlock(encryptedData, privateKey, isEncrypt: false);
decryptWatch.Stop();

bool dataRoundTripOk = sourceData.AsSpan().SequenceEqual(decryptedData);
Console.WriteLine($"原始数据大小: {sourceData.Length:N0} bytes");
Console.WriteLine($"加密后大小: {encryptedData.Length:N0} bytes");
Console.WriteLine($"加密耗时: {encryptWatch.ElapsedMilliseconds:N0} ms");
Console.WriteLine($"解密耗时: {decryptWatch.ElapsedMilliseconds:N0} ms");
Console.WriteLine(dataRoundTripOk
    ? "[通过] 1MB 数据加解密后 100% 一致。"
    : "[失败] 1MB 数据校验不一致。");

if (!dataRoundTripOk)
{
    throw new InvalidOperationException("1MB 压测往返校验失败。");
}

PrintSection("结论");
Console.WriteLine("全部测试通过：RSA 小模数分组逻辑正确、稳定、可用于实验演示。");

static int ExtractModulus(string key)
{
    string[] parts = key.Split('|');
    if (parts.Length != 2)
    {
        throw new ArgumentException("密钥格式无效，应为 \"指数|模数\"。", nameof(key));
    }

    return int.Parse(parts[1]);
}

static void PrintHeader(string title)
{
    Console.WriteLine(new string('=', 72));
    Console.WriteLine(title);
    Console.WriteLine(new string('=', 72));
}

static void PrintSection(string section)
{
    Console.WriteLine();
    Console.WriteLine($"[{section}]");
    Console.WriteLine(new string('-', 72));
}
