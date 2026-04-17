using System.Numerics;

namespace CryptoMathLib;

public sealed class RsaMath : IRsaCoreMath
{
    private const int MinPrime = 100;
    private const int MaxPrime = 250;
    private const int MaxModulus = 65535;

    private readonly Random _random = new();

    public (string publicKey, string privateKey) GenerateKeyPair()
    {
        BigInteger p;
        BigInteger q;
        BigInteger n;

        do
        {
            p = GenerateRandomPrime();
            q = GenerateRandomPrime();
            while (q == p)
            {
                q = GenerateRandomPrime();
            }

            n = p * q;
        } while (n >= MaxModulus || n <= byte.MaxValue);

        BigInteger phi = (p - 1) * (q - 1);
        BigInteger e = ChoosePublicExponent(phi);
        BigInteger d = ModInverse(e, phi);

        string publicKey = $"{e}|{n}";
        string privateKey = $"{d}|{n}";
        return (publicKey, privateKey);
    }

    public byte[] RsaProcessBlock(byte[] inputData, string key, bool isEncrypt)
    {
        if (inputData is null)
        {
            throw new ArgumentNullException(nameof(inputData));
        }

        (BigInteger exponent, BigInteger modulus) = ParseKey(key);

        if (modulus <= byte.MaxValue)
        {
            throw new ArgumentException("模数必须大于 255，才能满足 1-byte 明文块约束。", nameof(key));
        }

        if (isEncrypt)
        {
            return EncryptBlocks(inputData, exponent, modulus);
        }

        return DecryptBlocks(inputData, exponent, modulus);
    }

    public string ModPow(string baseNum, string exp, string mod)
    {
        BigInteger b = BigInteger.Parse(baseNum);
        BigInteger e = BigInteger.Parse(exp);
        BigInteger m = BigInteger.Parse(mod);

        if (m <= 0)
        {
            throw new ArgumentException("模数必须为正整数。", nameof(mod));
        }

        if (e < 0)
        {
            throw new ArgumentException("指数必须为非负整数。", nameof(exp));
        }

        // 使用平方-乘法进行快速模幂，避免依赖任何 RSA 封装 API。
        return PowMod(b, e, m).ToString();
    }

    private byte[] EncryptBlocks(byte[] inputData, BigInteger exponent, BigInteger modulus)
    {
        byte[] output = new byte[inputData.Length * 2];
        int writeIndex = 0;

        foreach (byte plainByte in inputData)
        {
            BigInteger cipher = PowMod(plainByte, exponent, modulus);
            if (cipher > ushort.MaxValue)
            {
                throw new InvalidOperationException("密文块超过 16bit，违反实验限制。");
            }

            ushort cipherShort = (ushort)cipher;
            output[writeIndex++] = (byte)(cipherShort >> 8);
            output[writeIndex++] = (byte)(cipherShort & 0xFF);
        }

        return output;
    }

    private byte[] DecryptBlocks(byte[] inputData, BigInteger exponent, BigInteger modulus)
    {
        if (inputData.Length % 2 != 0)
        {
            throw new ArgumentException("解密输入长度必须是 2 的倍数。", nameof(inputData));
        }

        byte[] output = new byte[inputData.Length / 2];
        int writeIndex = 0;

        for (int i = 0; i < inputData.Length; i += 2)
        {
            ushort cipherShort = (ushort)((inputData[i] << 8) | inputData[i + 1]);
            BigInteger plain = PowMod(cipherShort, exponent, modulus);

            if (plain < 0 || plain > byte.MaxValue)
            {
                throw new InvalidOperationException("解密结果超出 1-byte 范围。");
            }

            output[writeIndex++] = (byte)plain;
        }

        return output;
    }

    private (BigInteger exponent, BigInteger modulus) ParseKey(string key)
    {
        if (string.IsNullOrWhiteSpace(key))
        {
            throw new ArgumentException("密钥不能为空。", nameof(key));
        }

        string[] parts = key.Split('|');
        if (parts.Length != 2)
        {
            throw new ArgumentException("密钥格式应为 \"指数|模数\"。", nameof(key));
        }

        BigInteger exponent = BigInteger.Parse(parts[0]);
        BigInteger modulus = BigInteger.Parse(parts[1]);
        if (exponent <= 0 || modulus <= 0)
        {
            throw new ArgumentException("密钥参数必须是正整数。", nameof(key));
        }

        return (exponent, modulus);
    }

    private BigInteger GenerateRandomPrime()
    {
        while (true)
        {
            int candidate = _random.Next(MinPrime, MaxPrime + 1);
            if (IsPrime(candidate))
            {
                return candidate;
            }
        }
    }

    private static bool IsPrime(int value)
    {
        if (value < 2)
        {
            return false;
        }

        if (value % 2 == 0)
        {
            return value == 2;
        }

        int boundary = (int)Math.Sqrt(value);
        for (int divisor = 3; divisor <= boundary; divisor += 2)
        {
            if (value % divisor == 0)
            {
                return false;
            }
        }

        return true;
    }

    private static BigInteger ChoosePublicExponent(BigInteger phi)
    {
        BigInteger[] preferred = [65537, 257, 17, 5, 3];

        foreach (BigInteger candidate in preferred)
        {
            if (candidate > 1 && candidate < phi && Gcd(candidate, phi) == 1)
            {
                return candidate;
            }
        }

        for (BigInteger candidate = 3; candidate < phi; candidate += 2)
        {
            if (Gcd(candidate, phi) == 1)
            {
                return candidate;
            }
        }

        throw new InvalidOperationException("无法找到与 phi 互素的公钥指数 e。");
    }

    private static BigInteger ModInverse(BigInteger a, BigInteger mod)
    {
        (BigInteger gcd, BigInteger x, _) = ExtendedGcd(a, mod);
        if (gcd != 1)
        {
            throw new InvalidOperationException("a 与 mod 不互素，逆元不存在。");
        }

        BigInteger result = x % mod;
        return result < 0 ? result + mod : result;
    }

    private static (BigInteger gcd, BigInteger x, BigInteger y) ExtendedGcd(BigInteger a, BigInteger b)
    {
        if (b == 0)
        {
            return (a, 1, 0);
        }

        (BigInteger gcd, BigInteger x1, BigInteger y1) = ExtendedGcd(b, a % b);
        BigInteger x = y1;
        BigInteger y = x1 - (a / b) * y1;
        return (gcd, x, y);
    }

    private static BigInteger Gcd(BigInteger a, BigInteger b)
    {
        while (b != 0)
        {
            BigInteger t = b;
            b = a % b;
            a = t;
        }

        return BigInteger.Abs(a);
    }

    private static BigInteger PowMod(BigInteger baseNum, BigInteger exp, BigInteger mod)
    {
        if (mod == 1)
        {
            return 0;
        }

        BigInteger result = 1;
        BigInteger baseValue = ((baseNum % mod) + mod) % mod;
        BigInteger exponent = exp;

        while (exponent > 0)
        {
            if ((exponent & 1) == 1)
            {
                result = (result * baseValue) % mod;
            }

            exponent >>= 1;
            baseValue = (baseValue * baseValue) % mod;
        }

        return result;
    }
}
