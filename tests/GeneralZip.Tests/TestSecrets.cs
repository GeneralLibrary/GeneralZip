using System;
using System.Linq;
using System.Security.Cryptography;

namespace GeneralZip.Tests;

/// <summary>
/// 测试专用口令（非真实凭据）：运行时派生，避免在源码中书写明文口令字面量。
/// </summary>
internal static class TestSecrets
{
    private const string Alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    /// <summary>随机测试口令。</summary>
    public static string NewPassword(int length = 16)
    {
        var bytes = RandomNumberGenerator.GetBytes(length);
        return new string(bytes.Select(b => Alphabet[b % Alphabet.Length]).ToArray());
    }

    /// <summary>固定测试口令（运行时拼接派生，用例内确定性复用）。</summary>
    public static string Fixed(int variant = 0)
    {
        var head = Alphabet.Substring(variant % Alphabet.Length, 8);
        return head + Alphabet.Substring(10, 8) + variant.ToString("D2");
    }

    /// <summary>构造一个"必然错误"的口令（与正确口令不同的确定性串）。</summary>
    public static string Wrong(string correct) => new('Z', correct.Length + 4);
}
