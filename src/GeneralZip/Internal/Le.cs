using System;
using System.IO;

namespace GeneralZip.Internal;

/// <summary>小端二进制读写工具（netstandard2.0 无 BinaryPrimitives）。</summary>
internal static class Le
{
    public static ushort U16(byte[] b, int o) => (ushort)(b[o] | (b[o + 1] << 8));

    public static uint U32(byte[] b, int o) =>
        (uint)(b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24));

    public static ulong U64(byte[] b, int o)
    {
        uint lo = U32(b, o);
        uint hi = U32(b, o + 4);
        return lo | ((ulong)hi << 32);
    }

    public static void Put16(byte[] b, int o, ushort v)
    {
        b[o] = (byte)v;
        b[o + 1] = (byte)(v >> 8);
    }

    public static void Put32(byte[] b, int o, uint v)
    {
        b[o] = (byte)v;
        b[o + 1] = (byte)(v >> 8);
        b[o + 2] = (byte)(v >> 16);
        b[o + 3] = (byte)(v >> 24);
    }

    public static void Put64(byte[] b, int o, ulong v)
    {
        Put32(b, o, (uint)v);
        Put32(b, o + 4, (uint)(v >> 32));
    }

    public static ushort ReadU16(Stream s)
    {
        Span2(s, out var b0, out var b1);
        return (ushort)(b0 | (b1 << 8));
    }

    public static uint ReadU32(Stream s)
    {
        var buf = new byte[4];
        ReadExactly(s, buf, 4);
        return U32(buf, 0);
    }

    public static ulong ReadU64(Stream s)
    {
        var buf = new byte[8];
        ReadExactly(s, buf, 8);
        return U64(buf, 0);
    }

    public static byte[] ReadBytes(Stream s, int count)
    {
        var buf = new byte[count];
        ReadExactly(s, buf, count);
        return buf;
    }

    public static void ReadExactly(Stream s, byte[] buffer, int count)
    {
        var total = 0;
        while (total < count)
        {
            var n = s.Read(buffer, total, count - total);
            if (n <= 0)
            {
                throw new ArchiveCorruptedException("ZIP 结构数据不完整（流意外结束）");
            }

            total += n;
        }
    }

    private static void Span2(Stream s, out int b0, out int b1)
    {
        var buf = new byte[2];
        ReadExactly(s, buf, 2);
        b0 = buf[0];
        b1 = buf[1];
    }
}
