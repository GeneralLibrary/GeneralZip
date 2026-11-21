using System.Text;
using GeneralZip.Formats.Zip;
using Xunit;

namespace GeneralZip.Tests;

/// <summary>
/// ZIP 条目名/注释编码回退测试：无 UTF-8 标志时按 APPNOTE 约定回退 IBM437（CP437），
/// 显式指定 EntryNameEncoding 时的行为以用户指定为准。
/// </summary>
public class ZipNameEncodingTests
{
    [Fact]
    public void LegacyName_WithoutUtf8Flag_DecodesAsIbm437()
    {
        var entry = new ZipCentralEntry { NameRaw = new byte[] { 0x43, 0x41, 0x46, 0x90, 0x93 }, Flags = 0 };
        Assert.Equal("CAFÉô", entry.DecodeName(null));
    }

    [Fact]
    public void LegacyComment_WithoutUtf8Flag_DecodesAsIbm437()
    {
        var entry = new ZipCentralEntry { CommentRaw = new byte[] { 0x80, 0xFF }, Flags = 0 };
        Assert.Equal("Ç\u00A0", entry.DecodeComment(null));
    }

    [Fact]
    public void Utf8Flag_DecodesAsUtf8_RegardlessOfFallback()
    {
        var entry = new ZipCentralEntry { NameRaw = Encoding.UTF8.GetBytes("中文.zip"), Flags = ZipConstants.FlagUtf8 };
        Assert.Equal("中文.zip", entry.DecodeName(null));
    }

    [Fact]
    public void ExplicitFallback_OverridesLegacyDefault()
    {
        var entry = new ZipCentralEntry { NameRaw = new byte[] { 0x90 }, Flags = 0 };
        Assert.Equal("É", entry.DecodeName(null));
        Assert.Equal("?", entry.DecodeName(Encoding.ASCII));
    }

    [Fact]
    public void LegacyDecode_IsTotal_EveryByteMapsToAChar()
    {
        var all = new byte[256];
        for (int i = 0; i < 256; i++) all[i] = (byte)i;
        var decoded = ZipConstants.DecodeIbm437(all);
        Assert.Equal(256, decoded.Length);
        Assert.All(decoded, c => Assert.NotEqual('\uFFFD', c));
    }
}
