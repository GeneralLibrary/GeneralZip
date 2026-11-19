using System;
using System.Buffers.Binary;
using System.IO;
using System.Linq;
using System.Text;
using GeneralZip;
using GeneralZip.Abstractions;
using Xunit;

namespace GeneralZip.Tests;

/// <summary>CPIO 格式测试：newc 自写自读 + odc/binary 手工向量 + 符号链接。</summary>
public class CpioFormatTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), $"gzp-test-{Guid.NewGuid():N}");

    public CpioFormatTests()
    {
        Directory.CreateDirectory(_dir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { }
    }

    [Fact]
    public void Newc_Roundtrip()
    {
        var cpio = Path.Combine(_dir, "a.cpio");
        using (var w = GeneralZipWriter.CreateNew(cpio))
        {
            w.AddDirectoryEntry("dir/");
            var payload = Encoding.UTF8.GetBytes("你好 CPIO");
            w.AddStream("dir/hello.txt", new MemoryStream(payload), payload.Length);
            w.AddStream("empty.bin", new MemoryStream(Array.Empty<byte>()), 0);
            w.Finish();
        }

        Assert.Equal("CPIO", GeneralZip.DetectFormat(cpio)?.Name);

        using var r = GeneralZipReader.Open(cpio);
        Assert.Equal(3, r.Entries.Count);
        Assert.True(r.Entries[0].IsDirectory);
        Assert.True(r.Entries[1].IsDirectory == false);

        using var s = r.OpenEntryStream(r.Entries[1]);
        using var ms = new MemoryStream();
        s.CopyTo(ms);
        Assert.Equal("你好 CPIO", Encoding.UTF8.GetString(ms.ToArray()));
    }

    [Fact]
    public void Newc_SymlinkRoundtrip()
    {
        var cpio = Path.Combine(_dir, "sym.cpio");
        using (var w = GeneralZipWriter.CreateNew(cpio))
        {
            w.AddSymlink("alias", "target/x.txt");
            w.Finish();
        }

        using var r = GeneralZipReader.Open(cpio);
        var unix = Assert.IsAssignableFrom<IUnixEntry>(r.Entries.Single());
        Assert.Equal(0xA000u, unix.UnixMode & 0xF000u);
        using var s = r.OpenEntryStream(r.Entries[0]);
        using var ms = new MemoryStream();
        s.CopyTo(ms);
        Assert.Equal("target/x.txt", Encoding.UTF8.GetString(ms.ToArray()));
    }

    [Fact]
    public void Newc_UnixModePreserved()
    {
        var cpio = Path.Combine(_dir, "mode.cpio");
        using (var w = GeneralZipWriter.CreateNew(cpio))
        {
            w.AddStream("a.bin", new MemoryStream(new byte[] { 1 }), new ArchiveEntryMetadata
            {
                Size = 1,
                UnixMode = 0x81C0, // S_IFREG | 0700
            });
            w.Finish();
        }

        using var r = GeneralZipReader.Open(cpio);
        var unix = Assert.IsAssignableFrom<IUnixEntry>(r.Entries.Single());
        Assert.Equal(0x81C0u, unix.UnixMode);
    }

    /// <summary>手工构造 odc（070707，八进制 ASCII，无对齐）归档。</summary>
    [Fact]
    public void Odc_Vector_Read()
    {
        using var ms = new MemoryStream();
        WriteOdcEntry(ms, "od.txt", "odc!"u8.ToArray(), mode: 0x81A4, mtime: 42598);
        WriteOdcTrailer(ms);
        ms.Position = 0;

        using var r = GeneralZipReader.Open(ms);
        Assert.Single(r.Entries);
        Assert.Equal("od.txt", r.Entries[0].FullName);
        using var s = r.OpenEntryStream(r.Entries[0]);
        using var body = new MemoryStream();
        s.CopyTo(body);
        Assert.Equal("odc!", Encoding.UTF8.GetString(body.ToArray()));
    }

    /// <summary>手工构造 portable binary（0x71C7 LE）归档。</summary>
    [Fact]
    public void Binary_Vector_Read()
    {
        using var ms = new MemoryStream();
        var name = "bin.txt\0"u8.ToArray();
        var data = "bin"u8.ToArray();

        Span<byte> header = stackalloc byte[26];
        header[0] = 0x71;
        header[1] = 0xC7;
        BinaryPrimitives.WriteUInt16LittleEndian(header.Slice(2), 0);   // dev
        BinaryPrimitives.WriteUInt16LittleEndian(header.Slice(4), 1);   // ino
        BinaryPrimitives.WriteUInt16LittleEndian(header.Slice(6), 0x8180); // mode 0600
        BinaryPrimitives.WriteUInt16LittleEndian(header.Slice(8), 0);   // uid
        BinaryPrimitives.WriteUInt16LittleEndian(header.Slice(10), 0);  // gid
        BinaryPrimitives.WriteUInt16LittleEndian(header.Slice(12), 1);  // nlink
        BinaryPrimitives.WriteUInt16LittleEndian(header.Slice(14), 0);  // rdev
        BinaryPrimitives.WriteUInt16LittleEndian(header.Slice(16), 0);  // mtime hi
        BinaryPrimitives.WriteUInt16LittleEndian(header.Slice(18), 0);  // mtime lo
        BinaryPrimitives.WriteUInt16LittleEndian(header.Slice(20), (ushort)name.Length);
        BinaryPrimitives.WriteUInt16LittleEndian(header.Slice(22), 0);  // filesize hi
        BinaryPrimitives.WriteUInt16LittleEndian(header.Slice(24), (ushort)data.Length);
        ms.Write(header);
        ms.Write(name);
        ms.Write(data);

        // trailer（binary trailer 名 "TRAILER!!!"）
        var trailerName = Encoding.ASCII.GetBytes("TRAILER!!!\0");
        BinaryPrimitives.WriteUInt16LittleEndian(header.Slice(4), 2); // ino
        BinaryPrimitives.WriteUInt16LittleEndian(header.Slice(20), (ushort)trailerName.Length);
        ms.Write(header);
        ms.Write(trailerName);
        ms.Position = 0;

        using var r = GeneralZipReader.Open(ms);
        var entry = r.Entries.Single();
        Assert.Equal("bin.txt", entry.FullName);
        var unix = Assert.IsAssignableFrom<IUnixEntry>(entry);
        Assert.Equal(0x8180u, unix.UnixMode);
        using var s = r.OpenEntryStream(entry);
        using var body = new MemoryStream();
        s.CopyTo(body);
        Assert.Equal("bin", Encoding.UTF8.GetString(body.ToArray()));
    }

    private static void WriteOdcEntry(Stream s, string name, byte[] data, uint mode, long mtime)
    {
        var nameBytes = Encoding.UTF8.GetBytes(name + "\0");
        static string Oct(long v) => Convert.ToString(v, 8).PadLeft(6, '0');
        var header = "070707" + Oct(0) + Oct(1) + Oct(mode) + Oct(0) + Oct(0) + Oct(1) + Oct(0)
                     + Oct(mtime) + Oct(nameBytes.Length) + Oct(data.Length);
        var headerBytes = Encoding.ASCII.GetBytes(header);
        s.Write(headerBytes, 0, headerBytes.Length);
        s.Write(nameBytes, 0, nameBytes.Length);
        s.Write(data, 0, data.Length);
    }

    private static void WriteOdcTrailer(Stream s)
    {
        var nameBytes = Encoding.ASCII.GetBytes("TRAILER!!!\0");
        static string OctT(long v) => Convert.ToString(v, 8).PadLeft(6, '0');
        var header = "070707" + OctT(0) + OctT(2) + OctT(0) + OctT(0) + OctT(0) + OctT(1) + OctT(0)
                     + OctT(0) + OctT(nameBytes.Length) + OctT(0);
        var headerBytes = Encoding.ASCII.GetBytes(header);
        s.Write(headerBytes, 0, headerBytes.Length);
        s.Write(nameBytes, 0, nameBytes.Length);
    }

}
