using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using GeneralZip;
using GeneralZip.Abstractions;
using Xunit;

namespace GeneralZip.Tests;

/// <summary>ISO9660 / CAB（NONE）/ ZIP 分卷测试（手工构造字节级向量，自包含）。</summary>
public class IsoCabSplitTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), $"gzp-test-{Guid.NewGuid():N}");

    public IsoCabSplitTests()
    {
        Directory.CreateDirectory(_dir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { }
    }

    // ---------- ISO9660 ----------

    [Fact]
    public void Iso_HandCrafted_Read()
    {
        var iso = BuildMinimalIso();
        var path = Path.Combine(_dir, "mini.iso");
        File.WriteAllBytes(path, iso);

        Assert.Equal("ISO", GeneralZip.DetectFormat(path)?.Name);

        using var r = GeneralZipReader.Open(path);
        var names = r.Entries.Select(e => e.FullName).ToList();
        Assert.Contains("HELLO.TXT", names);
        Assert.Contains("SUB/", names);
        Assert.Contains("SUB/A.TXT", names);

        var hello = r.Entries.First(e => e.FullName == "HELLO.TXT");
        using var s = r.OpenEntryStream(hello);
        using var ms = new MemoryStream();
        s.CopyTo(ms);
        Assert.Equal("ISO9660你好", Encoding.UTF8.GetString(ms.ToArray()));
        Assert.Equal(13, ms.Length);
    }

    /// <summary>PVD + 根目录（1 文件 + 1 子目录）+ 子目录（1 文件）+ 文件数据，全部手工布局。</summary>
    private static byte[] BuildMinimalIso()
    {
        var sectors = new Dictionary<int, byte[]>();
        var payload = Encoding.UTF8.GetBytes("ISO9660你好"); // 12 bytes
        var subPayload = Encoding.UTF8.GetBytes("A");

        const int rootLba = 18;
        const int subLba = 19;
        const int fileLba = 20;
        const int subFileLba = 21;

        sectors[fileLba] = payload;
        sectors[subFileLba] = subPayload;

        byte[] MakeRecord(string name, uint lba, uint size, bool isDir)
        {
            var nameBytes = Encoding.ASCII.GetBytes(name.Length == 0 ? "\0" : name);
            var len = 33 + nameBytes.Length + ((nameBytes.Length & 1) == 0 ? 0 : 1);
            var rec = new byte[len];
            rec[0] = (byte)len;
            BinaryPrimitives.WriteUInt32LittleEndian(rec.AsSpan(2), lba);
            BinaryPrimitives.WriteUInt32BigEndian(rec.AsSpan(6), lba);
            BinaryPrimitives.WriteUInt32LittleEndian(rec.AsSpan(10), size);
            BinaryPrimitives.WriteUInt32BigEndian(rec.AsSpan(14), size);
            // 时间 7 字节（18..24）
            rec[25] = isDir ? (byte)0x02 : (byte)0x00;
            rec[28] = 1; // LE 顺序
            rec[30] = 1;
            rec[32] = (byte)nameBytes.Length;
            Buffer.BlockCopy(nameBytes, 0, rec, 33, nameBytes.Length);
            return rec;
        }

        byte[] MakeDirSector(params byte[][] records)
        {
            var sector = new byte[2048];
            var pos = 0;
            foreach (var rec in records)
            {
                Buffer.BlockCopy(rec, 0, sector, pos, rec.Length);
                pos += rec.Length;
            }

            return sector;
        }

        var rootRec = MakeRecord("\0", rootLba, 2048, isDir: true);
        var subRec = MakeRecord("\0", subLba, 2048, isDir: true);
        sectors[rootLba] = MakeDirSector(
            rootRec,
            rootRec,
            MakeRecord("HELLO.TXT;1", fileLba, (uint)payload.Length, isDir: false),
            MakeRecord("SUB", subLba, 2048, isDir: true));
        sectors[subLba] = MakeDirSector(
            subRec,
            subRec,
            MakeRecord("A.TXT;1", subFileLba, (uint)subPayload.Length, isDir: false));

        // PVD（LBA 16）
        var pvd = new byte[2048];
        pvd[0] = 1;
        "CD001"u8.CopyTo(pvd.AsSpan(1));
        "GZ"u8.CopyTo(pvd.AsSpan(8));
        "MINI"u8.CopyTo(pvd.AsSpan(40));
        BinaryPrimitives.WriteUInt32LittleEndian(pvd.AsSpan(80), 22); // 卷扇区数
        BinaryPrimitives.WriteUInt32BigEndian(pvd.AsSpan(84), 22);
        Buffer.BlockCopy(rootRec, 0, pvd, 156, rootRec.Length);
        // 卷序列号 + 卷集大小
        BinaryPrimitives.WriteUInt16LittleEndian(pvd.AsSpan(124), 1);
        BinaryPrimitives.WriteUInt16LittleEndian(pvd.AsSpan(126), 1);
        sectors[16] = pvd;

        // 终结符（LBA 17）
        var term = new byte[2048];
        term[0] = 255;
        "CD001"u8.CopyTo(term.AsSpan(1));
        sectors[17] = term;

        var ms = new MemoryStream();
        for (var lba = 0; lba <= 21; lba++)
        {
            ms.Write(sectors.TryGetValue(lba, out var sector) ? sector : new byte[2048]);
        }

        return ms.ToArray();
    }

    // ---------- CAB ----------

    [Fact]
    public void Cab_Stored_Roundtrip()
    {
        var cab = BuildStoredCab();
        var path = Path.Combine(_dir, "a.cab");
        File.WriteAllBytes(path, cab);

        Assert.Equal("CAB", GeneralZip.DetectFormat(path)?.Name);

        using var r = GeneralZipReader.Open(path);
        Assert.Equal(2, r.Entries.Count);

        using var s = r.OpenEntryStream(r.Entries[0]);
        using var ms = new MemoryStream();
        s.CopyTo(ms);
        Assert.Equal("CAB stored data", Encoding.UTF8.GetString(ms.ToArray()));

        using var s2 = r.OpenEntryStream(r.Entries[1]);
        using var ms2 = new MemoryStream();
        s2.CopyTo(ms2);
        Assert.Equal(300, ms2.Length);
    }

    private static byte[] BuildStoredCab()
    {
        var data1 = Encoding.ASCII.GetBytes("CAB stored data");
        var data2 = new byte[300];
        new Random(7).NextBytes(data2);

        var folderData = new MemoryStream();
        folderData.Write(data1);
        folderData.Write(data2);
        var folderBytes = folderData.ToArray();

        // CFFILE 区大小：cbFile + uoffFolderStart + iFolder + date/time/attrs + name + NUL
        var fileArea =
            (4 + 4 + 2 + 2 + 2 + 2 + ("FIRST.TXT".Length + 1)) +
            (4 + 4 + 2 + 2 + 2 + 2 + ("SECOND.BIN".Length + 1));

        var headerSize = 36;
        var folderStart = headerSize;                    // CFFOLDER 紧随 header
        var coffFiles = folderStart + 8;                 // CFFOLDER 8 字节
        var folderDataStart = coffFiles + fileArea;      // CFDATA 区

        using var ms = new MemoryStream();
        // CFHEADER（36 字节）
        ms.Write("MSCF"u8);
        ms.Write(BitConverter.GetBytes(0u));                       // reserved1
        ms.Write(BitConverter.GetBytes((uint)(folderDataStart + 12 + folderBytes.Length))); // cbCabinet
        ms.Write(BitConverter.GetBytes(0u));                       // reserved2
        ms.Write(BitConverter.GetBytes((uint)coffFiles));
        ms.Write(BitConverter.GetBytes(0u));                       // reserved3
        ms.WriteByte(1);                                           // verMinor
        ms.WriteByte(3);                                           // verMajor
        ms.Write(BitConverter.GetBytes((ushort)1));                // cFolders
        ms.Write(BitConverter.GetBytes((ushort)2));                // cFiles
        ms.Write(BitConverter.GetBytes((ushort)0));                // flags
        ms.Write(BitConverter.GetBytes((ushort)0x1234));           // setID
        ms.Write(BitConverter.GetBytes((ushort)0));                // iCab
        Assert.Equal(headerSize, ms.Length);

        // CFFOLDER（8 字节）
        ms.Write(BitConverter.GetBytes((uint)folderDataStart));    // coffCabStart
        ms.Write(BitConverter.GetBytes((ushort)1));                // cCFData
        ms.Write(BitConverter.GetBytes((ushort)0));                // typeCompress = NONE
        Assert.Equal(folderStart + 8, ms.Length);

        // CFFILE × 2
        void WriteFile(string name, uint size)
        {
            ms.Write(BitConverter.GetBytes(size));                 // cbFile
            ms.Write(BitConverter.GetBytes((uint)(name == "SECOND.BIN" ? data1.Length : 0))); // uoffFolderStart
            ms.Write(BitConverter.GetBytes((ushort)0));            // ufoldIdx
            ms.Write(BitConverter.GetBytes((ushort)0));            // date
            ms.Write(BitConverter.GetBytes((ushort)0));            // time
            ms.Write(BitConverter.GetBytes((ushort)0x20));         // attribs
            ms.Write(Encoding.ASCII.GetBytes(name + " "));
        }

        WriteFile("FIRST.TXT", (uint)data1.Length);
        WriteFile("SECOND.BIN", (uint)data2.Length);
        Assert.Equal(folderDataStart, ms.Length);

        // CFDATA × 1（NONE：块长 == 原长）
        ms.Write(BitConverter.GetBytes(0u));                       // checksum（读取器不校验）
        ms.Write(BitConverter.GetBytes((ushort)folderBytes.Length));
        ms.Write(BitConverter.GetBytes((ushort)folderBytes.Length));
        ms.Write(folderBytes);
        Assert.Equal(folderDataStart + 8 + folderBytes.Length, ms.Length);

        return ms.ToArray();
    }

    // ---------- ZIP 分卷 ----------

    [Fact]
    public void SplitVolume_WriteReadRoundtrip()
    {
        var basePath = Path.Combine(_dir, "split.zip");
        var payload1 = new byte[3000];
        var payload2 = new byte[5000];
        new Random(3).NextBytes(payload1);
        new Random(4).NextBytes(payload2);

        using (var w = GeneralZipWriter.CreateNew(basePath, o => o.VolumeSize = 1024))
        {
            w.AddStream("a.bin", new MemoryStream(payload1), payload1.Length);
            w.AddStream("b.bin", new MemoryStream(payload2), payload2.Length);
            w.Finish();
        }

        Assert.True(File.Exists(basePath + ".001"));
        Assert.True(File.Exists(basePath + ".002"));
        Assert.True(File.Exists(basePath + ".003"));
        Assert.False(File.Exists(basePath)); // 纯分卷：无单文件产物

        Assert.Equal("ZIP", GeneralZip.DetectFormat(basePath + ".001")?.Name);

        using var r = GeneralZipReader.Open(basePath + ".001");
        Assert.Equal(2, r.Entries.Count);

        using (var s = r.OpenEntryStream(r.Entries[0]))
        using (var ms = new MemoryStream())
        {
            s.CopyTo(ms);
            Assert.Equal(payload1, ms.ToArray());
        }

        using (var s = r.OpenEntryStream(r.Entries[1]))
        using (var ms = new MemoryStream())
        {
            s.CopyTo(ms);
            Assert.Equal(payload2, ms.ToArray());
        }
    }

    [Fact]
    public void SplitVolume_TestAll()
    {
        var basePath = Path.Combine(_dir, "t.zip");
        using (var w = GeneralZipWriter.CreateNew(basePath, o => o.VolumeSize = 512))
        {
            w.AddStream("x.bin", new MemoryStream(new byte[1500]), 1500);
            w.Finish();
        }

        var result = GeneralZip.Test(basePath + ".001");
        Assert.True(result.Success);
        Assert.Equal(1, result.ProcessedCount);
    }
}
