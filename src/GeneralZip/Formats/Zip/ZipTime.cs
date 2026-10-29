using System;

namespace GeneralZip.Formats.Zip;

/// <summary>MS-DOS 时间戳与 DateTimeOffset 互转（ZIP 标准精度：2 秒）。</summary>
internal static class ZipTime
{
    public static void ToDos(DateTimeOffset value, out uint dosTime, out uint dosDate)
    {
        var local = value.LocalDateTime;
        if (local.Year < 1980)
        {
            dosTime = 0;
            dosDate = (1 << 5) | 1; // 1980-01-01
            return;
        }

        dosDate = (uint)(((local.Year - 1980) << 9) | (local.Month << 5) | local.Day);
        dosTime = (uint)((local.Hour << 11) | (local.Minute << 5) | (local.Second >> 1));
    }

    public static DateTimeOffset? FromDos(uint dosTime, uint dosDate)
    {
        if (dosDate == 0 && dosTime == 0)
        {
            return null;
        }

        try
        {
            var year = 1980 + (int)(dosDate >> 9);
            var month = (int)((dosDate >> 5) & 0xF);
            var day = (int)(dosDate & 0x1F);
            var hour = (int)(dosTime >> 11);
            var minute = (int)((dosTime >> 5) & 0x3F);
            var second = (int)(dosTime & 0x1F) * 2;

            if (month is < 1 or > 12 || day is < 1 or > 31 || hour > 23 || minute > 59 || second > 59)
            {
                return null;
            }

            return new DateTimeOffset(year, month, day, hour, minute, second, TimeSpan.Zero).ToLocalTime();
        }
        catch (ArgumentOutOfRangeException)
        {
            return null;
        }
    }
}
