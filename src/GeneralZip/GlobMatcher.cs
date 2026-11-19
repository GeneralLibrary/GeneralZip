using System;
using System.Collections.Generic;

namespace GeneralZip;

/// <summary>
/// 极简 glob 匹配器（用于条目过滤）。
/// 语法：<c>*</c> 匹配单层内任意字符（不跨 '/'）；<c>**</c> 跨目录层；<c>?</c> 匹配单个非 '/' 字符；
/// <c>[abc]</c>/<c>[a-z]</c> 字符类；其余字面匹配。大小写不敏感（Windows 习惯）。
/// </summary>
public static class GlobMatcher
{
    public static bool Matches(string path, IReadOnlyList<string>? includePatterns, IReadOnlyList<string>? excludePatterns)
    {
        if (includePatterns != null && includePatterns.Count > 0)
        {
            var included = false;
            foreach (var pattern in includePatterns)
            {
                if (IsMatch(path, pattern))
                {
                    included = true;
                    break;
                }
            }

            if (!included)
            {
                return false;
            }
        }

        if (excludePatterns != null)
        {
            foreach (var pattern in excludePatterns)
            {
                if (IsMatch(path, pattern))
                {
                    return false;
                }
            }
        }

        return true;
    }

    public static bool IsMatch(string path, string pattern)
    {
        if (path == null) throw new ArgumentNullException(nameof(path));
        if (pattern == null) throw new ArgumentNullException(nameof(pattern));

        return MatchHere(path, 0, pattern, 0);
    }

    private static bool MatchHere(string text, int t, string pattern, int p)
    {
        while (p < pattern.Length)
        {
            var c = pattern[p];
            if (c == '*')
            {
                // "**" 跨目录层
                if (p + 1 < pattern.Length && pattern[p + 1] == '*')
                {
                    var pp = p + 2;
                    // 收敛 "**/"：可匹配零层（"a/**/b" 中 "a/b"）或任意多层
                    if (pp < pattern.Length && pattern[pp] == '/')
                    {
                        if (MatchHere(text, t, pattern, pp + 1))
                        {
                            return true;
                        }

                        // 只允许在 '/' 边界切层
                        for (var i = t + 1; i <= text.Length; i++)
                        {
                            if (text[i - 1] != '/')
                            {
                                continue;
                            }

                            if (MatchHere(text, i, pattern, pp + 1))
                            {
                                return true;
                            }
                        }

                        return false;
                    }

                    // 结尾或裸 "**"：任意后缀
                    for (var i = t; i <= text.Length; i++)
                    {
                        if (MatchHere(text, i, pattern, pp))
                        {
                            return true;
                        }
                    }

                    return false;
                }

                // 单星：不跨 '/'
                for (var i = t; i <= text.Length; i++)
                {
                    if (MatchHere(text, i, pattern, p + 1))
                    {
                        return true;
                    }

                    if (i >= text.Length || text[i] == '/')
                    {
                        break;
                    }
                }

                return false;
            }

            if (t >= text.Length)
            {
                return false;
            }

            switch (c)
            {
                case '?':
                    if (text[t] == '/')
                    {
                        return false;
                    }

                    t++;
                    p++;
                    break;
                case '[':
                    var (matched, next) = MatchClass(pattern, p, text[t]);
                    if (!matched)
                    {
                        return false;
                    }

                    t++;
                    p = next;
                    break;
                default:
                    if (!EqualsIgnoreCase(c, text[t]))
                    {
                        return false;
                    }

                    t++;
                    p++;
                    break;
            }
        }

        return t == text.Length;
    }

    private static bool EqualsIgnoreCase(char a, char b) =>
        char.ToLowerInvariant(a) == char.ToLowerInvariant(b);

    /// <summary>匹配字符类；返回 (是否匹配, 模式中 ']' 之后的下标)。</summary>
    private static (bool matched, int next) MatchClass(string pattern, int start, char input)
    {
        var p = start + 1;
        var negate = p < pattern.Length && (pattern[p] == '!' || pattern[p] == '^');
        if (negate)
        {
            p++;
        }

        var matched = false;
        var first = true;
        while (p < pattern.Length && (pattern[p] != ']' || first))
        {
            first = false;
            if (p + 2 < pattern.Length && pattern[p + 1] == '-' && pattern[p + 2] != ']')
            {
                var lo = char.ToLowerInvariant(pattern[p]);
                var hi = char.ToLowerInvariant(pattern[p + 2]);
                var c = char.ToLowerInvariant(input);
                if (lo <= c && c <= hi)
                {
                    matched = true;
                }

                p += 3;
            }
            else
            {
                if (EqualsIgnoreCase(pattern[p], input))
                {
                    matched = true;
                }

                p++;
            }
        }

        // 未闭合的 '[' 按字面处理
        if (p >= pattern.Length)
        {
            return (input == '[', start + 1);
        }

        return (matched != negate, p + 1);
    }
}
