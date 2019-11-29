using BenchmarkDotNet.Attributes;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace JsonWebToken.Performance
{
    [MemoryDiagnoser]
    public class Sha256Benchmarks
    {
        private static readonly SHA256 _clrSha256 = SHA256.Create();
        private static readonly Sha256 _sha256 = new Sha256();
        private readonly byte[] _buffer = new byte[32];

        [Benchmark(Baseline = false)]
        [ArgumentsSource(nameof(GetData))]
        public byte[] Sha256_Clr(byte[] value)
        {
            return _clrSha256.ComputeHash(value);
        }

        [Benchmark(Baseline = true)]
        [ArgumentsSource(nameof(GetData))]
        public byte[] Sha256_Optimized(byte[] value)
        {
            _sha256.ComputeHash(value, _buffer);
            return _buffer;
        }

        private static readonly uint[] W = new uint[64];

        [Benchmark(Baseline = false)]
        [ArgumentsSource(nameof(GetData))]
        public byte[] Sha256_Optimized2(byte[] value)
        {
            _sha256.ComputeHash(value, _buffer, default, W);
            return _buffer;
        }

        public static IEnumerable<byte[]> GetData()
        {
            yield return Encoding.UTF8.GetBytes("abc");
            //yield return Encoding.UTF8.GetBytes("abcdefghijklmnopqrstuvwxyz0123456abcdefghijklmnopqrstuvwxyz0123456abcdefghijklmnopqrstuvwxyz0123456abcdefghijklmnopqrstuvwxyz0123456abcdefghijklmnopqrstuvwxyz0123456abcdefghijklmnopqrstuvwxyz0123456abcdefghijklmnopqrstuvwxyz0123456abcdefghijklmnopqrstuvwxyz0123456abcdefghijklmnopqrstuvwxyz0123456abcdefghijklmnopqrstuvwxyz0123456abcdefghijklmnopqrstuvwxyz0123456abcdefghijklmnopqrstuvwxyz0123456abcdefghijklmnopqrstuvwxyz0123456abcdefghijklmnopqrstuvwxyz0123456abcdefghijklmnopqrstuvwxyz0123456abcdefghijklmnopqrstuvwxyz0123456");
            yield return Encoding.UTF8.GetBytes("abcdefghijklmnopqrstuvwxyz01234567890123456789012345678901234567abcdefghijklmnopqrstuvwxyz01234567890123456789012345678901234567abcdefghijklmnopqrstuvwxyz012345678abcdefghijklmnopqrstuvwxyz01234567890123456789012345678901234567abcdefghijklmnopqrstuvwxyz01234567890123456789012345678901234567abcdefghijklmnopqrstuvwxyz01234567890123456789012345678901234567abcdefghijklmnopqrstuvwxyz01234567890123456789012345678901234567abcdefghijklmnopqrstuvwxyz01234567890123456789012345678901234567abcdefghijklmnopqrstuvwxyz01234567890123456789012345678901234567abcdefghijklmnopqrstuvwxyz01234567890123456789012345678901234567abcdefghijklmnopqrstuvwxyz01234567890123456789012345678901234567abcdefghijklmnopqrstuvwxyz01234567890123456789012345678901234567abcdefghijklmnopqrstuvwxyz01234567890123456789012345678901234567abcdefghijklmnopqrstuvwxyz01234567890123456789012345678901234567abcdefghijklmnopqrstuvwxyz0123456789012345678901234567890123456790123456789012345678901234567abcdefghijklmnopqrstuvwxyz01234567890123456789012345678901234567abcdefghijklmnopqrstuvwxyz01234567890123456789012345678901234567abcdefghijklmnopqrstuvwxyz01234567890123456789012345678901234567abcdefghijklmnopqrstuvwxyz012345678abcdefghijklmnopqrstuvwxyz01234567890123456789012345678901234567abcdefghijklmnopqrstuvwxyz01234567890123456789012345678901234567abcdefghijklmnopqrstuvwxyz01234567890123456789012345678901234567abcdefghijklmnopqrstuvwxyz01234567890123456789012345678901234567abcdefghijklmnopqrstuvwxyz01234567890123456789012345678901234567abcdefghijklmnopqrstuvwxyz01234567890123456789012345678901234567abcdefghijklmnopqrstuvwxyz01234567890123456789012345678901234567abcdefghijklmnopqrstuvwxyz01234567890123456789012345678901234567abcdefghijklmnopqrstuvwxyz01234567890123456789012345678901234567abcdefghijklmnopqrstuvwxyz01234567890123456789012345678901234567abcdefghijklmnopqrstuvwxyz01234567890123456789012345678901234567abcdefghijklmnopqrstuvwxyz0123456789012345678901234567890123456790123456789012345678901234567abcdefghijklmnopqrstuvwxyz01234567890123456789012345678901234567");
            //yield return Encoding.UTF8.GetBytes("abcdefghijklmnopqrstuvwxyz01234567890123456789012345678901234567");
            //yield return Encoding.UTF8.GetBytes(Enumerable.Repeat("abcdefghijklmnopqrstuvwxyz01234567890123456789012345678901234567", 16).Aggregate(new StringBuilder(), (sb, x) => sb.Append(x), sb => sb.ToString()));
            //yield return Encoding.UTF8.GetBytes(Enumerable.Repeat("abcdefghijklmnopqrstuvwxyz01234567890123456789012345678901234567", 16384).Aggregate(new StringBuilder(), (sb, x) => sb.Append(x), sb => sb.ToString()));
            //var data = new byte[1000000];
            //Array.Fill<byte>(data, 0);
            //yield return data;
        }
    }
}
