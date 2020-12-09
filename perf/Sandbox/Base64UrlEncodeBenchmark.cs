using System.Buffers;
using System.Collections.Generic;
#if NETCOREAPP3_0
#endif
using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Diagnosers;

namespace JsonWebToken.Performance
{
    [MemoryDiagnoser]
    public class Base64UrlEncodeBenchmark
    {
        [ParamsSource(nameof(Values))]
        public EncodingWrapper Data { get; set; } = new EncodingWrapper(new byte[0], new byte[0], 0);

        public static IEnumerable<EncodingWrapper> Values()
        {
            foreach (var size in sizes)
            {
                var d = new byte[size];
                RandomNumberGenerator.Fill(d);
                yield return new EncodingWrapper(d, new byte[Base64Url.GetArraySizeRequiredToEncode(size)], size);
            }
        }

        private static int[] sizes = new[] { 0, 32, 64, 128, 256, 512, 1024, 4096, 16384, 65536 };


        private static readonly OldBase64UrlEncoder _old = new OldBase64UrlEncoder();

        [Benchmark(Baseline = true)]
        public OperationStatus Old()
        {
            return _old.TryEncode(Data.Source, Data.Destination, out _, out _);
        }

        [Benchmark]
        public OperationStatus Gfoidl()
        {
            return gfoidl.Base64.Base64.Url.Encode(Data.Source, Data.Destination, out _, out _);
        }
    }
}
