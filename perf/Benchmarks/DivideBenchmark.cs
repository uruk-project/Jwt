using System;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Diagnosers;

namespace JsonWebToken.Performance
{
    [MemoryDiagnoser]
    public class DivideBenchmark
    {
        internal static readonly long UnixEpochTicks = 621355968000000000;

        [Benchmark(Baseline = true)]
        public long Divide()
        {
            return (DateTime.UtcNow.Ticks - UnixEpochTicks) / 10000000;
        }

        [Benchmark]
        public long Multiply()
        {
            return (long)((DateTime.UtcNow.Ticks - UnixEpochTicks) * 1E-07);
        }

    }
}
