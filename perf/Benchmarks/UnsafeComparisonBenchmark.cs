using BenchmarkDotNet.Attributes;
using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Text;

namespace JsonWebToken.Performance
{
    public unsafe class UnsafeComparisonBenchmark
    {
        [Benchmark(Baseline = true)]
        [ArgumentsSource(nameof(GetData))]

        public uint X(Byte[] v)
        {
            fixed (byte* pValue = v)
            {
                if (*pValue == (byte)'D' && *(ushort*)(pValue + 1) == 17989u)
                {
                    return 12;
                }
            }

            return 0;
        }

        [Benchmark]
        [ArgumentsSource(nameof(GetData))]
        public uint Y(Byte[] v)
        {
            fixed (byte* pValue = v)
            {
                if ((*((uint*)pValue) & 0x00ffffff) == 4605252u)
                {
                    return 12;
                }
            }

            return 0;
        }

        [Benchmark]
        [ArgumentsSource(nameof(GetData))]
        public uint Z(Byte[] v)
        {
            if ((Unsafe.As<byte, uint>(ref v[0]) & 0x00ffffff) == 4605252u)
            {
                return 12;
            }

            return 0;
        }

        public IEnumerable<byte[]> GetData()
        {
            yield return Encoding.UTF8.GetBytes("DEF\0");
            yield return Encoding.UTF8.GetBytes("DEF");
            yield return Encoding.UTF8.GetBytes("FAKE");
        }
    }
}
