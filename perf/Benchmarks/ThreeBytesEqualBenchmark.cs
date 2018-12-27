#if NETCOREAPP3_0
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Diagnosers;
using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace JsonWebToken.Performance
{
    [MemoryDiagnoser]
    public class ThreeBytesEqualBenchmark
    {
        private readonly byte[] equal = { 10, 20, 30 };
        private readonly byte[] notEqual = new byte[3];
        private readonly byte[] bigger = new byte[4];

        private readonly byte[] valueSpan;

        public ThreeBytesEqualBenchmark()
        {
            valueSpan = new byte[] { 10, 20, 30 };
            using (var rnd = RandomNumberGenerator.Create())
            {
                rnd.GetNonZeroBytes(notEqual);
                rnd.GetNonZeroBytes(bigger);
            }
        }

        [Benchmark(Baseline = true)]
        public void Equals()
        {
            valueSpan.AsSpan().SequenceEqual(equal);
        }

        [Benchmark]
        public void Equals1()
        {
            ThreeBytesEqual(ref MemoryMarshal.GetReference(valueSpan.AsSpan()), ref equal[0], valueSpan.Length);
        }

        [Benchmark]
        public void Equals2()
        {
            ThreeBytesEqual2(ref MemoryMarshal.GetReference(valueSpan.AsSpan()), ref equal[0], valueSpan.Length); 
        }

        [Benchmark]
        public void Equals3()
        {
            ThreeBytesEqual3(ref MemoryMarshal.GetReference(valueSpan.AsSpan()), ref equal[0], valueSpan.Length);
        }

        [Benchmark]
        public void Equals4()
        {
            ThreeBytesEqual4(ref MemoryMarshal.GetReference(valueSpan.AsSpan()), ref equal[0], valueSpan.Length);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
        private static bool ThreeBytesEqual(ref byte first, ref byte second, int length)
        {
            if (length != 3)
            {
                goto NotEqual;
            }

            if (!first.Equals(second))
            {
                goto NotEqual;
            }

            if (!Unsafe.Add(ref first, 1).Equals(Unsafe.Add(ref second, 1)))
            {
                goto NotEqual;
            }

            if (!Unsafe.Add(ref first, 2).Equals(Unsafe.Add(ref second, 2)))
            {
                goto NotEqual;
            }

            return true;

            NotEqual: // Workaround for https://github.com/dotnet/coreclr/issues/13549
            return false;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
        private static bool ThreeBytesEqual4(ref byte first, ref byte second, int length)
        {
            if (length != 3)
            {
                goto NotEqual;
            }

            if (!first != second)
            {
                goto NotEqual;
            }

            if (Unsafe.Add(ref first, 1) != (Unsafe.Add(ref second, 1)))
            {
                goto NotEqual;
            }

            if (Unsafe.Add(ref first, 2) != (Unsafe.Add(ref second, 2)))
            {
                goto NotEqual;
            }

            return true;

            NotEqual: // Workaround for https://github.com/dotnet/coreclr/issues/13549
            return false;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
        private static bool ThreeBytesEqual2(ref byte first, ref byte second, int length)
        {
            if (length != 3)
            {
                goto NotEqual;
            }

            return ((uint)first << 16 | (uint)Unsafe.Add(ref first, 1) << 8 | Unsafe.Add(ref first, 2))
                == ((uint)second << 16 | (uint)Unsafe.Add(ref second, 1) << 8 | Unsafe.Add(ref second, 2));

            NotEqual: // Workaround for https://github.com/dotnet/coreclr/issues/13549
            return false;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
        private static bool ThreeBytesEqual3(ref byte first, ref byte second, int length)
        {
            if (length != 3)
            {
                goto NotEqual;
            }


            if (((uint)first << 8 | (uint)Unsafe.Add(ref first, 1) << 8)
                != ((uint)second << 16 | (uint)Unsafe.Add(ref second, 1) << 8))
            {
                goto NotEqual;
            }

            return Unsafe.Add(ref first, 2).Equals(Unsafe.Add(ref second, 2));

            NotEqual: // Workaround for https://github.com/dotnet/coreclr/issues/13549
            return false;
        }
    }
}
#endif