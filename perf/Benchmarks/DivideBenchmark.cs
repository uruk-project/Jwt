using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Diagnosers;
#if NETCOREAPP3_0
using System.Runtime.Intrinsics.X86;
#endif

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
    [MemoryDiagnoser]
    public class DivideBy3Benchmark
    {
        internal static readonly long UnixEpochTicks = 621355968000000000;

        [Benchmark(Baseline = true)]
        [Arguments(92)]
        public long Divide(int value)
        {
            return value / 3;
        }

        [Benchmark]
        [Arguments(92)]
        public int Fast(int value)
        {
            return (int)FastDiv3(value);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint FastDiv3(int value)
        {
            return (uint)((0xAAAAAAABUL * (uint)value) >> 33);
        }
    }

    [MemoryDiagnoser]
    public class ModuloBenchmark
    {
        [Benchmark(Baseline = true)]
        [Arguments(621355968)]
        [Arguments(621355967)]
        [Arguments(621355966)]
        public int Slow(int length)
        {
            return (((length + 2) / 3) << 2) - GetNumBase64PaddingCharsAddedByEncode_Slow(length);
        }

        [Benchmark]
        [Arguments(621355968)]
        [Arguments(621355967)]
        [Arguments(621355966)]
        public int Fast(int length)
        {
            return (((length + 2) / 3) << 2) - GetNumBase64PaddingCharsAddedByEncode_Fast(length);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static int GetNumBase64PaddingCharsAddedByEncode_Slow(int dataLength)
        {
            // Calculation is:
            // 0 -> 0
            // 1 -> 2
            // 2 -> 1
            int modulo = dataLength % 3;
            return modulo == 0 ? 0 : 3 - modulo;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static int GetNumBase64PaddingCharsAddedByEncode_Fast(int dataLength)
        {
            // Calculation is:
            // 0 -> 0
            // 1 -> 2
            // 2 -> 1
            uint modulo = FastMod((uint)dataLength, 3, 6148914691236517206);
            return (int)(modulo == 0 ? 0 : 3 - modulo);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static uint FastMod(uint value, uint divisor, ulong multiplier)
        {
            // Using fastmod from Daniel Lemire https://lemire.me/blog/2019/02/08/faster-remainders-when-the-divisor-is-a-constant-beating-compilers-and-libdivide/

            ulong lowbits = multiplier * value;
            uint high;
#if NETCOREAPP3_0
            if (Bmi2.X64.IsSupported)
            {
                high = (uint)Bmi2.X64.MultiplyNoFlags(lowbits, divisor);
            }
            else
#endif
            {
                // 64bit * 64bit => 128bit isn't currently supported by Math https://github.com/dotnet/corefx/issues/41822
                // otherwise we'd want this to be (uint)Math.MultiplyHigh(lowbits, divisor)
                high = (uint)((((ulong)(uint)lowbits * divisor >> 32) + (lowbits >> 32) * divisor) >> 32);
            }

            // TEST Debug.Assert(high == value % divisor);
            return high;
        }
    }
}
