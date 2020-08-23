using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Diagnosers;

namespace JsonWebToken.Performance
{
    [MemoryDiagnoser]
    public class InitStateBenchmark
    {
        [Benchmark(Baseline = true)]
        public void InitUint32_Original()
        {
            Span<uint> state = stackalloc uint[] {
                0x6a09e667u,
                0xbb67ae85u,
                0x3c6ef372u,
                0xa54ff53au,
                0x510e527fu,
                0x9b05688cu,
                0x1f83d9abu,
                0x5be0cd19u
            };
        }

        [Benchmark]
        public void InitUint32_UnsafeCopyBlock()
        {
            Span<uint> state = stackalloc uint[8];
            Unsafe.CopyBlock(ref MemoryMarshal.GetReference(MemoryMarshal.AsBytes(state)), ref MemoryMarshal.GetReference(InitState), 32);
        }

        [Benchmark]
        public void InitUint32_UnsafeCopyBlockUnaligned()
        {
            Span<uint> state = stackalloc uint[8];
            Unsafe.CopyBlockUnaligned(ref MemoryMarshal.GetReference(MemoryMarshal.AsBytes(state)), ref MemoryMarshal.GetReference(InitState), 32);
        }

        [Benchmark]
        public void InitUint32_SpanCopyTo()
        {
            Span<uint> state = stackalloc uint[8];
            InitState.CopyTo(MemoryMarshal.AsBytes(state));
        }

        [Benchmark]
        public void InitUint64_Original()
        {
            Span<ulong> state = stackalloc ulong[] {
                0x6a09e667f3bcc908ul,
                0xbb67ae8584caa73bul,
                0x3c6ef372fe94f82bul,
                0xa54ff53a5f1d36f1ul,
                0x510e527fade682d1ul,
                0x9b05688c2b3e6c1ful,
                0x1f83d9abfb41bd6bul,
                0x5be0cd19137e2179ul
            };
        }

        [Benchmark]
        public void InitUint64_UnsafeCopyBlockUnaligned()
        {
            Span<ulong> state = stackalloc ulong[8];
            Unsafe.CopyBlockUnaligned(ref MemoryMarshal.GetReference(MemoryMarshal.AsBytes(state)), ref MemoryMarshal.GetReference(InitState2), 64);
        }

        [Benchmark]
        public void InitUint64_UnsafeCopyBlock()
        {
            Span<ulong> state = stackalloc ulong[8];
            Unsafe.CopyBlock(ref MemoryMarshal.GetReference(MemoryMarshal.AsBytes(state)), ref MemoryMarshal.GetReference(InitState2), 64);
        }

        [Benchmark]
        public void InitUint64_SpanCopyTo()
        {
            Span<ulong> state = stackalloc ulong[8];
            InitState.CopyTo(MemoryMarshal.AsBytes(state));
        }

        private static ReadOnlySpan<byte> InitState2 => new byte[64]
        {
            8, 201, 188, 243, 103, 230, 9, 106,
            59, 167, 202, 132, 133, 174, 103, 187,
            43, 248, 148, 254, 114, 243, 110, 60,
            241, 54, 29, 95, 58, 245, 79 , 165,
            209, 130, 230, 173, 127, 82, 14, 81,
            31, 108, 62, 43, 140, 104, 5, 155,
            107, 189, 65, 251, 171, 217, 131, 31,
            121, 33, 126, 19, 25, 205, 224, 91
        };

        private static ReadOnlySpan<byte> InitState => new byte[32]
        {
            103, 230, 9, 106,
            133, 174, 103, 187,
            114, 243, 110, 60,
            58, 245, 79, 165,
            127, 82, 14, 81,
            140, 104, 5, 155,
            171, 217, 131, 31,
            25, 205, 224, 91
        };
    }
}
