using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Diagnosers;
using BenchmarkDotNet.Running;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace JsonWebToken.Performance
{
    [MemoryDiagnoser]
    public class ArrayEqual
    {
        [Benchmark(Baseline = true)]
        public void AreEqual_Small()
        {
            AreEqual(s_bytesA, s_bytesA);
        }

        [Benchmark]
        public void AreEqual_Optimized_Small()
        {
            AreEqual_Optimized(s_bytesA, s_bytesA);
        }

        [Benchmark]
        public void SequenceEqual_Small()
        {
            SequenceEqual(ref MemoryMarshal.GetReference(s_bytesA.AsSpan()), ref MemoryMarshal.GetReference(s_bytesA.AsSpan()), s_bytesA.Length);
        }

        [Benchmark]
        public void SequenceEqual_Optimized_Small()
        {
            SequenceEqual_Optimized(ref MemoryMarshal.GetReference(s_bytesA.AsSpan()), ref MemoryMarshal.GetReference(s_bytesA.AsSpan()), s_bytesA.Length);
        }
        
        private static readonly byte[] s_bytesA = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 };
        private static readonly byte[] s_bytesB = new byte[] { 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 };

        [MethodImpl(MethodImplOptions.NoOptimization | MethodImplOptions.NoInlining)]
        private static bool AreEqual(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
        {
            ReadOnlySpan<byte> first, second;

            if (((a == null) || (b == null)) || (a.Length != b.Length))
            {
                first = s_bytesA;
                second = s_bytesB;
            }
            else
            {
                first = a;
                second = b;
            }

            int result = 0;
            for (int i = 0; i < first.Length; i++)
            {
                result |= first[i] ^ second[i];
            }

            return result == 0;
        }
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static bool AreEqual_Optimized(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
        {
            ReadOnlySpan<byte> first, second;

            if (((a == null) || (b == null)) || (a.Length != b.Length))
            {
                first = s_bytesA;
                second = s_bytesB;
            }
            else
            {
                first = a;
                second = b;
            }

            int result = 0;
            for (int i = 0; i < first.Length; i++)
            {
                result |= first[i] ^ second[i];
            }

            return result == 0;
        }

        [MethodImpl(MethodImplOptions.NoOptimization | MethodImplOptions.NoInlining)]
        private static unsafe bool SequenceEqual(ref byte first, ref byte second, int length)
        {
            IntPtr i = (IntPtr)0; // Use IntPtr for arithmetic to avoid unnecessary 64->32->64 truncations
            IntPtr n = (IntPtr)(void*)length;

#if !netstandard11
            if (Vector.IsHardwareAccelerated && (byte*)n >= (byte*)Vector<byte>.Count)
            {
                Vector<byte> equals = Vector<byte>.Zero;
                n -= Vector<byte>.Count;
                while ((byte*)n > (byte*)i)
                {
                    equals |= (Unsafe.ReadUnaligned<Vector<byte>>(ref Unsafe.AddByteOffset(ref first, i)) ^ Unsafe.ReadUnaligned<Vector<byte>>(ref Unsafe.AddByteOffset(ref second, i)));
                    i += Vector<byte>.Count;
                }

                equals |= Unsafe.ReadUnaligned<Vector<byte>>(ref Unsafe.AddByteOffset(ref first, n)) ^ Unsafe.ReadUnaligned<Vector<byte>>(ref Unsafe.AddByteOffset(ref second, n));
                return equals == Vector<byte>.Zero;
            }
#endif

            if ((byte*)n >= (byte*)sizeof(UIntPtr))
            {
                bool equals = true;
                n -= sizeof(UIntPtr);
                while ((byte*)n > (byte*)i)
                {
                    equals &= Unsafe.ReadUnaligned<UIntPtr>(ref Unsafe.AddByteOffset(ref first, i)) == Unsafe.ReadUnaligned<UIntPtr>(ref Unsafe.AddByteOffset(ref second, i));
                    i += sizeof(UIntPtr);
                }

                return equals & Unsafe.ReadUnaligned<UIntPtr>(ref Unsafe.AddByteOffset(ref first, n)) == Unsafe.ReadUnaligned<UIntPtr>(ref Unsafe.AddByteOffset(ref second, n));
            }

            int result = 0;
            while ((byte*)n > (byte*)i)
            {
                result |= Unsafe.AddByteOffset(ref first, i) ^ Unsafe.AddByteOffset(ref second, i);
                i += 1;
            }

            return result == 0;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static unsafe bool SequenceEqual_Optimized(ref byte first, ref byte second, int length)
        {
            IntPtr i = (IntPtr)0; // Use IntPtr for arithmetic to avoid unnecessary 64->32->64 truncations
            IntPtr n = (IntPtr)(void*)length;

#if !netstandard11
            if (Vector.IsHardwareAccelerated && (byte*)n >= (byte*)Vector<byte>.Count)
            {
                Vector<byte> equals = Vector<byte>.Zero;
                n -= Vector<byte>.Count;
                while ((byte*)n > (byte*)i)
                {
                    equals |= (Unsafe.ReadUnaligned<Vector<byte>>(ref Unsafe.AddByteOffset(ref first, i)) ^ Unsafe.ReadUnaligned<Vector<byte>>(ref Unsafe.AddByteOffset(ref second, i)));
                    i += Vector<byte>.Count;
                }

                equals |= Unsafe.ReadUnaligned<Vector<byte>>(ref Unsafe.AddByteOffset(ref first, n)) ^ Unsafe.ReadUnaligned<Vector<byte>>(ref Unsafe.AddByteOffset(ref second, n));
                return equals == Vector<byte>.Zero;
            }
#endif

            if ((byte*)n >= (byte*)sizeof(UIntPtr))
            {
                bool equals = true;
                n -= sizeof(UIntPtr);
                while ((byte*)n > (byte*)i)
                {
                    equals &= Unsafe.ReadUnaligned<UIntPtr>(ref Unsafe.AddByteOffset(ref first, i)) == Unsafe.ReadUnaligned<UIntPtr>(ref Unsafe.AddByteOffset(ref second, i));
                    i += sizeof(UIntPtr);
                }

                return equals & Unsafe.ReadUnaligned<UIntPtr>(ref Unsafe.AddByteOffset(ref first, n)) == Unsafe.ReadUnaligned<UIntPtr>(ref Unsafe.AddByteOffset(ref second, n));
            }

            int result = 0;
            while ((byte*)n > (byte*)i)
            {
                result |= Unsafe.AddByteOffset(ref first, i) ^ Unsafe.AddByteOffset(ref second, i);
                i += 1;
            }

            return result == 0;
        }
    }
}
