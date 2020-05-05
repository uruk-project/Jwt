using System;
using System.Collections.Generic;
using System.Globalization;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Diagnosers;

namespace JsonWebToken.Performance
{
    [MemoryDiagnoser]
    public class FixedTimeEqualsBenchmark
    {

        [Benchmark(Baseline = true)]
        [ArgumentsSource(nameof(GetData))]
        public unsafe bool Equals_Current(FixedTimeEqualsBenchmarkItem item)
        {
            return CryptographicOperations.FixedTimeEquals(item.Left, item.Right);
        }

        [Benchmark]
        [ArgumentsSource(nameof(GetData))]
        public bool FixedTimeEquals_And(FixedTimeEqualsBenchmarkItem item)
        {
            return FixedTimeEquals_And(item.Left, item.Right);
        }


        [Benchmark]
        [ArgumentsSource(nameof(GetData))]
        public bool FixedTimeEquals_Minus(FixedTimeEqualsBenchmarkItem item)
        {
            return FixedTimeEquals_Minus(item.Left, item.Right);
        }

        [Benchmark]
        [ArgumentsSource(nameof(GetData))]
        public bool FixedTimeEquals_Xor(FixedTimeEqualsBenchmarkItem item)
        {
            return FixedTimeEquals_Xor(item.Left, item.Right);
        }

#if !NETCOREAPP2_0
        [Benchmark]
        [ArgumentsSource(nameof(GetData))]
        public bool Equals_FixedTime(FixedTimeEqualsBenchmarkItem item)
        {
            return System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(item.Left, item.Right);
        }
#endif

        public static IEnumerable<FixedTimeEqualsBenchmarkItem> GetData()
        {
            yield return PrepareData(0);
            yield return PrepareData(15);
            yield return PrepareData(64);
            yield return PrepareData(2048);
        }

        private static FixedTimeEqualsBenchmarkItem PrepareData(int length)
        {
            byte[] a = new byte[length];
            byte[] b = new byte[length];
            System.Security.Cryptography.RandomNumberGenerator.Fill(a);
            System.Security.Cryptography.RandomNumberGenerator.Fill(b);

            return  new FixedTimeEqualsBenchmarkItem(a, b);
        }

        public class FixedTimeEqualsBenchmarkItem
        {
            public FixedTimeEqualsBenchmarkItem(byte[] left, byte[] right)
            {
                Left = left;
                Right = right;
            }

            public byte[] Left { get; }
            public byte[] Right { get; }

            public override string ToString()
            {
                return Left.Length.ToString();
            }
        }

        [MethodImpl(MethodImplOptions.NoOptimization | MethodImplOptions.NoInlining)]
        private static unsafe bool AreEqual_Current(ref byte first, ref byte second, int l)
        {
            IntPtr length = (IntPtr)l;
#if !NETSTANDARD2_0 && !NET461 && !NET47 && !NETCOREAPP2_1
            if (Avx2.IsSupported && (byte*)length == (byte*)64)
            {
                return
                    Avx2.MoveMask(Avx2.CompareEqual(Unsafe.ReadUnaligned<Vector256<byte>>(ref first), Unsafe.ReadUnaligned<Vector256<byte>>(ref second))) == unchecked((int)0b1111_1111_1111_1111_1111_1111_1111_1111)
                  & Avx2.MoveMask(Avx2.CompareEqual(Unsafe.ReadUnaligned<Vector256<byte>>(ref Unsafe.AddByteOffset(ref first, (IntPtr)32)), Unsafe.ReadUnaligned<Vector256<byte>>(ref Unsafe.AddByteOffset(ref second, (IntPtr)32)))) == unchecked((int)0b1111_1111_1111_1111_1111_1111_1111_1111);
            }
            else if (Avx2.IsSupported && (byte*)length == (byte*)32)
            {
                return Avx2.MoveMask(Avx2.CompareEqual(Unsafe.ReadUnaligned<Vector256<byte>>(ref first), Unsafe.ReadUnaligned<Vector256<byte>>(ref second))) == unchecked((int)0b1111_1111_1111_1111_1111_1111_1111_1111);
            }
            else if (Sse2.IsSupported && (byte*)length == (byte*)16)
            {
                return Sse2.MoveMask(Sse2.CompareEqual(Unsafe.ReadUnaligned<Vector128<byte>>(ref first), Unsafe.ReadUnaligned<Vector128<byte>>(ref second))) == 0b1111_1111_1111_1111;
            }
            else
#endif
            if (Vector.IsHardwareAccelerated && (byte*)length >= (byte*)Vector<byte>.Count)
            {
                Vector<byte> accumulator = new Vector<byte>();
                IntPtr endOffset = length - sizeof(Vector<byte>);
                ref byte firstEnd = ref Unsafe.AddByteOffset(ref first, endOffset);
                ref byte secondEnd = ref Unsafe.AddByteOffset(ref second, endOffset);
                while (Unsafe.IsAddressLessThan(ref first, ref firstEnd))
                {
                    accumulator |= Unsafe.ReadUnaligned<Vector<byte>>(ref first) - Unsafe.ReadUnaligned<Vector<byte>>(ref second);
                    first = ref Unsafe.AddByteOffset(ref first, (IntPtr)sizeof(Vector<byte>));
                    second = ref Unsafe.AddByteOffset(ref second, (IntPtr)sizeof(Vector<byte>));
                }

                accumulator |= Unsafe.ReadUnaligned<Vector<byte>>(ref firstEnd) - Unsafe.ReadUnaligned<Vector<byte>>(ref secondEnd);
                return accumulator == Vector<byte>.Zero;
            }
            else if ((byte*)length >= (byte*)sizeof(ulong))
            {
                ulong accumulator = 0L;
                IntPtr endOffset = length - sizeof(ulong);
                ref byte firstEnd = ref Unsafe.AddByteOffset(ref first, endOffset);
                ref byte secondEnd = ref Unsafe.AddByteOffset(ref second, endOffset);
                while (Unsafe.IsAddressLessThan(ref first, ref firstEnd))
                {
                    accumulator |= Unsafe.ReadUnaligned<ulong>(ref first) ^ Unsafe.ReadUnaligned<ulong>(ref second);
                    first = ref Unsafe.AddByteOffset(ref first, (IntPtr)sizeof(ulong));
                    second = ref Unsafe.AddByteOffset(ref second, (IntPtr)sizeof(ulong));
                }

                accumulator |= Unsafe.ReadUnaligned<ulong>(ref firstEnd) ^ Unsafe.ReadUnaligned<ulong>(ref secondEnd);
                return accumulator == 0L;
            }
            else
            {
                int accumulator = 0;
                ref byte firstEnd = ref Unsafe.Add(ref first, length);
                while (Unsafe.IsAddressLessThan(ref first, ref firstEnd))
                {
                    accumulator |= first - second;
                    first = ref Unsafe.AddByteOffset(ref first, (IntPtr)1);
                    second = ref Unsafe.AddByteOffset(ref second, (IntPtr)1);
                }

                return accumulator == 0;
            }
        }

        [MethodImpl(MethodImplOptions.NoOptimization | MethodImplOptions.NoInlining)]
        private static unsafe bool AreEqual_Equals(ref byte first, ref byte second, int length)
        {
            IntPtr i = (IntPtr)0; // Use IntPtr for arithmetic to avoid unnecessary 64->32->64 truncations
            IntPtr n = (IntPtr)(void*)length;

            bool equals = true;
            if (Vector.IsHardwareAccelerated && (byte*)n >= (byte*)Vector<byte>.Count)
            {
                n -= Vector<byte>.Count;
                while ((byte*)n > (byte*)i)
                {
                    equals &= (Unsafe.ReadUnaligned<Vector<byte>>(ref Unsafe.AddByteOffset(ref first, i)) == Unsafe.ReadUnaligned<Vector<byte>>(ref Unsafe.AddByteOffset(ref second, i)));
                    i += Vector<byte>.Count;
                }

                return equals & Unsafe.ReadUnaligned<Vector<byte>>(ref Unsafe.AddByteOffset(ref first, n)) == Unsafe.ReadUnaligned<Vector<byte>>(ref Unsafe.AddByteOffset(ref second, n));
            }

            if ((byte*)n >= (byte*)sizeof(UIntPtr))
            {
                n -= sizeof(UIntPtr);
                while ((byte*)n > (byte*)i)
                {
                    equals &= Unsafe.ReadUnaligned<UIntPtr>(ref Unsafe.AddByteOffset(ref first, i)) == Unsafe.ReadUnaligned<UIntPtr>(ref Unsafe.AddByteOffset(ref second, i));
                    i += sizeof(UIntPtr);
                }

                return equals & Unsafe.ReadUnaligned<UIntPtr>(ref Unsafe.AddByteOffset(ref first, n)) == Unsafe.ReadUnaligned<UIntPtr>(ref Unsafe.AddByteOffset(ref second, n));
            }

            while ((byte*)n > (byte*)i)
            {
                equals &= Unsafe.AddByteOffset(ref first, i) == Unsafe.AddByteOffset(ref second, i);
                i += 1;
            }

            return equals;
        }


        [MethodImpl(MethodImplOptions.NoOptimization | MethodImplOptions.NoInlining)]
        private static unsafe bool AreEqual_Minus(ref byte first, ref byte second, int length)
        {
            IntPtr i = (IntPtr)0; // Use IntPtr for arithmetic to avoid unnecessary 64->32->64 truncations
            IntPtr n = (IntPtr)(void*)length;

            if (Vector.IsHardwareAccelerated && (byte*)n >= (byte*)Vector<byte>.Count)
            {
                Vector<byte> equals = Vector<byte>.Zero;
                n -= Vector<byte>.Count;
                while ((byte*)n > (byte*)i)
                {
                    equals |= Unsafe.ReadUnaligned<Vector<byte>>(ref Unsafe.AddByteOffset(ref first, i)) - Unsafe.ReadUnaligned<Vector<byte>>(ref Unsafe.AddByteOffset(ref second, i));
                    i += Vector<byte>.Count;
                }

                equals |= Unsafe.ReadUnaligned<Vector<byte>>(ref Unsafe.AddByteOffset(ref first, n)) - Unsafe.ReadUnaligned<Vector<byte>>(ref Unsafe.AddByteOffset(ref second, n));
                return equals == Vector<byte>.Zero;
            }

            if ((byte*)n >= (byte*)sizeof(ulong))
            {
                ulong equals = 0L;
                n -= sizeof(ulong);
                while ((byte*)n > (byte*)i)
                {
                    equals |= Unsafe.ReadUnaligned<ulong>(ref Unsafe.AddByteOffset(ref first, i)) - Unsafe.ReadUnaligned<ulong>(ref Unsafe.AddByteOffset(ref second, i));
                    i += sizeof(ulong);
                }

                equals |= Unsafe.ReadUnaligned<ulong>(ref Unsafe.AddByteOffset(ref first, n)) - Unsafe.ReadUnaligned<ulong>(ref Unsafe.AddByteOffset(ref second, n));
                return equals == 0L;
            }

            int result = 0;
            while ((byte*)n > (byte*)i)
            {
                result |= Unsafe.AddByteOffset(ref first, i) - Unsafe.AddByteOffset(ref second, i);
                i += 1;
            }

            return result == 0;
        }

        [MethodImpl(MethodImplOptions.NoOptimization | MethodImplOptions.NoInlining)]
        private static unsafe bool AreEqual_Xor(ref byte first, ref byte second, int length)
        {
            IntPtr i = (IntPtr)0; // Use IntPtr for arithmetic to avoid unnecessary 64->32->64 truncations
            IntPtr n = (IntPtr)(void*)length;

            if (Vector.IsHardwareAccelerated && (byte*)n >= (byte*)Vector<byte>.Count)
            {
                Vector<byte> equals = Vector<byte>.Zero;
                n -= Vector<byte>.Count;
                while ((byte*)n > (byte*)i)
                {
                    equals |= Unsafe.ReadUnaligned<Vector<byte>>(ref Unsafe.AddByteOffset(ref first, i)) ^ Unsafe.ReadUnaligned<Vector<byte>>(ref Unsafe.AddByteOffset(ref second, i));
                    i += sizeof(Vector<byte>);
                }

                equals |= Unsafe.ReadUnaligned<Vector<byte>>(ref Unsafe.AddByteOffset(ref first, n)) ^ Unsafe.ReadUnaligned<Vector<byte>>(ref Unsafe.AddByteOffset(ref second, n));
                return equals == Vector<byte>.Zero;
            }

            if ((byte*)n >= (byte*)sizeof(ulong))
            {
                ulong equals = 0L;
                n -= sizeof(ulong);
                while ((byte*)n > (byte*)i)
                {
                    equals |= Unsafe.ReadUnaligned<ulong>(ref Unsafe.AddByteOffset(ref first, i)) ^ Unsafe.ReadUnaligned<ulong>(ref Unsafe.AddByteOffset(ref second, i));
                    i += sizeof(ulong);
                }

                equals |= Unsafe.ReadUnaligned<ulong>(ref Unsafe.AddByteOffset(ref first, n)) ^ Unsafe.ReadUnaligned<ulong>(ref Unsafe.AddByteOffset(ref second, n));
                return equals == 0L;
            }

            int result = 0;
            while ((byte*)n > (byte*)i)
            {
                result |= Unsafe.AddByteOffset(ref first, i) - Unsafe.AddByteOffset(ref second, i);
                i += 1;
            }

            return result == 0;
        }

        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        public static bool FixedTimeEquals_Minus(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
        {
            // NoOptimization because we want this method to be exactly as non-short-circuiting
            // as written.
            //
            // NoInlining because the NoOptimization would get lost if the method got inlined.

            if (left.Length != right.Length)
            {
                return false;
            }

            int length = left.Length;
            int accum = 0;

            for (int i = 0; i < length; i++)
            {
                accum |= left[i] - right[i];
            }

            return accum == 0;
        }

        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        public static bool FixedTimeEquals_Xor(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
        {
            // NoOptimization because we want this method to be exactly as non-short-circuiting
            // as written.
            //
            // NoInlining because the NoOptimization would get lost if the method got inlined.

            if (left.Length != right.Length)
            {
                return false;
            }

            int length = left.Length;
            int accum = 0;

            for (int i = 0; i < length; i++)
            {
                accum |= left[i] ^ right[i];
            }

            return accum == 0;
        }

        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        public static bool FixedTimeEquals_And(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
        {
            // NoOptimization because we want this method to be exactly as non-short-circuiting
            // as written.
            //
            // NoInlining because the NoOptimization would get lost if the method got inlined.

            if (left.Length != right.Length)
            {
                return false;
            }

            int length = left.Length;
            bool accum = true;

            for (int i = 0; i < length; i++)
            {
                accum &= left[i] == right[i];
            }

            return accum;
        }


        internal static byte[] HexToByteArray(string hexString)
        {
            byte[] bytes = new byte[hexString.Length / 2];

            for (int i = 0; i < hexString.Length; i += 2)
            {
                string s = hexString.Substring(i, 2);
                bytes[i / 2] = byte.Parse(s, NumberStyles.HexNumber, null);
            }

            return bytes;
        }

    }
}
