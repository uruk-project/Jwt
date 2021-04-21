using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Diagnosers;

namespace JsonWebToken.Performance
{
    [MemoryDiagnoser]
    [DisassemblyDiagnoser(exportDiff: true)]
    public class FixedTimeEqualsBenchmarks
    {
        [Benchmark]
        public bool FixedTimeEquals_New()
        {
            return Cryptography.CryptographicOperations.FixedTimeEquals(Data, Data);
        }

        [Benchmark(Baseline = true)]
        public bool FixedTimeEquals()
        {
            return FixedTimeEquals(Data, Data);
        }

        //[Benchmark]
        //public bool FixedTimeEquals_unsafe()
        //{
        //    return FixedTimeEquals_unsafe(Data, Data);
        //}

        ////[Benchmark]
        ////public bool FixedTimeEquals_unsafe_unchecked()
        ////{
        ////    return FixedTimeEquals_unsafe(Data, Data);
        ////}

        ////[Benchmark]
        ////public bool FixedTimeEquals_unchecked()
        ////{
        ////    return FixedTimeEquals_unchecked(Data, Data);
        ////}

        ////[Benchmark]
        ////public bool FixedTimeEquals2()
        ////{
        ////    return FixedTimeEquals2(Data, Data);
        ////}

        ////[Benchmark]
        ////public bool FixedTimeEquals_static_long()
        ////{
        ////    return FixedTimeEquals_static_long(Data, Data);
        ////}

        ////[Benchmark]
        ////public bool FixedTimeEquals_static_int()
        ////{
        ////    return FixedTimeEquals_static_int(Data, Data);
        ////}

        //[Benchmark]
        //public bool FixedTimeEquals_static_int_unsafe()
        //{
        //    return FixedTimeEquals_static_int_unsafe(Data, Data);
        //}

        ////[Benchmark]
        ////public bool FixedTimeEquals_static_long_unsafe()
        ////{
        ////    return FixedTimeEquals_static_long_unsafe(Data, Data);
        ////}

        //[Benchmark]
        //public bool FixedTimeEquals_static_int_unsafe_simcrypt()
        //{
        //    return FixedTimeEquals_static_int_unsafe_simcrypt(Data, Data);
        //}

        //[Benchmark]
        //public bool FixedTimeEquals_static_int_unsafe_simcrypt_optimized()
        //{
        //    return FixedTimeEquals_static_int_unsafe_simcrypt_optimized(Data, Data);
        //}

        //[Benchmark]
        //public bool FixedTimeEquals_static_int_unsafe_overlap_end_intptr()
        //{
        //    return FixedTimeEquals_static_int_unsafe_overlap_end_intptr(Data, Data);
        //}
        //[Benchmark]
        //public bool FixedTimeEquals_static_int_unsafe_overlap_end()
        //{
        //    return FixedTimeEquals_static_int_unsafe_overlap_end(Data, Data);
        //}
        [Benchmark]
        public bool FixedTimeEquals_unsafe_optimized()
        {
            return FixedTimeEquals_static_int_unsafe_overlap_end_optimized(Data, Data);
        }

        [ParamsSource(nameof(Values))]
        public byte[] Data { get; set; } = Array.Empty<byte>();

        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        private static bool CryptographicEquals(byte[] a, byte[] b)
        {
            int result = 0;

            // Short cut if the lengths are not identical
            if (a.Length != b.Length)
                return false;

            unchecked
            {
                // Normally this caching doesn't matter, but with the optimizer off, this nets a non-trivial speedup.
                int aLength = a.Length;

                for (int i = 0; i < aLength; i++)
                    // We use subtraction here instead of XOR because the XOR algorithm gets ever so
                    // slightly faster as more and more differences pile up.
                    // This cannot overflow more than once (and back to 0) because bytes are 1 byte
                    // in length, and result is 4 bytes. The OR propagates all set bytes, so the differences
                    // can't add up and overflow a second time.
                    result = result | (a[i] - b[i]);
            }

            return (0 == result);
        }


        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        public static bool FixedTimeEquals(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
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
        public static unsafe bool FixedTimeEquals_unsafe(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
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

            fixed (byte* l = left)
            fixed (byte* r = right)
            {
                for (int i = 0; i < length; i++)
                {
                    accum |= *(l + i) - *(r + i);
                }
            }

            return accum == 0;
        }

        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        public static unsafe bool FixedTimeEquals_unsafe_unchecked(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
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
            unchecked
            {
                int accum = 0;

                fixed (byte* l = left)
                fixed (byte* r = right)
                {
                    for (int i = 0; i < length; i += sizeof(int))
                    {
                        accum |= *(l + i) - *(r + i);
                    }
                }

                return accum == 0;
            }
        }

        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        public static bool FixedTimeEquals_reversed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
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

            for (int i = length - 1; i >= 0; i--)
            {
                accum |= left[i] - right[i];
            }

            return accum == 0;
        }


        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        public static bool FixedTimeEquals_unchecked(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
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
            unchecked
            {
                for (int i = 0; i < length; i++)
                {
                    accum |= left[i] - right[i];
                }

                return accum == 0;
            }
        }

        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        public static bool FixedTimeEquals2(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
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

            if ((length & sizeof(long) - 1) == 0)
            {
                ref byte l = ref MemoryMarshal.GetReference(left);
                ref byte r = ref MemoryMarshal.GetReference(right);
                ref byte end = ref Unsafe.AddByteOffset(ref l, (IntPtr)length);
                long accum = 0;
                IntPtr i = (IntPtr)0;
                while (Unsafe.IsAddressLessThan(ref l, ref end))
                {
                    accum |= (Unsafe.ReadUnaligned<long>(ref l) - Unsafe.ReadUnaligned<long>(ref r));
                    i += sizeof(long);
                    l = ref Unsafe.AddByteOffset(ref l, i);
                    r = ref Unsafe.AddByteOffset(ref r, i);
                }
                return accum == 0;
            }
            else if ((length & sizeof(int) - 1) == 0)
            {
                ref byte l = ref MemoryMarshal.GetReference(left);
                ref byte r = ref MemoryMarshal.GetReference(right);
                ref byte end = ref Unsafe.AddByteOffset(ref l, (IntPtr)length);
                int accum = 0;
                IntPtr i = (IntPtr)0;
                while (Unsafe.IsAddressLessThan(ref l, ref end))
                {
                    accum |= (Unsafe.ReadUnaligned<int>(ref l) - Unsafe.ReadUnaligned<int>(ref r));
                    i += sizeof(int);
                    l = ref Unsafe.AddByteOffset(ref l, i);
                    r = ref Unsafe.AddByteOffset(ref r, i);
                }
                return accum == 0;
            }
            else
            {
                int accum = 0;

                for (int i = 0; i < length; i++)
                {
                    accum |= left[i] - right[i];
                }

                return accum == 0;
            }
        }

        public static bool FixedTimeEquals_static_long(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
        {
            // NoOptimization because we want this method to be exactly as non-short-circuiting
            // as written.
            //
            // NoInlining because the NoOptimization would get lost if the method got inlined.

            int length = left.Length;
            if (length != right.Length)
            {
                return false;
            }

            if ((length & sizeof(long) - 1) == 0)
            {
                ref byte l = ref MemoryMarshal.GetReference(left);
                ref byte r = ref MemoryMarshal.GetReference(right);
                ref byte end = ref Unsafe.AddByteOffset(ref l, (IntPtr)length);
                return LoopLong(ref l, ref r, ref end);
            }
            else if ((length & sizeof(int) - 1) == 0)
            {
                ref byte l = ref MemoryMarshal.GetReference(left);
                ref byte r = ref MemoryMarshal.GetReference(right);
                ref byte end = ref Unsafe.AddByteOffset(ref l, (IntPtr)length);
                return LoopInt(ref l, ref r, ref end);
            }
            else
            {
                int accum = 0;

                for (int i = 0; i < length; i++)
                {
                    accum |= left[i] - right[i];
                }

                return accum == 0;
            }

            [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
            static bool LoopLong(ref byte l, ref byte r, ref byte end)
            {
                unchecked
                {
                    long accum = 0;
                    IntPtr i = (IntPtr)0;
                    while (Unsafe.IsAddressLessThan(ref l, ref end))
                    {
                        accum |= (Unsafe.ReadUnaligned<long>(ref l) - Unsafe.ReadUnaligned<long>(ref r));
                        i += sizeof(long);
                        l = ref Unsafe.AddByteOffset(ref l, i);
                        r = ref Unsafe.AddByteOffset(ref r, i);
                    }
                    return accum == 0;
                }
            }
            [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
            static bool LoopInt(ref byte l, ref byte r, ref byte end)
            {
                //unchecked
                {
                    int accum = 0;
                    IntPtr i = (IntPtr)0;
                    while (Unsafe.IsAddressLessThan(ref l, ref end))
                    {
                        accum |= (Unsafe.ReadUnaligned<int>(ref l) - Unsafe.ReadUnaligned<int>(ref r));
                        i += sizeof(int);
                        l = ref Unsafe.AddByteOffset(ref l, i);
                        r = ref Unsafe.AddByteOffset(ref r, i);
                    }
                    return accum == 0;
                }
            }
        }

        public static bool FixedTimeEquals_static_int(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
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

            if ((length & sizeof(int) - 1) == 0)
            {
                ref byte l = ref MemoryMarshal.GetReference(left);
                ref byte r = ref MemoryMarshal.GetReference(right);
                ref byte end = ref Unsafe.AddByteOffset(ref l, (IntPtr)length);
                return LoopInt(ref l, ref r, ref end);
            }
            else
            {
                int accum = 0;

                for (int i = 0; i < length; i++)
                {
                    accum |= left[i] - right[i];
                }

                return accum == 0;
            }

            [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
            static bool LoopInt(ref byte l, ref byte r, ref byte end)
            {
                //unchecked
                {
                    int accum = 0;
                    IntPtr i = (IntPtr)0;
                    while (Unsafe.IsAddressLessThan(ref l, ref end))
                    {
                        accum |= (Unsafe.ReadUnaligned<int>(ref l) - Unsafe.ReadUnaligned<int>(ref r));
                        i += sizeof(int);
                        l = ref Unsafe.AddByteOffset(ref l, i);
                        r = ref Unsafe.AddByteOffset(ref r, i);
                    }
                    return accum == 0;
                }
            }
        }

        public static unsafe bool FixedTimeEquals_static_int_unsafe(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
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

            if ((length & sizeof(int) - 1) == 0)
            {
                fixed (byte* l = left)
                fixed (byte* r = right)
                {
                    return LoopInt(l, r, length);
                }
            }
            else
            {
                int accum = 0;

                for (int i = 0; i < length; i++)
                {
                    accum |= left[i] - right[i];
                }

                return accum == 0;
            }

            [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
            static bool LoopInt(byte* l, byte* r, int length)
            {
                //unchecked
                {
                    int accum = 0;
                    for (int i = 0; i < length; i += sizeof(int))
                    {
                        accum |= *(int*)(l + i) - *(int*)(r + i);
                    }
                    return accum == 0;
                }
            }
        }

        public static unsafe bool FixedTimeEquals_static_int_unsafe_simcrypt(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
        {
            int length = left.Length;
            if (length != right.Length)
            {
                return false;
            }

            fixed (byte* l = left)
            fixed (byte* r = right)
            {
                return LoopInt(l, r, length) == 0;
            }

            // NoOptimization because we want this method to be exactly as non-short-circuiting
            // as written.
            //
            // NoInlining because the NoOptimization would get lost if the method got inlined.
            [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
            static int LoopInt(byte* l, byte* r, int length)
            {
                int accum = 0;
                unchecked
                {
                    while (length >= 4)
                    {
                        accum |= *(int*)l ^ *(int*)r;
                        l += 4;
                        r += 4;
                        length -= 4;
                    }

                    while (length > 0)
                    {
                        accum |= *l ^ *r;
                        l++;
                        r++;
                        length--;
                    }
                }

                return accum;
            }
        }

        public static unsafe bool FixedTimeEquals_static_int_unsafe_simcrypt_optimized(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
        {
            int length = left.Length;
            if (length != right.Length)
            {
                return false;
            }

            fixed (byte* l = left)
            fixed (byte* r = right)
            {
                return LoopInt(l, r, length) == 0;
            }

            // NoOptimization because we want this method to be exactly as non-short-circuiting
            // as written.
            //
            // NoInlining because the NoOptimization would get lost if the method got inlined.
            //[MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
            static int LoopInt(byte* l, byte* r, int length)
            {
                int accum = 0;
                unchecked
                {
                    while (length >= 4)
                    {
                        accum |= *(int*)l ^ *(int*)r;
                        l += 4;
                        r += 4;
                        length -= 4;
                    }

                    while (length > 0)
                    {
                        accum |= *l ^ *r;
                        l++;
                        r++;
                        length--;
                    }
                }

                return accum;
            }
        }

        public static unsafe bool FixedTimeEquals_static_int_unsafe_overlap_end(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
        {
            int length = left.Length;
            if (length != right.Length)
            {
                return false;
            }

            fixed (byte* l = left)
            fixed (byte* r = right)
            {
                return LoopInt(l, r, length) == 0;
            }

            // NoOptimization because we want this method to be exactly as non-short-circuiting
            // as written.
            //
            // NoInlining because the NoOptimization would get lost if the method got inlined.
            [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
            static int LoopInt(byte* l, byte* r, int length)
            {
                int offset = 0;
                int accumulator = 0;
                unchecked
                {
                    int end = length - sizeof(int);
                    while ((int)(byte*)offset < length)
                    {
                        accumulator |= *(int*)(l + offset) ^ *(int*)(r + offset);
                        offset += sizeof(int);
                    }

                    return accumulator | *(int*)(l + end) ^ *(int*)(r + end);
                }
            }
        }

        public static unsafe bool FixedTimeEquals_static_int_unsafe_overlap_end_optimized(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
        {
            int length = left.Length;
            if (length != right.Length)
            {
                return false;
            }

            fixed (byte* l = left)
            fixed (byte* r = right)
            {
                int offset = 0;
                int accumulator = 0;
                unchecked
                {
                    int end = length - sizeof(int);
                    while ((int)(byte*)offset < length)
                    {
                        accumulator |= *(int*)(l + offset) ^ *(int*)(r + offset);
                        offset += sizeof(int);
                    }

                    return (accumulator | *(int*)(l + end) ^ *(int*)(r + end)) == 0;
                }
            }
        }

        public static unsafe bool FixedTimeEquals_static_int_unsafe_overlap_end_intptr(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
        {
            int length = left.Length;
            if (length != right.Length)
            {
                return false;
            }

            ref byte l = ref MemoryMarshal.GetReference(left);
            ref byte r = ref MemoryMarshal.GetReference(right);
            return LoopInt(ref l, ref r, length) == 0;

            // NoOptimization because we want this method to be exactly as non-short-circuiting
            // as written.
            //
            // NoInlining because the NoOptimization would get lost if the method got inlined.
            [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
            static int LoopInt(ref byte l, ref byte r, int length)
            {
                IntPtr offset = IntPtr.Zero;
                int accumulator = 0;
                unchecked
                {
                    IntPtr end = (IntPtr)length - sizeof(int);
                    while ((int)(byte*)offset < length)
                    {
                        accumulator |= Unsafe.ReadUnaligned<int>(ref Unsafe.AddByteOffset(ref l, offset)) ^ Unsafe.ReadUnaligned<int>(ref Unsafe.AddByteOffset(ref r, offset));
                        offset += sizeof(int);
                    }

                    return accumulator | (Unsafe.ReadUnaligned<int>(ref Unsafe.AddByteOffset(ref l, end)) ^ Unsafe.ReadUnaligned<int>(ref Unsafe.AddByteOffset(ref r, end)));
                }
            }
        }

        public static unsafe bool FixedTimeEquals_static_long_unsafe(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
        {
            // NoOptimization because we want this method to be exactly as non-short-circuiting
            // as written.
            //
            // NoInlining because the NoOptimization would get lost if the method got inlined.

            int length = left.Length;
            if (length != right.Length)
            {
                return false;
            }

            if ((length & sizeof(long) - 1) == 0)
            {
                fixed (byte* l = left)
                fixed (byte* r = right)
                {
                    return LoopLong(l, r, length);
                }
            }
            else if ((length & sizeof(int) - 1) == 0)
            {
                fixed (byte* l = left)
                fixed (byte* r = right)
                {
                    return LoopInt(l, r, length);
                }
            }
            else
            {
                unchecked
                {
                    int accum = 0;

                    for (int i = 0; i < length; i++)
                    {
                        accum |= left[i] - right[i];
                    }

                    return accum == 0;
                }
            }

            [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
            static bool LoopLong(byte* l, byte* r, int length)
            {
                unchecked
                {
                    long accum = 0;
                    for (int i = 0; i < length; i += sizeof(long))
                    {
                        accum |= *(long*)(l + i) - *(long*)(r + i);
                    }
                    return accum == 0;
                }
            }

            [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
            static bool LoopInt(byte* l, byte* r, int length)
            {
                unchecked
                {
                    int accum = 0;
                    for (int i = 0; i < length; i += sizeof(int))
                    {
                        accum |= *(int*)(l + i) - *(int*)(r + i);
                    }
                    return accum == 0;
                }
            }
        }

        public static IEnumerable<byte[]> Values()
        {
            yield return new byte[16];
            yield return new byte[64];
            yield return new byte[1024];
        }
    }
}
